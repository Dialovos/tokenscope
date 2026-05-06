//! Wire-format types shared between the BPF programs and userspace.
//! Layout MUST match `bpf/ts_event.h`. The static assertions in this
//! module are tripwires for accidental drift.

use core::mem::{align_of, size_of};

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TsEventType {
    NetConnect = 1,
    NetBytes = 2,
    TlsPlaintext = 3,
    LlmReqStart = 4,
    LlmReqEnd = 5,
    LlmToken = 6,
    ProcExec = 7,
    ProcExit = 8,
    CgroupNew = 9,
    CgroupGone = 10,
    Anomaly = 11,
    GpuSample = 12,
}

impl TsEventType {
    /// Convert the on-wire u16 into the typed enum, returning `None` for unknown values.
    /// Unknown values can occur during a rolling upgrade where the daemon is older than
    /// the BPF program — never panic.
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            1 => Some(Self::NetConnect),
            2 => Some(Self::NetBytes),
            3 => Some(Self::TlsPlaintext),
            4 => Some(Self::LlmReqStart),
            5 => Some(Self::LlmReqEnd),
            6 => Some(Self::LlmToken),
            7 => Some(Self::ProcExec),
            8 => Some(Self::ProcExit),
            9 => Some(Self::CgroupNew),
            10 => Some(Self::CgroupGone),
            11 => Some(Self::Anomaly),
            12 => Some(Self::GpuSample),
            _ => None,
        }
    }
}

/// Mirror of `struct ts_event_hdr` in `bpf/ts_event.h`.
///
/// Layout (natural alignment, no `packed`):
/// - 0..8   ts_ns      (u64)
/// - 8..12  cpu        (u32)
/// - 12..16 pid        (u32)
/// - 16..20 tgid       (u32)
/// - 20..24 _pad       (u32, padding to 8-byte align cgroup_id)
/// - 24..32 cgroup_id  (u64)
/// - 32..34 ty         (u16)
/// - 34..36 len        (u16)
/// - 36..40 _tail_pad  (u32, padding to round struct size up to 8-byte align)
///
/// Total size: 40 bytes. Alignment: 8.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TsEventHdr {
    pub ts_ns: u64,
    pub cpu: u32,
    pub pid: u32,
    pub tgid: u32,
    pub cgroup_id: u64,
    pub ty: u16,
    pub len: u16,
}

const _: () = assert!(size_of::<TsEventHdr>() == 40);
const _: () = assert!(align_of::<TsEventHdr>() == 8);

/// Errors that can happen while decoding a ringbuf record.
#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("event too short: got {got} bytes, need at least {need}")]
    Truncated { got: usize, need: usize },
    #[error("declared payload length {declared} exceeds available {available}")]
    BadLength { declared: usize, available: usize },
}

/// Decode a `TsEventHdr` from a ringbuf-delivered byte slice.
///
/// Reads unaligned to be safe regardless of how libbpf-rs hands us the buffer.
pub fn decode_header(buf: &[u8]) -> Result<TsEventHdr, DecodeError> {
    if buf.len() < size_of::<TsEventHdr>() {
        return Err(DecodeError::Truncated {
            got: buf.len(),
            need: size_of::<TsEventHdr>(),
        });
    }
    let hdr = unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const TsEventHdr) };
    let payload_avail = buf.len() - size_of::<TsEventHdr>();
    if hdr.len as usize > payload_avail {
        return Err(DecodeError::BadLength {
            declared: hdr.len as usize,
            available: payload_avail,
        });
    }
    Ok(hdr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_size_is_forty() {
        assert_eq!(size_of::<TsEventHdr>(), 40);
    }

    #[test]
    fn header_alignment_is_eight() {
        assert_eq!(align_of::<TsEventHdr>(), 8);
    }

    #[test]
    fn decode_truncated() {
        let buf = [0u8; 10];
        let err = decode_header(&buf).unwrap_err();
        assert!(matches!(err, DecodeError::Truncated { got: 10, need: 40 }));
    }

    #[test]
    fn decode_round_trip() {
        let original = TsEventHdr {
            ts_ns: 0xDEAD_BEEF_CAFE_F00D,
            cpu: 3,
            pid: 1234,
            tgid: 1234,
            cgroup_id: 0x4242_4242_4242_4242,
            ty: TsEventType::ProcExec as u16,
            len: 0,
        };
        let bytes: [u8; 40] = unsafe { core::mem::transmute(original) };
        let decoded = decode_header(&bytes).unwrap();
        assert_eq!(decoded.ts_ns, original.ts_ns);
        assert_eq!(decoded.cpu, original.cpu);
        assert_eq!(decoded.pid, original.pid);
        assert_eq!(decoded.tgid, original.tgid);
        assert_eq!(decoded.cgroup_id, original.cgroup_id);
        assert_eq!(decoded.ty, original.ty);
        assert_eq!(decoded.len, original.len);
        assert_eq!(
            TsEventType::from_u16(decoded.ty),
            Some(TsEventType::ProcExec)
        );
    }

    #[test]
    fn unknown_event_type_is_none() {
        assert_eq!(TsEventType::from_u16(255), None);
    }

    #[test]
    fn net_connect_payload_size_is_24() {
        assert_eq!(core::mem::size_of::<TsNetConnectPayload>(), 24);
    }

    #[test]
    fn net_connect_v4_round_trip() {
        let pl = TsNetConnectPayload {
            dst_addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4],
            dst_port: 443,
            family: 2,
            protocol: 6,
            _pad: [0; 3],
        };
        let bytes: [u8; 24] = unsafe { core::mem::transmute(pl) };
        let decoded = decode_net_connect(&bytes).unwrap();
        assert_eq!(decoded.dst_string(), "1.2.3.4:443");
    }

    #[test]
    fn net_connect_v6_round_trip() {
        let pl = TsNetConnectPayload {
            dst_addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            dst_port: 80,
            family: 10,
            protocol: 6,
            _pad: [0; 3],
        };
        let bytes: [u8; 24] = unsafe { core::mem::transmute(pl) };
        let decoded = decode_net_connect(&bytes).unwrap();
        assert_eq!(decoded.dst_string(), "[::1]:80");
    }

    #[test]
    fn net_connect_truncated() {
        let buf = [0u8; 10];
        let err = decode_net_connect(&buf).unwrap_err();
        assert!(matches!(err, DecodeError::Truncated { got: 10, need: 24 }));
    }
}

/// Mirror of `struct ts_net_connect_payload` in `bpf/ts_event.h`.
///
/// Layout:
/// - 0..16  dst_addr  (16 bytes; IPv4 in last 4 for AF_INET, full IPv6 for AF_INET6)
/// - 16..18 dst_port  (u16, host byte order)
/// - 18..20 family    (u16: 2=AF_INET, 10=AF_INET6)
/// - 20..21 protocol  (u8)
/// - 21..24 _pad
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TsNetConnectPayload {
    pub dst_addr: [u8; 16],
    pub dst_port: u16,
    pub family: u16,
    pub protocol: u8,
    pub _pad: [u8; 3],
}

const _: () = assert!(core::mem::size_of::<TsNetConnectPayload>() == 24);

impl TsNetConnectPayload {
    /// Render the destination as a string (`"1.2.3.4:443"` / `"[::1]:80"`).
    pub fn dst_string(&self) -> String {
        match self.family {
            2 => {
                let ip = std::net::Ipv4Addr::new(
                    self.dst_addr[12],
                    self.dst_addr[13],
                    self.dst_addr[14],
                    self.dst_addr[15],
                );
                format!("{ip}:{}", self.dst_port)
            }
            10 => {
                let ip = std::net::Ipv6Addr::from(self.dst_addr);
                format!("[{ip}]:{}", self.dst_port)
            }
            other => format!("af{other}/{:?}:{}", &self.dst_addr[..], self.dst_port),
        }
    }
}

/// Decode a TS_NET_CONNECT payload (caller passes the slice AFTER the header).
pub fn decode_net_connect(payload: &[u8]) -> Result<TsNetConnectPayload, DecodeError> {
    let need = core::mem::size_of::<TsNetConnectPayload>();
    if payload.len() < need {
        return Err(DecodeError::Truncated {
            got: payload.len(),
            need,
        });
    }
    let pl = unsafe { core::ptr::read_unaligned(payload.as_ptr() as *const TsNetConnectPayload) };
    Ok(pl)
}
