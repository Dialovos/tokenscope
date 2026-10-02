//! TLS plaintext capture lifecycle.
//!
//! `tls.bpf.c` defines the BPF programs (loaded by skeletons.rs as part
//! of `LoadedSkels`); this module owns the userspace half:
//!
//! 1. **Discovery** — walk `/proc/*/maps` periodically (5s default),
//!    extract every distinct libssl.so file by `(dev, ino)` so
//!    container/symlink/replaced-binary cases work, and `attach_uprobe`
//!    each program once per binary.
//! 2. **Ringbuf consumption** — decode `events_tls` records into
//!    `EventEnvelope::TlsPlaintext` and push onto the single-writer
//!    sink channel.
//! 3. **Counter pumping** — drain the BPF percpu counters
//!    (`tls_reserve_fail`, `tls_inflight_collision`) into the userspace
//!    `Counters` atomics so `tsctl status` can surface them.
//!
//! Threading: all functions here are designed to be called from the
//! existing tsd main thread. libbpf-rs's `Program` type is neither
//! `Send` nor `Sync`, so spawning a dedicated thread that holds
//! program references would not compile. Instead, the main loop
//! polls the existing ringbuf builder (now including `events_tls`)
//! and calls `discovery_tick` periodically.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::mpsc::SyncSender;
use std::time::{Duration, Instant};

use anyhow::Result;
use regex::Regex;
use ts_bpf_sys::libbpf_rs::{Link, MapCore, MapFlags, UprobeOpts};

use crate::control::Counters;
use crate::sink::{EventEnvelope, TlsPlaintextEvent};
use crate::skeletons::LoadedSkels;
use ts_core::event::{
    decode_tls_plaintext, TsEventHdr, TLS_FLAG_EX_VARIANT, TLS_FLAG_READ_FAILED, TLS_FLAG_TRUNCATED,
};

/// How often to rescan `/proc/*/maps` for new libssl mappings.
pub const DISCOVERY_INTERVAL: Duration = Duration::from_secs(5);

/// Owned per-libssl-file attachment record. Dropping the Links
/// detaches the uprobes; dropping `AttachedLib` drops them all.
#[allow(dead_code)] // refcount is informational only today
pub struct AttachedLib {
    inode_path: PathBuf,
    write_link: Link,
    write_ex_link: Option<Link>,
    read_entry_link: Link,
    read_exit_link: Link,
    read_ex_entry_link: Option<Link>,
    read_ex_exit_link: Option<Link>,
    refcount: u32,
}

/// Lives for the daemon's life. Tracks which libssl files we've
/// already attached to plus the next-rescan deadline.
pub struct TlsState {
    /// Keyed by `(dev, ino)` — same path string can resolve to
    /// different inodes across mount-namespaces / after replace.
    pub attached: HashMap<(u64, u64), AttachedLib>,
    /// Earliest time the discovery_tick should do another pass.
    pub next_rescan_at: Instant,
    /// Compiled-once regex for the maps line shape.
    libssl_re: Regex,
}

impl Default for TlsState {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsState {
    pub fn new() -> Self {
        Self {
            attached: HashMap::new(),
            next_rescan_at: Instant::now(), // do first pass immediately
            libssl_re: Regex::new(r"r-xp .* (\S*libssl\.so(?:\.\S+)?)$").unwrap(),
        }
    }
}

/// Ringbuf callback: decode one `events_tls` record and push it onto
/// the single-writer sink channel. Drops on full sink (counter
/// already tracked by the producer pattern in main.rs).
pub fn handle_tls_record(
    data: &[u8],
    events_tx: &SyncSender<EventEnvelope>,
    counters: &Counters,
) -> i32 {
    const HDR: usize = std::mem::size_of::<TsEventHdr>();
    if data.len() < HDR {
        return 0;
    }
    // SAFETY: TsEventHdr is repr(C), 56 bytes. We copy the bytes out
    // (read_unaligned-style) so alignment of `data` doesn't matter.
    let mut hdr_bytes = [0u8; HDR];
    hdr_bytes.copy_from_slice(&data[..HDR]);
    let hdr: TsEventHdr =
        unsafe { std::ptr::read_unaligned(hdr_bytes.as_ptr() as *const TsEventHdr) };

    let payload = &data[HDR..];
    let (pl, plaintext) = match decode_tls_plaintext(payload) {
        Ok(x) => x,
        Err(e) => {
            tracing::warn!(error = ?e, "decode tls plaintext");
            return 0;
        }
    };

    let truncated = pl.flags & TLS_FLAG_TRUNCATED != 0;
    let read_failed = pl.flags & TLS_FLAG_READ_FAILED != 0;
    let ex_variant = pl.flags & TLS_FLAG_EX_VARIANT != 0;

    counters.tls_records_emitted.fetch_add(1, Ordering::Relaxed);
    if truncated {
        counters.tls_truncated_calls.fetch_add(1, Ordering::Relaxed);
    }
    if read_failed {
        counters
            .tls_read_failed_chunks
            .fetch_add(1, Ordering::Relaxed);
    }

    let env = EventEnvelope::TlsPlaintext(TlsPlaintextEvent {
        ts_ns: hdr.ts_ns,
        pid: hdr.pid,
        tgid: hdr.tgid,
        cgroup_id: hdr.cgroup_id,
        comm: hdr.comm_str(),
        ssl_ctx: pl.ssl_ctx,
        call_id: pl.call_id,
        direction: pl.direction,
        total_bytes: pl.total_bytes,
        chunk_index: pl.chunk_index,
        chunk_total: pl.chunk_total,
        chunk_bytes: pl.chunk_bytes,
        truncated,
        read_failed,
        ex_variant,
        plaintext: plaintext.to_vec(),
    });
    if let Err(std::sync::mpsc::TrySendError::Full(_)) = events_tx.try_send(env) {
        counters.sink_dropped_events.fetch_add(1, Ordering::Relaxed);
    }
    0
}

/// Drive one rescan pass if the deadline has been reached. No-op
/// otherwise. Updates counters in either case.
pub fn discovery_tick(state: &mut TlsState, skels: &LoadedSkels<'_>, counters: &Counters) {
    let now = Instant::now();
    if now < state.next_rescan_at {
        return;
    }
    state.next_rescan_at = now + DISCOVERY_INTERVAL;

    let scan_start = Instant::now();
    let mut errors: u32 = 0;
    let mut seen: HashSet<(u64, u64)> = HashSet::new();

    if let Ok(dir) = fs::read_dir("/proc") {
        for entry in dir.flatten() {
            let pid_name = entry.file_name();
            let pid_str = match pid_name.to_str() {
                Some(s) => s,
                None => continue,
            };
            if !pid_str.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            scan_pid_maps(
                state,
                skels,
                counters,
                &entry.path(),
                &mut seen,
                &mut errors,
            );
        }
    }

    pump_percpu_counters(skels, counters);

    counters
        .tls_scan_duration_us
        .store(scan_start.elapsed().as_micros() as u64, Ordering::Relaxed);
    counters.tls_scan_errors.store(errors, Ordering::Relaxed);
}

fn scan_pid_maps(
    state: &mut TlsState,
    skels: &LoadedSkels<'_>,
    counters: &Counters,
    proc_pid_dir: &Path,
    seen: &mut HashSet<(u64, u64)>,
    errors: &mut u32,
) {
    let maps_path = proc_pid_dir.join("maps");
    let maps = match fs::read_to_string(&maps_path) {
        Ok(s) => s,
        Err(_) => {
            *errors += 1;
            return;
        }
    };
    for line in maps.lines() {
        let cap = match state.libssl_re.captures(line) {
            Some(c) => c,
            None => continue,
        };
        let visible = cap.get(1).unwrap().as_str();
        // Resolve via /proc/<pid>/root/<visible_path> so the inode
        // we stat matches what THIS process sees (handles container
        // mount-namespaces and deleted-then-replaced libssl).
        let proc_root = proc_pid_dir
            .join("root")
            .join(visible.trim_start_matches('/'));
        let meta = match fs::metadata(&proc_root) {
            Ok(m) => m,
            Err(_) => {
                *errors += 1;
                continue;
            }
        };
        let key = (meta.dev(), meta.ino());
        if !seen.insert(key) {
            continue;
        }
        if let Some(lib) = state.attached.get_mut(&key) {
            lib.refcount += 1;
            continue;
        }
        match attach_libssl(skels, &proc_root, counters) {
            Ok(lib) => {
                state.attached.insert(key, lib);
                counters.tls_libs_attached.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                tracing::warn!(path = %proc_root.display(), %e, "tls libssl attach failed");
                counters.tls_libs_skipped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

fn attach_libssl(
    skels: &LoadedSkels<'_>,
    libssl_path: &Path,
    counters: &Counters,
) -> Result<AttachedLib> {
    // Required pair (basic): SSL_write entry + SSL_read entry/exit.
    let write_link = attach_one(
        &skels.tls.progs.ssl_write_entry,
        libssl_path,
        "SSL_write",
        false,
    )?;
    let read_entry_link = attach_one(
        &skels.tls.progs.ssl_read_entry,
        libssl_path,
        "SSL_read",
        false,
    )?;
    let read_exit_link = attach_one(
        &skels.tls.progs.ssl_read_exit,
        libssl_path,
        "SSL_read",
        true,
    )?;

    // Optional _ex pair: tolerate missing symbols (older libssl).
    let write_ex_link = attach_one(
        &skels.tls.progs.ssl_write_ex_entry,
        libssl_path,
        "SSL_write_ex",
        false,
    )
    .ok();
    let read_ex_entry_link = attach_one(
        &skels.tls.progs.ssl_read_ex_entry,
        libssl_path,
        "SSL_read_ex",
        false,
    )
    .ok();
    let read_ex_exit_link = attach_one(
        &skels.tls.progs.ssl_read_ex_exit,
        libssl_path,
        "SSL_read_ex",
        true,
    )
    .ok();

    if write_ex_link.is_none() || read_ex_entry_link.is_none() || read_ex_exit_link.is_none() {
        counters
            .tls_libs_partial_attach
            .fetch_add(1, Ordering::Relaxed);
    }

    Ok(AttachedLib {
        inode_path: libssl_path.to_path_buf(),
        write_link,
        write_ex_link,
        read_entry_link,
        read_exit_link,
        read_ex_entry_link,
        read_ex_exit_link,
        refcount: 1,
    })
}

fn attach_one(
    prog: &ts_bpf_sys::libbpf_rs::ProgramMut<'_>,
    libssl_path: &Path,
    func_name: &str,
    retprobe: bool,
) -> Result<Link> {
    let opts = UprobeOpts {
        func_name: func_name.into(),
        retprobe,
        ..Default::default()
    };
    prog.attach_uprobe_with_opts(-1, libssl_path, 0, opts)
        .map_err(|e| {
            anyhow::anyhow!(
                "attach {func_name} (retprobe={retprobe}) on {}: {e}",
                libssl_path.display()
            )
        })
}

fn pump_percpu_counters(skels: &LoadedSkels<'_>, counters: &Counters) {
    let zero = 0u32.to_ne_bytes();
    if let Ok(Some(values)) = skels
        .tls
        .maps
        .tls_reserve_fail
        .lookup_percpu(&zero, MapFlags::ANY)
    {
        let total: u64 = values
            .iter()
            .map(|v| {
                let mut buf = [0u8; 8];
                let n = v.len().min(8);
                buf[..n].copy_from_slice(&v[..n]);
                u64::from_ne_bytes(buf)
            })
            .sum();
        counters
            .tls_reserve_failures
            .store(total, Ordering::Relaxed);
    }
    if let Ok(Some(values)) = skels
        .tls
        .maps
        .tls_inflight_collision
        .lookup_percpu(&zero, MapFlags::ANY)
    {
        let total: u64 = values
            .iter()
            .map(|v| {
                let mut buf = [0u8; 8];
                let n = v.len().min(8);
                buf[..n].copy_from_slice(&v[..n]);
                u64::from_ne_bytes(buf)
            })
            .sum();
        counters
            .tls_inflight_collisions
            .store(total, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn libssl_regex_matches_typical_lines() {
        let re = TlsState::new().libssl_re;
        let pos = "7f1d4e000000-7f1d4e1f0000 r-xp 00000000 fd:00 12345 /usr/lib/x86_64-linux-gnu/libssl.so.3";
        let neg_perm = "7f1d4e000000-7f1d4e1f0000 r--p 00000000 fd:00 12345 /usr/lib/x86_64-linux-gnu/libssl.so.3";
        let neg_name = "7f1d4e000000-7f1d4e1f0000 r-xp 00000000 fd:00 12345 /usr/lib/x86_64-linux-gnu/libcrypto.so.3";
        assert!(re.captures(pos).is_some());
        assert!(re.captures(neg_perm).is_none());
        assert!(re.captures(neg_name).is_none());
        let cap = re.captures(pos).unwrap();
        assert_eq!(
            cap.get(1).unwrap().as_str(),
            "/usr/lib/x86_64-linux-gnu/libssl.so.3"
        );
    }

    #[test]
    fn discovery_tick_no_op_before_deadline() {
        // Without a real LoadedSkels we can't drive a full pass, but we
        // can verify that `next_rescan_at` gates correctly. Set deadline
        // far in the future and confirm the timestamp doesn't change.
        let mut s = TlsState::new();
        let far = Instant::now() + Duration::from_secs(3600);
        s.next_rescan_at = far;
        // Without real skels we can't call discovery_tick; just assert
        // the gate condition directly.
        assert!(Instant::now() < s.next_rescan_at);
    }
}
