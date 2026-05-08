//! Wire types for the tsd ↔ tsctl Unix-domain-socket control plane.
//!
//! Newline-delimited JSON. The server reads one `Request` per
//! connection; the client reads one `StatusResponse` (status) or a
//! stream of `TailEvent`s (tail). On bad input the server replies
//! with one `ErrorResponse` and closes.
//!
//! These types are a **stable API surface** per SPEC §10. Adding a new
//! `Request` op or `TailEvent` variant is a minor version bump in
//! pre-1.0; renaming or removing fields is a major bump.

use serde::{Deserialize, Serialize};

/// Bumped when the wire format changes incompatibly. Server includes
/// it in `StatusResponse` so clients can warn on mismatch.
pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Status,
    Tail {
        /// Phase 2.A opt-in: when true, the server includes decrypted
        /// TLS plaintext bytes (with redaction) inline in tail frames
        /// for THIS subscriber. Default false keeps the wire shape of
        /// `{"op":"tail"}` from older tsctl backward-compatible.
        #[serde(default)]
        include_plaintext: bool,
    },
    Query {
        sql: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatusResponse {
    pub protocol_version: u32,
    pub version: String,
    pub uptime_s: u64,
    pub db_path: String,
    pub uds_path: String,
    pub probes_attached: Vec<String>,
    pub events_total: u64,
    /// Counts userspace `ringbuf.poll()` errors, NOT BPF-side ringbuf
    /// drops. A real drop counter via `bpf_ringbuf_query(0)` lands in
    /// Phase 2.
    pub ringbuf_poll_errors: u64,
    pub tail_subscribers_active: u32,

    // ---- Phase 2.A counters. #[serde(default)] keeps a new tsctl
    //      talking to an old tsd from blowing up on missing fields. ----
    #[serde(default)]
    pub tail_dropped_events: u64,
    #[serde(default)]
    pub sink_dropped_events: u64,
    #[serde(default)]
    pub tls_libs_attached: u32,
    #[serde(default)]
    pub tls_libs_skipped: u32,
    #[serde(default)]
    pub tls_libs_partial_attach: u32,
    #[serde(default)]
    pub tls_records_emitted: u64,
    #[serde(default)]
    pub tls_truncated_calls: u64,
    #[serde(default)]
    pub tls_read_failed_chunks: u64,
    #[serde(default)]
    pub tls_inflight_collisions: u64,
    #[serde(default)]
    pub tls_reserve_failures: u64,
    #[serde(default)]
    pub tls_scan_duration_us: u64,
    #[serde(default)]
    pub tls_scan_errors: u32,
    #[serde(default)]
    pub tls_subscribers_with_plaintext: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorResponse {
    pub error: String,
}

/// Live event emitted on tail subscriptions. `type` is the JSON tag.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TailEvent {
    ProcExec {
        ts_ns: u64,
        pid: u32,
        tgid: u32,
        comm: String,
        cmdline: String,
        /// Hex string ("0x15") — cgroup IDs are 64-bit and lose
        /// precision in JSON numbers (max safe = 2^53).
        cgroup_id: String,
    },
    NetConnect {
        ts_ns: u64,
        pid: u32,
        tgid: u32,
        comm: String,
        cmdline: String,
        cgroup_id: String,
        /// "1.2.3.4:443" or "[::1]:80"
        dst: String,
        family: u16,
        protocol: u8,
    },
    NetBytes {
        snapshot_ts_ns: u64,
        /// Hex string for the same reason as cgroup_id.
        sock_cookie: String,
        pid: u32,
        comm: String,
        cmdline: String,
        tx: u64,
        rx: u64,
        last_event_ns: u64,
    },
}

/// Streamed response to a `Request::Query`. The server sends exactly
/// one `Header` (or zero, if prepare itself fails), then zero or more
/// `Row`s, then exactly one terminator: `End` on success, `Error` on
/// failure or hard-cap overflow.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum QueryFrame {
    Header {
        columns: Vec<String>,
    },
    Row {
        /// One stringified value per column. Cells longer than 64 KiB
        /// are truncated by the server (at the last UTF-8 char
        /// boundary) and suffixed with `…[+N more bytes]`.
        values: Vec<String>,
    },
    End {
        row_count: u64,
        elapsed_ms: u64,
    },
    Error {
        message: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_status_round_trip() {
        let r = Request::Status;
        let s = serde_json::to_string(&r).unwrap();
        assert_eq!(s, r#"{"op":"status"}"#);
        assert_eq!(serde_json::from_str::<Request>(&s).unwrap(), r);
    }

    #[test]
    fn request_tail_round_trip() {
        let r = Request::Tail {
            include_plaintext: false,
        };
        let s = serde_json::to_string(&r).unwrap();
        // With #[serde(default)] the field is still emitted on
        // serialize; only deserialize is forgiving (tested below).
        assert_eq!(s, r#"{"op":"tail","include_plaintext":false}"#);
        assert_eq!(serde_json::from_str::<Request>(&s).unwrap(), r);
    }

    #[test]
    fn tail_request_default_include_plaintext_is_false() {
        // Backward-compat for old tsctl that sends the bare op tag.
        let r: Request = serde_json::from_str(r#"{"op":"tail"}"#).unwrap();
        match r {
            Request::Tail { include_plaintext } => assert!(!include_plaintext),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn tail_request_explicit_include_plaintext_true() {
        let r: Request = serde_json::from_str(r#"{"op":"tail","include_plaintext":true}"#).unwrap();
        match r {
            Request::Tail { include_plaintext } => assert!(include_plaintext),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn unknown_op_fails_to_deserialize() {
        let err = serde_json::from_str::<Request>(r#"{"op":"nope"}"#);
        assert!(err.is_err());
    }

    #[test]
    fn status_response_round_trip() {
        let r = StatusResponse {
            protocol_version: PROTOCOL_VERSION,
            version: "0.1.0".into(),
            uptime_s: 42,
            db_path: "/tmp/x.duckdb".into(),
            uds_path: "/tmp/tsd.sock".into(),
            probes_attached: vec!["sched_exec".into(), "tcp_sendmsg".into()],
            events_total: 100,
            ringbuf_poll_errors: 0,
            tail_subscribers_active: 2,
        };
        let s = serde_json::to_string(&r).unwrap();
        let back: StatusResponse = serde_json::from_str(&s).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn error_response_round_trip() {
        let r = ErrorResponse {
            error: "bad request: missing field `op`".into(),
        };
        let s = serde_json::to_string(&r).unwrap();
        let back: ErrorResponse = serde_json::from_str(&s).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn tail_event_proc_exec_round_trip() {
        let e = TailEvent::ProcExec {
            ts_ns: 123,
            pid: 4,
            tgid: 4,
            comm: "true".into(),
            cmdline: "[<gone>]".into(),
            cgroup_id: "0x15".into(),
        };
        let s = serde_json::to_string(&e).unwrap();
        assert!(s.contains(r#""type":"proc_exec""#));
        assert_eq!(serde_json::from_str::<TailEvent>(&s).unwrap(), e);
    }

    #[test]
    fn tail_event_net_bytes_round_trip() {
        let e = TailEvent::NetBytes {
            snapshot_ts_ns: 1,
            sock_cookie: "0xCAFE".into(),
            pid: 42,
            comm: "curl".into(),
            cmdline: "curl example.com".into(),
            tx: 1024,
            rx: 2048,
            last_event_ns: 99,
        };
        let s = serde_json::to_string(&e).unwrap();
        assert!(s.contains(r#""type":"net_bytes""#));
        assert!(s.contains(r#""tx":1024"#));
        assert_eq!(serde_json::from_str::<TailEvent>(&s).unwrap(), e);
    }

    #[test]
    fn request_query_round_trip() {
        let r = Request::Query {
            sql: "SELECT 1".into(),
        };
        let s = serde_json::to_string(&r).unwrap();
        assert_eq!(s, r#"{"op":"query","sql":"SELECT 1"}"#);
        assert_eq!(serde_json::from_str::<Request>(&s).unwrap(), r);
    }

    #[test]
    fn query_frame_header_round_trip() {
        let f = QueryFrame::Header {
            columns: vec!["comm".into(), "n".into()],
        };
        let s = serde_json::to_string(&f).unwrap();
        assert!(s.contains(r#""kind":"header""#));
        assert_eq!(serde_json::from_str::<QueryFrame>(&s).unwrap(), f);
    }

    #[test]
    fn query_frame_row_round_trip() {
        let f = QueryFrame::Row {
            values: vec!["curl".into(), "42".into()],
        };
        let s = serde_json::to_string(&f).unwrap();
        assert!(s.contains(r#""kind":"row""#));
        assert_eq!(serde_json::from_str::<QueryFrame>(&s).unwrap(), f);
    }

    #[test]
    fn query_frame_end_round_trip() {
        let f = QueryFrame::End {
            row_count: 2,
            elapsed_ms: 4,
        };
        let s = serde_json::to_string(&f).unwrap();
        assert!(s.contains(r#""kind":"end""#));
        assert_eq!(serde_json::from_str::<QueryFrame>(&s).unwrap(), f);
    }

    #[test]
    fn query_frame_error_round_trip() {
        let f = QueryFrame::Error {
            message: "syntax error".into(),
        };
        let s = serde_json::to_string(&f).unwrap();
        assert!(s.contains(r#""kind":"error""#));
        assert_eq!(serde_json::from_str::<QueryFrame>(&s).unwrap(), f);
    }
}
