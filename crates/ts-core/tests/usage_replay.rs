use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use ts_core::usage::*;
/// A tracker fed with the stream offsets tls.bpf.c attaches: each direction's
/// calls are contiguous unless a test supplies an explicit offset.
struct Replay {
    t: UsageTracker,
    next: HashMap<(ConnectionKey, u8), u64>,
    /// One clock for call entry (`call_id`) and return (`ts_ns`) times.
    clock: u64,
}
impl Default for Replay {
    fn default() -> Self {
        Self::new(Limits::default())
    }
}
impl Replay {
    fn new(limits: Limits) -> Self {
        Self {
            t: UsageTracker::new(limits),
            next: HashMap::new(),
            clock: 100,
        }
    }
    /// Entry and return times of the next call.
    fn tick(&mut self) -> (u64, u64) {
        self.clock += 2;
        (self.clock - 1, self.clock)
    }
    fn offset(&self, k: ConnectionKey, dir: u8) -> u64 {
        self.next.get(&(k, dir)).copied().unwrap_or(0)
    }
}
impl Deref for Replay {
    type Target = UsageTracker;
    fn deref(&self) -> &UsageTracker {
        &self.t
    }
}
impl DerefMut for Replay {
    fn deref_mut(&mut self) -> &mut UsageTracker {
        &mut self.t
    }
}
fn key() -> ConnectionKey {
    ConnectionKey {
        tgid: 7,
        process_start: 11,
        exec_generation: 1,
        ssl_ctx: 19,
        generation: 23,
    }
}
fn request() -> Vec<u8> {
    b"POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nAuthorization: Bearer PRIVATE-HEADER\r\nContent-Length: 27\r\n\r\n{\"prompt\":\"PRIVATE-PROMPT\"}".to_vec()
}
fn response(body: &str, sse: bool, chunked: bool) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {}\r\n",
        if sse {
            "text/event-stream"
        } else {
            "application/json"
        }
    );
    if chunked {
        out.push_str("Transfer-Encoding: chunked\r\n\r\n");
        out.push_str(&format!(
            "{:x};x=test\r\n{}\r\n0\r\nX-Test: ignored\r\n\r\n",
            body.len(),
            body
        ));
    } else {
        out.push_str(&format!("Content-Length: {}\r\n\r\n{}", body.len(), body));
    }
    out.into_bytes()
}
const COUNTS: &str = r#"{"choices":[],"usage":{"prompt_tokens":5,"completion_tokens":3,"total_tokens":8,"prompt_tokens_details":{"cached_tokens":2},"completion_tokens_details":{"reasoning_tokens":1}}}"#;
fn feed(t: &mut Replay, dir: u8, seq: u64, bytes: &[u8]) -> Vec<UsageObservation> {
    let offset = t.offset(key(), dir);
    feed_at(t, dir, seq, offset, bytes)
}
/// One single-chunk call at an explicit stream offset.
fn feed_at(t: &mut Replay, dir: u8, seq: u64, offset: u64, bytes: &[u8]) -> Vec<UsageObservation> {
    t.next.insert((key(), dir), offset + bytes.len() as u64);
    let (entry, ret) = t.tick();
    t.feed(CaptureChunk {
        connection: key(),
        ts_ns: ret,
        direction: dir,
        sequence: seq,
        loss_epoch: 0,
        call_id: entry,
        offset,
        chunk_index: 0,
        chunk_total: 1,
        total_bytes: bytes.len() as u32,
        truncated: false,
        failed: false,
        end: false,
        data: bytes,
    })
}
fn one(body: &str, sse: bool, chunked: bool) -> UsageObservation {
    let mut t = Replay::default();
    assert!(feed(&mut t, 0, 1, &request()).is_empty());
    let out = feed(&mut t, 1, 1, &response(body, sse, chunked));
    assert_eq!(out.len(), 1, "{out:?}");
    out.into_iter().next().unwrap()
}
#[test]
fn json_and_chunked_sse_at_every_split_boundary() {
    for (body, sse, chunks) in [
        (COUNTS.to_string(), false, false),
        (
            format!(": comment\r\ndata: {COUNTS}\r\n\r\ndata: [DONE]\r\n\r\n"),
            true,
            true,
        ),
    ] {
        let wire = response(&body, sse, chunks);
        for split in 1..wire.len() {
            let mut t = Replay::default();
            feed(&mut t, 0, 1, &request());
            let mut out = feed(&mut t, 1, 1, &wire[..split]);
            out.extend(feed(&mut t, 1, 2, &wire[split..]));
            assert_eq!(out.len(), 1, "split={split} {out:?}");
            assert_eq!(out[0].usage_state, "reported");
            assert_eq!(out[0].request_ordinal, Some(1));
            assert_eq!(out[0].reports[0].input, Some(5));
            assert_eq!(out[0].reports[0].cached_input, Some(2));
            let serialized = serde_json::to_string(&out).unwrap();
            for secret in ["PRIVATE-HEADER", "PRIVATE-PROMPT", "choices"] {
                assert!(!serialized.contains(secret));
            }
        }
    }
}
#[test]
fn requests_are_incremental_and_retries_are_not_deduplicated_by_content() {
    let bytes = request();
    for split in 1..bytes.len() {
        let mut t = Replay::default();
        feed(&mut t, 0, 1, &bytes[..split]);
        feed(&mut t, 0, 2, &bytes[split..]);
        feed(&mut t, 0, 3, &bytes);
        let r = response(COUNTS, false, false);
        let a = feed(&mut t, 1, 1, &r);
        let b = feed(&mut t, 1, 2, &r);
        assert_eq!(a[0].request_ordinal, Some(1));
        assert_eq!(b[0].request_ordinal, Some(2));
    }
}
#[test]
fn explicit_zero_missing_and_partial_are_distinct() {
    let zero = one(
        r#"{"usage":{"prompt_tokens":0,"completion_tokens":0,"total_tokens":0}}"#,
        false,
        false,
    );
    assert_eq!(zero.usage_state, "reported");
    assert_eq!(zero.reports[0].input, Some(0));
    let absent = one(r#"{"choices":[]}"#, false, false);
    assert_eq!(absent.usage_state, "absent");
    assert!(absent.reports.is_empty());
    let partial = one(r#"{"usage":{"prompt_tokens":0}}"#, false, false);
    assert_eq!(partial.usage_state, "reported_partial");
    assert_eq!(partial.reports[0].output, None);
}
#[test]
fn duplicate_snapshots_are_idempotent_and_conflicts_preserved() {
    let same = one(
        &format!("data: {COUNTS}\n\ndata: {COUNTS}\n\ndata: [DONE]\n\n"),
        true,
        true,
    );
    assert_eq!(same.usage_state, "reported");
    assert_eq!(same.reports.len(), 1);
    let different = COUNTS
        .replace("\"prompt_tokens\":5", "\"prompt_tokens\":6")
        .replace("\"total_tokens\":8", "\"total_tokens\":9");
    let conflict = one(
        &format!("data: {COUNTS}\n\ndata: {different}\n\ndata: [DONE]\n\n"),
        true,
        false,
    );
    assert_eq!(conflict.usage_state, "conflicting");
    assert_eq!(conflict.reports.len(), 2);
}
#[test]
fn malformed_payloads_do_not_invent_reports_or_hide_conflicts() {
    for body in ["not JSON", r#"{"usage":{"prompt_tokens":-1}}"#] {
        for sse in [false, true] {
            let wire = if sse {
                format!("data: {body}\n\ndata: [DONE]\n\n")
            } else {
                body.into()
            };
            let result = one(&wire, sse, false);
            assert_eq!(result.usage_state, "absent");
            assert!(result.reports.is_empty());
            assert_eq!(result.reason.as_deref(), Some("invalid_provider_payload"));
        }
    }
    let different = COUNTS
        .replace("\"prompt_tokens\":5", "\"prompt_tokens\":6")
        .replace("\"total_tokens\":8", "\"total_tokens\":9");
    let result = one(
        &format!("data: {COUNTS}\n\ndata: {different}\n\ndata: malformed\n\ndata: [DONE]\n\n"),
        true,
        false,
    );
    assert_eq!(result.usage_state, "conflicting");
    assert_eq!(result.reports.len(), 2);
    let partial = one(
        &format!("data: {COUNTS}\n\ndata: malformed\n\ndata: [DONE]\n\n"),
        true,
        false,
    );
    assert_eq!(partial.usage_state, "reported_partial");
    assert_eq!(partial.reports.len(), 1);
}
#[test]
fn malformed_usage_details_parents_are_rejected_in_json_and_sse() {
    for parent in ["prompt_tokens_details", "completion_tokens_details"] {
        for value in ["42", "[]", "\"invalid\"", "true"] {
            let body = format!(
                r#"{{"usage":{{"prompt_tokens":5,"completion_tokens":3,"total_tokens":8,"{parent}":{value}}}}}"#
            );
            for sse in [false, true] {
                let payload = if sse {
                    format!("data: {body}\n\ndata: [DONE]\n\n")
                } else {
                    body.clone()
                };
                let out = one(&payload, sse, false);
                assert_eq!(out.usage_state, "absent", "{payload}");
                assert!(out.reports.is_empty());
                assert_eq!(out.reason.as_deref(), Some("invalid_provider_payload"));
            }
        }
        for value in ["null", "{}"] {
            let body = format!(
                r#"{{"usage":{{"prompt_tokens":5,"completion_tokens":3,"total_tokens":8,"{parent}":{value}}}}}"#
            );
            assert_eq!(one(&body, false, false).usage_state, "reported");
        }
    }
}
#[test]
fn duplicate_content_type_does_not_select_the_last_media_type() {
    for (first, second) in [
        ("application/json", "text/event-stream"),
        ("text/event-stream", "application/json"),
        ("application/json", "application/json"),
    ] {
        let mut tracker = Replay::default();
        feed(&mut tracker, 0, 1, &request());
        let wire = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {first}\r\ncontent-type: {second}\r\nContent-Length: {}\r\n\r\n{COUNTS}",
            COUNTS.len()
        );
        let out = feed(&mut tracker, 1, 1, wire.as_bytes());
        assert_eq!(out.len(), 2); // Pending request and connection invalidation.
        assert_eq!(out[0].request_ordinal, Some(1));
        assert_eq!(out[1].request_ordinal, None);
        for observation in out {
            assert_eq!(observation.capture_integrity, "unverified");
            assert_eq!(
                observation.reason.as_deref(),
                Some("ambiguous_content_type")
            );
            assert!(observation.reports.is_empty());
        }
    }
}
#[test]
fn bodyless_204_has_no_usage_report() {
    let mut tracker = Replay::default();
    feed(&mut tracker, 0, 1, &request());
    let out = feed(&mut tracker, 1, 1, b"HTTP/1.1 204 No Content\r\n\r\n");
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].usage_state, "absent");
    assert!(out[0].reports.is_empty());
    assert_eq!(out[0].reason.as_deref(), Some("usage_not_reported"));
}
#[test]
fn sse_multiline_cr_utf8_and_undispatched_events() {
    let body="data: {\"content\":\"你好 PRIVATE-RESPONSE\"}\r\rdata: {\"usage\":\rdata: {\"prompt_tokens\":0,\"completion_tokens\":0,\"total_tokens\":0}}\r\rdata: [DONE]\r\r";
    assert_eq!(one(body, true, false).usage_state, "reported");
    let partial = one(&format!("data: {COUNTS}\n\n"), true, false);
    assert_eq!(partial.usage_state, "reported_partial");
    let no_dispatch = one(&format!("data: {COUNTS}"), true, false);
    assert!(no_dispatch.reports.is_empty());
}
#[test]
fn framing_ambiguity_and_unsupported_encodings_are_explicit() {
    for wire in [
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Encoding: gzip\r\n\r\n",
        b"HTTP/2 200 OK\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
    ] {
        let mut t = Replay::default();
        feed(&mut t, 0, 1, &request());
        let out = feed(&mut t, 1, 1, wire);
        assert!(out
            .iter()
            .all(|u| u.reports.is_empty() && u.capture_integrity == "unverified"));
        assert!(out.iter().any(|u| u.reason.is_some()));
    }
}
#[test]
fn informational_and_head_responses_keep_request_order() {
    let mut t = Replay::default();
    feed(
        &mut t,
        0,
        1,
        b"HEAD / HTTP/1.1\r\nHost: api.openai.com\r\n\r\n",
    );
    feed(&mut t, 0, 2, &request());
    assert!(feed(
        &mut t,
        1,
        1,
        b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\n"
    )
    .is_empty());
    let out = feed(&mut t, 1, 2, &response(COUNTS, false, false));
    assert_eq!(out[0].request_ordinal, Some(2));
}
#[test]
fn middle_whole_and_final_call_loss_never_make_usage_complete() {
    // Whole-call loss before the response: its bytes are sized by the offset.
    let mut t = Replay::default();
    feed(&mut t, 0, 1, &request());
    let out = feed_at(&mut t, 1, 2, 64, &response(COUNTS, false, false));
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].request_ordinal, Some(1));
    assert_eq!(out[0].reason.as_deref(), Some("capture_gap"));
    assert!(out.iter().all(|o| o.reports.is_empty()));
    // Whole final-call loss: the read never arrives. A live inventory ahead of
    // consumed records is in transit for one pass, and a gap on the next.
    let mut t = Replay::default();
    feed(&mut t, 0, 1, &request());
    let req = request().len() as u64;
    let lost = [req, response(COUNTS, false, false).len() as u64];
    assert!(t
        .checkpoint(key(), [1, 1], lost, [0, 0], 1, false, 103)
        .is_empty());
    let out = t.checkpoint(key(), [1, 1], lost, [0, 0], 2, false, 104);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].request_ordinal, Some(1));
    assert_eq!(out[0].reason.as_deref(), Some("capture_gap"));
    // A later read with no new request is discarded, never parsed.
    let later = feed_at(&mut t, 1, 2, lost[1], &response(COUNTS, false, false));
    assert!(later.is_empty());
    // Middle-chunk loss: the second chunk of a two-chunk read never arrives.
    let mut t = Replay::default();
    feed(&mut t, 0, 1, &request());
    let mut wire = response(&"x".repeat(5000), false, false);
    wire.truncate(4096 + 100);
    let first = t.feed(CaptureChunk {
        connection: key(),
        ts_ns: 102,
        direction: 1,
        sequence: 1,
        loss_epoch: 0,
        call_id: 1,
        offset: 0,
        chunk_index: 0,
        chunk_total: 2,
        total_bytes: wire.len() as u32,
        truncated: false,
        failed: false,
        end: false,
        data: &wire[..4096],
    });
    assert!(first.is_empty());
    let out = t.finish(104);
    assert_eq!(out.len(), 2);
    assert!(out.iter().all(|o| o.reports.is_empty()));
    assert_eq!(out[0].request_ordinal, Some(1));
}
#[test]
fn lifecycle_reuse_and_expiry_do_not_recreate_trust() {
    let mut t = Replay::new(Limits {
        idle_ns: 10,
        ..Limits::default()
    });
    feed(&mut t, 0, 1, &request());
    assert!(!t.expire(1000).is_empty());
    assert_eq!(t.retained_bytes(), 0);
    assert!(feed(&mut t, 1, 1, &response(COUNTS, false, false)).is_empty());
    let mut k = key();
    k.generation += 1;
    let req = request();
    let c = CaptureChunk {
        connection: k,
        ts_ns: 1001,
        direction: 0,
        sequence: 1,
        loss_epoch: 0,
        call_id: 1,
        offset: 0,
        chunk_index: 0,
        chunk_total: 1,
        total_bytes: req.len() as u32,
        truncated: false,
        failed: false,
        end: false,
        data: &req,
    };
    assert!(t.feed(c).is_empty());
    let mut k = key();
    k.process_start = 0;
    assert_eq!(
        t.feed(CaptureChunk {
            connection: k,
            ts_ns: 1002,
            direction: 0,
            sequence: 1,
            loss_epoch: 0,
            call_id: 1,
            offset: 0,
            chunk_index: 0,
            chunk_total: 1,
            total_bytes: 1,
            truncated: false,
            failed: false,
            end: false,
            data: b"x"
        })[0]
            .reason
            .as_deref(),
        Some("missing_lifecycle")
    );
}
#[test]
fn aggregate_and_many_small_incomplete_streams_stay_bounded() {
    let limits = Limits {
        connections: 4,
        total_bytes: 12,
        per_connection_bytes: 10,
        ..Limits::default()
    };
    let mut t = Replay::new(limits);
    for n in 0..100 {
        let mut k = key();
        k.ssl_ctx += n;
        let out = t.feed(CaptureChunk {
            connection: k,
            ts_ns: 100,
            direction: 0,
            sequence: 1,
            loss_epoch: 0,
            call_id: 1,
            offset: 0,
            chunk_index: 0,
            chunk_total: 1,
            total_bytes: 4,
            truncated: false,
            failed: false,
            end: false,
            data: b"POST",
        });
        assert!(out.iter().all(|u| u.reports.is_empty()));
        assert!(t.connection_count() <= 4);
        assert!(t.retained_bytes() <= 12);
    }
}
#[test]
fn untrusted_provider_numbers_never_turn_into_zero() {
    for body in [
        r#"{"usage":{"prompt_tokens":-1}}"#,
        r#"{"usage":{"prompt_tokens":"PRIVATE-SECRET"}}"#,
        r#"{"usage":{"prompt_tokens":5,"completion_tokens":3,"total_tokens":9}}"#,
    ] {
        let r = one(body, false, false);
        assert_ne!(r.usage_state, "reported");
        assert!(r.reports.is_empty());
        assert!(!serde_json::to_string(&r)
            .unwrap()
            .contains("PRIVATE-SECRET"));
    }
}

#[test]
fn global_loss_before_first_admission_requires_a_newer_lifetime() {
    let mut t = Replay::default();
    assert!(t.global_loss(100).is_empty());
    assert_eq!(
        feed(&mut t, 0, 1, &request())[0].reason.as_deref(),
        Some("global_loss_before_admission")
    );
    assert!(feed(&mut t, 1, 1, &response(COUNTS, false, false)).is_empty());
    // Refused lifetimes do not occupy parser slots.
    assert_eq!(t.connection_count(), 0);
    let mut k = key();
    k.generation = 200;
    let req = request();
    assert!(t
        .feed(CaptureChunk {
            connection: k,
            ts_ns: 201,
            direction: 0,
            sequence: 1,
            loss_epoch: 0,
            call_id: 1,
            offset: 0,
            chunk_index: 0,
            chunk_total: 1,
            total_bytes: req.len() as u32,
            truncated: false,
            failed: false,
            end: false,
            data: &req
        })
        .is_empty());
    let wire = response(COUNTS, false, false);
    let out = t.feed(CaptureChunk {
        connection: k,
        ts_ns: 202,
        direction: 1,
        sequence: 1,
        loss_epoch: 0,
        call_id: 1,
        offset: 0,
        chunk_index: 0,
        chunk_total: 1,
        total_bytes: wire.len() as u32,
        truncated: false,
        failed: false,
        end: false,
        data: &wire,
    });
    assert_eq!(out[0].usage_state, "reported");
}
#[test]
fn exec_reused_pointer_cannot_inherit_pending_request() {
    let mut t = Replay::default();
    feed(&mut t, 0, 1, &request());
    let mut k = key();
    k.exec_generation += 1;
    let wire = response(COUNTS, false, false);
    let out = t.feed(CaptureChunk {
        connection: k,
        ts_ns: 102,
        direction: 1,
        sequence: 1,
        loss_epoch: 0,
        call_id: 1,
        offset: 0,
        chunk_index: 0,
        chunk_total: 1,
        total_bytes: wire.len() as u32,
        truncated: false,
        failed: false,
        end: false,
        data: &wire,
    });
    assert!(out.iter().all(|u| u.reports.is_empty()));
    assert_eq!(out[0].reason.as_deref(), Some("response_without_request"));
}
#[test]
fn duplicate_json_keys_are_rejected_in_json_and_sse() {
    for body in [
        r#"{"usage":{"prompt_tokens":5,"prompt_tokens":6,"completion_tokens":3,"total_tokens":9}}"#,
        r#"{"usage":{"prompt_tokens":5},"usage":{"prompt_tokens":6,"completion_tokens":3,"total_tokens":9}}"#,
    ] {
        for sse in [false, true] {
            let text = if sse {
                format!("data: {body}\n\ndata: [DONE]\n\n")
            } else {
                body.into()
            };
            let r = one(&text, sse, false);
            assert_ne!(r.usage_state, "reported");
            assert!(r.reports.is_empty());
        }
    }
}
#[test]
fn allocated_capacity_and_pending_request_limits_are_enforced() {
    let mut t = Replay::new(Limits {
        total_bytes: 256,
        per_connection_bytes: 256,
        ..Limits::default()
    });
    for seq in 1..4 {
        let bytes = vec![b'x'; 80];
        let out = feed(&mut t, 0, seq, &bytes);
        assert!(out.iter().all(|u| u.reports.is_empty()));
        assert!(t.retained_bytes() <= 256);
    }
    let mut t = Replay::new(Limits {
        pending_requests: 1,
        ..Limits::default()
    });
    feed(&mut t, 0, 1, &request());
    let out = feed(&mut t, 0, 2, &request());
    assert!(out
        .iter()
        .any(|u| u.reason.as_deref() == Some("pending_request_limit")));
}

#[test]
fn an_inventory_ahead_of_queued_records_waits_one_pass() {
    // The read has occurred in the producer, but is still waiting in the queue.
    let mut tracker = Replay::default();
    feed(&mut tracker, 0, 1, &request());
    let accepted = [
        request().len() as u64,
        response(COUNTS, false, false).len() as u64,
    ];
    assert!(tracker
        .checkpoint(key(), [1, 1], accepted, [0, 0], 1, false, 102)
        .is_empty());
    let out = feed(&mut tracker, 1, 1, &response(COUNTS, false, false));
    assert_eq!(out[0].usage_state, "reported");
    assert!(tracker
        .checkpoint(key(), [1, 1], accepted, [0, 0], 2, false, 103)
        .is_empty());
    assert_eq!(tracker.connection_count(), 1);
    // A final inventory is read after capture stopped and the ring drained.
    let mut stopped = Replay::default();
    feed(&mut stopped, 0, 1, &request());
    let out = stopped.checkpoint(key(), [1, 1], accepted, [0, 0], 1, true, 102);
    assert_eq!(out[0].request_ordinal, Some(1));
    assert_eq!(out[0].reason.as_deref(), Some("capture_gap"));
    // Loss evidence and regressions never wait.
    for (sequence, accepted, loss, reason) in [
        ([1, 0], accepted, [0, 1], "inventory_loss"),
        ([0, 0], [0, 0], [0, 0], "inventory_regression"),
        ([1, 0], [1, 0], [0, 0], "inventory_regression"),
    ] {
        let mut t = Replay::default();
        feed(&mut t, 0, 1, &request());
        let out = t.checkpoint(key(), sequence, accepted, loss, 1, false, 102);
        assert!(out.iter().any(|o| o.reason.as_deref() == Some(reason)));
    }
}

#[test]
fn unseen_inventories_and_vanished_lifetimes_become_explicit() {
    let mut t = Replay::default();
    let mut other = key();
    other.ssl_ctx += 1;
    // Records may still be in transit at the first sighting.
    assert!(t
        .checkpoint(other, [1, 0], [9, 0], [0, 0], 1, false, 100)
        .is_empty());
    let out = t.checkpoint(other, [1, 0], [9, 0], [0, 0], 2, false, 101);
    assert_eq!(out[0].reason.as_deref(), Some("inventory_without_records"));
    // A live lifetime absent from two consecutive passes lost its closure.
    feed(&mut t, 0, 1, &request());
    assert!(t.checkpoint_pass_end(1, 102).is_empty());
    let out = t.checkpoint_pass_end(2, 103);
    assert!(out
        .iter()
        .any(|o| o.reason.as_deref() == Some("closure_unobserved")));
    assert_eq!(t.connection_count(), 0);
}
#[test]
fn completed_large_responses_release_retained_capacity() {
    let content = "PRIVATE-RESPONSE-".repeat(6000);
    let body = format!(
        r#"{{"choices":[{{"content":"{content}"}}],"usage":{{"prompt_tokens":5,"completion_tokens":3,"total_tokens":8}}}}"#
    );
    let wire = response(&body, false, false);
    assert!(wire.len() > 96 * 1024);
    let mut tracker = Replay::default();
    let mut read_sequence = 0;
    for ordinal in 1..=8 {
        feed(&mut tracker, 0, ordinal, &request());
        let mut out = vec![];
        for part in wire.chunks(4096) {
            read_sequence += 1;
            out.extend(feed(&mut tracker, 1, read_sequence, part));
            assert!(tracker.retained_bytes() <= Limits::default().per_connection_bytes);
        }
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].usage_state, "reported");
        assert_eq!(out[0].request_ordinal, Some(ordinal));
        assert_eq!(tracker.retained_bytes(), 0);
        assert!(!serde_json::to_string(&out)
            .unwrap()
            .contains("PRIVATE-RESPONSE"));
    }
}

/// One SSL call split into BPF-shaped chunks; calls above 64 KiB are truncated.
fn call(
    t: &mut Replay,
    k: ConnectionKey,
    dir: u8,
    seq: u64,
    bytes: &[u8],
) -> Vec<UsageObservation> {
    let truncated = bytes.len() > CALL_CAPTURE_BYTES as usize;
    let captured = &bytes[..bytes.len().min(CALL_CAPTURE_BYTES as usize)];
    let parts: Vec<_> = captured.chunks(CHUNK_BYTES as usize).collect();
    let offset = t.offset(k, dir);
    t.next.insert((k, dir), offset + bytes.len() as u64);
    let (entry, ret) = t.tick();
    let mut out = vec![];
    for (i, part) in parts.iter().enumerate() {
        out.extend(t.feed(CaptureChunk {
            connection: k,
            ts_ns: ret,
            direction: dir,
            sequence: seq,
            loss_epoch: 0,
            call_id: entry,
            offset,
            chunk_index: i as u16,
            chunk_total: parts.len() as u16,
            total_bytes: bytes.len() as u32,
            truncated,
            failed: false,
            end: false,
            data: part,
        }));
    }
    out
}
fn close(t: &mut Replay, k: ConnectionKey, sequence: [u64; 2]) -> Vec<UsageObservation> {
    let mut out = vec![];
    for dir in 0..2u8 {
        let offset = t.offset(k, dir);
        out.extend(t.feed(CaptureChunk {
            connection: k,
            ts_ns: 5000,
            direction: dir,
            sequence: sequence[dir as usize],
            loss_epoch: 0,
            call_id: 0,
            offset,
            chunk_index: 0,
            chunk_total: 1,
            total_bytes: 0,
            truncated: false,
            failed: false,
            end: true,
            data: b"",
        }));
    }
    out
}
fn chunk(text: &str) -> Vec<u8> {
    format!("{:x}\r\n{text}\r\n", text.len()).into_bytes()
}
/// A realistic streamed completion: one read per event, ~245 bytes each.
fn stream(
    t: &mut Replay,
    k: ConnectionKey,
    first_seq: u64,
    tokens: usize,
) -> (u64, Vec<UsageObservation>) {
    let mut seq = first_seq;
    let mut out = call(t, k, 1, seq, b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\nTransfer-Encoding: chunked\r\n\r\n");
    for _ in 0..tokens {
        seq += 1;
        let event = "data: {\"id\":\"chatcmpl-AbCdEfGhIjKlMnOpQrStUvWxYz012\",\"object\":\"chat.completion.chunk\",\"created\":1728000000,\"model\":\"gpt-4o-2024-08-06\",\"system_fingerprint\":\"fp_abc123def4\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\" PRIVATE\"},\"logprobs\":null,\"finish_reason\":null}],\"usage\":null}\n\n";
        out.extend(call(t, k, 1, seq, &chunk(event)));
    }
    seq += 1;
    let usage = format!("data: {{\"choices\":[],\"usage\":{{\"prompt_tokens\":5,\"completion_tokens\":{tokens},\"total_tokens\":{}}}}}\n\ndata: [DONE]\n\n", 5 + tokens);
    out.extend(call(t, k, 1, seq, &chunk(&usage)));
    seq += 1;
    out.extend(call(t, k, 1, seq, b"0\r\n\r\n"));
    (seq, out)
}
fn sized_request(body: usize) -> Vec<u8> {
    let body = format!("{{\"m\":\"{}\"}}", "P".repeat(body));
    format!("POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len()).into_bytes()
}

#[test]
fn long_streams_are_parsed_incrementally() {
    for tokens in [10, 600, 5000] {
        let mut t = Replay::default();
        call(&mut t, key(), 0, 1, &request());
        let (_, out) = stream(&mut t, key(), 1, tokens);
        assert_eq!(out.len(), 1, "tokens={tokens} {out:?}");
        assert_eq!(out[0].usage_state, "reported");
        assert_eq!(out[0].reports[0].output, Some(tokens as u64));
        assert!(t.retained_bytes() < 16 * 1024, "{}", t.retained_bytes());
        // Nothing unreconciled remains, so ending capture adds no rows.
        assert!(t.finish(1_000_000).is_empty());
    }
}

#[test]
fn large_prompts_are_skipped_by_length_including_truncated_calls() {
    for (body, write) in [
        (200_000, 16 * 1024),
        (200_000, usize::MAX),
        (2_000_000, usize::MAX),
    ] {
        let mut t = Replay::default();
        let wire = sized_request(body);
        let mut seq = 0;
        for part in wire.chunks(write.min(wire.len())) {
            seq += 1;
            assert!(call(&mut t, key(), 0, seq, part).is_empty());
        }
        let (_, out) = stream(&mut t, key(), 1, 10);
        assert_eq!(out[0].usage_state, "reported", "body={body} write={write}");
    }
    // Uncaptured bytes cannot hide framing: a truncated call whose tail would
    // contain the next request head invalidates instead of guessing.
    let mut t = Replay::default();
    let mut wire = sized_request(70_000);
    wire.extend(request());
    let out = call(&mut t, key(), 0, 1, &wire);
    assert!(out
        .iter()
        .any(|o| o.reason.as_deref() == Some("truncated_capture")));
    // Nor can they stand in for a provider body that must be parsed.
    let mut t = Replay::default();
    call(&mut t, key(), 0, 1, &request());
    let body = format!(
        r#"{{"choices":[{{"content":"{}"}}],"usage":{{"prompt_tokens":5,"completion_tokens":3,"total_tokens":8}}}}"#,
        "x".repeat(80_000)
    );
    let out = call(&mut t, key(), 1, 1, &response(&body, false, false));
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].request_ordinal, Some(1));
    assert_eq!(out[0].reason.as_deref(), Some("truncated_capture"));
    assert!(out.iter().all(|o| o.reports.is_empty()));
    // The lifetime continues at the next exchange.
    call(&mut t, key(), 0, 2, &request());
    let out = call(&mut t, key(), 1, 2, &response(COUNTS, false, false));
    assert_eq!(out[0].usage_state, "reported");
    assert_eq!(out[0].request_ordinal, Some(2));
    assert_eq!(out[0].capture_integrity, "observed_after_resync");
}

#[test]
fn closed_lifetimes_release_slots_and_refusal_is_explicit_not_sticky() {
    let mut t = Replay::new(Limits {
        connections: 4,
        ..Limits::default()
    });
    for n in 0..200u64 {
        let k = ConnectionKey {
            ssl_ctx: 1000 + n,
            generation: 100 + n,
            ..key()
        };
        call(&mut t, k, 0, 1, &request());
        let wire = response(COUNTS, false, false);
        let out = call(&mut t, k, 1, 1, &wire);
        assert_eq!(out[0].usage_state, "reported", "connection {n}");
        assert!(close(&mut t, k, [1, 1]).is_empty());
    }
    assert_eq!(t.connection_count(), 0);
    // Limit reached by open lifetimes: the newcomer gets one explicit row.
    for n in 0..4u64 {
        let k = ConnectionKey {
            ssl_ctx: 5000 + n,
            generation: 900 + n,
            ..key()
        };
        call(&mut t, k, 0, 1, &request());
    }
    let late = ConnectionKey {
        ssl_ctx: 6000,
        generation: 999,
        ..key()
    };
    let out = call(&mut t, late, 0, 1, &request());
    assert_eq!(out[0].reason.as_deref(), Some("connection_limit"));
    assert!(call(&mut t, late, 1, 1, &response(COUNTS, false, false)).is_empty());
    assert_eq!(t.refused_connections(), 1);
    // Once one closes, a new lifetime is admitted again.
    let first = ConnectionKey {
        ssl_ctx: 5000,
        generation: 900,
        ..key()
    };
    call(&mut t, first, 1, 1, &response(COUNTS, false, false));
    close(&mut t, first, [1, 1]);
    let next = ConnectionKey {
        ssl_ctx: 7000,
        generation: 1000,
        ..key()
    };
    call(&mut t, next, 0, 1, &request());
    let out = call(&mut t, next, 1, 1, &response(COUNTS, false, false));
    assert_eq!(out[0].usage_state, "reported");
}

#[test]
fn idle_keep_alive_lifetimes_stay_valid_and_stuck_ones_expire() {
    let mut t = Replay::default();
    call(&mut t, key(), 0, 1, &request());
    let (seq, out) = stream(&mut t, key(), 1, 10);
    assert_eq!(out[0].usage_state, "reported");
    assert!(t.expire(10 * 3_600_000_000_000).is_empty());
    call(&mut t, key(), 0, 2, &request());
    let (_, out) = stream(&mut t, key(), seq + 1, 10);
    assert_eq!(out[0].usage_state, "reported");
    assert_eq!(out[0].request_ordinal, Some(2));
    // A request without a response for longer than the backstop is unverified.
    call(&mut t, key(), 0, 3, &request());
    let out = t.expire(20 * 3_600_000_000_000);
    assert_eq!(out[0].request_ordinal, Some(3));
    assert_eq!(out[0].reason.as_deref(), Some("idle_expiry"));
}

#[test]
fn other_origins_are_released_without_rows() {
    let mut t = Replay::default();
    let out = call(
        &mut t,
        key(),
        0,
        1,
        b"GET /simple/ HTTP/1.1\r\nHost: pypi.org\r\n\r\n",
    );
    assert!(out.is_empty());
    assert_eq!(t.connection_count(), 0);
    assert_eq!(t.out_of_scope_connections(), 1);
    // Later records of the released lifetime are ignored, not re-admitted.
    assert!(call(
        &mut t,
        key(),
        1,
        1,
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    )
    .is_empty());
    assert!(close(&mut t, key(), [1, 1]).is_empty());
    assert_eq!(t.connection_count(), 0);
    // A server reads the peer's request first; its lifetime is released too.
    let mut t = Replay::default();
    assert!(call(&mut t, key(), 1, 1, &request()).is_empty());
    assert!(call(&mut t, key(), 0, 1, &response(COUNTS, false, false)).is_empty());
    assert_eq!(t.out_of_scope_connections(), 1);
}

#[test]
fn process_exit_reconciles_the_final_inventory() {
    // Clean: every call consumed, nothing pending.
    let mut t = Replay::default();
    call(&mut t, key(), 0, 1, &request());
    call(&mut t, key(), 1, 1, &response(COUNTS, false, false));
    let accepted = [
        request().len() as u64,
        response(COUNTS, false, false).len() as u64,
    ];
    assert!(t
        .lifetime_gone(key(), [1, 1], accepted, [0, 0], 200)
        .is_empty());
    assert_eq!(t.connection_count(), 0);
    // Final read missing, pending request, kernel loss, or no records at all.
    for (sequence, accepted, loss, reason) in [
        ([1, 1], accepted, [0, 0], "capture_gap"),
        (
            [1, 0],
            [accepted[0], 0],
            [0, 0],
            "lifetime_ended_without_close",
        ),
        ([1, 0], [accepted[0], 0], [1, 0], "inventory_loss"),
    ] {
        let mut t = Replay::default();
        call(&mut t, key(), 0, 1, &request());
        let out = t.lifetime_gone(key(), sequence, accepted, loss, 200);
        assert_eq!(out[0].request_ordinal, Some(1), "{reason}");
        assert_eq!(out[0].reason.as_deref(), Some(reason));
    }
    let mut t = Replay::default();
    let out = t.lifetime_gone(key(), [2, 2], [10, 10], [0, 0], 200);
    assert_eq!(out[0].reason.as_deref(), Some("inventory_without_records"));
}

#[test]
fn attributed_userspace_loss_and_unadmitted_closure_are_explicit() {
    let mut t = Replay::default();
    call(&mut t, key(), 0, 1, &request());
    let out = t.capture_loss(key(), 200);
    assert_eq!(out[0].request_ordinal, Some(1));
    assert_eq!(out[0].reason.as_deref(), Some("capture_loss"));
    assert!(call(&mut t, key(), 1, 1, &response(COUNTS, false, false)).is_empty());
    // Every record of a lifetime lost: its closure reveals the calls.
    let mut t = Replay::default();
    let out = close(&mut t, key(), [1, 1]);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].reason.as_deref(), Some("inventory_without_records"));
    // An unused lifetime closes silently.
    let mut t = Replay::default();
    let mut unused = key();
    unused.ssl_ctx += 9;
    assert!(close(&mut t, unused, [0, 0]).is_empty());
    // Untracked lifetimes produce one row, not one row per chunk.
    let mut t = Replay::default();
    let mut untracked = key();
    untracked.generation = 0;
    assert_eq!(call(&mut t, untracked, 0, 1, &request()).len(), 1);
    assert!(call(&mut t, untracked, 1, 1, &response(COUNTS, false, false)).is_empty());
}

/// Skip one call of `bytes` without delivering it, as if its records were lost.
fn lose(t: &mut Replay, k: ConnectionKey, dir: u8, bytes: &[u8]) {
    let offset = t.offset(k, dir);
    t.next.insert((k, dir), offset + bytes.len() as u64);
    t.tick();
}

#[test]
fn a_lost_call_inside_a_skipped_body_costs_nothing() {
    let mut t = Replay::default();
    let wire = sized_request(100_000);
    let parts: Vec<_> = wire.chunks(16 * 1024).collect();
    for (i, part) in parts.iter().enumerate() {
        if i == 3 {
            lose(&mut t, key(), 0, part);
        } else {
            assert!(call(&mut t, key(), 0, i as u64 + 1, part).is_empty());
        }
    }
    let (_, out) = stream(&mut t, key(), 1, 10);
    assert_eq!(out[0].usage_state, "reported");
    assert_eq!(out[0].capture_integrity, "observed_contiguous");
}

#[test]
fn a_lost_response_read_costs_only_its_request() {
    let mut t = Replay::default();
    call(&mut t, key(), 0, 1, &request());
    let head =
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n";
    call(&mut t, key(), 1, 1, head);
    lose(&mut t, key(), 1, &chunk("data: {\"choices\":[]}\n\n"));
    let usage = format!("data: {COUNTS}\n\ndata: [DONE]\n\n");
    let out = call(&mut t, key(), 1, 3, &chunk(&usage));
    assert_eq!(out.len(), 1, "{out:?}");
    assert_eq!(out[0].request_ordinal, Some(1));
    assert_eq!(out[0].reason.as_deref(), Some("capture_gap"));
    assert!(out[0].reports.is_empty());
    assert!(call(&mut t, key(), 1, 4, b"0\r\n\r\n").is_empty());
    // The next exchange is parsed again, and labelled as relying on resync.
    call(&mut t, key(), 0, 2, &request());
    let out = call(&mut t, key(), 1, 5, &response(COUNTS, false, false));
    assert_eq!(out[0].usage_state, "reported");
    assert_eq!(out[0].request_ordinal, Some(2));
    assert_eq!(out[0].capture_integrity, "observed_after_resync");
}

#[test]
fn resync_waits_for_a_read_entered_after_the_next_request() {
    let mut t = Replay::default();
    call(&mut t, key(), 0, 1, &request());
    lose(&mut t, key(), 1, &response(COUNTS, false, false));
    // A read entered before the next request was written still belongs to the
    // abandoned response, even though it returns afterwards.
    let early = t.tick().0;
    call(&mut t, key(), 0, 2, &request());
    let tail = b"stale tail of the abandoned response";
    let offset = t.offset(key(), 1);
    t.next.insert((key(), 1), offset + tail.len() as u64);
    let ret = t.tick().1;
    let out = t.feed(CaptureChunk {
        connection: key(),
        ts_ns: ret,
        direction: 1,
        sequence: 2,
        loss_epoch: 0,
        call_id: early,
        offset,
        chunk_index: 0,
        chunk_total: 1,
        total_bytes: tail.len() as u32,
        truncated: false,
        failed: false,
        end: false,
        data: tail,
    });
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].reason.as_deref(), Some("capture_gap"));
    let out = call(&mut t, key(), 1, 3, &response(COUNTS, false, false));
    assert_eq!(out[0].request_ordinal, Some(2));
    assert_eq!(out[0].usage_state, "reported");
}

#[test]
fn pipelining_or_a_conservative_policy_turns_gaps_into_invalidation() {
    // Both requests were written before the revealing read entered, so either
    // response may overlap the lost bytes: both are unverified, none guessed.
    let mut t = Replay::default();
    call(&mut t, key(), 0, 1, &request());
    call(&mut t, key(), 0, 2, &request());
    lose(&mut t, key(), 1, &response(COUNTS, false, false));
    let out = call(&mut t, key(), 1, 2, &response(COUNTS, false, false));
    let ordinals: Vec<_> = out.iter().map(|o| o.request_ordinal).collect();
    assert_eq!(ordinals, [Some(1), Some(2)]);
    assert!(out
        .iter()
        .all(|o| o.reason.as_deref() == Some("capture_gap")));
    assert_eq!(t.connection_count(), 1);
    // A request written before the previous response completed marks the
    // lifetime as pipelined for good.
    let mut t = Replay::default();
    call(&mut t, key(), 0, 1, &request());
    call(&mut t, key(), 0, 2, &request());
    call(&mut t, key(), 1, 1, &response(COUNTS, false, false));
    call(&mut t, key(), 1, 2, &response(COUNTS, false, false));
    call(&mut t, key(), 0, 3, &request());
    lose(&mut t, key(), 1, &response(COUNTS, false, false));
    let out = call(&mut t, key(), 1, 4, &response(COUNTS, false, false));
    assert!(out.iter().any(|o| o.request_ordinal.is_none()));
    // Without recovery, any lost record invalidates the lifetime.
    let mut t = Replay {
        t: UsageTracker::with_recovery(
            Limits::default(),
            Recovery {
                skip_known_gaps: false,
                resync_responses: false,
            },
        ),
        ..Replay::default()
    };
    let wire = sized_request(100_000);
    let parts: Vec<_> = wire.chunks(16 * 1024).collect();
    call(&mut t, key(), 0, 1, parts[0]);
    lose(&mut t, key(), 0, parts[1]);
    let out = call(&mut t, key(), 0, 3, parts[2]);
    assert_eq!(out.last().unwrap().reason.as_deref(), Some("capture_gap"));
    assert_eq!(t.connection_count(), 0);
}

#[test]
fn a_response_lost_while_resyncing_moves_the_resume_point() {
    let mut t = Replay::default();
    call(&mut t, key(), 0, 1, &request());
    let head =
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n";
    call(&mut t, key(), 1, 1, head);
    lose(&mut t, key(), 1, &chunk("data: {\"choices\":[]}\n\n"));
    // Revealed before request 2 was written: only request 1 is abandoned.
    let out = call(&mut t, key(), 1, 3, b"0\r\n\r\n");
    assert_eq!(out[0].request_ordinal, Some(1));
    // Request 2 is written and its whole response is lost; then request 3.
    call(&mut t, key(), 0, 2, &request());
    lose(&mut t, key(), 1, &response(COUNTS, false, false));
    call(&mut t, key(), 0, 3, &request());
    let three = COUNTS
        .replace("\"prompt_tokens\":5", "\"prompt_tokens\":7")
        .replace("\"total_tokens\":8", "\"total_tokens\":10");
    // The read revealing the loss entered after the resume point: request 3's
    // response must not be credited to request 2.
    let out = call(&mut t, key(), 1, 5, &response(&three, false, false));
    let ordinals: Vec<_> = out.iter().map(|o| o.request_ordinal).collect();
    assert_eq!(ordinals, [Some(2), Some(3)], "{out:?}");
    assert!(out.iter().all(|o| o.reports.is_empty()));
    // The lifetime recovers at the next exchange.
    call(&mut t, key(), 0, 4, &request());
    let out = call(&mut t, key(), 1, 6, &response(COUNTS, false, false));
    assert_eq!(out[0].request_ordinal, Some(4));
    assert_eq!(out[0].reports[0].input, Some(5));
}
