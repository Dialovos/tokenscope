//! E4 replay ablation: does lifetime/loss evidence prevent falsely complete
//! usage without discarding too much recoverable usage?
//!
//! Deterministic simulation, not live capture. Synthetic keep-alive HTTP/1.1
//! traffic is encoded exactly as tls.bpf.c emits it (4 KiB chunks, 64 KiB call
//! capture, per-direction call sequences and byte offsets, closure records and
//! inventory passes that race with records in transit). Faults are injected,
//! then each observer replays the same stream through `UsageTracker`.
//!
//! Run: cargo run --release -p ts-core --example usage_ablation -- [trials]
use std::collections::{HashMap, HashSet};
use ts_core::usage::*;

const CONNECTIONS: usize = 6;
const REQUESTS: usize = 12;
const READ_BYTES: usize = 16 * 1024;
const TGID: u32 = 4242;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn chance(&mut self, p: f64) -> bool {
        (self.next() >> 11) as f64 / ((1u64 << 53) as f64) < p
    }
}

#[derive(Clone, Copy)]
struct Truth {
    usage: Option<(u64, u64)>,
}

#[derive(Clone)]
enum Rec {
    Data {
        key: ConnectionKey,
        dir: u8,
        seq: u64,
        loss: u64,
        /// Call entry time; `ts` is its return time, on the same clock.
        call_id: u64,
        ts: u64,
        offset: u64,
        index: u16,
        chunks: u16,
        total: u32,
        truncated: bool,
        data: Vec<u8>,
    },
    End {
        key: ConnectionKey,
        dir: u8,
        seq: u64,
        offset: u64,
        loss: u64,
    },
    Checkpoint {
        key: ConnectionKey,
        seq: [u64; 2],
        accepted: [u64; 2],
        loss: [u64; 2],
        pass: u64,
    },
    PassEnd(u64),
    /// The writer learned that a closure record of this lifetime was dropped.
    Poison(ConnectionKey),
}

struct Faults {
    kernel: f64,
    user: f64,
}

struct Kernel {
    seq: [u64; 2],
    accepted: [u64; 2],
    loss: [u64; 2],
}

/// Builds the record stream a daemon writer would receive for one trial.
struct Capture<'a> {
    rng: &'a mut Rng,
    faults: &'a Faults,
    out: Vec<Rec>,
    /// (connection, request ordinal) whose own calls lost a record.
    damaged: HashSet<(usize, usize)>,
    clock: u64,
}
impl Capture<'_> {
    fn deliver(&mut self, rec: Rec, owner: Option<(usize, usize)>) {
        let droppable = matches!(rec, Rec::Data { .. } | Rec::End { .. });
        if droppable && self.rng.chance(self.faults.user) {
            // Queue full. Offsets size a lost data record; a lost closure is
            // reported beside the queue, and the writer can drain that signal
            // while older records are still queued.
            if let Rec::End { key, .. } = rec {
                let back = self.rng.below(64) as usize;
                let at = self.out.len().saturating_sub(back);
                self.out.insert(at, Rec::Poison(key));
            }
            if let Some(owner) = owner {
                self.damaged.insert(owner);
            }
            return;
        }
        self.out.push(rec);
    }
    fn call(
        &mut self,
        k: &mut Kernel,
        key: ConnectionKey,
        dir: u8,
        bytes: &[u8],
        owner: (usize, usize),
    ) {
        let d = dir as usize;
        k.seq[d] += 1;
        let seq = k.seq[d];
        let loss = k.loss[d];
        let offset = k.accepted[d];
        k.accepted[d] += bytes.len() as u64;
        let total = bytes.len() as u32;
        let truncated = total > CALL_CAPTURE_BYTES;
        let captured = &bytes[..bytes.len().min(CALL_CAPTURE_BYTES as usize)];
        let chunks = captured.len().div_ceil(CHUNK_BYTES as usize);
        let fail_at = self
            .rng
            .chance(self.faults.kernel)
            .then(|| self.rng.below(chunks as u64) as usize);
        self.clock += 2;
        let (entry, ret) = (self.clock - 1, self.clock);
        for (i, part) in captured.chunks(CHUNK_BYTES as usize).enumerate() {
            if fail_at.is_some_and(|f| i >= f) {
                break;
            }
            let rec = Rec::Data {
                key,
                dir,
                seq,
                loss,
                call_id: entry,
                ts: ret,
                offset,
                index: i as u16,
                chunks: chunks as u16,
                total,
                truncated,
                data: part.to_vec(),
            };
            self.deliver(rec, Some(owner));
        }
        if fail_at.is_some() {
            // Ring reservation failed: sized by sequence and offset, no epoch.
            self.damaged.insert(owner);
        }
    }
}

fn request_wire(body_len: usize) -> Vec<u8> {
    let filler = body_len.saturating_sub(16).max(1);
    let body = format!("{{\"messages\":\"{}\"}}", "p".repeat(filler));
    let mut wire = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    wire.extend(body.into_bytes());
    wire
}
fn usage_json(u: (u64, u64)) -> String {
    format!(
        r#""usage":{{"prompt_tokens":{},"completion_tokens":{},"total_tokens":{}}}"#,
        u.0,
        u.1,
        u.0 + u.1
    )
}
fn chunk(text: &str) -> Vec<u8> {
    format!("{:x}\r\n{text}\r\n", text.len()).into_bytes()
}
/// Response bytes grouped by SSL_read call.
fn response_reads(
    rng: &mut Rng,
    stream: bool,
    error: bool,
    t: Truth,
    completion: u64,
) -> Vec<Vec<u8>> {
    if error {
        let body = r#"{"error":{"message":"rate limited","type":"requests"}}"#;
        return vec![format!(
            "HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()];
    }
    if !stream {
        let usage = t
            .usage
            .map(|u| format!(",{}", usage_json(u)))
            .unwrap_or_default();
        let body = format!(
            r#"{{"id":"chatcmpl-{}","object":"chat.completion","choices":[{{"index":0,"message":{{"role":"assistant","content":"{}"}}}}]{usage}}}"#,
            rng.next(),
            "t".repeat(completion as usize * 4)
        );
        let wire = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes();
        return wire.chunks(READ_BYTES).map(<[u8]>::to_vec).collect();
    }
    let mut reads = vec![b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec()];
    for _ in 0..completion {
        reads.push(chunk("data: {\"id\":\"chatcmpl-AbCdEfGhIjKlMnOpQrStUvWxYz012\",\"object\":\"chat.completion.chunk\",\"created\":1728000000,\"model\":\"gpt-4o-2024-08-06\",\"system_fingerprint\":\"fp_abc123def4\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\" tok\"},\"logprobs\":null,\"finish_reason\":null}],\"usage\":null}\n\n"));
    }
    let mut last = vec![];
    if let Some(u) = t.usage {
        last.extend(chunk(&format!(
            "data: {{\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"choices\":[],{}}}\n\n",
            usage_json(u)
        )));
    }
    last.extend(chunk("data: [DONE]\n\n"));
    last.extend(b"0\r\n\r\n");
    reads.push(last);
    reads
}

struct Trial {
    /// Truth per connection, indexed by request ordinal - 1.
    truth: Vec<Vec<Truth>>,
    /// The full-evidence record stream the writer receives.
    stream: Vec<Rec>,
    /// (connection, ordinal) whose own calls lost a record.
    damaged: HashSet<(usize, usize)>,
}

fn trial(seed: u64, faults: &Faults) -> Trial {
    let mut rng = Rng(seed);
    let mut plan_rng = Rng(seed ^ 0x5EED);
    let keys: Vec<_> = (0..CONNECTIONS)
        .map(|c| ConnectionKey {
            tgid: TGID,
            process_start: 1,
            exec_generation: 1,
            ssl_ctx: 0x1000 + c as u64,
            generation: 1000 + c as u64,
        })
        .collect();
    let whole_writes: Vec<bool> = (0..CONNECTIONS).map(|_| plan_rng.chance(0.5)).collect();
    let mut kernels: Vec<_> = (0..CONNECTIONS)
        .map(|_| Kernel {
            seq: [0, 0],
            accepted: [0, 0],
            loss: [0, 0],
        })
        .collect();
    let mut truth = vec![vec![]; CONNECTIONS];
    let mut cap = Capture {
        rng: &mut rng,
        faults,
        out: vec![],
        damaged: HashSet::new(),
        clock: 10_000,
    };
    let mut pass = 0;
    for round in 0..REQUESTS {
        for c in 0..CONNECTIONS {
            let body = match plan_rng.below(100) {
                0..=49 => 500 + plan_rng.below(4_000),
                50..=79 => 5_000 + plan_rng.below(40_000),
                80..=94 => 60_000 + plan_rng.below(140_000),
                _ => 200_000 + plan_rng.below(400_000),
            } as usize;
            let stream = plan_rng.chance(0.7);
            let error = plan_rng.chance(0.03);
            let reported = !error && (!stream || plan_rng.chance(0.9));
            let completion = loop {
                let n = 20 + plan_rng.below(580);
                let prompt = body as u64 / 4;
                if !truth[c]
                    .iter()
                    .any(|t: &Truth| t.usage == Some((prompt, n)))
                {
                    break n;
                }
            };
            let t = Truth {
                usage: reported.then_some((body as u64 / 4, completion)),
            };
            truth[c].push(t);
            let owner = (c, round + 1);
            let wire = request_wire(body);
            let parts: Vec<&[u8]> = if whole_writes[c] {
                vec![&wire]
            } else {
                wire.chunks(READ_BYTES).collect()
            };
            for part in parts {
                cap.call(&mut kernels[c], keys[c], 0, part, owner);
            }
            for read in response_reads(&mut plan_rng, stream, error, t, completion) {
                cap.call(&mut kernels[c], keys[c], 1, &read, owner);
            }
        }
        // An inventory pass races with the last few records still in transit.
        pass += 1;
        let back = cap.rng.below(4) as usize;
        let at = cap.out.len().saturating_sub(back);
        let mut inventory: Vec<_> = (0..CONNECTIONS)
            .map(|c| Rec::Checkpoint {
                key: keys[c],
                seq: kernels[c].seq,
                accepted: kernels[c].accepted,
                loss: kernels[c].loss,
                pass,
            })
            .collect();
        inventory.push(Rec::PassEnd(pass));
        cap.out.splice(at..at, inventory);
    }
    for c in 0..CONNECTIONS {
        for dir in 0..2u8 {
            let rec = Rec::End {
                key: keys[c],
                dir,
                seq: kernels[c].seq[dir as usize],
                offset: kernels[c].accepted[dir as usize],
                loss: kernels[c].loss[dir as usize],
            };
            cap.deliver(rec, None);
        }
    }
    Trial {
        truth,
        stream: cap.out,
        damaged: cap.damaged,
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Observer {
    /// Sequences, offsets and inventories; skips known gaps and resyncs responses.
    Full,
    /// As `Full`, without response resync.
    SkipOnly,
    /// Any lost record invalidates its lifetime (the first implementation).
    Conservative,
    /// Pre-improvement metadata: chunks of one call, no call sequences.
    ChunkMetadata,
    /// Bytes in arrival order, no capture metadata.
    Naive,
}
impl Observer {
    fn name(self) -> &'static str {
        match self {
            Observer::Full => "full_recovery",
            Observer::SkipOnly => "skip_known_gaps_only",
            Observer::Conservative => "conservative_invalidation",
            Observer::ChunkMetadata => "chunk_metadata_only",
            Observer::Naive => "naive",
        }
    }
    fn recovery(self) -> Recovery {
        Recovery {
            skip_known_gaps: matches!(self, Observer::Full | Observer::SkipOnly),
            resync_responses: self == Observer::Full,
        }
    }
}

fn view(observer: Observer, stream: &[Rec]) -> Vec<Rec> {
    match observer {
        Observer::Full | Observer::SkipOnly | Observer::Conservative => stream.to_vec(),
        Observer::ChunkMetadata | Observer::Naive => without_sequences(observer, stream),
    }
}

/// Renumber calls and offsets in arrival order so whole-call gaps vanish. The
/// naive view also re-forms damaged calls from whatever chunks arrived.
fn without_sequences(observer: Observer, stream: &[Rec]) -> Vec<Rec> {
    let mut calls: Vec<(ConnectionKey, u8, u64, Vec<&Rec>)> = vec![];
    let mut order: Vec<Option<usize>> = vec![];
    for r in stream {
        match r {
            Rec::Data { key, dir, seq, .. } => match calls.last_mut() {
                Some(last) if last.0 == *key && last.1 == *dir && last.2 == *seq => {
                    last.3.push(r);
                    order.push(None);
                }
                _ => {
                    calls.push((*key, *dir, *seq, vec![r]));
                    order.push(Some(calls.len() - 1));
                }
            },
            _ => order.push(None),
        }
    }
    let mut counts: HashMap<(ConnectionKey, u8), (u64, u64)> = HashMap::new();
    let mut out = vec![];
    for (i, r) in stream.iter().enumerate() {
        if let Some(call) = order[i] {
            let (key, dir, _, parts) = &calls[call];
            let (n, offset) = counts.entry((*key, *dir)).or_default();
            *n += 1;
            let Rec::Data {
                call_id,
                ts,
                chunks,
                total,
                truncated,
                ..
            } = parts[0]
            else {
                unreachable!()
            };
            let complete = parts.len() == *chunks as usize
                && parts
                    .iter()
                    .enumerate()
                    .all(|(j, p)| matches!(p, Rec::Data { index, .. } if *index as usize == j));
            if complete || observer == Observer::ChunkMetadata {
                for p in parts {
                    let Rec::Data { index, data, .. } = p else {
                        unreachable!()
                    };
                    out.push(Rec::Data {
                        key: *key,
                        dir: *dir,
                        seq: *n,
                        loss: 0,
                        call_id: *call_id,
                        ts: *ts,
                        offset: *offset,
                        index: *index,
                        chunks: *chunks,
                        total: *total,
                        truncated: *truncated,
                        data: data.clone(),
                    });
                }
                *offset += u64::from(*total);
            } else {
                let bytes: Vec<u8> = parts
                    .iter()
                    .flat_map(|p| match p {
                        Rec::Data { data, .. } => data.clone(),
                        _ => unreachable!(),
                    })
                    .collect();
                let pieces: Vec<_> = bytes.chunks(CHUNK_BYTES as usize).collect();
                for (j, piece) in pieces.iter().enumerate() {
                    out.push(Rec::Data {
                        key: *key,
                        dir: *dir,
                        seq: *n,
                        loss: 0,
                        call_id: *call_id,
                        ts: *ts,
                        offset: *offset,
                        index: j as u16,
                        chunks: pieces.len() as u16,
                        total: bytes.len() as u32,
                        truncated: false,
                        data: piece.to_vec(),
                    });
                }
                *offset += bytes.len() as u64;
            }
        } else if let Rec::End { key, dir, .. } = r {
            let (n, offset) = counts.get(&(*key, *dir)).copied().unwrap_or_default();
            out.push(Rec::End {
                key: *key,
                dir: *dir,
                seq: n,
                offset,
                loss: 0,
            });
        }
    }
    out
}

fn replay(stream: &[Rec], recovery: Recovery) -> Vec<UsageObservation> {
    let mut t = UsageTracker::with_recovery(Limits::default(), recovery);
    let mut out = vec![];
    let mut now = 0;
    for r in stream {
        if let Rec::Data { ts, .. } = r {
            now = *ts;
        }
        let ts = now;
        out.extend(match r {
            Rec::Data {
                key,
                dir,
                seq,
                loss,
                call_id,
                offset,
                index,
                chunks,
                total,
                truncated,
                data,
                ..
            } => t.feed(CaptureChunk {
                connection: *key,
                ts_ns: ts,
                direction: *dir,
                sequence: *seq,
                loss_epoch: *loss,
                call_id: *call_id,
                offset: *offset,
                chunk_index: *index,
                chunk_total: *chunks,
                total_bytes: *total,
                truncated: *truncated,
                failed: false,
                end: false,
                data,
            }),
            Rec::End {
                key,
                dir,
                seq,
                offset,
                loss,
            } => t.feed(CaptureChunk {
                connection: *key,
                ts_ns: ts,
                direction: *dir,
                sequence: *seq,
                loss_epoch: *loss,
                call_id: 0,
                offset: *offset,
                chunk_index: 0,
                chunk_total: 1,
                total_bytes: 0,
                truncated: false,
                failed: false,
                end: true,
                data: &[],
            }),
            Rec::Checkpoint {
                key,
                seq,
                accepted,
                loss,
                pass,
            } => t.checkpoint(*key, *seq, *accepted, *loss, *pass, false, ts),
            Rec::PassEnd(pass) => t.checkpoint_pass_end(*pass, ts),
            Rec::Poison(key) => t.capture_loss(*key, ts),
        });
    }
    out.extend(t.finish(u64::MAX / 2));
    out
}

#[derive(Default)]
struct Score {
    requests: u64,
    with_usage: u64,
    exact: u64,
    correct_absent: u64,
    unknown: u64,
    partial_or_conflicting: u64,
    false_complete: u64,
    misassociated: u64,
    false_complete_token_error: u64,
    intact_with_usage: u64,
    exact_intact: u64,
    true_tokens: u64,
    reported_tokens: u64,
}

fn score(
    s: &mut Score,
    truth: &[Vec<Truth>],
    damaged: &HashSet<(usize, usize)>,
    rows: &[UsageObservation],
) {
    let mut by_attempt: HashMap<(usize, u64), Vec<&UsageObservation>> = HashMap::new();
    for r in rows {
        if let Some(o) = r.request_ordinal {
            let c = (r.connection.ssl_ctx - 0x1000) as usize;
            by_attempt.entry((c, o)).or_default().push(r);
        }
    }
    for (c, requests) in truth.iter().enumerate() {
        for (i, t) in requests.iter().enumerate() {
            let rows = by_attempt.remove(&(c, i as u64 + 1)).unwrap_or_default();
            s.requests += 1;
            let reported: Vec<_> = rows
                .iter()
                .filter(|r| r.usage_state == "reported")
                .collect();
            for r in &reported {
                let got = &r.reports[0];
                let got = (got.input.unwrap(), got.output.unwrap());
                s.reported_tokens += got.0 + got.1;
                if t.usage != Some(got) {
                    s.false_complete += 1;
                    let truth_total = t.usage.map(|u| u.0 + u.1).unwrap_or(0);
                    s.false_complete_token_error += (got.0 + got.1).abs_diff(truth_total);
                    if requests.iter().any(|o| o.usage == Some(got)) {
                        s.misassociated += 1;
                    }
                }
            }
            match t.usage {
                Some(u) => {
                    s.with_usage += 1;
                    s.true_tokens += u.0 + u.1;
                    let exact = reported.iter().any(|r| {
                        let g = &r.reports[0];
                        (g.input, g.output) == (Some(u.0), Some(u.1))
                    });
                    let intact = !damaged.contains(&(c, i + 1));
                    s.intact_with_usage += intact as u64;
                    if exact {
                        s.exact += 1;
                        s.exact_intact += intact as u64;
                    } else if rows.iter().any(|r| {
                        matches!(r.usage_state.as_str(), "reported_partial" | "conflicting")
                    }) {
                        s.partial_or_conflicting += 1;
                    } else {
                        s.unknown += 1;
                    }
                }
                None => {
                    if reported.is_empty()
                        && rows.iter().any(|r| {
                            r.usage_state == "absent"
                                && matches!(
                                    r.reason.as_deref(),
                                    Some("http_error" | "usage_not_reported")
                                )
                        })
                    {
                        s.correct_absent += 1;
                    }
                }
            }
        }
    }
    // Reported rows for attempts that were never sent (ordinal shifted past the end).
    for rows in by_attempt.values() {
        for r in rows.iter().filter(|r| r.usage_state == "reported") {
            let g = &r.reports[0];
            s.false_complete += 1;
            s.misassociated += 1;
            s.reported_tokens += g.total.unwrap();
            s.false_complete_token_error += g.total.unwrap();
        }
    }
}

fn main() {
    let trials: u64 = std::env::args()
        .nth(1)
        .map(|a| a.parse().expect("trials"))
        .unwrap_or(40);
    let observers = [
        Observer::Full,
        Observer::SkipOnly,
        Observer::Conservative,
        Observer::ChunkMetadata,
        Observer::Naive,
    ];
    let mut cells = vec![];
    let conditions: Vec<(&str, f64, Faults)> = std::iter::once((
        "none",
        0.0,
        Faults {
            kernel: 0.0,
            user: 0.0,
        },
    ))
    .chain([0.0005, 0.002, 0.01].into_iter().flat_map(|p| {
        [
            (
                "kernel_reserve_failure",
                p,
                Faults {
                    kernel: p,
                    user: 0.0,
                },
            ),
            (
                "userspace_queue_drop",
                p,
                Faults {
                    kernel: 0.0,
                    user: p,
                },
            ),
        ]
    }))
    .collect();
    for (fault, rate, faults) in &conditions {
        let mut scores: Vec<Score> = observers.iter().map(|_| Score::default()).collect();
        for trial_index in 0..trials {
            let seed = 0x7015_2026_1015 ^ (trial_index * 0x1_0000_0001);
            let t = trial(seed, faults);
            for (o, observer) in observers.iter().enumerate() {
                let rows = replay(&view(*observer, &t.stream), observer.recovery());
                score(&mut scores[o], &t.truth, &t.damaged, &rows);
            }
        }
        for (observer, s) in observers.iter().zip(scores) {
            let rate_of = |n: u64, d: u64| if d == 0 { 0.0 } else { n as f64 / d as f64 };
            cells.push(format!(
                concat!(
                    "    {{\"fault\":\"{}\",\"rate\":{},\"observer\":\"{}\",\"requests\":{},",
                    "\"with_usage\":{},\"exact\":{},\"exact_rate\":{:.4},\"unknown\":{},",
                    "\"partial_or_conflicting\":{},\"correct_absent\":{},",
                    "\"false_complete\":{},\"false_complete_per_1000\":{:.3},\"misassociated\":{},",
                    "\"false_complete_token_error\":{},\"intact_with_usage\":{},",
                    "\"exact_of_intact\":{:.4},\"true_tokens\":{},\"reported_tokens\":{}}}"
                ),
                fault,
                rate,
                observer.name(),
                s.requests,
                s.with_usage,
                s.exact,
                rate_of(s.exact, s.with_usage),
                s.unknown,
                s.partial_or_conflicting,
                s.correct_absent,
                s.false_complete,
                1000.0 * rate_of(s.false_complete, s.requests),
                s.misassociated,
                s.false_complete_token_error,
                s.intact_with_usage,
                rate_of(s.exact_intact, s.intact_with_usage),
                s.true_tokens,
                s.reported_tokens,
            ));
        }
    }
    println!(
        "{{\n  \"experiment\":\"E4 replay ablation (deterministic simulation)\",\n  \"trials\":{trials},\n  \"connections_per_trial\":{CONNECTIONS},\n  \"requests_per_connection\":{REQUESTS},\n  \"cells\":[\n{}\n  ]\n}}",
        cells.join(",\n")
    );
}
