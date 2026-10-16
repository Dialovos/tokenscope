//! Bounded, conservative HTTP/1.1 reported usage. Never serializes body/header text.
//!
//! Captured calls stream through incremental HTTP/1.1, chunked and SSE state
//! machines. Only a header block, one JSON response body or one SSE line/event
//! is buffered at a time; request bodies and responses that cannot carry
//! provider usage are skipped by length.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConnectionKey {
    pub tgid: u32,
    pub process_start: u64,
    pub exec_generation: u64,
    pub ssl_ctx: u64,
    pub generation: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenCounts {
    pub input: Option<u64>,
    pub output: Option<u64>,
    pub total: Option<u64>,
    pub cached_input: Option<u64>,
    pub reasoning_output: Option<u64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageObservation {
    pub connection: ConnectionKey,
    #[serde(default)]
    pub capture_epoch: String,
    pub ts_ns: u64,
    pub request_ordinal: Option<u64>,
    pub usage_state: String,
    pub capture_integrity: String,
    pub termination: String,
    pub reason: Option<String>,
    pub reports: Vec<TokenCounts>,
}
impl UsageObservation {
    fn unavailable(key: ConnectionKey, ts_ns: u64, ordinal: Option<u64>, reason: &str) -> Self {
        Self {
            connection: key,
            capture_epoch: String::new(),
            ts_ns,
            request_ordinal: ordinal,
            usage_state: "absent".into(),
            capture_integrity: "unverified".into(),
            termination: "incomplete".into(),
            reason: Some(reason.into()),
            reports: vec![],
        }
    }
}
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Admitted lifetimes still being parsed. Closed, released and
    /// invalidated lifetimes leave this set and become tombstones.
    pub connections: usize,
    /// Remembered retired identities, so late records cannot restart them.
    pub tombstones: usize,
    pub per_connection_bytes: usize,
    pub total_bytes: usize,
    pub header_bytes: usize,
    /// Buffered JSON response body of a provider request.
    pub body_bytes: usize,
    /// One SSE line or dispatched event.
    pub event_bytes: usize,
    pub pending_requests: usize,
    /// Backstop for lifetimes that stop mid-message without lifecycle evidence.
    pub idle_ns: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            connections: 1024,
            tombstones: 65536,
            per_connection_bytes: 2 * 1024 * 1024,
            total_bytes: 16 * 1024 * 1024,
            header_bytes: 16 * 1024,
            body_bytes: 1024 * 1024,
            event_bytes: 256 * 1024,
            pending_requests: 16,
            idle_ns: 30 * 60 * 1_000_000_000,
        }
    }
}
/// tls.bpf.c copies at most 16 chunks of 4 KiB from one SSL call.
pub const CHUNK_BYTES: u32 = 4096;
pub const CALL_CAPTURE_BYTES: u32 = 16 * CHUNK_BYTES;

/// How the tracker continues after missing bytes of known size.
#[derive(Debug, Clone, Copy)]
pub struct Recovery {
    /// Skip a gap that lies inside a length-delimited body being discarded
    /// (request bodies, responses that cannot carry provider usage). Sound:
    /// framing is preserved by the known length.
    pub skip_known_gaps: bool,
    /// After an unrecoverable gap in a response, report that request as
    /// unverified and resume at the first read entered after the client's next
    /// request write. Assumes the client does not pipeline; observed pipelining
    /// disables it per lifetime, and later rows say `observed_after_resync`.
    pub resync_responses: bool,
}
impl Default for Recovery {
    fn default() -> Self {
        Self {
            skip_known_gaps: true,
            resync_responses: true,
        }
    }
}

/// Successful OpenSSL call chunks only. A lifecycle closure uses `end=true`.
pub struct CaptureChunk<'a> {
    pub connection: ConnectionKey,
    pub ts_ns: u64,
    pub direction: u8,
    pub sequence: u64,
    pub loss_epoch: u64,
    /// Call entry time (BPF ktime); `ts_ns` is the return time.
    pub call_id: u64,
    /// Accepted bytes in this direction before the call. Closure records carry
    /// the final count.
    pub offset: u64,
    pub chunk_index: u16,
    pub chunk_total: u16,
    /// Accepted bytes of the whole call, including any uncaptured tail.
    pub total_bytes: u32,
    /// The call exceeded `CALL_CAPTURE_BYTES`; only its prefix was copied.
    pub truncated: bool,
    /// The copy failed; this chunk's bytes are missing.
    pub failed: bool,
    pub end: bool,
    pub data: &'a [u8],
}

#[derive(Default)]
enum Framing {
    #[default]
    Head,
    Fixed(u64),
    Chunked(ChunkPhase),
}
#[derive(Clone, Copy)]
enum ChunkPhase {
    Size,
    Data(u64),
    DataEnd(u8),
    Trailer,
}
#[derive(Default)]
enum Sink {
    #[default]
    Discard,
    Json(Vec<u8>),
    Sse(Box<Sse>),
}
struct Response {
    ordinal: u64,
    provider: bool,
    /// Known before the body: the body is skipped and this reason is reported.
    absent: Option<&'static str>,
}
#[derive(Default)]
struct Stream {
    sequence: u64,
    call_id: u64,
    chunk_total: u16,
    /// Stream position up to which bytes were parsed or skipped.
    consumed: u64,
    /// End position of the latest call seen.
    call_end: u64,
    closed: bool,
    framing: Framing,
    /// Header block, chunk-size line or trailer section being assembled.
    buf: Vec<u8>,
    sink: Sink,
    response: Option<Response>,
    /// Responses only: discarding after a gap. `Some(t)` resumes at the first
    /// read entered after `t`, the return of the next request's first write.
    resync: Option<Option<u64>>,
    /// Requests only: return time of the call holding the head's first byte.
    head_start_ns: u64,
}
impl Stream {
    fn bytes(&self) -> usize {
        self.buf.capacity()
            + match &self.sink {
                Sink::Discard => 0,
                Sink::Json(b) => b.capacity(),
                Sink::Sse(s) => s.line.capacity() + s.data.capacity(),
            }
    }
    fn push(&mut self, data: &[u8], limits: &Limits) -> Result<(), &'static str> {
        match &mut self.sink {
            Sink::Discard => Ok(()),
            Sink::Json(body) => {
                if body.len() + data.len() > limits.body_bytes {
                    return Err("body_limit");
                }
                body.extend_from_slice(data);
                Ok(())
            }
            Sink::Sse(sse) => sse.feed(data, limits.event_bytes),
        }
    }
}
struct Pending {
    ordinal: u64,
    provider: bool,
    head: bool,
    /// Return time of the call holding the request's first byte.
    written_ns: u64,
}
enum Step {
    Continue,
    Closed,
    OutOfScope,
}
struct Connection {
    dirs: [Stream; 2],
    pending: VecDeque<Pending>,
    next_ordinal: u64,
    last_ns: u64,
    last_seen_pass: u64,
    /// Kernel accepted-byte inventory from the previous checkpoint pass.
    inventory: Option<[u64; 2]>,
    host_checked: bool,
    out_of_scope: bool,
    /// A response began while a later request was already written.
    pipelined: bool,
    /// Association after this point relies on the resync assumption.
    resynced: bool,
}
impl Connection {
    fn new(now: u64, pass: u64) -> Self {
        Self {
            dirs: Default::default(),
            pending: VecDeque::new(),
            next_ordinal: 1,
            last_ns: now,
            last_seen_pass: pass,
            inventory: None,
            host_checked: false,
            out_of_scope: false,
            pipelined: false,
            resynced: false,
        }
    }
    fn bytes(&self) -> usize {
        self.dirs.iter().map(Stream::bytes).sum()
    }
    /// Anything observed but not yet reconciled into a complete message.
    fn partial(&self) -> bool {
        !self.pending.is_empty()
            || self.dirs.iter().any(|d| {
                d.consumed < d.call_end
                    || !matches!(d.framing, Framing::Head)
                    || !d.buf.is_empty()
                    || d.response.is_some()
            })
    }
    fn rows(&self, key: ConnectionKey, now: u64, reason: &str) -> Vec<UsageObservation> {
        let active = self.dirs[1]
            .response
            .iter()
            .filter(|r| r.provider)
            .map(|r| r.ordinal);
        let pending = self
            .pending
            .iter()
            .filter(|p| p.provider)
            .map(|p| p.ordinal);
        let mut out: Vec<_> = active
            .chain(pending)
            .map(|o| UsageObservation::unavailable(key, now, Some(o), reason))
            .collect();
        out.push(UsageObservation::unavailable(key, now, None, reason));
        out
    }
    /// Reconcile a kernel byte count for direction `di` that is known to be
    /// final up to `accepted`: anything not consumed was lost.
    fn reconcile(
        &mut self,
        key: ConnectionKey,
        di: usize,
        accepted: u64,
        ts: u64,
        recovery: &Recovery,
        out: &mut Vec<UsageObservation>,
    ) -> Result<(), &'static str> {
        let consumed = self.dirs[di].consumed;
        if accepted < consumed {
            return Err("inventory_regression");
        }
        self.gap(key, di, accepted - consumed, true, None, ts, recovery, out)
    }
    #[allow(clippy::too_many_arguments)]
    fn step(
        &mut self,
        key: ConnectionKey,
        ch: &CaptureChunk<'_>,
        limits: &Limits,
        recovery: &Recovery,
        out: &mut Vec<UsageObservation>,
    ) -> Result<Step, &'static str> {
        let di = ch.direction as usize;
        let ts = ch.ts_ns;
        if ch.end {
            if ch.loss_epoch != 0 || ch.sequence < self.dirs[di].sequence {
                return Err("closure_gap");
            }
            self.reconcile(key, di, ch.offset, ts, recovery, out)?;
            self.dirs[di].closed = true;
            if self.dirs.iter().all(|d| d.closed) {
                if self.partial() {
                    return Err("incomplete_message_at_close");
                }
                return Ok(Step::Closed);
            }
            return Ok(Step::Continue);
        }
        if ch.loss_epoch != 0 {
            // Calls of unknown size happened on this stream.
            return Err("capture_loss");
        }
        let d = &mut self.dirs[di];
        let chunks = if ch.truncated {
            CALL_CAPTURE_BYTES / CHUNK_BYTES
        } else {
            ch.total_bytes.div_ceil(CHUNK_BYTES)
        };
        if d.closed
            || ch.total_bytes == 0
            || ch.truncated != (ch.total_bytes > CALL_CAPTURE_BYTES)
            || u32::from(ch.chunk_total) != chunks
            || ch.chunk_index >= ch.chunk_total
        {
            return Err("invalid_chunk");
        }
        let within = u32::from(ch.chunk_index) * CHUNK_BYTES;
        let expected = (ch.total_bytes - within).min(CHUNK_BYTES) as usize;
        if ch.data.len() != if ch.failed { 0 } else { expected } {
            return Err("chunk_length_mismatch");
        }
        let position = ch.offset + u64::from(within);
        let new_call = ch.sequence != d.sequence;
        if position < d.consumed || ch.sequence < d.sequence {
            return Err("chunk_regression");
        }
        if new_call {
            if ch.offset < d.call_end {
                return Err("chunk_regression");
            }
            d.sequence = ch.sequence;
            d.call_id = ch.call_id;
            d.chunk_total = ch.chunk_total;
            d.call_end = ch.offset + u64::from(ch.total_bytes);
        } else if ch.call_id != d.call_id
            || ch.chunk_total != d.chunk_total
            || ch.offset + u64::from(ch.total_bytes) != d.call_end
        {
            return Err("chunk_mismatch");
        }
        // Records of whole calls or chunks that never arrived: sized exactly.
        let missing = position - d.consumed;
        let read = Some(ch.call_id);
        self.gap(key, di, missing, true, read, ts, recovery, out)?;
        if self.out_of_scope {
            return Ok(Step::OutOfScope);
        }
        let d = &mut self.dirs[1];
        if di == 1 && new_call && ch.chunk_index == 0 {
            if let Some(Some(after)) = d.resync {
                if ch.call_id > after {
                    d.resync = None;
                }
            }
        }
        if ch.failed {
            self.gap(key, di, expected as u64, true, read, ts, recovery, out)?;
        } else {
            self.consume(key, di, ch.data, ts, limits, out)?;
            self.dirs[di].consumed = position + expected as u64;
        }
        if ch.truncated && ch.chunk_index + 1 == ch.chunk_total {
            let uncaptured = u64::from(ch.total_bytes - CALL_CAPTURE_BYTES);
            self.gap(key, di, uncaptured, false, read, ts, recovery, out)?;
        }
        Ok(if self.out_of_scope {
            Step::OutOfScope
        } else {
            Step::Continue
        })
    }
    /// Account for `bytes` that were accepted but never seen. `lost` gaps come
    /// from missing records; the others are uncaptured tails of truncated calls.
    /// `read` is the entry time of the call that revealed the gap, if any.
    #[allow(clippy::too_many_arguments)]
    fn gap(
        &mut self,
        key: ConnectionKey,
        di: usize,
        bytes: u64,
        lost: bool,
        read: Option<u64>,
        ts: u64,
        recovery: &Recovery,
        out: &mut Vec<UsageObservation>,
    ) -> Result<(), &'static str> {
        if bytes == 0 || self.out_of_scope {
            self.dirs[di].consumed += bytes;
            return Ok(());
        }
        let d = &mut self.dirs[di];
        if let Some(target) = d.resync {
            d.consumed += bytes;
            // Lost reads may have entered after the resume point, so the
            // response being waited for may be among them.
            let unplaced = match (target, read) {
                (Some(after), Some(entered)) => entered > after,
                (Some(_), None) => true,
                (None, _) => false,
            };
            if unplaced {
                let reason = if lost {
                    "capture_gap"
                } else {
                    "truncated_capture"
                };
                self.abandon_response(key, read, ts, reason, out)?;
            }
            return Ok(());
        }
        let skippable = !lost || recovery.skip_known_gaps;
        match d.framing {
            Framing::Fixed(remaining)
                if skippable && remaining >= bytes && matches!(d.sink, Sink::Discard) =>
            {
                d.consumed += bytes;
                if remaining == bytes {
                    self.complete(key, di, ts, out);
                } else {
                    d.framing = Framing::Fixed(remaining - bytes);
                }
                Ok(())
            }
            _ if di == 1 && recovery.resync_responses => {
                let reason = if lost {
                    "capture_gap"
                } else {
                    "truncated_capture"
                };
                self.abandon_response(key, read, ts, reason, out)?;
                self.dirs[1].consumed += bytes;
                Ok(())
            }
            _ if lost => Err("capture_gap"),
            _ => Err("truncated_capture"),
        }
    }
    /// Response bytes of unknown framing were lost. Every request whose
    /// response may overlap them is reported unverified; responses are then
    /// discarded until the first read entered after the next request's write.
    ///
    /// Assumes a non-pipelining client: a request is written only after the
    /// previous response was read to its end. Lost reads that entered before the
    /// revealing read (`read`) cannot hold responses to requests written after
    /// it; without a revealing read, every outstanding request is affected.
    fn abandon_response(
        &mut self,
        key: ConnectionKey,
        read: Option<u64>,
        ts: u64,
        reason: &'static str,
        out: &mut Vec<UsageObservation>,
    ) -> Result<(), &'static str> {
        if self.pipelined {
            return Err(reason);
        }
        let mut affected = vec![];
        if let Some(r) = self.dirs[1].response.take() {
            affected.push((r.ordinal, r.provider));
        }
        while let Some(p) = self.pending.front() {
            if read.is_some_and(|entered| p.written_ns > entered) {
                break;
            }
            affected.push((p.ordinal, p.provider));
            self.pending.pop_front();
        }
        if affected.is_empty() {
            // Response bytes with no outstanding request.
            return Err(reason);
        }
        for (ordinal, provider) in affected {
            if provider {
                out.push(UsageObservation::unavailable(
                    key,
                    ts,
                    Some(ordinal),
                    reason,
                ));
            }
        }
        let d = &mut self.dirs[1];
        d.framing = Framing::Head;
        d.buf = Vec::new();
        d.sink = Sink::Discard;
        d.resync = Some(self.pending.front().map(|p| p.written_ns));
        self.resynced = true;
        Ok(())
    }
    fn consume(
        &mut self,
        key: ConnectionKey,
        di: usize,
        mut input: &[u8],
        ts: u64,
        limits: &Limits,
        out: &mut Vec<UsageObservation>,
    ) -> Result<(), &'static str> {
        if self.dirs[di].resync.is_some() {
            return Ok(());
        }
        while !input.is_empty() && !self.out_of_scope {
            let used = match self.dirs[di].framing {
                Framing::Head => {
                    let d = &mut self.dirs[di];
                    if d.buf.is_empty() {
                        d.head_start_ns = ts;
                    }
                    let (used, end) = scan(
                        &mut d.buf,
                        input,
                        b"\r\n\r\n",
                        limits.header_bytes,
                        "header_limit",
                    )?;
                    if let Some(end) = end {
                        let block = std::mem::take(&mut d.buf);
                        if !self.host_checked && (di == 1) != block.starts_with(b"HTTP/") {
                            // The peer spoke first: this process is the server.
                            self.host_checked = true;
                            self.out_of_scope = true;
                            return Ok(());
                        }
                        let head = parse_head(&block[..end - 4], di == 1)?;
                        self.on_head(key, di, head, ts, limits, out)?;
                    }
                    used
                }
                Framing::Fixed(remaining) => {
                    let used = remaining.min(input.len() as u64) as usize;
                    self.dirs[di].push(&input[..used], limits)?;
                    if remaining == used as u64 {
                        self.complete(key, di, ts, out);
                    } else {
                        self.dirs[di].framing = Framing::Fixed(remaining - used as u64);
                    }
                    used
                }
                Framing::Chunked(phase) => self.chunked(key, di, phase, input, ts, limits, out)?,
            };
            input = &input[used..];
        }
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    fn chunked(
        &mut self,
        key: ConnectionKey,
        di: usize,
        phase: ChunkPhase,
        input: &[u8],
        ts: u64,
        limits: &Limits,
        out: &mut Vec<UsageObservation>,
    ) -> Result<usize, &'static str> {
        let d = &mut self.dirs[di];
        match phase {
            ChunkPhase::Size => {
                let (used, end) = scan(
                    &mut d.buf,
                    input,
                    b"\r\n",
                    limits.header_bytes,
                    "chunk_header_limit",
                )?;
                if let Some(end) = end {
                    let line = std::mem::take(&mut d.buf);
                    let line = std::str::from_utf8(&line[..end - 2])
                        .map_err(|_| "invalid_chunk_length")?;
                    let size_text = line.split(';').next().unwrap();
                    if size_text.is_empty() || !size_text.bytes().all(|b| b.is_ascii_hexdigit()) {
                        return Err("invalid_chunk_length");
                    }
                    let size =
                        u64::from_str_radix(size_text, 16).map_err(|_| "invalid_chunk_length")?;
                    d.framing = Framing::Chunked(if size == 0 {
                        // The size line's CRLF begins the trailer section, which
                        // therefore always ends with CRLF CRLF.
                        d.buf.extend_from_slice(b"\r\n");
                        ChunkPhase::Trailer
                    } else {
                        ChunkPhase::Data(size)
                    });
                }
                Ok(used)
            }
            ChunkPhase::Data(remaining) => {
                let used = remaining.min(input.len() as u64) as usize;
                d.push(&input[..used], limits)?;
                d.framing = Framing::Chunked(if remaining == used as u64 {
                    ChunkPhase::DataEnd(0)
                } else {
                    ChunkPhase::Data(remaining - used as u64)
                });
                Ok(used)
            }
            ChunkPhase::DataEnd(matched) => {
                let want = &b"\r\n"[matched as usize..];
                let used = want.len().min(input.len());
                if input[..used] != want[..used] {
                    return Err("invalid_chunk_terminator");
                }
                let matched = matched as usize + used;
                d.framing = Framing::Chunked(if matched == 2 {
                    ChunkPhase::Size
                } else {
                    ChunkPhase::DataEnd(matched as u8)
                });
                Ok(used)
            }
            ChunkPhase::Trailer => {
                let (used, end) = scan(
                    &mut d.buf,
                    input,
                    b"\r\n\r\n",
                    limits.header_bytes,
                    "trailer_limit",
                )?;
                if let Some(end) = end {
                    let section = std::mem::take(&mut d.buf);
                    if end > 4 {
                        let trailers = std::str::from_utf8(&section[2..end - 4])
                            .map_err(|_| "invalid_trailer")?;
                        for line in trailers.split("\r\n") {
                            let (name, _) = line.split_once(':').ok_or("invalid_trailer")?;
                            if !token(name)
                                || name.eq_ignore_ascii_case("content-length")
                                || name.eq_ignore_ascii_case("transfer-encoding")
                            {
                                return Err("invalid_trailer");
                            }
                        }
                    }
                    self.complete(key, di, ts, out);
                }
                Ok(used)
            }
        }
    }
    fn on_head(
        &mut self,
        key: ConnectionKey,
        di: usize,
        h: Head,
        ts: u64,
        limits: &Limits,
        out: &mut Vec<UsageObservation>,
    ) -> Result<(), &'static str> {
        if di == 0 {
            if !self.host_checked {
                self.host_checked = true;
                // HTTP/1.1 clients keep one origin per TLS connection. A lifetime
                // whose first request is not for the provider is released.
                if !h.host_provider {
                    self.out_of_scope = true;
                    return Ok(());
                }
            }
            let written_ns = self.dirs[0].head_start_ns;
            if let Some(after @ None) = &mut self.dirs[1].resync {
                *after = Some(written_ns);
            }
            if self.pending.len() >= limits.pending_requests {
                return Err("pending_request_limit");
            }
            let ordinal = self.next_ordinal;
            self.next_ordinal += 1;
            self.pending.push_back(Pending {
                ordinal,
                provider: h.endpoint && h.host_provider,
                head: h.head_method,
                written_ns,
            });
            let d = &mut self.dirs[0];
            d.sink = Sink::Discard;
            d.framing = if h.chunked {
                Framing::Chunked(ChunkPhase::Size)
            } else {
                match h.length {
                    Some(n) if n > 0 => Framing::Fixed(n),
                    _ => Framing::Head,
                }
            };
            return Ok(());
        }
        if h.informational {
            return Ok(());
        }
        if self.pending.len() > 1 {
            // A later request was written before this response began.
            self.pipelined = true;
        }
        let p = self.pending.pop_front().ok_or("response_without_request")?;
        let success = (200..300).contains(&h.status);
        let absent = if !p.provider {
            None
        } else if !success {
            Some("http_error")
        } else if h.status == 204 {
            Some("usage_not_reported")
        } else if !h.sse && !h.json {
            Some("unsupported_media_type")
        } else {
            None
        };
        let d = &mut self.dirs[1];
        d.sink = match (p.provider && absent.is_none(), h.sse) {
            (true, true) => Sink::Sse(Box::default()),
            (true, false) => Sink::Json(Vec::new()),
            (false, _) => Sink::Discard,
        };
        d.response = Some(Response {
            ordinal: p.ordinal,
            provider: p.provider,
            absent,
        });
        if p.head || h.status == 204 || h.status == 304 {
            self.complete(key, 1, ts, out);
        } else if h.chunked {
            d.framing = Framing::Chunked(ChunkPhase::Size);
        } else if let Some(n) = h.length {
            if matches!(d.sink, Sink::Json(_)) && n > limits.body_bytes as u64 {
                return Err("body_limit");
            }
            if n == 0 {
                self.complete(key, 1, ts, out);
            } else {
                d.framing = Framing::Fixed(n);
            }
        } else {
            return Err("unsupported_close_delimited_body");
        }
        Ok(())
    }
    fn complete(
        &mut self,
        key: ConnectionKey,
        di: usize,
        ts: u64,
        out: &mut Vec<UsageObservation>,
    ) {
        let d = &mut self.dirs[di];
        d.framing = Framing::Head;
        let sink = std::mem::take(&mut d.sink);
        let Some(r) = d.response.take() else {
            return;
        };
        if !r.provider {
            return;
        }
        let (state, reports, reason) = match (r.absent, sink) {
            (Some(reason), _) => ("absent", vec![], Some(reason)),
            (None, Sink::Json(body)) => {
                let mut acc = Accumulator::default();
                match std::str::from_utf8(&body) {
                    Ok(text) => add_report(text, &mut acc.reports, &mut acc.invalid),
                    Err(_) => acc.invalid = true,
                }
                acc.finish(false)
            }
            (None, Sink::Sse(sse)) => sse.acc.finish(true),
            (None, Sink::Discard) => ("absent", vec![], Some("usage_not_reported")),
        };
        out.push(UsageObservation {
            connection: key,
            capture_epoch: String::new(),
            ts_ns: ts,
            request_ordinal: Some(r.ordinal),
            usage_state: state.into(),
            capture_integrity: if self.resynced {
                "observed_after_resync"
            } else {
                "observed_contiguous"
            }
            .into(),
            termination: "http_complete".into(),
            reason: reason.map(str::to_owned),
            reports,
        });
    }
}

/// Append `input` to `buf` until `pat` terminates a section of at most `limit`
/// bytes. Returns the input bytes used and, when found, the section's end.
fn scan(
    buf: &mut Vec<u8>,
    input: &[u8],
    pat: &[u8],
    limit: usize,
    error: &'static str,
) -> Result<(usize, Option<usize>), &'static str> {
    let old = buf.len();
    let take = input.len().min(limit.saturating_sub(old));
    buf.extend_from_slice(&input[..take]);
    let from = old.saturating_sub(pat.len() - 1);
    if let Some(p) = buf[from..].windows(pat.len()).position(|w| w == pat) {
        let end = from + p + pat.len();
        buf.truncate(end);
        return Ok((end - old, Some(end)));
    }
    if buf.len() >= limit {
        return Err(error);
    }
    Ok((take, None))
}

#[derive(Default)]
struct Accumulator {
    reports: Vec<TokenCounts>,
    invalid: bool,
    terminal: bool,
    utf8_invalid: bool,
}
impl Accumulator {
    fn finish(self, sse: bool) -> (&'static str, Vec<TokenCounts>, Option<&'static str>) {
        if self.utf8_invalid {
            return ("absent", vec![], Some("invalid_utf8"));
        }
        let terminal = !sse || self.terminal;
        let reports = self.reports;
        // A malformed event cannot erase disagreement already established by valid
        // reports, nor create a reported value when no valid count was observed.
        if reports.len() > 1 {
            return ("conflicting", reports, Some("conflicting_usage"));
        }
        if self.invalid {
            return (
                if reports.is_empty() {
                    "absent"
                } else {
                    "reported_partial"
                },
                reports,
                Some("invalid_provider_payload"),
            );
        }
        if reports.is_empty() {
            return (
                "absent",
                reports,
                Some(if terminal {
                    "usage_not_reported"
                } else {
                    "missing_sse_terminal"
                }),
            );
        }
        let r = &reports[0];
        if !terminal || r.input.is_none() || r.output.is_none() || r.total.is_none() {
            (
                "reported_partial",
                reports,
                Some(if terminal {
                    "missing_usage_field"
                } else {
                    "missing_sse_terminal"
                }),
            )
        } else {
            ("reported", reports, None)
        }
    }
}

/// Incremental SSE: LF, CRLF and bare CR end lines; data lines join with
/// newline; a blank line dispatches. An unterminated event is never dispatched.
#[derive(Default)]
struct Sse {
    line: Vec<u8>,
    data: Vec<u8>,
    after_cr: bool,
    started: bool,
    acc: Accumulator,
}
impl Sse {
    fn feed(&mut self, mut input: &[u8], limit: usize) -> Result<(), &'static str> {
        while !input.is_empty() {
            if self.after_cr {
                self.after_cr = false;
                if input[0] == b'\n' {
                    input = &input[1..];
                    continue;
                }
            }
            let Some(p) = input.iter().position(|&b| b == b'\n' || b == b'\r') else {
                if self.line.len() + input.len() > limit {
                    return Err("sse_event_limit");
                }
                self.line.extend_from_slice(input);
                return Ok(());
            };
            if self.line.len() + p > limit {
                return Err("sse_event_limit");
            }
            self.line.extend_from_slice(&input[..p]);
            self.after_cr = input[p] == b'\r';
            input = &input[p + 1..];
            self.end_line(limit)?;
        }
        Ok(())
    }
    fn end_line(&mut self, limit: usize) -> Result<(), &'static str> {
        let mut line = std::mem::take(&mut self.line);
        if !self.started {
            self.started = true;
            if line.starts_with(b"\xEF\xBB\xBF") {
                line.drain(..3);
            }
        }
        // CR and LF never occur inside a UTF-8 sequence, so line validation
        // equals validating the whole stream.
        if std::str::from_utf8(&line).is_err() {
            self.acc.utf8_invalid = true;
        }
        if line.is_empty() {
            if !self.data.is_empty() {
                let mut data = std::mem::take(&mut self.data);
                data.pop();
                self.dispatch(&data);
            }
        } else if let Some(value) = line.strip_prefix(b"data:".as_slice()) {
            let value = value.strip_prefix(b" ".as_slice()).unwrap_or(value);
            if self.data.len() + value.len() + 1 > limit {
                return Err("sse_event_limit");
            }
            self.data.extend_from_slice(value);
            self.data.push(b'\n');
        } else if line == b"data" {
            if self.data.len() + 1 > limit {
                return Err("sse_event_limit");
            }
            self.data.push(b'\n');
        }
        line.clear();
        if line.capacity() <= 4096 {
            self.line = line;
        }
        Ok(())
    }
    fn dispatch(&mut self, data: &[u8]) {
        let Ok(text) = std::str::from_utf8(data) else {
            return;
        };
        if text == "[DONE]" {
            self.acc.terminal = true;
        } else if self.acc.terminal {
            self.acc.invalid = true;
        } else {
            add_report(text, &mut self.acc.reports, &mut self.acc.invalid);
        }
    }
}

struct Head {
    status: u16,
    informational: bool,
    head_method: bool,
    endpoint: bool,
    host_provider: bool,
    length: Option<u64>,
    chunked: bool,
    sse: bool,
    json: bool,
}
fn parse_head(block: &[u8], response: bool) -> Result<Head, &'static str> {
    let headers = std::str::from_utf8(block).map_err(|_| "invalid_header")?;
    let mut lines = headers.split("\r\n");
    let first = lines.next().ok_or("invalid_start_line")?;
    let words: Vec<_> = first.split(' ').collect();
    let (status, head_method, endpoint) = if response {
        if words.len() < 2 || words[0] != "HTTP/1.1" || words[1].len() != 3 {
            return Err("unsupported_protocol");
        }
        let status = words[1].parse::<u16>().map_err(|_| "invalid_status")?;
        if !(100..=599).contains(&status) || status == 101 {
            return Err("unsupported_status");
        }
        (status, false, false)
    } else {
        if words.len() != 3 || words[2] != "HTTP/1.1" || !token(words[0]) || words[0] == "CONNECT" {
            return Err("unsupported_protocol");
        }
        (
            0,
            words[0] == "HEAD",
            words[0] == "POST" && words[1] == "/v1/chat/completions",
        )
    };
    let mut length = None;
    let mut chunked = false;
    let mut sse = false;
    let mut json = false;
    let mut content_type_seen = false;
    let mut host_provider = false;
    let mut host_seen = false;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or("invalid_header")?;
        if !token(name) {
            return Err("invalid_header");
        }
        let value = value.trim_matches([' ', '\t']);
        if value.bytes().any(|b| b < 32 && b != b'\t' || b == 127) {
            return Err("invalid_header");
        }
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() || value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err("ambiguous_length");
            }
            length = Some(value.parse::<u64>().map_err(|_| "invalid_length")?);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if chunked || !value.eq_ignore_ascii_case("chunked") {
                return Err("unsupported_transfer_encoding");
            }
            chunked = true;
        } else if name.eq_ignore_ascii_case("content-encoding")
            && !value.eq_ignore_ascii_case("identity")
        {
            return Err("unsupported_content_encoding");
        } else if name.eq_ignore_ascii_case("content-type") {
            if content_type_seen {
                return Err("ambiguous_content_type");
            }
            content_type_seen = true;
            let media = value.split(';').next().unwrap().trim();
            sse = media.eq_ignore_ascii_case("text/event-stream");
            json = media.eq_ignore_ascii_case("application/json");
        } else if name.eq_ignore_ascii_case("host") {
            if host_seen {
                return Err("ambiguous_host");
            }
            host_seen = true;
            host_provider = value.eq_ignore_ascii_case("api.openai.com")
                || value.eq_ignore_ascii_case("api.openai.com:443");
        }
    }
    if chunked && length.is_some() {
        return Err("ambiguous_length");
    }
    if !response && !host_seen {
        return Err("missing_host");
    }
    Ok(Head {
        status,
        informational: response && (100..200).contains(&status),
        head_method,
        endpoint,
        host_provider,
        length,
        chunked,
        sse,
        json,
    })
}
fn token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

pub struct UsageTracker {
    limits: Limits,
    recovery: Recovery,
    live: HashMap<ConnectionKey, Connection>,
    tombstones: HashSet<ConnectionKey>,
    tombstone_order: VecDeque<ConnectionKey>,
    /// Kernel inventories without records yet: (first pass, last pass).
    unseen: HashMap<ConnectionKey, (u64, u64)>,
    retained: usize,
    generation_barrier: u64,
    pass: u64,
    refused: u64,
    out_of_scope: u64,
}
impl Default for UsageTracker {
    fn default() -> Self {
        Self::new(Limits::default())
    }
}
impl UsageTracker {
    pub fn new(limits: Limits) -> Self {
        Self::with_recovery(limits, Recovery::default())
    }
    pub fn with_recovery(limits: Limits, recovery: Recovery) -> Self {
        Self {
            limits,
            recovery,
            live: HashMap::new(),
            tombstones: HashSet::new(),
            tombstone_order: VecDeque::new(),
            unseen: HashMap::new(),
            retained: 0,
            generation_barrier: 0,
            pass: 0,
            refused: 0,
            out_of_scope: 0,
        }
    }
    pub fn retained_bytes(&self) -> usize {
        self.retained
    }
    /// The live-lifetime limit is currently reached; new lifetimes are refused
    /// with an explicit `connection_limit` row until one closes.
    pub fn admission_blocked(&self) -> bool {
        self.live.len() >= self.limits.connections
    }
    pub fn generation_barrier(&self) -> u64 {
        self.generation_barrier
    }
    pub fn connection_count(&self) -> usize {
        self.live.len()
    }
    pub fn refused_connections(&self) -> u64 {
        self.refused
    }
    pub fn out_of_scope_connections(&self) -> u64 {
        self.out_of_scope
    }
    fn bury(&mut self, key: ConnectionKey) {
        if self.tombstones.insert(key) {
            self.tombstone_order.push_back(key);
            while self.tombstone_order.len() > self.limits.tombstones {
                if let Some(old) = self.tombstone_order.pop_front() {
                    self.tombstones.remove(&old);
                }
            }
        }
    }
    fn retire(&mut self, key: ConnectionKey) -> Option<Connection> {
        let c = self.live.remove(&key)?;
        self.retained = self.retained.saturating_sub(c.bytes());
        self.bury(key);
        Some(c)
    }
    fn kill(&mut self, key: ConnectionKey, now: u64, reason: &str) -> Vec<UsageObservation> {
        self.retire(key)
            .map(|c| c.rows(key, now, reason))
            .unwrap_or_default()
    }
    fn refuse(&mut self, key: ConnectionKey, now: u64, reason: &str) -> Vec<UsageObservation> {
        self.unseen.remove(&key);
        self.bury(key);
        vec![UsageObservation::unavailable(key, now, None, reason)]
    }
    pub fn invalidate_all(&mut self, now: u64, reason: &str) -> Vec<UsageObservation> {
        let keys: Vec<_> = self.live.keys().copied().collect();
        keys.into_iter()
            .flat_map(|k| self.kill(k, now, reason))
            .collect()
    }
    /// Loss whose lifetime is unknown. Every open lifetime and every lifetime
    /// created before `now` that has not been admitted yet loses trust.
    pub fn global_loss(&mut self, now: u64) -> Vec<UsageObservation> {
        self.generation_barrier = self.generation_barrier.max(now);
        self.invalidate_all(now, "global_capture_loss")
    }
    /// Loss attributed to one lifetime, such as a dropped userspace record.
    pub fn capture_loss(&mut self, key: ConnectionKey, now: u64) -> Vec<UsageObservation> {
        if self.tombstones.contains(&key) {
            return vec![];
        }
        if self.live.contains_key(&key) {
            self.kill(key, now, "capture_loss")
        } else {
            self.refuse(key, now, "capture_loss")
        }
    }
    /// Backstop for lifetimes stuck mid-message. Idle lifetimes with nothing
    /// unreconciled stay valid; keep-alive reuse remains observable.
    pub fn expire(&mut self, now: u64) -> Vec<UsageObservation> {
        let stale: Vec<_> = self
            .live
            .iter()
            .filter(|(_, c)| c.partial() && now.saturating_sub(c.last_ns) > self.limits.idle_ns)
            .map(|(k, _)| *k)
            .collect();
        stale
            .into_iter()
            .flat_map(|k| self.kill(k, now, "idle_expiry"))
            .collect()
    }
    /// Capture ended. Unreconciled messages are reported as unverified.
    pub fn finish(&mut self, now: u64) -> Vec<UsageObservation> {
        let keys: Vec<_> = self.live.keys().copied().collect();
        let mut out = vec![];
        for k in keys {
            if self.live[&k].partial() {
                out.extend(self.kill(k, now, "capture_ended_without_reconciled_close"));
            } else {
                self.retire(k);
            }
        }
        self.unseen.clear();
        out
    }
    /// One kernel inventory read during checkpoint pass `pass`: call sequences,
    /// accepted bytes and loss epochs per direction. Records already emitted can
    /// still be in transit, so bytes accepted beyond those consumed only count
    /// as lost if they are still missing at the next pass. `final_pass`
    /// inventories are read after capture stopped and the ring drained.
    #[allow(clippy::too_many_arguments)]
    pub fn checkpoint(
        &mut self,
        key: ConnectionKey,
        sequence: [u64; 2],
        accepted: [u64; 2],
        loss: [u64; 2],
        pass: u64,
        final_pass: bool,
        now: u64,
    ) -> Vec<UsageObservation> {
        if self.tombstones.contains(&key) {
            return vec![];
        }
        let recovery = self.recovery;
        let Some(c) = self.live.get_mut(&key) else {
            if sequence == [0, 0] && loss == [0, 0] {
                return vec![];
            }
            if final_pass {
                return self.refuse(key, now, "inventory_without_records");
            }
            let full = self.unseen.len() >= self.limits.tombstones;
            match self.unseen.get_mut(&key) {
                Some((first, _)) if *first < pass => {
                    return self.refuse(key, now, "inventory_without_records");
                }
                Some((_, last)) => *last = pass,
                None if full => return self.refuse(key, now, "inventory_limit"),
                None => {
                    self.unseen.insert(key, (pass, pass));
                }
            }
            return vec![];
        };
        c.last_seen_pass = c.last_seen_pass.max(pass);
        let mut out = vec![];
        let result = if loss != [0, 0] {
            Err("inventory_loss")
        } else if (0..2)
            .any(|i| sequence[i] < c.dirs[i].sequence || accepted[i] < c.dirs[i].consumed)
        {
            Err("inventory_regression")
        } else {
            let settled = if final_pass {
                Some(accepted)
            } else {
                c.inventory
            };
            c.inventory = Some(accepted);
            (0..2).try_for_each(|i| match settled {
                Some(settled) if settled[i] > c.dirs[i].consumed => {
                    c.reconcile(key, i, settled[i], now, &recovery, &mut out)
                }
                _ => Ok(()),
            })
        };
        if let Err(reason) = result {
            out.extend(self.kill(key, now, reason));
        }
        out
    }
    /// All inventories of `pass` were sent. A live lifetime missing from two
    /// consecutive passes ended without its closure records.
    pub fn checkpoint_pass_end(&mut self, pass: u64, now: u64) -> Vec<UsageObservation> {
        self.pass = self.pass.max(pass);
        self.unseen.retain(|_, (_, last)| *last >= pass);
        let vanished: Vec<_> = self
            .live
            .iter()
            .filter(|(_, c)| c.last_seen_pass + 2 <= pass)
            .map(|(k, _)| *k)
            .collect();
        vanished
            .into_iter()
            .flat_map(|k| self.kill(k, now, "closure_unobserved"))
            .collect()
    }
    /// The owning process exited one pass ago, so every record it emitted has
    /// been delivered. The final inventory is exact.
    pub fn lifetime_gone(
        &mut self,
        key: ConnectionKey,
        sequence: [u64; 2],
        accepted: [u64; 2],
        loss: [u64; 2],
        now: u64,
    ) -> Vec<UsageObservation> {
        self.unseen.remove(&key);
        if self.tombstones.contains(&key) {
            return vec![];
        }
        let recovery = self.recovery;
        let Some(c) = self.live.get_mut(&key) else {
            if sequence == [0, 0] && loss == [0, 0] {
                return vec![];
            }
            return self.refuse(key, now, "inventory_without_records");
        };
        let mut out = vec![];
        let result = if loss != [0, 0] {
            Err("inventory_loss")
        } else if (0..2).any(|i| sequence[i] < c.dirs[i].sequence) {
            Err("inventory_regression")
        } else {
            (0..2).try_for_each(|i| c.reconcile(key, i, accepted[i], now, &recovery, &mut out))
        };
        let reason = match result {
            Err(reason) => Some(reason),
            Ok(()) if c.partial() => Some("lifetime_ended_without_close"),
            Ok(()) => None,
        };
        match reason {
            Some(reason) => out.extend(self.kill(key, now, reason)),
            None => {
                self.retire(key);
            }
        }
        out
    }
    pub fn feed(&mut self, chunk: CaptureChunk<'_>) -> Vec<UsageObservation> {
        let k = chunk.connection;
        let now = chunk.ts_ns;
        if self.tombstones.contains(&k) {
            return vec![];
        }
        if k.generation == 0 || k.process_start == 0 || chunk.direction > 1 {
            return self.refuse(k, now, "missing_lifecycle");
        }
        if !self.live.contains_key(&k) {
            if chunk.end {
                // Closure of a lifetime never admitted: unused, or all records lost.
                if chunk.sequence == 0 && chunk.loss_epoch == 0 {
                    return vec![];
                }
                return self.refuse(k, now, "inventory_without_records");
            }
            if k.generation <= self.generation_barrier {
                return self.refuse(k, now, "global_loss_before_admission");
            }
            if self.live.len() >= self.limits.connections {
                self.refused += 1;
                return self.refuse(k, now, "connection_limit");
            }
            self.unseen.remove(&k);
            self.live.insert(k, Connection::new(now, self.pass));
        }
        let limits = self.limits;
        let recovery = self.recovery;
        let c = self.live.get_mut(&k).unwrap();
        let before = c.bytes();
        c.last_ns = now;
        let mut out = vec![];
        let step = c.step(k, &chunk, &limits, &recovery, &mut out);
        let after = c.bytes();
        self.retained = self.retained.saturating_sub(before) + after;
        match step {
            Err(reason) => out.extend(self.kill(k, now, reason)),
            Ok(Step::Closed) => {
                self.retire(k);
            }
            Ok(Step::OutOfScope) => {
                self.out_of_scope += 1;
                self.retire(k);
            }
            Ok(Step::Continue) => {
                if after > limits.per_connection_bytes || self.retained > limits.total_bytes {
                    out.extend(self.kill(k, now, "buffer_limit"));
                }
            }
        }
        out
    }
}
fn add_report(text: &str, reports: &mut Vec<TokenCounts>, invalid: &mut bool) {
    let Ok(v) = serde_json::from_str::<UniqueValue>(text) else {
        *invalid = true;
        return;
    };
    let v = v.0;
    if !v.is_object() {
        *invalid = true;
        return;
    }
    let Some(u) = v.get("usage").filter(|u| !u.is_null()) else {
        return;
    };
    if !u.is_object() {
        *invalid = true;
        return;
    }
    let count = |name: &str| -> Result<Option<u64>, ()> {
        match u.get(name) {
            None | Some(Value::Null) => Ok(None),
            Some(v) => v
                .as_u64()
                .filter(|n| *n <= i64::MAX as u64)
                .map(Some)
                .ok_or(()),
        }
    };
    let nested = |parent: &str, name: &str| -> Result<Option<u64>, ()> {
        let parent = match u.get(parent) {
            None | Some(Value::Null) => return Ok(None),
            Some(Value::Object(p)) => p,
            Some(_) => return Err(()),
        };
        match parent.get(name) {
            None | Some(Value::Null) => Ok(None),
            Some(v) => v
                .as_u64()
                .filter(|n| *n <= i64::MAX as u64)
                .map(Some)
                .ok_or(()),
        }
    };
    let r = match (
        count("prompt_tokens"),
        count("completion_tokens"),
        count("total_tokens"),
        nested("prompt_tokens_details", "cached_tokens"),
        nested("completion_tokens_details", "reasoning_tokens"),
    ) {
        (Ok(input), Ok(output), Ok(total), Ok(cached_input), Ok(reasoning_output)) => TokenCounts {
            input,
            output,
            total,
            cached_input,
            reasoning_output,
        },
        _ => {
            *invalid = true;
            return;
        }
    };
    if let (Some(i), Some(o), Some(t)) = (r.input, r.output, r.total) {
        if i.checked_add(o) != Some(t) {
            *invalid = true;
            return;
        }
    }
    if matches!((r.cached_input,r.input), (Some(c),Some(i)) if c > i)
        || matches!((r.reasoning_output,r.output), (Some(c),Some(o)) if c > o)
    {
        *invalid = true;
        return;
    }
    if r.input.is_none()
        && r.output.is_none()
        && r.total.is_none()
        && r.cached_input.is_none()
        && r.reasoning_output.is_none()
    {
        return;
    }
    if !reports.contains(&r) {
        if reports.len() >= 16 {
            *invalid = true;
            return;
        }
        reports.push(r);
    }
}

// serde_json::Value normally collapses duplicate names. Never choose one value
// from ambiguous usage or any parent object silently.
struct UniqueValue(Value);
impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = UniqueValue;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("JSON without duplicate keys")
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Bool(v)))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Number(v.into())))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Number(v.into())))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| UniqueValue(Value::Number(n)))
                    .ok_or_else(|| E::custom("invalid number"))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::String(v.into())))
            }
            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::String(v)))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut out = vec![];
                while let Some(v) = seq.next_element::<UniqueValue>()? {
                    out.push(v.0);
                }
                Ok(UniqueValue(Value::Array(out)))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut out = serde_json::Map::new();
                while let Some(k) = map.next_key::<String>()? {
                    if out.contains_key(&k) {
                        return Err(serde::de::Error::custom("duplicate JSON key"));
                    }
                    out.insert(k, map.next_value::<UniqueValue>()?.0);
                }
                Ok(UniqueValue(Value::Object(out)))
            }
        }
        d.deserialize_any(Visitor)
    }
}
