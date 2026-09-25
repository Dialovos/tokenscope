# TokenScope Phase 1.G — tsctl Query (SQL over UDS) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Plan revision history:** initial draft proposed `Connection::open_with_flags(db_path, ReadOnly)` for the worker thread (a fresh `duckdb_open_ext`). Codex review (read-only second opinion) flagged that this is not proven safe alongside a live writer in the same process and may hit locking issues. Same review caught: `Statement::query()` materializes the full result *before* our row counter can intervene; no concurrent-query limit; no shutdown cancellation in the worker; UTF-8 boundary fix lived only in the self-review notes; premature-EOF on the client returns success; old `tsd` returns `ErrorResponse` instead of a `QueryFrame` so new `tsctl` would render a confusing "missing kind" error. All folded in below.

**Goal:** Add `tsctl query <SQL>` to the Phase 1.F control plane. The daemon executes each query in a worker thread that opens an **in-memory** DuckDB primary and `ATTACH '…events.duckdb' AS data (READ_ONLY)` — DuckDB's read-only attach is the designed-for path for "let other tools query my live database file without taking a write lock", and the engine itself rejects any INSERT/UPDATE/DELETE/DDL against an RO-attached database. Rows stream back as newline-delimited `QueryFrame` JSON; tsctl renders them as a `tabled` ASCII table.

**Architecture:**
- Worker thread per query: `Connection::open_in_memory()` → `ATTACH '…' AS data (READ_ONLY)` → `USE data` → wrap user SQL with a `SELECT * FROM (<sql>) LIMIT N` envelope (only for SELECT/WITH/VALUES; EXPLAIN/SHOW/DESCRIBE/PRAGMA are passed through) → `prepare` → `query` → stream rows.
- Hard caps enforced server-side: **100K rows per query**, **64 KiB per stringified value** (truncated at the last UTF-8 char boundary with a marker), **50 MB cumulative bytes per query** (cumulative-frame size; abort with `QueryFrame::Error` on overrun), **4 concurrent queries** (active-query semaphore — past 4, immediate Error).
- Worker checks the shared `Arc<AtomicBool>` shutdown flag every 256 rows so a long-running query doesn't block process exit.
- tsctl decodes each line as either `QueryFrame` or — fallback — `ErrorResponse` (so a new tsctl talking to an old tsd that doesn't know `Query` reports the error cleanly instead of "missing kind"). Tracks a `saw_terminator` flag and returns `Err` on premature EOF.

**Tech Stack:** Same as 1.F plus `tabled 0.16` (tsctl only).

---

## Scope & Out-of-Scope

**In scope (Phase 1.G):**
- New wire variants in `ts_core::control`: `Request::Query { sql }` and `QueryFrame { Header, Row, End, Error }` (tagged enum with `kind`)
- `tsd::control` Query handler: in-memory primary + `ATTACH ... READ_ONLY`, SQL `LIMIT` envelope wrap, hard caps (rows + per-value + cumulative bytes + concurrent-query semaphore), periodic shutdown check
- `tsctl query <SQL>` subcommand: connect, send Query, render header + rows as `tabled` ASCII table, print `(N rows, M ms)` summary on stderr; treat premature EOF as error; decode `ErrorResponse` fallback
- Integration test covering: a successful GROUP BY query, **mutating SQL gets rejected** (engine-level), invalid SQL exits non-zero with a clear error, multibyte-UTF-8 cell truncates safely
- DOC.md update + tag `v0.0.8-phase1g`

**Explicitly deferred:**
- True streaming via Arrow batches (`stream_arrow`) — duckdb-rs has it but the Row→String conversion path is more code; v1 uses `LIMIT` wrap + in-process materialization which is safe under the row+byte caps. Revisit when a query routinely produces > 100K rows.
- Wall-time query timeout — duckdb-rs doesn't expose `interrupt_handle()` cleanly in 1.10502 stable; periodic shutdown check is the v1 cancellation path.
- Pagination / cursors — single-shot stream; large dumps should hit Parquet (Phase 2).
- `--json` / `--csv` output mode for tsctl — Phase 2 once we have machine consumers.
- Concurrent query test (spawning 5 parallel tsctls) — fast-flake risk in CI; manually verifiable; document the cap and add a unit test on the semaphore counter logic.
- Authentication — UDS file permissions still the only auth.

---

## Wire Protocol Additions

**Request:** existing `Request` enum gains one variant.

```json
{"op":"query","sql":"SELECT comm, COUNT(*) FROM events_net_bytes GROUP BY 1"}
```

**Response:** newline-delimited stream of `QueryFrame` lines, then close.

```json
{"kind":"header","columns":["comm","count_star()"]}
{"kind":"row","values":["curl","3"]}
{"kind":"row","values":["control_plane_s","2"]}
{"kind":"end","row_count":2,"elapsed_ms":4}
```

On error mid-stream:
```json
{"kind":"header","columns":["comm","x"]}
{"kind":"error","message":"Catalog Error: column \"x\" not found"}
```

If the SQL fails to prepare (no header sent yet):
```json
{"kind":"error","message":"Parser Error: syntax error at \"SLECT\""}
```

If a mutating statement is attempted (engine rejects via RO attach):
```json
{"kind":"error","message":"... database \"data\" is opened in read-only mode ..."}
```

**Hard limits (server enforces, documented to client):**
- Max rows streamed per query: **100,000**. Implementation: SELECT/WITH/VALUES queries are wrapped as `SELECT * FROM (<user_sql>) LIMIT 100000`; EXPLAIN/SHOW/DESCRIBE/PRAGMA pass through (their result sets are bounded by definition).
- Max per-value byte length: **64 KiB**. Truncated at the last UTF-8 char boundary, suffixed with `…[+N more bytes]`.
- Max cumulative bytes per query: **50 MB** of frame JSON. Tracked across all `Row` lines; on overrun the worker sends a final `Error` and closes.
- Max concurrent queries server-side: **4**. Past 4, the 5th request gets an immediate `Error` ("server too busy") and closes.
- Request line cap: **64 KiB** (same as Phase 1.F).
- Read timeout: **5 s** for the initial request line.
- Write timeout: **1 s** per frame.
- Periodic shutdown poll: every **256 rows** the worker checks the global shutdown flag; on shutdown sends an `Error` ("daemon shutting down") and closes.

**Why pre-stringified values:** keeps the wire compact and the client trivial — no JSON-vs-DuckDB type impedance.

**Compatibility:**
- Adding `Query` to `Request` and `QueryFrame` as a new top-level type is a minor version bump per SPEC §10. `PROTOCOL_VERSION` stays at 1; bump only when a removal/rename happens.
- Old `tsd` doesn't know `Query` and will reply with `ErrorResponse`. New `tsctl query` decodes each line as `QueryFrame | ErrorResponse`; on `ErrorResponse` it surfaces the error cleanly instead of failing on "missing kind".
- New `tsd` to old `tsctl`: doesn't apply — old `tsctl` doesn't have the `query` subcommand, so this combo isn't constructible.

---

## File Structure (delta from Phase 1.F)

```
tokenscope/
├── crates/ts-core/src/control.rs           # +Query variant, +QueryFrame enum, +tests
├── crates/tsd/
│   ├── src/control.rs                      # +Request::Query arm, +query worker, +caps, +shutdown poll, +UTF-8-safe truncation
│   └── tests/control_query.rs              # NEW — e2e SQL round-trip + RO-rejection + UTF-8 truncation
└── crates/tsctl/
    ├── Cargo.toml                          # +tabled
    └── src/main.rs                         # +query subcommand, +ErrorResponse fallback, +premature-EOF guard
```

---

## Task 1: Wire types — add `Request::Query` + `QueryFrame` **(INLINE)**

**Files:**
- Modify: `crates/ts-core/src/control.rs`

**Why inline:** Same contract-fixing rationale as 1.F Task 1 — typo here cascades to tsd + tsctl + the integration test.

- [ ] **Step 1: Extend `Request` enum**

In `crates/ts-core/src/control.rs`, replace the `Request` enum with:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Status,
    Tail,
    Query { sql: String },
}
```

- [ ] **Step 2: Add `QueryFrame` enum**

Append to the same file (after `TailEvent`):

```rust
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
```

- [ ] **Step 3: Add round-trip tests**

Append inside `mod tests { ... }` (before its closing `}`):

```rust
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
```

- [ ] **Step 4: Run the new tests**

```
cd /home/hoang/code/personal/active/tokenscope
cargo test -p ts-core control:: 2>&1 | tail -10
```

Expected: 12 tests pass (7 from 1.F + 5 new).

- [ ] **Step 5: Commit**

```
cd /home/hoang/code/personal/active/tokenscope
git add crates/ts-core/src/control.rs
git commit -m "feat(ts-core): Request::Query + QueryFrame for the control-plane query path"
```

---

## Task 2: tsd Query handler — ATTACH READ_ONLY, hard caps, shutdown-aware **(INLINE)**

**Files:**
- Modify: `crates/tsd/src/control.rs`

**Why inline:** ATTACH-based engine-level RO enforcement + LIMIT envelope wrap + per-query active-query semaphore + per-row shutdown check + UTF-8-safe value truncation all need to land together; partial states are a footgun.

- [ ] **Step 1: Add `active_queries` to `Counters`**

In `crates/tsd/src/control.rs`, replace the `Counters` struct with:

```rust
#[derive(Default)]
pub struct Counters {
    pub events_total: AtomicU64,
    pub ringbuf_poll_errors: AtomicU64,
    pub tail_subscribers_active: AtomicU32,
    /// Currently-executing query workers. Bumped by an RAII guard on
    /// query entry; checked against MAX_CONCURRENT_QUERIES.
    pub active_queries: AtomicU32,
}
```

- [ ] **Step 2: Add caps + helpers near the existing `probes_attached()` function**

Append in `crates/tsd/src/control.rs`:

```rust
/// Per-stringified-value cap. Cells longer get truncated.
const MAX_VALUE_BYTES: usize = 64 * 1024;

/// Hard cap on rows a single query can return. Enforced via a SQL
/// envelope wrap on SELECT/WITH/VALUES; pass-through queries
/// (EXPLAIN/SHOW/DESCRIBE/PRAGMA) are bounded by their own definition.
const MAX_QUERY_ROWS: u64 = 100_000;

/// Cumulative bytes-on-the-wire cap per query. Catches the "wide rows
/// of huge text/blob" vector that row-count alone misses.
const MAX_QUERY_BYTES: u64 = 50 * 1024 * 1024;

/// Server-side concurrent-query limit. Past this the next query is
/// rejected with an Error frame, no thread is spawned for the work.
const MAX_CONCURRENT_QUERIES: u32 = 4;

/// How often (in rows) the worker checks the shutdown flag.
const SHUTDOWN_POLL_EVERY_N_ROWS: u64 = 256;

/// Stringify a DuckDB value for the wire. Cells longer than the cap
/// are truncated AT THE LAST UTF-8 CHAR BOUNDARY (so we never split
/// a multi-byte codepoint) and suffixed with `…[+N more bytes]`.
fn value_to_display(v: &duckdb::types::Value) -> String {
    use duckdb::types::Value;
    let s = match v {
        Value::Null => "NULL".to_string(),
        Value::Boolean(b) => b.to_string(),
        Value::TinyInt(n) => n.to_string(),
        Value::SmallInt(n) => n.to_string(),
        Value::Int(n) => n.to_string(),
        Value::BigInt(n) => n.to_string(),
        Value::HugeInt(n) => n.to_string(),
        Value::UTinyInt(n) => n.to_string(),
        Value::USmallInt(n) => n.to_string(),
        Value::UInt(n) => n.to_string(),
        Value::UBigInt(n) => n.to_string(),
        Value::Float(n) => n.to_string(),
        Value::Double(n) => n.to_string(),
        Value::Text(s) => s.clone(),
        Value::Blob(b) => format!("<blob:{} bytes>", b.len()),
        Value::Timestamp(_, n) => n.to_string(),
        Value::Date32(d) => d.to_string(),
        Value::Time64(_, n) => n.to_string(),
        other => format!("{other:?}"),
    };
    if s.len() > MAX_VALUE_BYTES {
        let mut end = MAX_VALUE_BYTES;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        let extra = s.len() - end;
        format!("{}…[+{} more bytes]", &s[..end], extra)
    } else {
        s
    }
}

/// SELECT/WITH/VALUES queries get wrapped with `LIMIT N` so a 100M-row
/// result can't materialize before our row counter notices. Other
/// statement types (EXPLAIN/SHOW/DESCRIBE/PRAGMA) pass through —
/// their result sets are inherently bounded.
fn maybe_wrap_with_limit(sql: &str) -> String {
    let trimmed = sql.trim_start();
    // Strip leading line comments + uppercase the first ~20 chars to
    // sniff the statement type.
    let head: String = trimmed
        .lines()
        .find(|l| !l.trim_start().starts_with("--") && !l.trim().is_empty())
        .unwrap_or("")
        .trim_start()
        .chars()
        .take(20)
        .collect::<String>()
        .to_uppercase();
    if head.starts_with("SELECT") || head.starts_with("WITH") || head.starts_with("VALUES") {
        // Wrap. The user's own LIMIT (if any) takes effect inside the
        // subquery; the outer LIMIT just caps the result.
        format!("SELECT * FROM ({}) AS user_query LIMIT {}", sql, MAX_QUERY_ROWS)
    } else {
        sql.to_string()
    }
}

/// RAII guard for the active-query counter. Decrements on drop so
/// any panic / early return / error path still releases the slot.
struct ActiveQueryGuard {
    counters: Arc<Counters>,
}

impl ActiveQueryGuard {
    /// Try to acquire a slot. Returns `None` if MAX_CONCURRENT_QUERIES
    /// is already busy.
    fn try_acquire(counters: Arc<Counters>) -> Option<Self> {
        let prev = counters.active_queries.fetch_add(1, Ordering::SeqCst);
        if prev >= MAX_CONCURRENT_QUERIES {
            // Roll back; we exceeded the cap.
            counters.active_queries.fetch_sub(1, Ordering::SeqCst);
            None
        } else {
            Some(Self { counters })
        }
    }
}

impl Drop for ActiveQueryGuard {
    fn drop(&mut self) {
        self.counters.active_queries.fetch_sub(1, Ordering::SeqCst);
    }
}
```

- [ ] **Step 3: Thread shutdown into `handle_query`**

Update the `match req {` block in `handle_conn` to add the Query arm:

```rust
        Request::Query { sql } => {
            handle_query(
                &mut writer,
                &db_path,
                &sql,
                &counters,
                &global_shutdown,
                &server_shutdown,
            );
        }
```

(Keep the existing Status and Tail arms unchanged.)

- [ ] **Step 4: Add `handle_query`**

Append at the bottom of `crates/tsd/src/control.rs` (after `default_uds_path`):

```rust
#[allow(clippy::too_many_arguments)]
fn handle_query(
    writer: &mut UnixStream,
    db_path: &Path,
    sql: &str,
    counters: &Arc<Counters>,
    global_shutdown: &Arc<AtomicBool>,
    server_shutdown: &Arc<AtomicBool>,
) {
    use duckdb::types::Value;
    use ts_core::control::QueryFrame;

    let started = Instant::now();

    // Closure that serializes a frame and writes it. Returns Err on
    // I/O error so the caller can break out cleanly.
    let mut bytes_sent: u64 = 0;
    let mut send = |writer: &mut UnixStream, frame: &QueryFrame| -> Result<()> {
        let line = serde_json::to_string(frame).context("serialize QueryFrame")?;
        // Add 1 for the newline.
        let frame_size = line.len() as u64 + 1;
        bytes_sent = bytes_sent.saturating_add(frame_size);
        writeln!(writer, "{line}").context("write frame")?;
        Ok(())
    };

    // Concurrent-query limit.
    let _slot = match ActiveQueryGuard::try_acquire(counters.clone()) {
        Some(g) => g,
        None => {
            let _ = send(
                writer,
                &QueryFrame::Error {
                    message: format!(
                        "server too busy: {MAX_CONCURRENT_QUERIES} concurrent queries already running"
                    ),
                },
            );
            return;
        }
    };

    // In-memory primary + ATTACH READ_ONLY of the daemon's DB file.
    // RO attach is DuckDB's designed-for path for "let other tools
    // query my live database file without taking a write lock", and
    // the engine itself rejects mutations against an RO-attached DB.
    let conn = match duckdb::Connection::open_in_memory() {
        Ok(c) => c,
        Err(e) => {
            let _ = send(
                writer,
                &QueryFrame::Error {
                    message: format!("open in-memory: {e}"),
                },
            );
            return;
        }
    };
    let attach_sql = format!(
        "ATTACH '{}' AS data (READ_ONLY)",
        db_path.display().to_string().replace('\'', "''")
    );
    if let Err(e) = conn.execute_batch(&attach_sql) {
        let _ = send(
            writer,
            &QueryFrame::Error {
                message: format!("attach read-only: {e}"),
            },
        );
        return;
    }
    if let Err(e) = conn.execute_batch("USE data") {
        let _ = send(
            writer,
            &QueryFrame::Error {
                message: format!("use data: {e}"),
            },
        );
        return;
    }

    // Wrap SELECT-y SQL with LIMIT N so a giant result can't
    // materialize before we count rows.
    let effective_sql = maybe_wrap_with_limit(sql);

    let mut stmt = match conn.prepare(&effective_sql) {
        Ok(s) => s,
        Err(e) => {
            let _ = send(
                writer,
                &QueryFrame::Error {
                    message: format!("prepare: {e}"),
                },
            );
            return;
        }
    };

    let columns: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    let col_count = columns.len();
    if send(
        writer,
        &QueryFrame::Header {
            columns: columns.clone(),
        },
    )
    .is_err()
    {
        return;
    }

    let mut rows = match stmt.query([]) {
        Ok(r) => r,
        Err(e) => {
            let _ = send(
                writer,
                &QueryFrame::Error {
                    message: format!("execute: {e}"),
                },
            );
            return;
        }
    };

    let mut row_count: u64 = 0;
    loop {
        // Periodic shutdown check — every N rows the worker yields to
        // the global shutdown flag so a long query doesn't pin the
        // process at exit.
        if row_count.is_multiple_of(SHUTDOWN_POLL_EVERY_N_ROWS)
            && (global_shutdown.load(Ordering::Relaxed) || server_shutdown.load(Ordering::Relaxed))
        {
            let _ = send(
                writer,
                &QueryFrame::Error {
                    message: "daemon shutting down".to_string(),
                },
            );
            return;
        }
        match rows.next() {
            Ok(Some(row)) => {
                let mut values: Vec<String> = Vec::with_capacity(col_count);
                for i in 0..col_count {
                    let v: Value = row.get(i).unwrap_or(Value::Null);
                    values.push(value_to_display(&v));
                }
                if send(writer, &QueryFrame::Row { values }).is_err() {
                    return; // client disconnected
                }
                row_count += 1;
                if bytes_sent > MAX_QUERY_BYTES {
                    let _ = send(
                        writer,
                        &QueryFrame::Error {
                            message: format!(
                                "byte cap ({} MiB) exceeded after {} rows",
                                MAX_QUERY_BYTES / 1024 / 1024,
                                row_count
                            ),
                        },
                    );
                    return;
                }
            }
            Ok(None) => break,
            Err(e) => {
                let _ = send(
                    writer,
                    &QueryFrame::Error {
                        message: format!("row iter: {e}"),
                    },
                );
                return;
            }
        }
    }

    let _ = send(
        writer,
        &QueryFrame::End {
            row_count,
            elapsed_ms: started.elapsed().as_millis() as u64,
        },
    );
}
```

- [ ] **Step 5: Add unit test for `maybe_wrap_with_limit`**

Append a `#[cfg(test)] mod tests` at the bottom of `crates/tsd/src/control.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_select_adds_limit() {
        let out = maybe_wrap_with_limit("SELECT 1");
        assert!(out.contains("LIMIT 100000"), "{out}");
        assert!(out.contains("SELECT 1"), "{out}");
    }

    #[test]
    fn wrap_with_cte_adds_limit() {
        let out = maybe_wrap_with_limit("WITH x AS (SELECT 1) SELECT * FROM x");
        assert!(out.contains("LIMIT 100000"), "{out}");
    }

    #[test]
    fn wrap_explain_passes_through() {
        let out = maybe_wrap_with_limit("EXPLAIN SELECT 1");
        assert_eq!(out, "EXPLAIN SELECT 1");
    }

    #[test]
    fn wrap_pragma_passes_through() {
        let out = maybe_wrap_with_limit("PRAGMA show_tables");
        assert_eq!(out, "PRAGMA show_tables");
    }

    #[test]
    fn value_truncation_respects_utf8_boundary() {
        // 65537-byte string ending with a 4-byte emoji at the boundary.
        // Build a string that's exactly MAX_VALUE_BYTES + 4 bytes of UTF-8.
        let pad = "a".repeat(MAX_VALUE_BYTES - 1);
        let s = format!("{pad}🦀"); // 🦀 is 4 bytes; total = MAX_VALUE_BYTES + 3
        assert!(s.len() > MAX_VALUE_BYTES);
        let v = duckdb::types::Value::Text(s);
        let out = value_to_display(&v);
        // Must not panic and must be valid UTF-8 ending with a marker.
        assert!(out.contains("…[+"));
        // Crucially, the slice we kept ended on a char boundary —
        // value_to_display returning at all means no panic; also verify
        // the whole output is valid UTF-8 (it always is — String guarantees that).
        let _ = out.chars().count();
    }

    #[test]
    fn active_query_guard_caps_concurrency() {
        let counters = Arc::new(Counters::default());
        let mut held = Vec::new();
        for _ in 0..MAX_CONCURRENT_QUERIES {
            held.push(ActiveQueryGuard::try_acquire(counters.clone()).expect("under cap"));
        }
        assert!(
            ActiveQueryGuard::try_acquire(counters.clone()).is_none(),
            "{}-th acquire should fail",
            MAX_CONCURRENT_QUERIES + 1
        );
        drop(held);
        assert_eq!(counters.active_queries.load(Ordering::Relaxed), 0);
        // After releasing, we can acquire again.
        assert!(ActiveQueryGuard::try_acquire(counters.clone()).is_some());
    }
}
```

- [ ] **Step 6: Build + fmt + clippy + unit test**

```
cd /home/hoang/code/personal/active/tokenscope
cargo build -p tsd -j 2 2>&1 | tail -10
cargo fmt --all
cargo clippy --workspace --all-targets -j 2 -- -D warnings 2>&1 | tail -10
cargo test -p tsd --bin tsd 2>&1 | grep -E "^test result|FAILED" | head -10
```

Expected: build clean, clippy clean. tsd unit tests: 14 (proc_cache 9 + store 5) + 5 new control tests = **19 tests pass**.

If `Connection::open_in_memory` doesn't exist: `Connection::open(":memory:")` is the fallback in older versions.

- [ ] **Step 7: Commit**

```
cd /home/hoang/code/personal/active/tokenscope
git add crates/tsd/src/control.rs
git commit -m "feat(tsd): control-plane Query handler — ATTACH READ_ONLY, hard caps, shutdown-aware"
```

---

## Task 3: tsctl `query <SQL>` subcommand — ASCII table + ErrorResponse fallback + EOF guard **(INLINE)**

**Files:**
- Modify: `crates/tsctl/Cargo.toml`
- Modify: `crates/tsctl/src/main.rs`

**Why inline:** Frame-state-machine + dual-decode (QueryFrame | ErrorResponse) + EOF-guard need to feel cohesive with status/tail UX.

- [ ] **Step 1: Add `tabled` to `crates/tsctl/Cargo.toml`**

Read the file. Under `[dependencies]`, append:
```toml
tabled = "0.16"
```

- [ ] **Step 2: Add `Query` to the `Cmd` enum + dispatch**

In `crates/tsctl/src/main.rs`, replace the `Cmd` enum with:

```rust
#[derive(Subcommand, Debug)]
enum Cmd {
    /// Print build info and exit.
    Version,
    /// One-shot daemon status snapshot.
    Status,
    /// Live event stream from tsd. Exits on SIGINT.
    Tail,
    /// Run an ad-hoc SQL query against the daemon's DuckDB (executed
    /// server-side via in-memory primary + ATTACH READ_ONLY).
    Query {
        /// The SQL statement.
        sql: String,
    },
}
```

In `main()`, add the dispatch after the existing arms:

```rust
        Cmd::Query { sql } => cmd_query(&args.uds_path, &sql)?,
```

- [ ] **Step 3: Add `cmd_query`**

Append after `cmd_tail` in `crates/tsctl/src/main.rs`:

```rust
fn cmd_query(uds_path: &PathBuf, sql: &str) -> Result<()> {
    use tabled::{builder::Builder, settings::Style};
    use ts_core::control::QueryFrame;

    let mut stream = connect(uds_path)?;
    let req = serde_json::to_string(&Request::Query { sql: sql.into() })?;
    writeln!(stream, "{req}").context("write request")?;

    let reader = BufReader::new(stream);
    let mut builder = Builder::default();
    let mut have_header = false;
    let mut row_count: u64 = 0;
    let mut elapsed_ms: u64 = 0;
    let mut saw_terminator = false;

    for line in reader.lines() {
        let line = line.context("read frame")?;
        // First try QueryFrame; if that fails, try ErrorResponse so a
        // new tsctl talking to an old tsd that doesn't know `Query`
        // surfaces the daemon's typed error instead of "missing kind".
        match serde_json::from_str::<QueryFrame>(&line) {
            Ok(QueryFrame::Header { columns }) => {
                builder.push_record(&columns);
                have_header = true;
            }
            Ok(QueryFrame::Row { values }) => {
                builder.push_record(&values);
            }
            Ok(QueryFrame::End {
                row_count: n,
                elapsed_ms: ms,
            }) => {
                row_count = n;
                elapsed_ms = ms;
                saw_terminator = true;
                break;
            }
            Ok(QueryFrame::Error { message }) => {
                return Err(anyhow!("query error: {message}"));
            }
            Err(_) => {
                // Fallback: maybe an old daemon spat back ErrorResponse.
                if let Ok(err) = serde_json::from_str::<ErrorResponse>(&line) {
                    return Err(anyhow!("tsd error: {}", err.error));
                }
                return Err(anyhow!("unparseable frame: {line}"));
            }
        }
    }

    if !saw_terminator {
        return Err(anyhow!(
            "stream ended before End/Error frame (daemon disconnect?)"
        ));
    }
    if have_header {
        println!("{}", builder.build().with(Style::sharp()));
    }
    eprintln!("({row_count} rows, {elapsed_ms} ms)");
    Ok(())
}
```

- [ ] **Step 4: Build + smoke test**

```
cd /home/hoang/code/personal/active/tokenscope
cargo build -p tsctl -j 2 2>&1 | tail -10
./target/debug/tsctl --help
./target/debug/tsctl query --help
```

Expected: `tsctl --help` lists `version`, `status`, `tail`, `query`. `tsctl query --help` shows the `<SQL>` positional arg.

- [ ] **Step 5: fmt + clippy**

```
cd /home/hoang/code/personal/active/tokenscope
cargo fmt --all
cargo clippy -p tsctl -- -D warnings 2>&1 | tail -10
```

Expected: clean.

- [ ] **Step 6: Commit**

```
cd /home/hoang/code/personal/active/tokenscope
git add Cargo.lock crates/tsctl/Cargo.toml crates/tsctl/src/main.rs
git commit -m "feat(tsctl): query subcommand — ASCII table + ErrorResponse fallback + EOF guard"
```

---

## Task 4: End-to-End Integration Test **(INLINE)**

**Files:**
- Create: `crates/tsd/tests/control_query.rs`

**Why inline:** Cross-binary + real DuckDB + RO-rejection-from-engine + UTF-8 truncation all in one verification.

- [ ] **Step 1: Create `crates/tsd/tests/control_query.rs`**

```rust
//! End-to-end test for the Phase 1.G control-plane Query path.
//!
//! Spawns tsd with a temp DB + temp UDS, drives some loopback TCP
//! so events land in DuckDB, then exercises tsctl query against
//! the daemon. Asserts:
//!   - a successful GROUP BY returns >= 1 row + correct headers
//!   - mutating SQL is rejected by the engine (read-only ATTACH)
//!   - syntactically-invalid SQL exits non-zero with "error" on stderr
//!
//! Requires CAP_BPF or root; ignored by default.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use tempfile::TempDir;

const PAYLOAD: &[u8] = &[b'P'; 1024];

fn target_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tsd"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn tsd_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tsd"))
}

fn tsctl_bin() -> PathBuf {
    let candidate = target_dir().join("tsctl");
    if !candidate.exists() {
        let status = Command::new("cargo")
            .args(["build", "--bin", "tsctl"])
            .status()
            .expect("invoke cargo build for tsctl");
        assert!(status.success(), "cargo build -p tsctl failed");
    }
    candidate
}

fn drain_stderr(child: &mut std::process::Child) -> thread::JoinHandle<String> {
    let mut stderr = child.stderr.take().expect("piped stderr");
    thread::spawn(move || {
        let mut buf = String::new();
        let _ = stderr.read_to_string(&mut buf);
        buf
    })
}

#[test]
#[ignore = "requires CAP_BPF or root; run with --include-ignored under sudo"]
fn control_plane_query_returns_rows_and_rejects_mutations() {
    let dir = TempDir::new().expect("tempdir");
    let db_path = dir.path().join("events.duckdb");
    let uds_path = dir.path().join("tsd.sock");

    let tsd = tsd_bin();
    let tsctl = tsctl_bin();

    let mut child = Command::new(&tsd)
        .args([
            "--db-path",
            db_path.to_str().unwrap(),
            "--uds-path",
            uds_path.to_str().unwrap(),
            "--flush-interval-ms",
            "300",
            "--no-stdout",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tsd");
    let stderr_drain = drain_stderr(&mut child);

    // Wait for UDS bind.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !uds_path.exists() {
        if Instant::now() > deadline {
            let _ = child.kill();
            let logs = stderr_drain.join().unwrap_or_default();
            panic!(
                "tsd never created uds at {} — stderr: {}",
                uds_path.display(),
                logs
            );
        }
        thread::sleep(Duration::from_millis(100));
    }
    thread::sleep(Duration::from_millis(400));

    // Drive a known loopback transfer so events_net_bytes has rows.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = thread::spawn(move || {
        let (mut s, _) = listener.accept().expect("accept");
        let mut buf = [0u8; 4096];
        let _ = s.read(&mut buf);
    });
    let mut client = TcpStream::connect(addr).expect("connect");
    client.write_all(PAYLOAD).expect("write");
    client.flush().ok();
    drop(client);
    let _ = server.join();
    thread::sleep(Duration::from_millis(900));

    // ---- (1) Successful GROUP BY ----
    let out = Command::new(&tsctl)
        .args([
            "--uds-path",
            uds_path.to_str().unwrap(),
            "query",
            "SELECT comm, COUNT(*) AS n FROM events_net_bytes GROUP BY 1 ORDER BY 2 DESC",
        ])
        .output()
        .expect("run tsctl query");
    assert!(
        out.status.success(),
        "tsctl query failed (stdout={:?}, stderr={:?})",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    eprintln!("--- query (1) stdout ---\n{stdout}");
    eprintln!("--- query (1) stderr ---\n{stderr}");
    assert!(stdout.contains("comm"), "no comm header: {stdout}");
    assert!(stdout.contains("n"), "no n header: {stdout}");
    let row_count_line = stderr
        .lines()
        .find(|l| l.contains("rows,"))
        .expect("summary line");
    let row_count: u64 = row_count_line
        .trim_start_matches('(')
        .split_whitespace()
        .next()
        .and_then(|s| s.parse().ok())
        .expect("parse row count");
    assert!(row_count >= 1, "expected >= 1 row, got {row_count}");

    // ---- (2) Mutating SQL must be rejected by the RO ATTACH ----
    let mut_out = Command::new(&tsctl)
        .args([
            "--uds-path",
            uds_path.to_str().unwrap(),
            "query",
            "DELETE FROM events_net_bytes",
        ])
        .output()
        .expect("run tsctl query (delete)");
    assert!(
        !mut_out.status.success(),
        "DELETE should be rejected; got stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&mut_out.stdout),
        String::from_utf8_lossy(&mut_out.stderr),
    );
    let mut_stderr = String::from_utf8_lossy(&mut_out.stderr).into_owned();
    eprintln!("--- query (2) stderr ---\n{mut_stderr}");
    assert!(
        mut_stderr.to_lowercase().contains("error"),
        "DELETE should mention error: {mut_stderr}"
    );
    // Sanity: the data should still be there.
    let count_out = Command::new(&tsctl)
        .args([
            "--uds-path",
            uds_path.to_str().unwrap(),
            "query",
            "SELECT COUNT(*) AS n FROM events_net_bytes",
        ])
        .output()
        .expect("run tsctl query (count after delete)");
    let count_stdout = String::from_utf8_lossy(&count_out.stdout).into_owned();
    eprintln!("--- post-DELETE count ---\n{count_stdout}");
    assert!(
        count_out.status.success(),
        "count after attempted DELETE failed: {count_out:?}"
    );
    // The table still has rows (DELETE was rejected).
    let count_stderr = String::from_utf8_lossy(&count_out.stderr);
    let count_line = count_stderr
        .lines()
        .find(|l| l.contains("rows,"))
        .expect("post-DELETE summary");
    let count_n: u64 = count_line
        .trim_start_matches('(')
        .split_whitespace()
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    assert!(count_n >= 1, "expected count >= 1 after rejected DELETE");

    // ---- (3) Invalid SQL exits non-zero ----
    let err_out = Command::new(&tsctl)
        .args([
            "--uds-path",
            uds_path.to_str().unwrap(),
            "query",
            "SLECT * FROM nope",
        ])
        .output()
        .expect("run tsctl query (bad sql)");
    assert!(
        !err_out.status.success(),
        "bad SQL should fail; got stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&err_out.stdout),
        String::from_utf8_lossy(&err_out.stderr),
    );
    let err_stderr = String::from_utf8_lossy(&err_out.stderr);
    assert!(
        err_stderr.to_lowercase().contains("error"),
        "bad SQL should mention error: {err_stderr}"
    );

    // ---- Shutdown ----
    unsafe { libc::kill(child.id() as i32, libc::SIGINT) };
    let status = child.wait().expect("wait tsd");
    assert!(status.success(), "tsd exited non-zero: {status}");
    let _ = stderr_drain.join();
    assert!(!uds_path.exists(), "tsd should remove socket on shutdown");
}
```

- [ ] **Step 2: Build the test binary**

```
cd /home/hoang/code/personal/active/tokenscope
cargo build --tests -p tsd -j 2 2>&1 | tail -10
```

Expected: clean.

- [ ] **Step 3: Ask the user to run the integration suite**

User runs:
```
cd /home/hoang/code/personal/active/tokenscope && sudo -E env "PATH=$PATH" /home/hoang/.cargo/bin/cargo test -p tsd -- --ignored --nocapture
```

Expected: 7 integration tests pass — the 6 from prior phases plus `control_plane_query_returns_rows_and_rejects_mutations`. The new test prints three sections labeled `--- query (1) stdout/stderr ---` (rendered ASCII table + summary), `--- query (2) stderr ---` (DELETE rejection error), and `--- post-DELETE count ---` (proof rows survived).

If `tsd` exits non-zero on shutdown and the test panics on `assert!(status.success(), ...)`: check whether the new ATTACH connection is leaking; the per-query `conn` should drop at the end of `handle_query` and release any locks it took.

If the DELETE test passes (i.e., DELETE succeeds — bad!): the ATTACH command is wrong. Confirm `attach_sql` actually contains `(READ_ONLY)`. DuckDB's syntax is exactly that; case insensitive but parens required.

- [ ] **Step 4: Commit**

```
cd /home/hoang/code/personal/active/tokenscope
git add crates/tsd/tests/control_query.rs
git commit -m "test(tsd): e2e — query returns rows, rejects mutations, errors exit non-zero"
```

---

## Task 5: Phase 1.G Wrap-up — DOC.md, Tag, optional LEARNED.md **(INLINE)**

**Files:**
- Modify: `DOC.md`

- [ ] **Step 1: Run all gates**

```
cd /home/hoang/code/personal/active/tokenscope
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Expected: ts-core 25 (20 + 5 QueryFrame), tsd 19 (14 + 5 control unit tests), all clean.

- [ ] **Step 2: Update DOC.md — insert above Phase 1.F**

Edit `DOC.md`. Find `### Phase 1.F — tsctl Control Plane` and insert ABOVE it:

```markdown
### Phase 1.G — tsctl Query (shipped 2026-05-07, tag `v0.0.8-phase1g`)

`tsctl query <SQL>` ships, completing the Phase 1 user-visible surface. The daemon executes each query in a worker thread that opens an **in-memory** DuckDB primary and `ATTACH '…events.duckdb' AS data (READ_ONLY)` — DuckDB's read-only attach is the designed-for path for "let other tools query my live database file without taking a write lock", and the engine itself rejects any INSERT/UPDATE/DELETE/DDL against an RO-attached database. SELECT/WITH/VALUES queries are wrapped as `SELECT * FROM (<user_sql>) LIMIT 100000` so a giant result can't materialize before the row counter notices.

Hard caps: 100K rows, 64 KiB per stringified value (truncated at the last UTF-8 char boundary, suffixed with `…[+N more bytes]`), 50 MB cumulative bytes-on-the-wire per query (catches the "wide rows of huge text/blob" vector that row-count alone misses), 4 concurrent queries (RAII semaphore), 256-row periodic shutdown poll (long queries don't pin process exit).

tsctl renders rows as a `tabled` ASCII table with `(N rows, M ms)` summary on stderr. The frame loop tracks a `saw_terminator` flag so a daemon disconnect mid-stream returns a clear error instead of pretending success. Each line decodes as either `QueryFrame` or — fallback — `ErrorResponse`, so a new `tsctl` talking to an old `tsd` (one that doesn't know `Query`) surfaces the typed error instead of "missing kind".

**Codex second-opinion review caught three blockers in the initial plan** (`Connection::open_with_flags(path, ReadOnly)` not proven safe alongside live writer in same process → pivoted to `ATTACH READ_ONLY`; `Statement::query()` materializes results before the row cap can fire → added SQL `LIMIT` envelope wrap + cumulative byte cap; resource caps insufficient → added concurrent-query semaphore + per-frame byte tracking) and three should-fixes (no shutdown cancellation in worker → 256-row periodic check; UTF-8 fix lived only in self-review → folded into shipped code; premature EOF + new-tsctl/old-tsd combo → `saw_terminator` flag + `ErrorResponse` fallback). All folded into the final design before any code was written.

**Gate evidence (verified 2026-05-07):**
- `cargo fmt --check` / `cargo clippy --workspace --all-targets -- -D warnings` clean
- `cargo test --workspace` — ts-core 25 (20 + 5 QueryFrame round-trip) + tsd lib 19 (14 + 5 control unit tests) = 44 unit tests pass
- `sudo cargo test -p tsd -- --ignored` — 7 integration tests pass
  - `control_plane_query_returns_rows_and_rejects_mutations` confirms (1) `tsctl query "SELECT comm, COUNT(*) FROM events_net_bytes GROUP BY 1"` returns ≥ 1 row, (2) `DELETE FROM events_net_bytes` is rejected at the engine level AND rows survive, (3) syntactically-invalid SQL exits non-zero with "error" on stderr
- Plan: `docs/superpowers/plans/2026-05-07-phase-1g-tsctl-query.md`

**Known gaps:**
- No wall-time query timeout — duckdb-rs 1.10502 doesn't cleanly expose `interrupt_handle()`; bounded by row + value + cumulative-byte caps + 256-row shutdown poll
- No pagination / cursors — single-shot stream
- No `--json` / `--csv` output mode for tsctl — Phase 2
- True streaming via Arrow batches deferred — `LIMIT` wrap + caps are the v1 safety net; revisit when a query routinely produces > 100K rows
- Concurrent-query limit (4) tested at unit-level only; e2e parallel-tsctl test deferred (CI flake risk)

### Phase 1.F — tsctl Control Plane (shipped 2026-05-07, tag `v0.0.7-phase1f`)
```

- [ ] **Step 3: Commit DOC.md and tag**

```
cd /home/hoang/code/personal/active/tokenscope
git add DOC.md
git commit -m "docs: mark Phase 1.G shipped (tsctl query) with gate evidence"
git tag -a v0.0.8-phase1g -m "Phase 1.G — tsctl Query (SQL over UDS)"
git tag --list
```

Expected: tag list now includes `v0.0.8-phase1g`.

- [ ] **Step 4: Append LEARNED.md notes (only if non-trivial)**

If the implementation surfaced anything genuinely worth keeping (e.g., DuckDB ATTACH READ_ONLY behavior under contention, a quirk in `Statement::query()` materialization vs streaming, an unexpected serde tag interaction), append to `~/.claude/LEARNED.md`. Skip if it all went textbook.

---

## Definition of Done (Phase 1.G acceptance gate)

All must be true:
1. `cargo build --workspace` succeeds.
2. `cargo test --workspace` exits 0 (ts-core 25 + tsd 19 = 44 unit tests).
3. `sudo cargo test -p tsd -- --ignored` exits 0 — 7 integration tests pass including `control_plane_query_returns_rows_and_rejects_mutations`.
4. Live: `sudo tsd --no-stdout &` + `tsctl query "SELECT COUNT(*) FROM events_net_bytes"` prints a tiny table; `tsctl query "DELETE FROM events_net_bytes"` exits non-zero; `tsctl query "SLECT *"` exits non-zero.
5. `cargo fmt --check` and `cargo clippy -D warnings` clean.
6. `tsctl --help` lists `version`, `status`, `tail`, `query` subcommands.
7. Mutating SQL is rejected by the read-only ATTACH (covered by integration test).
8. DOC.md reflects Phase 1.G shipped.
9. Git tag `v0.0.8-phase1g` exists locally.

---

## Self-Review Notes

**Spec coverage check:**
- SPEC §6 line 622: `tsctl query "SELECT model, SUM(cost_usd) FROM calls ..."` → shipped (subject to columns existing — Phase 1's schema is `events_net_*`, not `calls`).
- SPEC §10 stability surface for `tsctl tail event JSON schema` — same reasoning extended to `QueryFrame`. Documented as a stable surface.

**Type/name consistency:**
- `Request::Query { sql: String }` matches between ts-core definition (Task 1) + tsd dispatch (Task 2 step 3) + tsctl construction (Task 3 step 3).
- `QueryFrame` variants (`Header`, `Row`, `End`, `Error`) and field names (`columns`, `values`, `row_count`, `elapsed_ms`, `message`) match between ts-core, tsd's `handle_query`, and tsctl's `cmd_query`.
- `MAX_VALUE_BYTES = 64 KiB`, `MAX_QUERY_ROWS = 100_000`, `MAX_QUERY_BYTES = 50 MB`, `MAX_CONCURRENT_QUERIES = 4`, `SHUTDOWN_POLL_EVERY_N_ROWS = 256` defined once in `crates/tsd/src/control.rs` and documented in the wire-protocol section.

**Placeholder scrub:** none of the forbidden phrases appear.

**Borrow-checker plan:**
- `handle_query` takes `&mut UnixStream` for writes, `&Path` for the db, `&Arc<Counters>` and `&Arc<AtomicBool>` for shared state. The local `conn`/`stmt`/`rows` chain is straightforward — `rows` borrows from `stmt`, `stmt` from `conn`. All on the worker thread's stack; no cross-thread sharing.
- `value_to_display` takes `&Value` and returns owned `String`. No lifetime issues.
- `ActiveQueryGuard` holds an `Arc<Counters>` clone; trivial.

**Concurrency safety (with codex's concerns explicitly addressed):**
- **Q: Is opening a second `Connection::open_with_flags(path, ReadOnly)` alongside the writer's Connection in the same process safe?** Codex flagged this as not proven. **A: WE NO LONGER DO THIS.** The pivot to in-memory primary + `ATTACH ... READ_ONLY` is DuckDB's documented path for exactly this scenario.
- **Q: Does `Statement::query()` actually stream or buffer in memory?** Codex says it materializes via Arrow. **A: Accepted as a v1 limitation. Mitigated via the `SELECT * FROM (<sql>) LIMIT 100000` envelope wrap (caps materialization at 100K rows) AND the 50 MB cumulative-byte cap during streaming (catches wide-row vector). True Arrow streaming via `stream_arrow` lands in Phase 2 when we hit a real workload that exceeds these caps.**
- **Q: Resource exhaustion vectors?** **A:** Active-query semaphore (4 concurrent), per-value cap (64 KiB), per-query byte cap (50 MB), row cap (100K via SQL envelope). Each is a separate guardrail.
- **Q: UTF-8 boundary?** **A: Fixed in shipped code** (Task 2 step 2 `value_to_display`), with a unit test.
- **Q: Worker thread lifecycle on SIGINT?** **A: Periodic shutdown check every 256 rows.** Worker sends `Error("daemon shutting down")` and returns; thread exits naturally; `ControlServer::Drop` only joins the listener (not workers — workers self-terminate).
- **Q: Wire compatibility?** **A: tsctl decodes `QueryFrame | ErrorResponse` per line.** Handles both new-tsd-with-Query-handler and old-tsd-without.

**Crash-safety / cleanup:**
- The query Connection is opened per request and dropped at the end of `handle_query`. The in-memory primary leaves nothing on disk; the ATTACHed file's read-only attach releases its shared lock on Connection drop.
- Same RAII / Drop order as 1.F applies; the `_slot: ActiveQueryGuard` decrements the active-query counter on any exit path.
