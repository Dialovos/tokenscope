# Phase 2.A — TLS Plaintext Capture via libssl Uprobes (Design Spec)

> **Status:** approved-pending-implementation. Date: 2026-05-07. Predecessor: Phase 1.G (`v0.0.8-phase1g`). This spec is the first of the Phase 2 split (2.A plumbing → 2.B HTTP demux → 2.C parsers + cost → 2.D `tstop` v1).

## Goal

Capture decrypted TLS payload bytes from `OpenSSL`/`libssl.so`-using processes on the host, attribute each chunk to `(pid, tgid, comm, cgroup_id)`, persist to DuckDB, and surface human-scannable summaries (with opt-in raw-bytes mode) over the existing `tsctl tail` channel. **No HTTP framing, no parsers, no cost calculation.** Those land in 2.B–2.D.

## Non-Goals (explicit, to bound scope)

1. Go binaries that statically link `crypto/tls` — invisible. Future phase via runtime offset discovery.
2. Rust binaries using `rustls` — invisible. Future phase via FFI-surface uprobes or kTLS sniffing.
3. BoringSSL / NSS / GnuTLS / s2n / mbedTLS — out of scope. Documented as gap.
4. Statically-linked `OpenSSL` baked into a binary — current discovery only walks shared-lib mappings.
5. HTTP/1.1 or HTTP/2 framing, body reassembly across calls — Phase 2.B.
6. Anthropic / OpenAI / Ollama protocol parsers — Phase 2.C.
7. UI dashboard — Phase 2.D (`tstop`).

## Architecture (data flow)

```
                              libssl.so.3 in target proc
                                          │
        SSL_write / SSL_write_ex ── uprobe entry ─┐
                                                  │
        SSL_read  / SSL_read_ex  ── uprobe entry ─┤── stash & emit
                                                  │
        SSL_read  / SSL_read_ex  ── uretprobe ────┘
                                                  │
                                     ┌────────────┘
                                     ▼
                              tls.bpf.c (kernel)
                                     │
                                     ▼
                       bpf_ringbuf (events_tls, 4 MiB default)
                                     │
                                     ▼
                       tsd ringbuf consumer thread (tls.rs)
                                     │
                                     ▼
                       events_tx mpsc::SyncSender<EventEnvelope>
                       (the existing single-writer channel)
                                     │
                                     ▼
                  store-writer thread ─→ store.rs (DuckDB Appender)
                                     │
                                     └─→ control.rs::broadcast_to_tail_subs
                                              │
                                  per-subscriber render
                                  (include_plaintext bool from Tail Request)
                                              │
                                              ▼
                                     UDS clients (tsctl tail)
```

Same shape as net.bpf.c, with three corrections vs. the Phase 1 sink. Each is a real refactor of the Phase 1 code, not just a TLS addition:

1. **Introduce a single-writer DuckDB channel.** Phase 1 has each ringbuf consumer thread call `store.insert_*()` directly *and* `subscribers.broadcast(&line)` directly (verified 2026-05-07: `store.rs` exposes thread-callable inserts, `Subscribers::broadcast` takes a pre-rendered `&str`). For 2.A this is refactored: a new `events_tx: SyncSender<EventEnvelope>` channel is introduced, `EventEnvelope` is a new enum in `tsd::sink` with one variant per event family (`ProcExec`, `NetConnect`, `NetBytesSnapshot`, `TlsPlaintext`), and a single `store-writer` thread owns the DuckDB `Connection` and consumes the channel. Existing ringbuf consumers (`net_bytes.rs`, the exec consumer) switch to push `EventEnvelope` onto `events_tx` instead of calling `store` and `subscribers` directly. The `store-writer` thread fans out to `Subscribers` after persisting (or in parallel; ordering between persist and broadcast is not guaranteed).
2. **DuckDB `Appender` API for the TLS table.** `events_proc_exec`, `events_net_*` keep their existing `INSERT … VALUES` statements (low rate, no measured pressure). `events_tls_plaintext` uses `Connection::appender("events_tls_plaintext")` because TLS records can burst at thousands/sec; per-row `INSERT` is a known throughput cliff. Validated against TLS-scale bursts in the Layer 2 streaming-response test.
3. **Per-subscriber tail rendering.** Today: `Subscribers::broadcast(&str)` pushes one pre-rendered string to every UDS subscriber. For 2.A: `Subscribers` stores a per-subscriber `include_plaintext: bool` (captured at `Tail` request time) plus a `Vec<u8>` channel; the broadcast loop calls a new `render_tail_line(env, include_plaintext) -> String` helper per subscriber. Plaintext bytes are **never** placed in the rendered string for subscribers without `include_plaintext=true`. Redaction is a server-side decision, not a `tsctl` filter.

## Wire Format

### Header (unchanged)

`bpf/ts_event.h::ts_event_hdr` is unchanged. `TS_TLS_PLAINTEXT = 3` was reserved during Phase 0 and is used now.

`hdr.len` is set per-record to `sizeof(struct ts_tls_plaintext_payload) + chunk_bytes` so userspace decoders never run past the trailing plaintext slice.

### Payload

```c
/* bpf/ts_event.h — append below ts_net_bytes_value */

struct ts_tls_plaintext_payload {
    __u64 ssl_ctx;        /* userspace SSL* pointer; process-scoped only */
    __u64 call_id;        /* entry ktime_ns; unique within (tgid, ssl_ctx, dir) */
    __u64 entry_cgroup_id;/* cgroup at SSL_* entry; emit this, not return-time */
    __u32 total_bytes;    /* bytes in this SSL_* call (pre-chunking) */
    __u16 chunk_index;    /* 0-based */
    __u16 chunk_total;    /* 1..16 */
    __u16 chunk_bytes;    /* 0..4096 */
    __u8  direction;      /* 0 = write, 1 = read */
    __u8  flags;          /* bit 0 = truncated, bit 1 = read_user_failed,
                             bit 2 = write_ex / read_ex variant */
    __u8  _pad[4];        /* explicit; assert struct == 40 bytes */
    /* followed by chunk_bytes plaintext (max 4096) */
};

/* Compile-time alignment tripwire */
_Static_assert(sizeof(struct ts_tls_plaintext_payload) == 40,
               "tls payload must be exactly 40 bytes");
```

Total fixed payload: **40 bytes** (codex BLOCKING #1 fix — was 20 in draft, actually 24 with natural padding, now 40 with deliberate `call_id` + `entry_cgroup_id` additions). Plus variable `chunk_bytes` ≤ 4096. Per-record max: 56 (header) + 40 (payload) + 4096 (plaintext) = **4192 bytes**.

### Rust mirror

```rust
// crates/ts-core/src/event.rs — append below TsNetBytesValue

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TsTlsPlaintextPayload {
    pub ssl_ctx: u64,
    pub call_id: u64,
    pub entry_cgroup_id: u64,
    pub total_bytes: u32,
    pub chunk_index: u16,
    pub chunk_total: u16,
    pub chunk_bytes: u16,
    pub direction: u8,
    pub flags: u8,
    pub _pad: [u8; 4],
}
const _: () = assert!(size_of::<TsTlsPlaintextPayload>() == 40);
const _: () = assert!(align_of::<TsTlsPlaintextPayload>() == 8);

pub const TLS_FLAG_TRUNCATED: u8       = 1 << 0;
pub const TLS_FLAG_READ_FAILED: u8     = 1 << 1;
pub const TLS_FLAG_EX_VARIANT: u8      = 1 << 2;

pub fn decode_tls_plaintext(buf: &[u8])
    -> Result<(TsTlsPlaintextPayload, &[u8]), DecodeError>;
```

`decode_tls_plaintext` returns `(payload, plaintext_slice)` where the slice is borrowed from the ringbuf record (zero-copy until handed to DuckDB, where it's `ColumnVal::Blob` from a clone).

## DuckDB Schema

```sql
-- store.rs::SCHEMA_V2 — bumps schema_version row to 2
CREATE TABLE IF NOT EXISTS events_tls_plaintext (
    ts_ns           BIGINT  NOT NULL,
    pid             INTEGER NOT NULL,
    tgid            INTEGER NOT NULL,
    cgroup_id       BIGINT  NOT NULL,  -- entry-time cgroup_id, not return-time
    comm            VARCHAR NOT NULL,
    ssl_ctx         BIGINT  NOT NULL,  -- process-scoped pointer
    call_id         BIGINT  NOT NULL,  -- entry ktime_ns; (tgid,ssl_ctx,dir,call_id) is the stream-call key
    direction       TINYINT NOT NULL,  -- 0=write, 1=read
    total_bytes     INTEGER NOT NULL,
    chunk_index     SMALLINT NOT NULL,
    chunk_total     SMALLINT NOT NULL,
    chunk_bytes     SMALLINT NOT NULL,
    truncated       BOOLEAN NOT NULL,
    read_failed     BOOLEAN NOT NULL,
    ex_variant      BOOLEAN NOT NULL,  -- SSL_read_ex / SSL_write_ex
    plaintext       BLOB
);

CREATE INDEX IF NOT EXISTS idx_tls_ts ON events_tls_plaintext(ts_ns);
CREATE INDEX IF NOT EXISTS idx_tls_call
    ON events_tls_plaintext(tgid, ssl_ctx, direction, call_id, chunk_index);
```

Migration: bump `schema_version` row from 1 to 2 inside the existing `ensure_schema()` flow. New databases get v2 directly; existing v1 databases get the new table appended (no destructive migration; `events_proc_exec`/`events_net_*` are unchanged).

## BPF Program (`bpf/tls.bpf.c`)

### Maps

```c
/* Inflight slot per (pid_tgid) — keyed by full kernel PID×TGID, not tgid.
 * Two threads in the same process calling SSL_read concurrently MUST get
 * separate slots (codex BLOCKING #2). */
struct tls_inflight_key {
    __u64 pid_tgid;
};

struct tls_inflight_val {
    __u64 ssl_ctx;
    __u64 buf_ptr;
    __u64 entry_ts_ns;     /* for stale-detection sweep */
    __u64 entry_cgroup_id; /* emit on return so cgroup migration during
                              long blocking reads doesn't confuse output */
    __u64 readbytes_ptr;   /* SSL_read_ex out-param; 0 for non-_ex reads */
    __u32 num;             /* requested byte count */
    __u8  is_ex;           /* 1 if SSL_read_ex (return value semantics differ) */
    __u8  _pad[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);  /* doubled vs draft; concurrent thread slots */
    __type(key, struct tls_inflight_key);
    __type(value, struct tls_inflight_val);
} tls_inflight SEC(".maps");

/* Cgroup tracking filter, PINNED so cgroup.rs and tls.rs share one map.
 * Pinned at /sys/fs/bpf/tokenscope/cgroup_filter (created at tsd startup,
 * see "Userspace Setup" below).
 *
 * Key: u64 cgroup_id. Value: u8 (always 1; presence == "tracked").
 *
 * Note: this map does NOT exist in the codebase today (verified 2026-05-07).
 * Phase 2.A creates it AND populates it (initially with just the daemon's
 * own cgroup; per-cgroup attach controls land later). cgroup/connect
 * probes are not migrated to use it in 2.A — they remain naturally
 * cgroup-scoped via their attach point. The filter exists to scope uprobes
 * (which have no natural cgroup attachment). */
struct cgroup_filter_key { __u64 cgroup_id; };
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, struct cgroup_filter_key);
    __type(value, __u8);
} cgroup_filter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);  /* 4 MiB default; codex BLOCKING #7 */
} events_tls SEC(".maps");

/* BPF-side reserve-failure counter (codex SHOULD-FIX, complements the
 * existing userspace-poll-error counter). One u64 in a single-element
 * percpu array. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} tls_reserve_fail SEC(".maps");

/* Inflight collision counter (BPF_NOEXIST insert failed → another thread
 * already had this pid_tgid slot, which on a sane libssl flow shouldn't
 * happen but we count for visibility). */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} tls_inflight_collision SEC(".maps");
```

### Probe shape

All four probes follow the same shell:

```c
static __always_inline bool cgroup_tracked(__u64 cgid) {
    struct cgroup_filter_key k = { .cgroup_id = cgid };
    return bpf_map_lookup_elem(&cgroup_filter, &k) != NULL;
}

#define MAX_CHUNKS 16
#define CHUNK_BYTES 4096

static __always_inline int emit_plaintext_chunks(
    __u64 ssl_ctx, __u64 call_id, __u64 entry_cgid,
    const void *src, __u32 total_bytes,
    __u8 direction, __u8 ex_variant)
{
    __u32 n_chunks = total_bytes / CHUNK_BYTES + (total_bytes % CHUNK_BYTES ? 1 : 0);
    __u8  truncated = 0;
    if (n_chunks > MAX_CHUNKS) {
        n_chunks = MAX_CHUNKS;
        truncated = 1;
    }

    /* Codex SHOULD-FIX: fixed for-loop with #pragma unroll, NOT bpf_loop().
     * Verifier accepts this with constant trip count and constant
     * record size on every iteration. */
    #pragma unroll
    for (__u32 i = 0; i < MAX_CHUNKS; i++) {
        if (i >= n_chunks) break;

        __u32 off = i * CHUNK_BYTES;
        __u32 chunk_bytes = (i + 1 == n_chunks)
            ? (total_bytes - off > CHUNK_BYTES ? CHUNK_BYTES : total_bytes - off)
            : CHUNK_BYTES;
        if (chunk_bytes > CHUNK_BYTES) chunk_bytes = CHUNK_BYTES;  /* verifier */

        struct tls_record {
            struct ts_event_hdr hdr;
            struct ts_tls_plaintext_payload pl;
            __u8 plaintext[CHUNK_BYTES];
        } *r;

        r = bpf_ringbuf_reserve(&events_tls, sizeof(*r), 0);
        if (!r) {
            __u32 zero = 0;
            __u64 *c = bpf_map_lookup_elem(&tls_reserve_fail, &zero);
            if (c) __sync_fetch_and_add(c, 1);
            return -1;
        }

        __u64 pid_tgid = bpf_get_current_pid_tgid();
        r->hdr.ts_ns     = bpf_ktime_get_ns();
        r->hdr.cpu       = bpf_get_smp_processor_id();
        r->hdr.pid       = (__u32)(pid_tgid & 0xFFFFFFFFu);
        r->hdr.tgid      = (__u32)(pid_tgid >> 32);
        r->hdr.cgroup_id = entry_cgid;  /* not return-time */
        r->hdr.type      = TS_TLS_PLAINTEXT;
        r->hdr.len       = sizeof(struct ts_tls_plaintext_payload) + chunk_bytes;
        bpf_get_current_comm(&r->hdr.comm, sizeof(r->hdr.comm));

        r->pl.ssl_ctx         = ssl_ctx;
        r->pl.call_id         = call_id;
        r->pl.entry_cgroup_id = entry_cgid;
        r->pl.total_bytes     = total_bytes;
        r->pl.chunk_index     = i;
        r->pl.chunk_total     = n_chunks;
        r->pl.chunk_bytes     = chunk_bytes;
        r->pl.direction       = direction;
        r->pl.flags           = (truncated && i + 1 == n_chunks ? TLS_FLAG_TRUNCATED : 0)
                              | (ex_variant ? TLS_FLAG_EX_VARIANT : 0);
        __builtin_memset(r->pl._pad, 0, sizeof(r->pl._pad));

        long ret = bpf_probe_read_user(r->plaintext, chunk_bytes, src + off);
        if (ret) {
            r->pl.flags |= TLS_FLAG_READ_FAILED;
            r->pl.chunk_bytes = 0;
            __builtin_memset(r->plaintext, 0, CHUNK_BYTES);  /* don't leak */
        }

        bpf_ringbuf_submit(r, 0);
    }
    return 0;
}
```

#### Probes

```c
SEC("uprobe/SSL_write")
int BPF_UPROBE(ssl_write_entry, void *ssl, const void *buf, int num) {
    if (num <= 0) return 0;
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!cgroup_tracked(cgid)) return 0;
    __u64 call_id = bpf_ktime_get_ns();
    return emit_plaintext_chunks((__u64)ssl, call_id, cgid, buf,
                                  (__u32)num, 0, 0);
}

SEC("uprobe/SSL_write_ex")
int BPF_UPROBE(ssl_write_ex_entry, void *ssl, const void *buf, size_t num,
               size_t *written) {
    if (num == 0) return 0;
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!cgroup_tracked(cgid)) return 0;
    __u64 call_id = bpf_ktime_get_ns();
    /* num is size_t; cap to UINT_MAX for our wire format. */
    __u32 total = (num > 0xFFFFFFFFu) ? 0xFFFFFFFFu : (__u32)num;
    return emit_plaintext_chunks((__u64)ssl, call_id, cgid, buf,
                                  total, 0, 1);
}

SEC("uprobe/SSL_read")
int BPF_UPROBE(ssl_read_entry, void *ssl, void *buf, int num) {
    if (num <= 0) return 0;
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!cgroup_tracked(cgid)) return 0;

    struct tls_inflight_key k = { .pid_tgid = bpf_get_current_pid_tgid() };
    struct tls_inflight_val v = {
        .ssl_ctx         = (__u64)ssl,
        .buf_ptr         = (__u64)buf,
        .entry_ts_ns     = bpf_ktime_get_ns(),
        .entry_cgroup_id = cgid,
        .num             = (__u32)num,
        .is_ex           = 0,
    };
    long ret = bpf_map_update_elem(&tls_inflight, &k, &v, BPF_ANY);
    if (ret) {
        /* BPF_NOEXIST would be ideal, but LRU semantics + concurrent threads
         * mean we accept overwrites and just count them. */
        __u32 zero = 0;
        __u64 *c = bpf_map_lookup_elem(&tls_inflight_collision, &zero);
        if (c) __sync_fetch_and_add(c, 1);
    }
    return 0;
}

SEC("uretprobe/SSL_read")
int BPF_URETPROBE(ssl_read_exit, int ret) {
    if (ret <= 0) return 0;
    struct tls_inflight_key k = { .pid_tgid = bpf_get_current_pid_tgid() };
    struct tls_inflight_val *v = bpf_map_lookup_elem(&tls_inflight, &k);
    if (!v) return 0;
    __u32 nbytes = ((__u32)ret < v->num) ? (__u32)ret : v->num;
    /* Use the call_id captured at entry so chunks are linkable */
    __u64 call_id = v->entry_ts_ns;
    __u64 ssl_ctx = v->ssl_ctx;
    __u64 entry_cgid = v->entry_cgroup_id;
    void *src = (void *)v->buf_ptr;
    __u8 ex_variant = v->is_ex;
    bpf_map_delete_elem(&tls_inflight, &k);
    return emit_plaintext_chunks(ssl_ctx, call_id, entry_cgid, src, nbytes,
                                  1, ex_variant);
}

/* SSL_read_ex(ssl, buf, num, &readbytes) -> 1 on success, 0 on fail.
 * The bytes written are at *readbytes, NOT in the return value.
 * Capture readbytes pointer at entry so uretprobe can deref it. */
SEC("uprobe/SSL_read_ex")
int BPF_UPROBE(ssl_read_ex_entry, void *ssl, void *buf, size_t num,
               size_t *readbytes) {
    if (num == 0) return 0;
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!cgroup_tracked(cgid)) return 0;

    struct tls_inflight_key k = { .pid_tgid = bpf_get_current_pid_tgid() };
    struct tls_inflight_val v = {
        .ssl_ctx         = (__u64)ssl,
        .buf_ptr         = (__u64)buf,
        .entry_ts_ns     = bpf_ktime_get_ns(),
        .entry_cgroup_id = cgid,
        .num             = (num > 0xFFFFFFFFu) ? 0xFFFFFFFFu : (__u32)num,
        .is_ex           = 1,
        .readbytes_ptr   = (__u64)readbytes,  /* extra field on val */
    };
    long ret = bpf_map_update_elem(&tls_inflight, &k, &v, BPF_ANY);
    if (ret) {
        __u32 zero = 0;
        __u64 *c = bpf_map_lookup_elem(&tls_inflight_collision, &zero);
        if (c) __sync_fetch_and_add(c, 1);
    }
    return 0;
}

SEC("uretprobe/SSL_read_ex")
int BPF_URETPROBE(ssl_read_ex_exit, int ret) {
    if (ret != 1) return 0;  /* SSL_read_ex returns 1 on success */
    struct tls_inflight_key k = { .pid_tgid = bpf_get_current_pid_tgid() };
    struct tls_inflight_val *v = bpf_map_lookup_elem(&tls_inflight, &k);
    if (!v || !v->is_ex) return 0;

    size_t readbytes = 0;
    long pr = bpf_probe_read_user(&readbytes, sizeof(readbytes),
                                   (void *)v->readbytes_ptr);
    if (pr) { bpf_map_delete_elem(&tls_inflight, &k); return 0; }
    __u32 nbytes = (readbytes > v->num) ? v->num
                  : (readbytes > 0xFFFFFFFFu ? 0xFFFFFFFFu : (__u32)readbytes);

    __u64 call_id = v->entry_ts_ns;
    __u64 ssl_ctx = v->ssl_ctx;
    __u64 entry_cgid = v->entry_cgroup_id;
    void *src = (void *)v->buf_ptr;
    bpf_map_delete_elem(&tls_inflight, &k);
    return emit_plaintext_chunks(ssl_ctx, call_id, entry_cgid, src, nbytes,
                                  1 /* read */, 1 /* ex_variant */);
}
```

`tls_inflight_val` extends to add one extra field — `__u64 readbytes_ptr` — which is unused (zero) for non-`_ex` reads. Single inflight map keeps the LRU eviction story uniform across all four read probes.

### Verifier notes

- `chunk_bytes` is bounded `<= CHUNK_BYTES` immediately before `bpf_probe_read_user` — verifier accepts.
- Loop is `#pragma unroll`'d to 16 iterations, each iteration does a constant-size `bpf_ringbuf_reserve(sizeof(struct tls_record), 0)`.
- `r->plaintext` is `PTR_TO_MEM | MEM_RINGBUF` per Linux 5.8+ verifier semantics (codex SHOULD-FIX confirmed). No stack pressure (`tls_record` is allocated *in* the ringbuf, not on the BPF stack).
- Min supported kernel: **5.15** (LTS, ringbuf landed in 5.8, MEM_RINGBUF dest writes from `bpf_probe_read_user` stable in 5.15+). Documented in DOC.md.

## Userspace (`crates/tsd/src/tls.rs`)

### Setup at daemon start

```rust
pub struct TlsAttachManager {
    skel: TlsSkel<'static>,
    attached: Mutex<HashMap<(u64, u64), AttachedLib>>, // (dev, ino) → handles
    cgroup_filter_fd: BorrowedFd<'static>,             // pinned map FD
    events_tx: SyncSender<EventEnvelope>,              // shared sink channel
    counters: Arc<Counters>,
    shutdown: Arc<AtomicBool>,
    discover_thread: Option<JoinHandle<()>>,
    consumer_thread: Option<JoinHandle<()>>,
}

struct AttachedLib {
    inode_path: PathBuf,        // canonical /proc/<pid>/map_files/<range> resolution
    write_link: Link,
    write_ex_link: Option<Link>,
    read_entry_link: Link,
    read_exit_link: Link,
    read_ex_entry_link: Option<Link>,
    read_ex_exit_link: Option<Link>,
    refcount: u32,
}
```

#### Cgroup filter map setup

1. `bpffs_dir = "/sys/fs/bpf/tokenscope"` — `mkdir(0755)` if absent.
2. Before loading the TLS skeleton, the daemon sets the pin path on the `cgroup_filter` map so libbpf attaches it at `/sys/fs/bpf/tokenscope/cgroup_filter` on first load and reuses on subsequent loads.
3. Daemon populates the filter at startup with at least its own `cgroup_id` (so the smoke test "tsd makes a TLS call → tsd sees its own bytes" works). Per-cgroup attach controls (`tsctl cgroup add /sys/fs/cgroup/...`) land in a later phase; for 2.A, the filter is configurable via a new `--track-cgroup <PATH>` repeated CLI flag on `tsd` (default: own cgroup only).

### Discovery (codex BLOCKING #5 fix)

```rust
fn discover_libssl_loop(state: Arc<TlsAttachManager>) {
    let re = Regex::new(r"r-xp .* (\S*libssl\.so(?:\.\S+)?)$").unwrap(); // precompiled once
    while !state.shutdown.load(Ordering::Relaxed) {
        let scan_start = Instant::now();
        let mut errors = 0u32;
        let mut found_inodes: HashSet<(u64, u64)> = HashSet::new();

        for entry in fs::read_dir("/proc").ok().into_iter().flatten().flatten() {
            let pid_str = entry.file_name();
            let pid_str = match pid_str.to_str() { Some(s) => s, None => continue };
            if !pid_str.bytes().all(|b| b.is_ascii_digit()) { continue; }

            let maps = match fs::read_to_string(entry.path().join("maps")) {
                Ok(s) => s,
                Err(_) => { errors += 1; continue; }
            };
            for line in maps.lines() {
                let cap = match re.captures(line) {
                    Some(c) => c,
                    None => continue,
                };
                let visible_path = cap.get(1).unwrap().as_str();

                // Resolve through /proc/<pid>/root/<visible_path> so we get
                // the inode AS SEEN BY THIS PROCESS — handles container
                // mount-namespaces, symlinks, deleted-then-replaced files.
                let proc_root_path = entry.path().join("root").join(
                    visible_path.trim_start_matches('/'));
                let meta = match fs::metadata(&proc_root_path) {
                    Ok(m) => m,
                    Err(_) => { errors += 1; continue; }
                };
                use std::os::unix::fs::MetadataExt;
                let key = (meta.dev(), meta.ino());
                if !found_inodes.insert(key) { continue; } // already-seen this scan

                {
                    let mut attached = state.attached.lock().unwrap();
                    if attached.contains_key(&key) {
                        attached.get_mut(&key).unwrap().refcount += 1;
                        continue;
                    }
                    // attach via the same /proc/<pid>/root/... path so the
                    // kernel resolves the inode the same way we did.
                    match attach_libssl(&state.skel, &proc_root_path) {
                        Ok(lib) => {
                            attached.insert(key, lib);
                            state.counters.tls_libs_attached.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => {
                            tracing::warn!(?proc_root_path, ?e, "tls libssl attach failed");
                            state.counters.tls_libs_skipped.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
        }

        let dur_us = scan_start.elapsed().as_micros() as u64;
        state.counters.tls_scan_duration_us.store(dur_us, Ordering::Relaxed);
        state.counters.tls_scan_errors.store(errors, Ordering::Relaxed);

        thread::sleep(Duration::from_secs(5));
    }
}
```

`attach_libssl()` opens an FD on the resolved path and calls `prog.attach_uprobe_with_opts(-1, &path, 0, UprobeOpts { func_name: "SSL_write", retprobe: false, .. })` for each of (`SSL_write`, `SSL_write_ex`, `SSL_read` entry, `SSL_read` retprobe, `SSL_read_ex` entry, `SSL_read_ex` retprobe). `_ex` variants that aren't found in older libssl get skipped silently (counted in `tls_libs_partial_attach` rather than `tls_libs_skipped` — partial coverage is still useful).

### Counters

Added to `tsd::Counters`:
- `tls_libs_attached: AtomicU32` — distinct (dev, ino) currently with at least one Link
- `tls_libs_skipped: AtomicU32` — symbol resolution failed entirely
- `tls_libs_partial_attach: AtomicU32` — basic SSL_read/write attached, _ex variants missing
- `tls_records_emitted: AtomicU64`
- `tls_truncated_calls: AtomicU64` — last record had `TLS_FLAG_TRUNCATED`
- `tls_read_failed_chunks: AtomicU64` — `bpf_probe_read_user` failures
- `tls_inflight_collisions: AtomicU64` — pulled from BPF percpu map every 5s during discovery scan
- `tls_reserve_failures: AtomicU64` — same
- `tls_scan_duration_us: AtomicU64` — last completed scan duration
- `tls_scan_errors: AtomicU32` — `/proc/<pid>/maps` read errors during last scan
- `tls_subscribers_with_plaintext: AtomicU32` — subset of tail subs that asked for plaintext

## Control Plane (`crates/ts-core/src/control.rs` + `tsd/src/control.rs`)

### Tail Request — backward-compatible extension (codex BLOCKING #6 fix)

`Request::Tail` becomes `Request::Tail { include_plaintext: bool }` with serde default `false`. Old `tsctl` clients that send `{"op":"Tail"}` keep working; new `tsctl tail --show-plaintext` sends `{"op":"Tail","include_plaintext":true}`.

```rust
pub enum Request {
    // existing variants unchanged
    Tail {
        #[serde(default)]
        include_plaintext: bool,
    },
    // ...
}
```

### Per-subscriber rendering

Today (verified 2026-05-07): each ringbuf consumer pre-renders one JSON line and calls `Subscribers::broadcast(&line)`, which `try_send`s the same `String` to every subscriber's `SyncSender<String>`. For 2.A this becomes:

```rust
// New shared envelope (in tsd::sink):
pub enum EventEnvelope {
    ProcExec(ProcExecEvent),
    NetConnect(NetConnectEvent),
    NetBytesSnapshot(NetBytesSnapshot),
    TlsPlaintext(TlsPlaintextEvent),  // includes the plaintext Vec<u8>
}

// Subscriber registry: per-subscriber options + binary-safe channel.
struct Subscriber {
    sender: SyncSender<Vec<u8>>,
    include_plaintext: bool,    // captured at Tail handshake time
}

// New helper, one entry point per envelope:
//   render_tail_line(env: &EventEnvelope, include_plaintext: bool) -> String
// Returns one newline-terminated JSON line. For TlsPlaintext the
// `plaintext_b64` field is omitted entirely when include_plaintext=false.

// Broadcast loop:
for sub in subs.iter() {
    let line = render_tail_line(env, sub.include_plaintext);
    match sub.sender.try_send(line.into_bytes()) {
        Ok(_) => {}
        Err(TrySendError::Full(_)) => {
            counters.tail_dropped_events.fetch_add(1, Ordering::Relaxed);
        }
        Err(TrySendError::Disconnected(_)) => { /* removed by SubscriberGuard */ }
    }
}
```

Plaintext bytes are **only** placed into the rendered line for subscribers with `include_plaintext = true`. Non-plaintext events (net/exec) ignore the flag and render identically for all subscribers.

`tail_dropped_events: AtomicU64` is a NEW counter introduced in 2.A. Today the broadcast loop logs `try_send` failures via `tracing::trace!` only — no counter exists. The new counter shows up in `tsctl status`.

### `render_tail_line` for `TS_TLS_PLAINTEXT` records

Default form (no plaintext):

```
[2026-05-07T10:31:22.114Z] tls.write pid=1234 tgid=1234 comm=python ssl_ctx=0x7f8a1c0 call_id=1715073082114000000 bytes=4096 chunk=1/3 sha256=ab12cd34
```

With `include_plaintext`:

```
[2026-05-07T10:31:22.114Z] tls.write pid=1234 tgid=1234 comm=python ssl_ctx=0x7f8a1c0 call_id=1715073082114000000 bytes=4096 chunk=1/3 │ POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nAuthorization: Bearer ***REDACTED***\r\n...
```

JSON form (default no plaintext; with `include_plaintext`, `plaintext_b64` field appears):

```json
{"ts_ns":1715073082114000000,"kind":"tls.write","pid":1234,"tgid":1234,
 "comm":"python","ssl_ctx":"0x7f8a1c0","call_id":1715073082114000000,
 "total_bytes":10295,"chunk_index":0,"chunk_total":3,"chunk_bytes":4096,
 "truncated":false,"ex_variant":false,"plaintext_sha256":"ab12cd34..."}
```

### Redaction (codex SHOULD-FIX expansion)

Render-time only. Stored BLOB keeps full fidelity. Patterns (compiled once at server startup, all case-insensitive where applicable):

**Header-style:**
- `(?i)\b(authorization|x-api-key|api-key|x-auth-token|x-goog-api-key|api[-_]?key|password|secret|token|client[-_]?secret)\s*[:=]\s*\S+` → `$1: ***REDACTED***`

**Provider tokens:**
- `\bsk-ant-[\w-]{20,}\b`
- `\bsk-[\w-]{20,}\b`              (OpenAI)
- `\bgsk_[\w]{20,}\b`              (Groq)
- `\bhf_[\w]{20,}\b`               (HuggingFace)
- `\bAIza[\w-]{30,}\b`             (Google API key)
- `\bgithub_pat_[\w]{20,}\b`
- `\bgh[pousr]_[\w]{20,}\b`        (GitHub legacy)
- `\bglpat-[\w-]{20,}\b`           (GitLab)
- `\bAKIA[A-Z0-9]{16}\b` and `\bASIA[A-Z0-9]{16}\b`  (AWS)

**Generic:**
- JWT: `\beyJ[\w-]+\.[\w-]+\.[\w-]+\b`
- PEM private key blocks: `-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`

All matches replaced with `***REDACTED***`.

### `tsctl status` additions

```
tls libs attached      7
tls libs skipped       1
tls libs partial       0
tls records emitted    1247
tls truncated calls    3
tls read failed chunks 0
tls inflight collisions 0
tls reserve failures   0
tls scan duration (us) 4823
tls scan errors        0
```

## Error Handling

| Failure | Behavior |
|---|---|
| `SSL_*` symbol not found | Log once at WARN per (dev,ino), bump `tls_libs_skipped`, surface in status |
| `_ex` variant only missing | Bump `tls_libs_partial_attach`, attach what we can |
| `bpf_probe_read_user` failure | Emit record with `read_failed=1`, `chunk_bytes=0`, plaintext zeroed |
| `tls_inflight` LRU eviction or BPF_ANY overwrite | Bump `tls_inflight_collisions`, no record from the lost-entry call |
| `uretprobe` doesn't fire (process death/exec/pthread_exit/longjmp) | Stale entry sweeps in the next `SSL_read` entry on the same `pid_tgid` slot — overwritten and counted |
| libssl unloaded mid-attach | Kernel keeps inode-based attachment alive against the original inode; rescan finds replacement |
| 16-chunk truncation | Last record sets `TLS_FLAG_TRUNCATED`; downstream reassembler in 2.B treats as "end of capture" |
| Ringbuf reserve failure (4 MiB exhausted) | BPF emits no record, bumps `tls_reserve_failures` percpu counter; userspace surfaces in status |
| Tail subscriber `try_send` full | Drop newest, bump new `tail_dropped_events` counter (added in 2.A; see Per-subscriber rendering) |

## Documented Gaps (also goes into DOC.md "Known gaps" of Phase 2.A)

1. **Go static `crypto/tls`:** invisible. Future phase.
2. **rustls:** invisible. Future phase.
3. **BoringSSL stripped (Chrome/Electron):** likely shows as `tls_libs_skipped`.
4. **Static-linked OpenSSL into a binary:** discovery only walks shared lib mappings.
5. **`SSL_write` captures *attempted* bytes, not transmitted:** if the underlying socket `write` fails, we still recorded the plaintext. Documented; not a bug.
6. **Per-cgroup attach UI deferred:** filter populated only with daemon's own cgroup + whatever `--track-cgroup` flags pass. `tsctl cgroup add/remove` lands later.
7. **No per-stream sequence numbers across calls:** within one `SSL_*` call, chunks have ordered `chunk_index`. Ordering across calls within `(tgid, ssl_ctx, direction)` is by `call_id` (which is `entry_ts_ns` and is monotonic per CPU but NOT globally monotonic across CPUs in pathological clock skew). Phase 2.B reassembler treats `call_id` ordering as best-effort; HTTP demux will resync on framing.
8. **Min kernel 5.15.** Older kernels rejected at skeleton load.

## Testing

### Layer 1 — Unit (`cargo test --workspace`, no root)

`crates/ts-core/src/event.rs`:
- `decode_tls_plaintext_round_trip` — encode payload + 1024-byte plaintext, decode, assert byte-equal.
- `decode_tls_plaintext_zero_chunk_bytes` — `chunk_bytes=0` (read_failed path) returns `(payload, &[])`.
- `decode_tls_plaintext_truncated_header` — input shorter than 40-byte payload returns `Err(Truncated)`.
- `decode_tls_plaintext_bad_length` — declared `chunk_bytes=4096` but only 100 bytes follow returns `Err(BadLength)`.
- Compile-time: `size_of::<TsTlsPlaintextPayload>() == 40`, `align == 8`.

`crates/tsd/src/tls.rs` (mockable parts):
- `chunk_math(total_bytes)` returns `(n_chunks, last_chunk_bytes, truncated)` for inputs 0, 1, 4095, 4096, 4097, 65536, 65537, 1_000_000.
- Counter increments via direct manager method calls (no BPF).

`crates/tsd/src/control.rs`:
- `redact("Authorization: Bearer sk-ant-abc123def456789...")` contains `***REDACTED***`, doesn't contain `sk-ant-abc`.
- `redact` for each provider pattern listed.
- `render_tail_line` for `TS_TLS_PLAINTEXT` with `include_plaintext=false` doesn't contain plaintext bytes.
- `render_tail_line` with `include_plaintext=true` contains the redacted plaintext.

### Layer 2 — Integration (`sudo cargo test -- --ignored`, requires CAP_BPF + libssl + cc + pkg-config)

Build a tiny dynamic C OpenSSL client at test-build time (`build.rs` or `cc::Build` invocation in the test):

```c
/* tests/fixtures/tls_client.c — built via cc, linked against -lssl -lcrypto */
#include <openssl/ssl.h>
#include <openssl/err.h>
/* connects to argv[1]:argv[2], does TLS handshake, writes argv[3] payload,
 * reads response, prints "OK" or err to stderr, exits.
 * Reads "GO\n" from stdin before doing the SSL_write so the test driver
 * can wait for tsd to attach before triggering. */
```

Test fixture (`tests/tls_e2e.rs`):
```rust
#[test]
#[ignore = "requires CAP_BPF + libssl + cc/pkg-config"]
fn tls_attach_emits_chunks_in_both_directions() {
    // 1. Skip with clear message if pkg-config can't find libssl
    // 2. Build tls_client.c at fixture-init time
    // 3. Spawn rustls echo server on 127.0.0.1:0 with self-signed cert
    // 4. Spawn tsd with --track-cgroup=<test's cgroup>
    // 5. Wait for `tsctl status` to show tls_libs_attached >= 1
    // 6. Spawn ./tls_client localhost <port> "<payload>"
    // 7. Send "GO\n" to its stdin
    // 8. Wait for client exit
    // 9. tsctl query "SELECT direction, COUNT(*), SUM(chunk_bytes)
    //                 FROM events_tls_plaintext GROUP BY 1"
    // 10. Assert: write rows >= 1 AND read rows >= 1
    //     AND SUM(chunk_bytes) for write >= len(payload)
}

#[test]
#[ignore = "requires CAP_BPF + libssl + cc/pkg-config"]
fn tls_streaming_response_chunks_correctly() {
    // Same setup; rustls server streams 50 KiB response in 4-KiB writes.
    // Assert chunk_total math holds: SUM(chunk_bytes WHERE direction=1) >= 50_000.
}

#[test]
#[ignore = "requires CAP_BPF + libssl + cc/pkg-config"]
fn tls_redaction_filters_authorization_in_show_plaintext() {
    // Drive a request with "Authorization: Bearer sk-ant-test12345..." prefix.
    // Run `tsctl tail --show-plaintext` for ~1.5s capturing stdout.
    // Assert stdout contains "***REDACTED***" AND does NOT contain "sk-ant-test12345".
}

#[test]
#[ignore = "requires CAP_BPF + libssl + cc/pkg-config"]
fn tls_truncation_at_16_chunks() {
    // Single 80 KiB SSL_write. Assert exactly 16 records, last has truncated=true.
}

#[test]
#[ignore = "requires CAP_BPF + libssl + cc/pkg-config"]
fn tls_default_tail_does_not_leak_plaintext() {
    // Drive a request with a magic string in the body.
    // Run `tsctl tail` (NO --show-plaintext) for ~1.5s.
    // Assert stdout does NOT contain the magic string.
    // (Catches any regression of codex BLOCKING #6.)
}
```

If `pkg-config --exists openssl` fails or `cc` isn't present, the tests `eprintln!` a clear "skipping: needs libssl-dev + build-essential" and `return;` — they don't fail. CI documentation notes this.

### Layer 3 — Manual smoke (DOC.md)

```
$ python -c "import urllib.request; urllib.request.urlopen('https://api.anthropic.com')"
$ tsctl tail --show-plaintext
[expected: tls.write line with HTTP request body visible, Authorization redacted]
$ tsctl query "SELECT direction, COUNT(*), SUM(chunk_bytes) FROM events_tls_plaintext GROUP BY 1"
[expected: at least one write row, at least one read row]
```

## Out-of-Scope (revisit later)

- Per-cgroup `tsctl cgroup add/remove` UX → Phase 2.E or later
- HTTP/1.1 + HTTP/2 framing reassembly → Phase 2.B
- Provider-specific parsers → Phase 2.C
- TLS metadata enrichment (cipher suite, SNI) → if needed, Phase 2.B
- Detaching uprobes when refcount reaches 0 → not worth the kernel-side churn until measured

## Implementation Order (preview for the writing-plans pass)

1. Wire format + Rust mirror + DuckDB schema migration (no BPF yet; pure Rust + tests).
2. Cgroup filter map plumbing (pinned bpffs, `--track-cgroup` CLI, populate own cgroup).
3. `bpf/tls.bpf.c` + skeleton generation; loaded but probes not yet attached.
4. Discovery loop + `attach_libssl` (plus the dev/ino keying); attach `SSL_write` only first.
5. Add `SSL_write_ex` + verify ringbuf records flowing.
6. Add `SSL_read` + uretprobe; verify both-directions.
7. Add `SSL_read_ex`.
8. Wire into the existing single-writer DuckDB channel; switch to `Appender` for TLS table.
9. Tail Request `include_plaintext` + per-subscriber render + redaction.
10. Counters into `tsctl status`.
11. Layer 2 integration tests.
12. DOC.md + DOC gaps + LEARNED.md entries for any new patterns.
13. Tag `v0.0.9-phase2a`.
