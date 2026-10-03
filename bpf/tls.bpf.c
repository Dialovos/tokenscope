/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Phase 2.A. uprobes on libssl.so SSL_write{,_ex} and SSL_read{,_ex}
 * (entry + uretprobe on the read side). Emits TS_TLS_PLAINTEXT records
 * onto a dedicated 4 MiB ringbuf. Cgroup-scoped via the pinned
 * `cgroup_filter` map shared with future per-cgroup attach work.
 *
 * Tasks 5-8 fill the probe bodies; this file (Task 4) ships the maps
 * and stub probes so the verifier accepts the program at load time.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "ts_event.h"

char LICENSE[] SEC("license") = "GPL";

#define MAX_CHUNKS 16
#define CHUNK_BYTES 4096

/* Older libbpf headers (Ubuntu 22.04) lack barrier_var. */
#ifndef barrier_var
#define barrier_var(var) asm volatile("" : "+r"(var))
#endif

#define TLS_FLAG_TRUNCATED   (1 << 0)
#define TLS_FLAG_READ_FAILED (1 << 1)
#define TLS_FLAG_EX_VARIANT  (1 << 2)

/* Pinned by name so userspace and (later) cgroup.rs share one map.
 * Pinned at /sys/fs/bpf/tokenscope/cgroup_filter on first load. */
struct cgroup_filter_key { __u64 cgroup_id; };
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, struct cgroup_filter_key);
    __type(value, __u8);
} cgroup_filter SEC(".maps");

/* Per-call inflight slot keyed on full kernel pid_tgid (NOT tgid alone —
 * threads in the same process can call SSL_read concurrently and must
 * not alias). Populated in SSL_read{,_ex} entry, drained in uretprobe. */
struct tls_inflight_key { __u64 pid_tgid; };
struct tls_inflight_val {
    __u64 ssl_ctx;
    __u64 buf_ptr;
    __u64 entry_ts_ns;     /* serves as call_id; also for stale-detection */
    __u64 entry_cgroup_id; /* emit on return so cgroup migration during
                              long blocking reads doesn't confuse output */
    __u64 readbytes_ptr;   /* SSL_read_ex out-param; 0 for non-_ex reads */
    __u32 num;             /* requested byte count */
    __u8  is_ex;           /* 1 if SSL_read_ex (return value semantics differ) */
    __u8  _pad[3];
};
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct tls_inflight_key);
    __type(value, struct tls_inflight_val);
} tls_inflight SEC(".maps");

/* 4 MiB ringbuf — sized so several max-bytes (64 KiB) calls can land
 * before backpressure. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} events_tls SEC(".maps");

/* Per-CPU counter bumped when bpf_ringbuf_reserve fails. Userspace
 * pumps this into Counters.tls_reserve_failures. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} tls_reserve_fail SEC(".maps");

/* Per-CPU counter bumped when an inflight insert overwrites an existing
 * pid_tgid slot (BPF_ANY semantics — we accept overwrites and count
 * them). Should be ~0 on a sane libssl flow. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} tls_inflight_collision SEC(".maps");

static __always_inline bool cgroup_tracked(__u64 cgid) {
    struct cgroup_filter_key k = { .cgroup_id = cgid };
    return bpf_map_lookup_elem(&cgroup_filter, &k) != NULL;
}

/* The full per-chunk record. Sized so the verifier sees a constant
 * allocation per loop iteration. Total: 56 (hdr) + 40 (payload) + 4096. */
struct tls_record {
    struct ts_event_hdr hdr;
    struct ts_tls_plaintext_payload pl;
    __u8 plaintext[CHUNK_BYTES];
};

/* Chunk a single SSL_* call's plaintext into up to MAX_CHUNKS records.
 * Each record reserves a constant-size slot in the ringbuf and writes
 * directly into the ringbuf-resident plaintext buffer (no BPF stack
 * pressure). Returns 0 on success, -1 on the first reserve failure. */
static __always_inline int emit_plaintext_chunks(
    __u64 ssl_ctx, __u64 call_id, __u64 entry_cgid,
    const void *src, __u32 total_bytes,
    __u8 direction, __u8 ex_variant)
{
    if (total_bytes == 0) return 0;
    __u32 n_chunks = total_bytes / CHUNK_BYTES + (total_bytes % CHUNK_BYTES ? 1 : 0);
    __u8 truncated = 0;
    if (n_chunks > MAX_CHUNKS) {
        n_chunks = MAX_CHUNKS;
        truncated = 1;
    }

    #pragma clang loop unroll(full)
    for (__u32 i = 0; i < MAX_CHUNKS; i++) {
        if (i >= n_chunks) break;

        __u32 off = i * CHUNK_BYTES;
        __u32 chunk_bytes = CHUNK_BYTES;
        if (i + 1 == n_chunks) {
            __u32 rem = total_bytes - off;
            chunk_bytes = (rem > CHUNK_BYTES) ? CHUNK_BYTES : rem;
        }
        if (chunk_bytes > CHUNK_BYTES) chunk_bytes = CHUNK_BYTES; /* verifier */

        struct tls_record *r = bpf_ringbuf_reserve(&events_tls, sizeof(*r), 0);
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
        r->hdr.cgroup_id = entry_cgid;
        r->hdr.type      = TS_TLS_PLAINTEXT;
        r->hdr.len       = sizeof(struct ts_tls_plaintext_payload) + chunk_bytes;
        bpf_get_current_comm(&r->hdr.comm, sizeof(r->hdr.comm));

        r->pl.ssl_ctx         = ssl_ctx;
        r->pl.call_id         = call_id;
        r->pl.entry_cgroup_id = entry_cgid;
        r->pl.total_bytes     = total_bytes;
        r->pl.chunk_index     = (__u16)i;
        r->pl.chunk_total     = (__u16)n_chunks;
        r->pl.chunk_bytes     = (__u16)chunk_bytes;
        r->pl.direction       = direction;
        r->pl.flags           = (truncated && i + 1 == n_chunks ? TLS_FLAG_TRUNCATED : 0)
                              | (ex_variant ? TLS_FLAG_EX_VARIANT : 0);
        __builtin_memset(r->pl._pad, 0, sizeof(r->pl._pad));

        /* chunk_bytes is spilled across the helper calls above, and older
         * verifiers (Ubuntu 22.04's kernel) lose its bounds on the reload.
         * Clamp a 64-bit copy, so the checked register is the one passed
         * to the helper; barrier_var keeps clang from dropping the check. */
        __u64 read_len = chunk_bytes;
        barrier_var(read_len);
        if (read_len > CHUNK_BYTES) read_len = CHUNK_BYTES;
        long pr = bpf_probe_read_user(r->plaintext, read_len,
                                      (const __u8 *)src + off);
        if (pr) {
            /* Read failed: don't bother zeroing the (4 KiB, ringbuf-
             * resident) buffer — verifier rejects __builtin_memset on
             * a buffer this large, and chunk_bytes=0 tells userspace
             * not to read past the empty plaintext slice. */
            r->pl.flags |= TLS_FLAG_READ_FAILED;
            r->pl.chunk_bytes = 0;
        }

        bpf_ringbuf_submit(r, 0);
    }
    return 0;
}

SEC("uprobe/SSL_write")
int BPF_UPROBE(ssl_write_entry, void *ssl, const void *buf, int num)
{
    if (num <= 0) return 0;
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!cgroup_tracked(cgid)) return 0;
    __u64 call_id = bpf_ktime_get_ns();
    return emit_plaintext_chunks((__u64)ssl, call_id, cgid, buf,
                                  (__u32)num, 0 /* write */, 0 /* not _ex */);
}

SEC("uprobe/SSL_write_ex")
int BPF_UPROBE(ssl_write_ex_entry, void *ssl, const void *buf, size_t num,
               size_t *written)
{
    (void)written;
    if (num == 0) return 0;
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!cgroup_tracked(cgid)) return 0;
    __u64 call_id = bpf_ktime_get_ns();
    /* num is size_t; cap to UINT_MAX for our wire format. */
    __u32 total = (num > 0xFFFFFFFFu) ? 0xFFFFFFFFu : (__u32)num;
    return emit_plaintext_chunks((__u64)ssl, call_id, cgid, buf,
                                  total, 0 /* write */, 1 /* ex_variant */);
}

SEC("uprobe/SSL_read")
int BPF_UPROBE(ssl_read_entry, void *ssl, void *buf, int num)
{
    if (num <= 0) return 0;
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!cgroup_tracked(cgid)) return 0;

    struct tls_inflight_key k = { .pid_tgid = bpf_get_current_pid_tgid() };
    struct tls_inflight_val v = {
        .ssl_ctx         = (__u64)ssl,
        .buf_ptr         = (__u64)buf,
        .entry_ts_ns     = bpf_ktime_get_ns(),
        .entry_cgroup_id = cgid,
        .readbytes_ptr   = 0,
        .num             = (__u32)num,
        .is_ex           = 0,
    };
    long ret = bpf_map_update_elem(&tls_inflight, &k, &v, BPF_ANY);
    if (ret) {
        __u32 zero = 0;
        __u64 *c = bpf_map_lookup_elem(&tls_inflight_collision, &zero);
        if (c) __sync_fetch_and_add(c, 1);
    }
    return 0;
}

SEC("uretprobe/SSL_read")
int BPF_URETPROBE(ssl_read_exit, int ret)
{
    if (ret <= 0) return 0;
    struct tls_inflight_key k = { .pid_tgid = bpf_get_current_pid_tgid() };
    struct tls_inflight_val *v = bpf_map_lookup_elem(&tls_inflight, &k);
    if (!v || v->is_ex) return 0;

    __u32 nbytes = ((__u32)ret < v->num) ? (__u32)ret : v->num;
    __u64 call_id = v->entry_ts_ns;
    __u64 ssl_ctx = v->ssl_ctx;
    __u64 entry_cgid = v->entry_cgroup_id;
    void *src = (void *)v->buf_ptr;
    bpf_map_delete_elem(&tls_inflight, &k);
    return emit_plaintext_chunks(ssl_ctx, call_id, entry_cgid, src, nbytes,
                                  1 /* read */, 0 /* not _ex */);
}

SEC("uprobe/SSL_read_ex")
int BPF_UPROBE(ssl_read_ex_entry, void *ssl, void *buf, size_t num,
               size_t *readbytes)
{
    if (num == 0) return 0;
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!cgroup_tracked(cgid)) return 0;

    struct tls_inflight_key k = { .pid_tgid = bpf_get_current_pid_tgid() };
    struct tls_inflight_val v = {
        .ssl_ctx         = (__u64)ssl,
        .buf_ptr         = (__u64)buf,
        .entry_ts_ns     = bpf_ktime_get_ns(),
        .entry_cgroup_id = cgid,
        .readbytes_ptr   = (__u64)readbytes,
        .num             = (num > 0xFFFFFFFFu) ? 0xFFFFFFFFu : (__u32)num,
        .is_ex           = 1,
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
int BPF_URETPROBE(ssl_read_ex_exit, int ret)
{
    if (ret != 1) return 0;  /* SSL_read_ex returns 1 on success */
    struct tls_inflight_key k = { .pid_tgid = bpf_get_current_pid_tgid() };
    struct tls_inflight_val *v = bpf_map_lookup_elem(&tls_inflight, &k);
    if (!v || !v->is_ex) return 0;

    size_t readbytes = 0;
    long pr = bpf_probe_read_user(&readbytes, sizeof(readbytes),
                                   (void *)v->readbytes_ptr);
    if (pr) { bpf_map_delete_elem(&tls_inflight, &k); return 0; }
    __u32 nbytes;
    if (readbytes > v->num) nbytes = v->num;
    else if (readbytes > 0xFFFFFFFFu) nbytes = 0xFFFFFFFFu;
    else nbytes = (__u32)readbytes;

    __u64 call_id = v->entry_ts_ns;
    __u64 ssl_ctx = v->ssl_ctx;
    __u64 entry_cgid = v->entry_cgroup_id;
    void *src = (void *)v->buf_ptr;
    bpf_map_delete_elem(&tls_inflight, &k);
    return emit_plaintext_chunks(ssl_ctx, call_id, entry_cgid, src, nbytes,
                                  1 /* read */, 1 /* ex_variant */);
}
