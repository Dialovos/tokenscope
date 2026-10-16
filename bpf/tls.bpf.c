/* SPDX-License-Identifier: Apache-2.0 */
/* OpenSSL accepted-byte capture. Missing lifecycle/state is explicitly untrusted.
 * Lost records are sized by per-direction call sequences and byte offsets; the
 * loss epoch marks only activity whose size is unknown (nested, out-of-scope,
 * stateless or failed-outparam calls). */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "ts_event.h"
char LICENSE[] SEC("license") = "GPL";
#define MAX_CHUNKS 16
#define CHUNK_BYTES 4096
#define TLS_FLAG_TRUNCATED 1
#define TLS_FLAG_READ_FAILED 2
#define TLS_FLAG_EX_VARIANT 4
#define TLS_FLAG_LIFETIME_UNKNOWN 8
#define TLS_FLAG_END 16

/* Older libbpf headers (Ubuntu 22.04) lack barrier_var. */
#ifndef barrier_var
#define barrier_var(var) asm volatile("" : "+r"(var))
#endif

struct cgroup_filter_key { __u64 cgroup_id; };
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, struct cgroup_filter_key); __type(value, __u8);
} cgroup_filter SEC(".maps");

/* A library's probes stay inert until userspace attaches every required API. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096);
    __type(key, __u64); __type(value, __u8);
} tls_enabled_libraries SEC(".maps");
static __always_inline bool library_enabled(void *ctx) {
    __u64 cookie = bpf_get_attach_cookie(ctx);
    return bpf_map_lookup_elem(&tls_enabled_libraries, &cookie) != NULL;
}

/* No silent LRU eviction: capacity failure is counted and invalidates trust. */
struct tls_connection_key { __u64 tgid; __u64 process_start; __u64 exec_generation; __u64 ssl_ctx; };
struct tls_connection_val {
    __u64 generation; __u64 sequence[2]; __u64 loss_epoch[2];
    __u64 accepted_bytes[2];
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 8192);
    __type(key, struct tls_connection_key); __type(value, struct tls_connection_val);
} tls_connections SEC(".maps");

struct tls_inflight_key { __u64 pid_tgid; __u64 direction; };
struct tls_inflight_val {
    __u64 ssl_ctx; __u64 buf_ptr; __u64 entry_ts_ns; __u64 entry_cgroup_id;
    __u64 count_ptr; __u64 process_start; __u64 exec_generation; __u32 num; __u32 depth; __u8 is_ex;
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 8192);
    __type(key, struct tls_inflight_key); __type(value, struct tls_inflight_val);
} tls_inflight SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 4 * 1024 * 1024); }
    events_tls SEC(".maps");
#define COUNTER(name) struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); \
    __uint(max_entries, 1); __type(key, __u32); __type(value, __u64); } name SEC(".maps")
COUNTER(tls_reserve_fail);
COUNTER(tls_inflight_collision); /* nested entry, suppressed rather than overwritten */
COUNTER(tls_map_fail);
COUNTER(tls_missing_state);
COUNTER(tls_outparam_fail);
/* Lifetime evidence destroyed before userspace could read it (unattributable). */
COUNTER(tls_close_lost);
#define BUMP(name) do { __u32 z = 0; __u64 *c = bpf_map_lookup_elem(&name, &z); \
    if (c) __sync_fetch_and_add(c, 1); } while (0)

static __always_inline bool tracked(__u64 cgid) {
    struct cgroup_filter_key k = { cgid };
    return bpf_map_lookup_elem(&cgroup_filter, &k) != NULL;
}
static __always_inline __u64 process_start(void) {
    struct task_struct *t = (struct task_struct *)bpf_get_current_task_btf();
    return BPF_CORE_READ(t, group_leader, start_boottime);
}
static __always_inline __u64 exec_generation(void) {
    struct task_struct *t = (struct task_struct *)bpf_get_current_task_btf();
    return BPF_CORE_READ(t, group_leader, self_exec_id);
}
static __always_inline struct tls_connection_key connection_key(__u64 ssl, __u64 start) {
    struct tls_connection_key k = { bpf_get_current_pid_tgid() >> 32, start, exec_generation(), ssl };
    return k;
}
struct tls_record {
    struct ts_event_hdr hdr; struct ts_tls_plaintext_payload pl; __u8 plaintext[CHUNK_BYTES];
};
static __always_inline int emit(__u64 ssl, __u64 call, __u64 cgid, __u64 start,
    const void *src, __u32 total, __u8 dir, __u8 flags, struct tls_connection_val *life)
{
    __u64 generation = life ? life->generation : 0;
    __u64 seq = 0, loss = 0, offset = 0;
    if (dir > 1) return 0;
    if (life) {
        /* The byte offset sizes any later gap exactly, so ring and copy
         * failures need no loss epoch. END carries the final offset. */
        if (!(flags & TLS_FLAG_END)) {
            seq = __sync_add_and_fetch(&life->sequence[dir], 1);
            offset = __sync_fetch_and_add(&life->accepted_bytes[dir], total);
        } else {
            seq = life->sequence[dir];
            offset = life->accepted_bytes[dir];
        }
        loss = life->loss_epoch[dir];
    } else flags |= TLS_FLAG_LIFETIME_UNKNOWN;
    __u32 chunks = total / CHUNK_BYTES + (total % CHUNK_BYTES ? 1 : 0);
    if (chunks > MAX_CHUNKS) { chunks = MAX_CHUNKS; flags |= TLS_FLAG_TRUNCATED; }
    if (flags & TLS_FLAG_END) chunks = 1;
    if (chunks == 0) return 0;
    #pragma clang loop unroll(disable)
    for (__u32 i = 0; i < MAX_CHUNKS; i++) {
        if (i >= chunks) break;
        __u32 off = i * CHUNK_BYTES;
        __u32 bytes = total > off ? total - off : 0;
        if (bytes > CHUNK_BYTES) bytes = CHUNK_BYTES;
        struct tls_record *r = bpf_ringbuf_reserve(&events_tls, sizeof(*r), 0);
        if (!r) {
            BUMP(tls_reserve_fail);
            return -1;
        }
        __u64 pt = bpf_get_current_pid_tgid();
        r->hdr.ts_ns = bpf_ktime_get_ns(); r->hdr.cpu = bpf_get_smp_processor_id();
        r->hdr.pid = (__u32)pt; r->hdr.tgid = (__u32)(pt >> 32);
        r->hdr.cgroup_id = cgid; r->hdr.type = TS_TLS_PLAINTEXT;
        r->hdr.len = sizeof(r->pl) + bytes;
        bpf_get_current_comm(r->hdr.comm, sizeof(r->hdr.comm));
        r->pl.ssl_ctx = ssl; r->pl.call_id = call; r->pl.entry_cgroup_id = cgid;
        r->pl.total_bytes = total; r->pl.chunk_index = i; r->pl.chunk_total = chunks;
        r->pl.chunk_bytes = bytes; r->pl.direction = dir; r->pl.flags = flags;
        __builtin_memset(r->pl._pad, 0, sizeof(r->pl._pad));
        r->pl.process_start = start; r->pl.connection_generation = generation;
        r->pl.call_sequence = seq; r->pl.loss_epoch = loss; r->pl.exec_generation = exec_generation();
        r->pl.stream_offset = offset;
        /* bytes is spilled across the helper calls above, and older verifiers
         * (Ubuntu 22.04's kernel) lose its bounds on the reload. Clamp a 64-bit
         * copy so the checked register is the one passed to the helper. */
        __u64 read_len = bytes;
        barrier_var(read_len);
        if (read_len > CHUNK_BYTES) read_len = CHUNK_BYTES;
        if (read_len && bpf_probe_read_user(r->plaintext, read_len, (const __u8 *)src + off)) {
            r->pl.flags |= TLS_FLAG_READ_FAILED; r->pl.chunk_bytes = 0;
        }
        bpf_ringbuf_submit(r, 0);
    }
    return 0;
}

static __always_inline int enter(void *ssl, const void *buf, size_t num,
    size_t *count, __u8 dir, __u8 ex)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    struct tls_inflight_key k = { bpf_get_current_pid_tgid(), dir };
    struct tls_inflight_val *old = bpf_map_lookup_elem(&tls_inflight, &k);
    if (old && (old->process_start != process_start()
        || old->exec_generation != exec_generation())) {
        /* An entry surviving thread/PID reuse or exec is not a nested call. */
        struct tls_connection_key stale = { k.pid_tgid >> 32, old->process_start,
            old->exec_generation, old->ssl_ctx };
        struct tls_connection_val *life = bpf_map_lookup_elem(&tls_connections, &stale);
        if (life) __sync_fetch_and_add(&life->loss_epoch[dir], 1);
        BUMP(tls_missing_state);
        bpf_map_delete_elem(&tls_inflight, &k);
        old = NULL;
    }
    if (old) {
        old->depth++; BUMP(tls_inflight_collision);
        /* Equal buffers/lengths do not prove wrapper equivalence. Until a
         * runtime-specific rule is qualified, every nested call loses trust. */
        BUMP(tls_missing_state);
        struct tls_connection_key ck = connection_key((__u64)ssl, process_start());
        struct tls_connection_val *life = bpf_map_lookup_elem(&tls_connections,&ck);
        if (life) __sync_fetch_and_add(&life->loss_epoch[dir],1);
        ck = connection_key(old->ssl_ctx,old->process_start);
        life = bpf_map_lookup_elem(&tls_connections,&ck);
        if (life) __sync_fetch_and_add(&life->loss_epoch[dir],1);
        return 0;
    }
    if (!tracked(cgid)) {
        /* Leaving the capture scope must not hide a request on a known stream.
         * Retain no payload or inflight buffer; poison trust before returning. */
        struct tls_connection_key ck = connection_key((__u64)ssl, process_start());
        struct tls_connection_val *life = bpf_map_lookup_elem(&tls_connections, &ck);
        if (life) __sync_fetch_and_add(&life->loss_epoch[dir], 1);
        return 0;
    }
    struct tls_inflight_val v = {};
    v.ssl_ctx = (__u64)ssl; v.buf_ptr = (__u64)buf; v.entry_ts_ns = bpf_ktime_get_ns();
    v.entry_cgroup_id = cgid; v.process_start = process_start(); v.exec_generation = exec_generation();
    v.count_ptr = (__u64)count; v.num = num > 0xFFFFFFFFu ? 0xFFFFFFFFu : num;
    v.is_ex = ex; v.depth = 1;
    if (bpf_map_update_elem(&tls_inflight, &k, &v, BPF_NOEXIST)) {
        /* The return will find no state; the stream loses this call. */
        BUMP(tls_map_fail);
        struct tls_connection_key ck = connection_key((__u64)ssl, v.process_start);
        struct tls_connection_val *life = bpf_map_lookup_elem(&tls_connections, &ck);
        if (life) __sync_fetch_and_add(&life->loss_epoch[dir], 1);
    }
    return 0;
}
static __always_inline int leave(int ret, __u8 dir, __u8 ex) {
    struct tls_inflight_key k = { bpf_get_current_pid_tgid(), dir };
    struct tls_inflight_val *slot = bpf_map_lookup_elem(&tls_inflight, &k);
    if (!slot) {
        if (tracked(bpf_get_current_cgroup_id())) BUMP(tls_missing_state);
        return 0;
    }
    if (slot->depth > 1) { slot->depth--; return 0; }
    struct tls_inflight_val v = *slot;
    bpf_map_delete_elem(&tls_inflight, &k); /* every outer return, including WANT/error */
    struct tls_connection_key ck = connection_key(v.ssl_ctx,v.process_start);
    struct tls_connection_val *life = bpf_map_lookup_elem(&tls_connections,&ck);
    if (v.is_ex != ex || v.process_start != process_start()
        || v.exec_generation != exec_generation()) {
        if (life) __sync_fetch_and_add(&life->loss_epoch[dir],1);
        BUMP(tls_missing_state); return 0;
    }
    if (ex ? ret != 1 : ret <= 0) return 0;
    size_t count = ret;
    if (ex && bpf_probe_read_user(&count, sizeof(count), (void *)v.count_ptr)) {
        if (life) __sync_fetch_and_add(&life->loss_epoch[dir],1);
        BUMP(tls_outparam_fail); return 0;
    }
    if (count > v.num) { if (life) __sync_fetch_and_add(&life->loss_epoch[dir],1);
        BUMP(tls_outparam_fail); return 0; }
    if (!count) return 0;
    return emit(v.ssl_ctx, v.entry_ts_ns, v.entry_cgroup_id, v.process_start,
        (void *)v.buf_ptr, count, dir, ex ? TLS_FLAG_EX_VARIANT : 0, life);
}
SEC("uprobe/SSL_write")
int BPF_UPROBE(ssl_write_entry, void *ssl, const void *buf, int num) {
    if (!library_enabled(ctx)) return 0;
    return enter(ssl, buf, num > 0 ? num : 0, 0, 0, 0);
}
SEC("uretprobe/SSL_write")
int BPF_URETPROBE(ssl_write_exit, int ret) {
    if (!library_enabled(ctx)) return 0;
    return leave(ret, 0, 0);
}
SEC("uprobe/SSL_write_ex")
int BPF_UPROBE(ssl_write_ex_entry, void *ssl, const void *buf, size_t num, size_t *n) {
    if (!library_enabled(ctx)) return 0;
    return enter(ssl, buf, num, n, 0, 1);
}
SEC("uretprobe/SSL_write_ex")
int BPF_URETPROBE(ssl_write_ex_exit, int ret) {
    if (!library_enabled(ctx)) return 0;
    return leave(ret, 0, 1);
}
SEC("uprobe/SSL_read")
int BPF_UPROBE(ssl_read_entry, void *ssl, void *buf, int num) {
    if (!library_enabled(ctx)) return 0;
    return enter(ssl, buf, num > 0 ? num : 0, 0, 1, 0);
}
SEC("uretprobe/SSL_read")
int BPF_URETPROBE(ssl_read_exit, int ret) {
    if (!library_enabled(ctx)) return 0;
    return leave(ret, 1, 0);
}
SEC("uprobe/SSL_read_ex")
int BPF_UPROBE(ssl_read_ex_entry, void *ssl, void *buf, size_t num, size_t *n) {
    if (!library_enabled(ctx)) return 0;
    return enter(ssl, buf, num, n, 1, 1);
}
SEC("uretprobe/SSL_read_ex")
int BPF_URETPROBE(ssl_read_ex_exit, int ret) {
    if (!library_enabled(ctx)) return 0;
    return leave(ret, 1, 1);
}
SEC("uretprobe/SSL_new")
int BPF_URETPROBE(ssl_new_exit, void *ssl) {
    if (!library_enabled(ctx)) return 0;
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!ssl || !tracked(cgid)) return 0;
    struct tls_connection_key k = connection_key((__u64)ssl, process_start());
    /* A surviving entry means its closure was never observed; replacing it
     * destroys that lifetime's inventory. */
    if (bpf_map_lookup_elem(&tls_connections, &k)) BUMP(tls_close_lost);
    struct tls_connection_val v = {}; v.generation = bpf_ktime_get_ns();
    if (bpf_map_update_elem(&tls_connections, &k, &v, BPF_ANY)) BUMP(tls_map_fail);
    return 0;
}
static __always_inline int close_lifetime(void *ssl, bool reopen) {
    struct tls_connection_key k = connection_key((__u64)ssl, process_start());
    struct tls_connection_val *v = bpf_map_lookup_elem(&tls_connections, &k);
    if (!v) return 0;
    __u64 cgid = bpf_get_current_cgroup_id();
    int lost = emit((__u64)ssl, bpf_ktime_get_ns(), cgid, k.process_start, 0, 0, 0, TLS_FLAG_END, v);
    lost |= emit((__u64)ssl, bpf_ktime_get_ns(), cgid, k.process_start, 0, 0, 1, TLS_FLAG_END, v);
    /* Replacing or deleting the entry removes the only other copy of the
     * final inventory. */
    if (lost) BUMP(tls_close_lost);
    if (reopen) {
        struct tls_connection_val fresh = {};
        fresh.generation = bpf_ktime_get_ns();
        if (!bpf_map_update_elem(&tls_connections, &k, &fresh, BPF_EXIST)) return 0;
        BUMP(tls_map_fail);
    }
    bpf_map_delete_elem(&tls_connections, &k);
    return 0;
}
SEC("uprobe/SSL_free")
int BPF_UPROBE(ssl_free_entry, void *ssl) {
    if (!library_enabled(ctx)) return 0;
    return close_lifetime(ssl, false);
}
/* OpenSSL's handshake state machine calls SSL_clear before every first
 * handshake, and applications may call it to reuse an object for a new
 * connection. Either way the old stream ends here: close its lifetime and start
 * a new generation, so nothing before the clear joins what follows. */
SEC("uprobe/SSL_clear")
int BPF_UPROBE(ssl_clear_entry, void *ssl) {
    if (!library_enabled(ctx)) return 0;
    return close_lifetime(ssl, true);
}

static __always_inline void abandon_inflight(__u8 dir) {
    struct tls_inflight_key k = { bpf_get_current_pid_tgid(), dir };
    struct tls_inflight_val *entry = bpf_map_lookup_elem(&tls_inflight, &k);
    if (!entry) return;
    struct tls_connection_key ck = { k.pid_tgid >> 32, entry->process_start,
        entry->exec_generation, entry->ssl_ctx };
    struct tls_connection_val *life = bpf_map_lookup_elem(&tls_connections, &ck);
    if (life) __sync_fetch_and_add(&life->loss_epoch[dir], 1);
    BUMP(tls_missing_state);
    bpf_map_delete_elem(&tls_inflight, &k);
}
SEC("tracepoint/sched/sched_process_exit")
int tls_thread_exit(void *ctx) {
    abandon_inflight(0);
    abandon_inflight(1);
    return 0;
}
