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

/* ------------------------------------------------------------------ */
/* Stub probes — Tasks 5-8 fill the bodies. These exist now so the     */
/* skeleton loads cleanly and the verifier accepts the program shape.  */
/* ------------------------------------------------------------------ */

SEC("uprobe/SSL_write")
int BPF_UPROBE(ssl_write_entry, void *ssl, const void *buf, int num)
{
    (void)ssl; (void)buf; (void)num;
    return 0;
}

SEC("uprobe/SSL_write_ex")
int BPF_UPROBE(ssl_write_ex_entry, void *ssl, const void *buf, size_t num,
               size_t *written)
{
    (void)ssl; (void)buf; (void)num; (void)written;
    return 0;
}

SEC("uprobe/SSL_read")
int BPF_UPROBE(ssl_read_entry, void *ssl, void *buf, int num)
{
    (void)ssl; (void)buf; (void)num;
    return 0;
}

SEC("uretprobe/SSL_read")
int BPF_URETPROBE(ssl_read_exit, int ret)
{
    (void)ret;
    return 0;
}

SEC("uprobe/SSL_read_ex")
int BPF_UPROBE(ssl_read_ex_entry, void *ssl, void *buf, size_t num,
               size_t *readbytes)
{
    (void)ssl; (void)buf; (void)num; (void)readbytes;
    return 0;
}

SEC("uretprobe/SSL_read_ex")
int BPF_URETPROBE(ssl_read_ex_exit, int ret)
{
    (void)ret;
    return 0;
}
