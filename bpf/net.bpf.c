/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Phase 1.A. cgroup/connect{4,6} hooks — fire on every connect() syscall
 * for an inet socket inside the attached cgroup hierarchy. Emit one
 * TS_NET_CONNECT ringbuf record per call.
 *
 * The cgroup attach point is /sys/fs/cgroup (v2 unified root) by default,
 * giving system-wide coverage. Per-cgroup scoping is a Phase 6+ extension.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "ts_event.h"

char LICENSE[] SEC("license") = "GPL";

#define AF_INET   2
#define AF_INET6  10

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/*
 * Per-socket TX/RX accumulator. Keyed by socket cookie (stable across
 * PID reuse). Cleared via LRU eviction at 65k entries — sufficient for
 * any realistic single-host workload. Userspace iterates this map on a
 * timer to surface counts.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct ts_net_bytes_key);
    __type(value, struct ts_net_bytes_value);
} net_bytes SEC(".maps");

/*
 * Combined header + payload reserved as one record for atomic delivery.
 */
struct net_connect_record {
    struct ts_event_hdr hdr;
    struct ts_net_connect_payload pl;
};

static __always_inline int emit_connect(struct bpf_sock_addr *ctx, __u16 family)
{
    struct net_connect_record *r;

    r = bpf_ringbuf_reserve(&events, sizeof(*r), 0);
    if (!r)
        return 1; /* must return 1 from cgroup/connect on success */

    __u64 pid_tgid = bpf_get_current_pid_tgid();

    r->hdr.ts_ns     = bpf_ktime_get_ns();
    r->hdr.cpu       = bpf_get_smp_processor_id();
    r->hdr.pid       = (__u32)(pid_tgid & 0xFFFFFFFFu);
    r->hdr.tgid      = (__u32)(pid_tgid >> 32);
    r->hdr.cgroup_id = bpf_get_current_cgroup_id();
    r->hdr.type      = TS_NET_CONNECT;
    r->hdr.len       = sizeof(struct ts_net_connect_payload);
    bpf_get_current_comm(&r->hdr.comm, sizeof(r->hdr.comm));

    /* user_port is __be16 in network byte order; convert. */
    r->pl.dst_port = bpf_ntohs(ctx->user_port);
    r->pl.family   = family;
    r->pl.protocol = ctx->protocol;
    __builtin_memset(r->pl._pad, 0, sizeof(r->pl._pad));

    if (family == AF_INET) {
        /* user_ip4 is __be32; copy into the last 4 bytes (v4-mapped layout). */
        __builtin_memset(r->pl.dst_addr, 0, 12);
        __u32 ip4 = ctx->user_ip4;
        __builtin_memcpy(&r->pl.dst_addr[12], &ip4, 4);
    } else {
        /* user_ip6 is __be32[4]. The BPF verifier disallows memcpy via a
         * modified ctx pointer, so we must read each field individually.
         * Each load is a u32 read from a named ctx field, which the
         * verifier permits.
         */
        __u32 ip6_0 = ctx->user_ip6[0];
        __u32 ip6_1 = ctx->user_ip6[1];
        __u32 ip6_2 = ctx->user_ip6[2];
        __u32 ip6_3 = ctx->user_ip6[3];
        __builtin_memcpy(&r->pl.dst_addr[0], &ip6_0, 4);
        __builtin_memcpy(&r->pl.dst_addr[4], &ip6_1, 4);
        __builtin_memcpy(&r->pl.dst_addr[8], &ip6_2, 4);
        __builtin_memcpy(&r->pl.dst_addr[12], &ip6_3, 4);
    }

    bpf_ringbuf_submit(r, 0);
    return 1; /* ALLOW the connect; cgroup/connect can also block (return 0) */
}

SEC("cgroup/connect4")
int handle_connect4(struct bpf_sock_addr *ctx)
{
    return emit_connect(ctx, AF_INET);
}

SEC("cgroup/connect6")
int handle_connect6(struct bpf_sock_addr *ctx)
{
    return emit_connect(ctx, AF_INET6);
}

/*
 * Atomically bump tx_bytes (rx==0) or rx_bytes (rx==1) for the given
 * socket cookie. Inserts a new entry on first observation; updates
 * last_ns and (only on insert) pid.
 */
static __always_inline void bump_bytes(__u64 cookie, __s32 bytes, int rx)
{
    if (bytes <= 0)
        return;

    struct ts_net_bytes_key k = { .sock_cookie = cookie };
    struct ts_net_bytes_value *v = bpf_map_lookup_elem(&net_bytes, &k);

    __u64 now_ns = bpf_ktime_get_ns();

    if (v) {
        if (rx)
            __sync_fetch_and_add(&v->rx_bytes, (__u64)bytes);
        else
            __sync_fetch_and_add(&v->tx_bytes, (__u64)bytes);
        v->last_ns = now_ns;
    } else {
        struct ts_net_bytes_value nv = {
            .tx_bytes = rx ? 0 : (__u64)bytes,
            .rx_bytes = rx ? (__u64)bytes : 0,
            .last_ns  = now_ns,
            .pid      = (__u32)(bpf_get_current_pid_tgid() >> 32),
            ._pad     = 0,
        };
        bpf_get_current_comm(&nv.comm, sizeof(nv.comm));
        bpf_map_update_elem(&net_bytes, &k, &nv, BPF_NOEXIST);
    }
}

/*
 * fexit/tcp_sendmsg: fires on tcp_sendmsg return.
 * Kernel signature: int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
 */
SEC("fexit/tcp_sendmsg")
int BPF_PROG(handle_sendmsg, struct sock *sk, struct msghdr *msg, size_t size, int ret)
{
    if (ret <= 0)
        return 0;
    __u64 cookie = bpf_get_socket_cookie(sk);
    bump_bytes(cookie, ret, 0 /* tx */);
    return 0;
}

/*
 * fexit/tcp_recvmsg.
 * Kernel signature (5.19+):
 *   int tcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
 *                   int flags, int *addr_len)
 */
SEC("fexit/tcp_recvmsg")
int BPF_PROG(handle_recvmsg, struct sock *sk, struct msghdr *msg, size_t len,
             int flags, int *addr_len, int ret)
{
    if (ret <= 0)
        return 0;
    __u64 cookie = bpf_get_socket_cookie(sk);
    bump_bytes(cookie, ret, 1 /* rx */);
    return 0;
}
