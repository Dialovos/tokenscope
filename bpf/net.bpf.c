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
