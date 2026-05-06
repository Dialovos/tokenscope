/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Wire-format event types shared between BPF programs and userspace.
 * Layout MUST match `crates/ts-core/src/event.rs::TsEventHdr`.
 *
 * Naming: kernel-style `ts_*`. Userspace mirrors as `Ts*` in CamelCase.
 */
#ifndef TS_EVENT_H
#define TS_EVENT_H

enum ts_event_type {
    TS_NET_CONNECT    = 1,
    TS_NET_BYTES      = 2,
    TS_TLS_PLAINTEXT  = 3,
    TS_LLM_REQ_START  = 4,
    TS_LLM_REQ_END    = 5,
    TS_LLM_TOKEN      = 6,
    TS_PROC_EXEC      = 7,
    TS_PROC_EXIT      = 8,
    TS_CGROUP_NEW     = 9,
    TS_CGROUP_GONE    = 10,
    TS_ANOMALY        = 11,
    TS_GPU_SAMPLE     = 12,
};

/*
 * Header for every ringbuf record.
 *
 * Natural alignment (NOT __attribute__((packed)) — packed forces
 * unaligned access in BPF which the verifier dislikes for some helpers).
 * The 4-byte hole at offset 20 and the 4-byte tail padding to 40 are
 * intentional. The Rust mirror has identical size/alignment asserted at
 * compile time.
 */
struct ts_event_hdr {
    __u64 ts_ns;       /* CLOCK_MONOTONIC, kernel time */
    __u32 cpu;
    __u32 pid;         /* userspace PID == kernel TGID */
    __u32 tgid;        /* kernel TGID == thread group leader */
    /* 4-byte implicit padding for 8-byte align of cgroup_id */
    __u64 cgroup_id;
    __u16 type;        /* enum ts_event_type */
    __u16 len;         /* payload bytes following the header */
    /* 4-byte implicit tail padding to align struct size to 8 */
};

/*
 * Payload for TS_NET_CONNECT. Follows ts_event_hdr immediately;
 * hdr.len = sizeof(struct ts_net_connect_payload).
 *
 * Layout:
 *   0..16  dst_addr  (16 bytes; IPv4 in last 4 for AF_INET, full IPv6 for AF_INET6)
 *   16..18 dst_port  (u16, host byte order — converted in BPF)
 *   18..20 family    (u16: AF_INET=2, AF_INET6=10)
 *   20..21 protocol  (u8: IPPROTO_TCP=6, IPPROTO_UDP=17)
 *   21..24 _pad      (3 bytes reserved)
 *
 * Total: 24 bytes. Alignment: 2.
 */
struct ts_net_connect_payload {
    __u8  dst_addr[16];
    __u16 dst_port;
    __u16 family;
    __u8  protocol;
    __u8  _pad[3];
};

#endif /* TS_EVENT_H */
