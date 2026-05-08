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
    __u32 pid;         /* kernel PID (TID in userspace) */
    __u32 tgid;        /* kernel TGID (== userspace PID) */
    /* 4-byte implicit padding for 8-byte align of cgroup_id */
    __u64 cgroup_id;
    __u16 type;        /* enum ts_event_type */
    __u16 len;         /* payload bytes following the header */
    char  comm[16];    /* bpf_get_current_comm() at event emit time, NUL-padded */
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

/*
 * Key for the net_bytes LRU hash map. One entry per TCP socket.
 * sock_cookie is from bpf_get_socket_cookie() — a stable per-socket id
 * that survives PID reuse and connection migration within the kernel.
 *
 * Layout: 0..8 sock_cookie (u64). Total: 8 bytes.
 */
struct ts_net_bytes_key {
    __u64 sock_cookie;
};

/*
 * Value for the net_bytes LRU hash map.
 *
 * Layout (natural alignment):
 *   0..8   tx_bytes  (u64)
 *   8..16  rx_bytes  (u64)
 *   16..24 last_ns   (u64)
 *   24..28 pid       (u32) — first observed userspace PID (TGID)
 *   28..32 _pad      (u32)
 *   32..48 comm      (char[16]) — bpf_get_current_comm at first observation
 *
 * Total: 48 bytes. Alignment: 8.
 */
struct ts_net_bytes_value {
    __u64 tx_bytes;
    __u64 rx_bytes;
    __u64 last_ns;
    __u32 pid;
    __u32 _pad;
    char  comm[16];
};

/*
 * Payload for TS_TLS_PLAINTEXT (one record per chunk; up to 16 chunks per
 * SSL_* call). Total fixed payload: 40 bytes. Trailing plaintext slice of
 * exactly chunk_bytes follows; max 4096 bytes.
 *
 * Stream-call key: (tgid, ssl_ctx, direction, call_id) where call_id =
 * entry ktime_ns. Within a call, chunk_index orders bytes.
 */
struct ts_tls_plaintext_payload {
    __u64 ssl_ctx;          /* userspace SSL* pointer; process-scoped */
    __u64 call_id;          /* entry ktime_ns; unique within (tgid,ssl,dir) */
    __u64 entry_cgroup_id;  /* cgroup at SSL_* entry; emit this, not return-time */
    __u32 total_bytes;      /* bytes in this SSL_* call (pre-chunking) */
    __u16 chunk_index;
    __u16 chunk_total;      /* 1..16 */
    __u16 chunk_bytes;      /* 0..4096 */
    __u8  direction;        /* 0 = write, 1 = read */
    __u8  flags;            /* bit 0=truncated, bit 1=read_failed, bit 2=ex_variant */
    __u8  _pad[4];
};

_Static_assert(sizeof(struct ts_tls_plaintext_payload) == 40,
               "tls payload must be exactly 40 bytes");

#endif /* TS_EVENT_H */
