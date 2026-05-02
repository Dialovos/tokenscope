/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Phase 0 probe. Fires on every successful exec() and emits a TsEventHdr
 * with type=TS_PROC_EXEC. No payload yet (Phase 1 adds cmdline).
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "ts_event.h"

/* Required by the BPF verifier — without "GPL" some helpers refuse to load. */
char LICENSE[] SEC("license") = "GPL";

/*
 * 256 KiB ringbuf. Tunable via [daemon].ringbuf_size_kb in later phases.
 * Must be a power of two.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/*
 * Tracepoint format for sched_process_exec:
 *   field:__data_loc char[] filename
 *   field:pid_t pid
 *   field:pid_t old_pid
 *
 * We don't use the filename in Phase 0 (verifier-friendly to keep this
 * program tiny). Phase 1 will use bpf_probe_read_kernel_str against the
 * tracepoint's __data_loc.
 */
SEC("tracepoint/sched/sched_process_exec")
int handle_exec(void *ctx)
{
    struct ts_event_hdr *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        /* Ringbuf full — userspace fell behind. Drop and move on. */
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();

    e->ts_ns     = bpf_ktime_get_ns();
    e->cpu       = bpf_get_smp_processor_id();
    e->pid       = (__u32)(pid_tgid & 0xFFFFFFFFu);
    e->tgid      = (__u32)(pid_tgid >> 32);
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->type      = TS_PROC_EXEC;
    e->len       = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
