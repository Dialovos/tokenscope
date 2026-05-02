//! TokenScope daemon (Phase 0).
//!
//! Loads the `sched_exec` BPF program, attaches its tracepoint, drains
//! the ringbuf, and prints each event as a debug line on stdout. Phase 1
//! replaces stdout with the in-process pipeline.

use std::mem::MaybeUninit;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use ts_bpf_sys::libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use ts_bpf_sys::libbpf_rs::{OpenObject, RingBufferBuilder};
use ts_bpf_sys::sched_exec::SchedExecSkelBuilder;
use ts_core::{decode_header, TsEventType};

#[derive(Parser, Debug)]
#[command(name = "tsd", version, about = "TokenScope daemon")]
struct Args {
    /// RUST_LOG-style filter for tracing.
    #[arg(long, default_value = "info")]
    log_filter: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_new(&args.log_filter).unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    info!("tsd starting (Phase 0 — sched_exec only)");

    let skel_builder = SchedExecSkelBuilder::default();
    let mut open_object: MaybeUninit<OpenObject> = MaybeUninit::uninit();
    let open_skel = skel_builder
        .open(&mut open_object)
        .context("open BPF skeleton")?;
    let mut skel = open_skel.load().context("load BPF skeleton (verifier)")?;
    skel.attach().context("attach BPF programs")?;

    info!("BPF program attached — listening for sched_process_exec");

    let mut builder = RingBufferBuilder::new();
    builder
        .add(&skel.maps.events, handle_event)
        .map_err(|e| anyhow!("add ringbuf consumer: {e}"))?;
    let ringbuf = builder.build().map_err(|e| anyhow!("build ringbuf: {e}"))?;

    loop {
        match ringbuf.poll(Duration::from_millis(200)) {
            Ok(_) => {}
            Err(e) => {
                error!(?e, "ringbuf poll error");
            }
        }
    }
}

/// Called by libbpf-rs for each ringbuf record. Returns 0 to keep
/// consuming; non-zero would stop the ringbuf entirely.
fn handle_event(data: &[u8]) -> i32 {
    match decode_header(data) {
        Ok(hdr) => {
            let kind = TsEventType::from_u16(hdr.ty)
                .map(|t| format!("{t:?}"))
                .unwrap_or_else(|| format!("Unknown({})", hdr.ty));
            println!(
                "TsEventHdr {{ kind: {kind}, pid: {pid}, tgid: {tgid}, cpu: {cpu}, cgroup_id: {cgid:#x}, ts_ns: {ts}, len: {len} }}",
                kind = kind,
                pid = hdr.pid,
                tgid = hdr.tgid,
                cpu = hdr.cpu,
                cgid = hdr.cgroup_id,
                ts = hdr.ts_ns,
                len = hdr.len,
            );
            0
        }
        Err(e) => {
            error!(?e, len = data.len(), "failed to decode ringbuf event");
            0
        }
    }
}
