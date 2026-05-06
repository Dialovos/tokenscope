//! TokenScope daemon (Phase 1.B).
//!
//! Loads two BPF skeletons (sched_exec + net), drains both ringbufs,
//! and on a configurable cadence prints accumulated TCP byte counts
//! from the `net_bytes` LRU map. Phase 1.D replaces stdout with the
//! DuckDB sink.

mod cgroup;
mod net_bytes;
mod skeletons;

use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use ts_bpf_sys::libbpf_rs::RingBufferBuilder;
use ts_core::{decode_header, decode_net_connect, TsEventType};

use crate::skeletons::{load_all, SkelStorage};

#[derive(Parser, Debug)]
#[command(name = "tsd", version, about = "TokenScope daemon")]
struct Args {
    /// RUST_LOG-style filter for tracing.
    #[arg(long, default_value = "info")]
    log_filter: String,

    /// How often to scan + print the per-socket byte counter map (milliseconds).
    #[arg(long, default_value_t = 5000)]
    flush_interval_ms: u64,
}

fn main() -> Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_new(&args.log_filter).unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    info!("tsd starting (Phase 1.B — sched_exec + cgroup/connect + tcp byte counting)");

    let cgroup_root = cgroup::open_unified_root().context("open cgroup root")?;
    let mut storage = SkelStorage::new();
    let skels = load_all(&mut storage, cgroup_root).context("load skeletons")?;

    info!(flush_ms = args.flush_interval_ms, "BPF programs attached");

    let mut builder = RingBufferBuilder::new();
    builder
        .add(&skels.sched.maps.events, handle_event)
        .map_err(|e| anyhow!("add sched ringbuf: {e}"))?;
    builder
        .add(&skels.net.maps.events, handle_event)
        .map_err(|e| anyhow!("add net ringbuf: {e}"))?;
    let ringbuf = builder.build().map_err(|e| anyhow!("build ringbuf: {e}"))?;

    let flush_interval = Duration::from_millis(args.flush_interval_ms);
    let mut last_flush = Instant::now();

    loop {
        if let Err(e) = ringbuf.poll(Duration::from_millis(200)) {
            error!(?e, "ringbuf poll error");
        }
        if last_flush.elapsed() >= flush_interval {
            net_bytes::flush(&skels.net.maps.net_bytes);
            last_flush = Instant::now();
        }
    }
}

fn handle_event(data: &[u8]) -> i32 {
    let hdr = match decode_header(data) {
        Ok(h) => h,
        Err(e) => {
            error!(?e, len = data.len(), "decode header failed");
            return 0;
        }
    };

    let kind = TsEventType::from_u16(hdr.ty);
    let payload = &data[std::mem::size_of::<ts_core::TsEventHdr>()..];

    match kind {
        Some(TsEventType::ProcExec) => {
            println!(
                "TsEventHdr {{ kind: ProcExec, pid: {pid}, tgid: {tgid}, cpu: {cpu}, cgroup_id: {cgid:#x}, ts_ns: {ts}, len: {len} }}",
                pid = hdr.pid,
                tgid = hdr.tgid,
                cpu = hdr.cpu,
                cgid = hdr.cgroup_id,
                ts = hdr.ts_ns,
                len = hdr.len,
            );
        }
        Some(TsEventType::NetConnect) => match decode_net_connect(payload) {
            Ok(pl) => {
                println!(
                    "TsEventHdr {{ kind: NetConnect, pid: {pid}, tgid: {tgid}, cpu: {cpu}, cgroup_id: {cgid:#x}, dst: {dst}, proto: {proto} }}",
                    pid = hdr.pid,
                    tgid = hdr.tgid,
                    cpu = hdr.cpu,
                    cgid = hdr.cgroup_id,
                    dst = pl.dst_string(),
                    proto = pl.protocol,
                );
            }
            Err(e) => error!(?e, "decode net_connect failed"),
        },
        Some(other) => {
            println!(
                "TsEventHdr {{ kind: {other:?}, pid: {pid}, len: {len} }}",
                pid = hdr.pid,
                len = hdr.len,
            );
        }
        None => {
            println!(
                "TsEventHdr {{ kind: Unknown({ty}), pid: {pid}, len: {len} }}",
                ty = hdr.ty,
                pid = hdr.pid,
                len = hdr.len,
            );
        }
    }
    0
}
