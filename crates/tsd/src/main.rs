//! TokenScope daemon (Phase 1.C).
//!
//! Adds a `proc_cache` that resolves pid → (comm, cmdline) lazily from
//! /proc. Both the ringbuf event handler and the periodic net_bytes
//! flush borrow the cache via closures. Single-threaded throughout —
//! `RefCell` is correct because the main loop polls and flushes
//! serially.

mod cgroup;
mod net_bytes;
mod proc_cache;
mod skeletons;
mod store;

use std::cell::RefCell;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use ts_bpf_sys::libbpf_rs::RingBufferBuilder;
use ts_core::{decode_header, decode_net_connect, TsEventType};

use crate::proc_cache::ProcessCache;
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

    info!("tsd starting (Phase 1.C — sched_exec + cgroup/connect + tcp bytes + /proc enrichment)");

    let cgroup_root = cgroup::open_unified_root().context("open cgroup root")?;
    let mut storage = SkelStorage::new();
    let skels = load_all(&mut storage, cgroup_root).context("load skeletons")?;

    info!(flush_ms = args.flush_interval_ms, "BPF programs attached");

    let cache = RefCell::new(ProcessCache::new());

    let mut builder = RingBufferBuilder::new();
    builder
        .add(&skels.sched.maps.events, |data| handle_event(data, &cache))
        .map_err(|e| anyhow!("add sched ringbuf: {e}"))?;
    builder
        .add(&skels.net.maps.events, |data| handle_event(data, &cache))
        .map_err(|e| anyhow!("add net ringbuf: {e}"))?;
    let ringbuf = builder.build().map_err(|e| anyhow!("build ringbuf: {e}"))?;

    let flush_interval = Duration::from_millis(args.flush_interval_ms);
    let mut last_flush = Instant::now();

    loop {
        if let Err(e) = ringbuf.poll(Duration::from_millis(200)) {
            error!(?e, "ringbuf poll error");
        }
        if last_flush.elapsed() >= flush_interval {
            net_bytes::flush(&skels.net.maps.net_bytes, &cache);
            last_flush = Instant::now();
        }
    }
}

fn handle_event(data: &[u8], cache: &RefCell<ProcessCache>) -> i32 {
    let hdr = match decode_header(data) {
        Ok(h) => h,
        Err(e) => {
            error!(?e, len = data.len(), "decode header failed");
            return 0;
        }
    };

    let kind = TsEventType::from_u16(hdr.ty);
    let payload = &data[std::mem::size_of::<ts_core::TsEventHdr>()..];

    // Comm comes from the event payload (BPF captured it at event time)
    // — no /proc race. Cache is consulted only for cmdline (best-effort,
    // may show "[<gone>]" for short-lived processes).
    let comm = hdr.comm_str();
    let cmdline = {
        let mut cache_mut = cache.borrow_mut();
        cache_mut.get_or_load(hdr.tgid).display_cmdline()
    };

    match kind {
        Some(TsEventType::ProcExec) => {
            println!(
                "TsEventHdr {{ kind: ProcExec, pid: {pid}, tgid: {tgid}, comm: {comm:?}, cmdline: {cmdline:?}, cpu: {cpu}, cgroup_id: {cgid:#x}, ts_ns: {ts} }}",
                pid = hdr.pid,
                tgid = hdr.tgid,
                cpu = hdr.cpu,
                cgid = hdr.cgroup_id,
                ts = hdr.ts_ns,
            );
        }
        Some(TsEventType::NetConnect) => match decode_net_connect(payload) {
            Ok(pl) => {
                println!(
                    "TsEventHdr {{ kind: NetConnect, pid: {pid}, tgid: {tgid}, comm: {comm:?}, cmdline: {cmdline:?}, dst: {dst}, proto: {proto}, cgroup_id: {cgid:#x} }}",
                    pid = hdr.pid,
                    tgid = hdr.tgid,
                    dst = pl.dst_string(),
                    proto = pl.protocol,
                    cgid = hdr.cgroup_id,
                );
            }
            Err(e) => error!(?e, "decode net_connect failed"),
        },
        Some(other) => {
            println!(
                "TsEventHdr {{ kind: {other:?}, pid: {pid}, comm: {comm:?}, len: {len} }}",
                pid = hdr.pid,
                len = hdr.len,
            );
        }
        None => {
            println!(
                "TsEventHdr {{ kind: Unknown({ty}), pid: {pid}, comm: {comm:?}, len: {len} }}",
                ty = hdr.ty,
                pid = hdr.pid,
                len = hdr.len,
            );
        }
    }
    0
}
