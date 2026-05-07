//! TokenScope daemon (Phase 1.E).
//!
//! Loads BPF skeletons, drains ringbufs, periodically flushes the
//! per-socket byte counter map. Two sinks now: stdout (live human
//! view, suppressible with --no-stdout) and a DuckDB file (queryable
//! system of record, default ~/.local/share/tokenscope/events.duckdb).
//! SIGINT/SIGTERM flip an atomic flag so the main loop exits cleanly
//! and DuckDB closes its file consistently.

mod cgroup;
mod net_bytes;
mod proc_cache;
mod skeletons;
mod store;

use std::cell::RefCell;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use ts_bpf_sys::libbpf_rs::RingBufferBuilder;
use ts_core::{decode_header, decode_net_connect, TsEventType};

use crate::proc_cache::ProcessCache;
use crate::skeletons::{load_all, SkelStorage};
use crate::store::Store;

#[derive(Parser, Debug)]
#[command(name = "tsd", version, about = "TokenScope daemon")]
struct Args {
    /// RUST_LOG-style filter for tracing.
    #[arg(long, default_value = "info")]
    log_filter: String,

    /// How often to scan + persist the per-socket byte counter map (ms).
    #[arg(long, default_value_t = 5000)]
    flush_interval_ms: u64,

    /// Path to the DuckDB file. Parent dir is created if missing.
    #[arg(long, default_value_os_t = default_db_path())]
    db_path: PathBuf,

    /// Suppress live stdout printing. The DuckDB sink still receives all events.
    #[arg(long)]
    no_stdout: bool,
}

fn default_db_path() -> PathBuf {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local").join("share")))
        .unwrap_or_else(|| PathBuf::from("/var/lib"));
    base.join("tokenscope").join("events.duckdb")
}

fn main() -> Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_new(&args.log_filter).unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    info!("tsd starting (Phase 1.E — sched_exec + cgroup/connect + tcp bytes + DuckDB sink)");
    info!(db_path = %args.db_path.display(), "opening store");

    let cgroup_root = cgroup::open_unified_root().context("open cgroup root")?;
    let mut storage = SkelStorage::new();
    let skels = load_all(&mut storage, cgroup_root).context("load skeletons")?;
    info!(flush_ms = args.flush_interval_ms, "BPF programs attached");

    let cache = RefCell::new(ProcessCache::new());
    let store = RefCell::new(Store::open(&args.db_path).context("open DuckDB store")?);
    let stdout_enabled = !args.no_stdout;

    // Shutdown flag — flipped by SIGINT/SIGTERM via the ctrlc handler.
    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let s = shutdown.clone();
        ctrlc::set_handler(move || s.store(true, Ordering::SeqCst))
            .context("install signal handler")?;
    }

    let mut builder = RingBufferBuilder::new();
    builder
        .add(&skels.sched.maps.events, |data| {
            handle_event(data, &cache, &store, stdout_enabled)
        })
        .map_err(|e| anyhow!("add sched ringbuf: {e}"))?;
    builder
        .add(&skels.net.maps.events, |data| {
            handle_event(data, &cache, &store, stdout_enabled)
        })
        .map_err(|e| anyhow!("add net ringbuf: {e}"))?;
    let ringbuf = builder.build().map_err(|e| anyhow!("build ringbuf: {e}"))?;

    let flush_interval = Duration::from_millis(args.flush_interval_ms);
    let mut last_flush = Instant::now();

    while !shutdown.load(Ordering::Relaxed) {
        if let Err(e) = ringbuf.poll(Duration::from_millis(200)) {
            error!(?e, "ringbuf poll error");
        }
        if last_flush.elapsed() >= flush_interval {
            net_bytes::flush(&skels.net.maps.net_bytes, &cache, &store, stdout_enabled);
            last_flush = Instant::now();
        }
    }

    info!("shutting down — flushing one last time and closing store");
    net_bytes::flush(&skels.net.maps.net_bytes, &cache, &store, stdout_enabled);
    // Natural drop order: ringbuf releases its closure-borrows first,
    // then `store` (and its DuckDB Connection) is dropped on scope exit.
    Ok(())
}

fn handle_event(
    data: &[u8],
    cache: &RefCell<ProcessCache>,
    store: &RefCell<Store>,
    stdout: bool,
) -> i32 {
    let hdr = match decode_header(data) {
        Ok(h) => h,
        Err(e) => {
            error!(?e, len = data.len(), "decode header failed");
            return 0;
        }
    };

    let kind = TsEventType::from_u16(hdr.ty);
    let payload = &data[std::mem::size_of::<ts_core::TsEventHdr>()..];

    let comm = hdr.comm_str();
    let cmdline = {
        let mut cache_mut = cache.borrow_mut();
        cache_mut.get_or_load(hdr.tgid).display_cmdline()
    };

    match kind {
        Some(TsEventType::ProcExec) => {
            if stdout {
                println!(
                    "TsEventHdr {{ kind: ProcExec, pid: {pid}, tgid: {tgid}, comm: {comm:?}, cmdline: {cmdline:?}, cpu: {cpu}, cgroup_id: {cgid:#x}, ts_ns: {ts} }}",
                    pid = hdr.pid,
                    tgid = hdr.tgid,
                    cpu = hdr.cpu,
                    cgid = hdr.cgroup_id,
                    ts = hdr.ts_ns,
                );
            }
            if let Err(e) = store.borrow().insert_proc_exec(
                hdr.ts_ns,
                hdr.pid,
                hdr.tgid,
                hdr.cgroup_id,
                &comm,
                &cmdline,
            ) {
                warn!(?e, "store proc_exec");
            }
        }
        Some(TsEventType::NetConnect) => match decode_net_connect(payload) {
            Ok(pl) => {
                if stdout {
                    println!(
                        "TsEventHdr {{ kind: NetConnect, pid: {pid}, tgid: {tgid}, comm: {comm:?}, cmdline: {cmdline:?}, dst: {dst}, proto: {proto}, cgroup_id: {cgid:#x} }}",
                        pid = hdr.pid,
                        tgid = hdr.tgid,
                        dst = pl.dst_string(),
                        proto = pl.protocol,
                        cgid = hdr.cgroup_id,
                    );
                }
                if let Err(e) = store.borrow().insert_net_connect(
                    hdr.ts_ns,
                    hdr.pid,
                    hdr.tgid,
                    hdr.cgroup_id,
                    &comm,
                    &cmdline,
                    &pl.dst_addr,
                    pl.dst_port,
                    pl.family,
                    pl.protocol,
                ) {
                    warn!(?e, "store net_connect");
                }
            }
            Err(e) => error!(?e, "decode net_connect failed"),
        },
        Some(other) => {
            if stdout {
                println!(
                    "TsEventHdr {{ kind: {other:?}, pid: {pid}, comm: {comm:?}, len: {len} }}",
                    pid = hdr.pid,
                    len = hdr.len,
                );
            }
        }
        None => {
            if stdout {
                println!(
                    "TsEventHdr {{ kind: Unknown({ty}), pid: {pid}, comm: {comm:?}, len: {len} }}",
                    ty = hdr.ty,
                    pid = hdr.pid,
                    len = hdr.len,
                );
            }
        }
    }
    0
}

/// Wall-clock nanoseconds since UNIX epoch. Used as the snapshot timestamp
/// in `events_net_bytes` so queries can correlate with absolute time.
pub fn wall_clock_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}
