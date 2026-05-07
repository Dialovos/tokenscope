//! TokenScope daemon (Phase 1.F).
//!
//! Loads BPF skeletons, drains ringbufs, periodically flushes the
//! per-socket byte counter map. Three sinks: stdout (live human
//! view, suppressible), DuckDB (queryable system of record), and the
//! Unix-domain control plane (status responses + live tail
//! subscriptions). SIGINT/SIGTERM flip an atomic flag so the main
//! loop and the control listener exit cleanly.

mod cgroup;
mod control;
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
use ts_core::control::TailEvent;
use ts_core::{decode_header, decode_net_connect, TsEventType};

use crate::control::{Counters, Subscribers};
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

    /// Suppress live stdout printing. The DuckDB sink and control
    /// plane still receive all events.
    #[arg(long)]
    no_stdout: bool,

    /// Path to the Unix domain socket tsctl connects to. Default:
    /// $XDG_RUNTIME_DIR/tokenscope/tsd.sock (falls back to /run/tokenscope/tsd.sock).
    #[arg(long, default_value_os_t = control::default_uds_path())]
    uds_path: PathBuf,

    /// Skip starting the control-plane listener.
    #[arg(long)]
    no_control: bool,
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

    info!(
        "tsd starting (Phase 1.F — sched_exec + cgroup/connect + tcp bytes + DuckDB + UDS control)"
    );
    info!(db_path = %args.db_path.display(), "opening store");

    let cgroup_root = cgroup::open_unified_root().context("open cgroup root")?;
    let mut storage = SkelStorage::new();
    let skels = load_all(&mut storage, cgroup_root).context("load skeletons")?;
    info!(flush_ms = args.flush_interval_ms, "BPF programs attached");

    let cache = RefCell::new(ProcessCache::new());
    let store = RefCell::new(Store::open(&args.db_path).context("open DuckDB store")?);
    let stdout_enabled = !args.no_stdout;

    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let s = shutdown.clone();
        ctrlc::set_handler(move || s.store(true, Ordering::SeqCst))
            .context("install signal handler")?;
    }

    let counters = Arc::new(Counters::default());
    let subscribers = Subscribers::new(counters.clone());
    let started_at = Instant::now();

    let _control_server = if args.no_control {
        info!("control plane disabled (--no-control)");
        None
    } else {
        Some(
            control::ControlServer::start(
                args.uds_path.clone(),
                args.db_path.clone(),
                subscribers.clone(),
                counters.clone(),
                started_at,
                shutdown.clone(),
            )
            .context("start control plane")?,
        )
    };

    let mut builder = RingBufferBuilder::new();
    builder
        .add(&skels.sched.maps.events, |data| {
            handle_event(
                data,
                &cache,
                &store,
                &subscribers,
                &counters,
                stdout_enabled,
            )
        })
        .map_err(|e| anyhow!("add sched ringbuf: {e}"))?;
    builder
        .add(&skels.net.maps.events, |data| {
            handle_event(
                data,
                &cache,
                &store,
                &subscribers,
                &counters,
                stdout_enabled,
            )
        })
        .map_err(|e| anyhow!("add net ringbuf: {e}"))?;
    let ringbuf = builder.build().map_err(|e| anyhow!("build ringbuf: {e}"))?;

    let flush_interval = Duration::from_millis(args.flush_interval_ms);
    let mut last_flush = Instant::now();

    while !shutdown.load(Ordering::Relaxed) {
        if let Err(e) = ringbuf.poll(Duration::from_millis(200)) {
            error!(?e, "ringbuf poll error");
            counters.ringbuf_poll_errors.fetch_add(1, Ordering::Relaxed);
        }
        if last_flush.elapsed() >= flush_interval {
            net_bytes::flush(
                &skels.net.maps.net_bytes,
                &cache,
                &store,
                &subscribers,
                &counters,
                stdout_enabled,
            );
            last_flush = Instant::now();
        }
    }

    info!("shutting down — flushing once and closing");
    net_bytes::flush(
        &skels.net.maps.net_bytes,
        &cache,
        &store,
        &subscribers,
        &counters,
        stdout_enabled,
    );
    // Drop order on scope exit:
    //   ringbuf  -> releases closure borrows on &subscribers / &counters / &store
    //   _control_server -> Drop flips its own shutdown, joins listener, removes socket
    //   store    -> closes DuckDB
    //   subscribers / counters -> Arcs go to zero
    // No explicit drops needed; the natural reverse-declaration order
    // handles everything.
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_event(
    data: &[u8],
    cache: &RefCell<ProcessCache>,
    store: &RefCell<Store>,
    subscribers: &Subscribers,
    counters: &Counters,
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
            let event = TailEvent::ProcExec {
                ts_ns: hdr.ts_ns,
                pid: hdr.pid,
                tgid: hdr.tgid,
                comm: comm.clone(),
                cmdline: cmdline.clone(),
                cgroup_id: format!("{:#x}", hdr.cgroup_id),
            };
            if let Ok(line) = serde_json::to_string(&event) {
                subscribers.broadcast(&line);
            }
            counters.events_total.fetch_add(1, Ordering::Relaxed);
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
                let event = TailEvent::NetConnect {
                    ts_ns: hdr.ts_ns,
                    pid: hdr.pid,
                    tgid: hdr.tgid,
                    comm: comm.clone(),
                    cmdline: cmdline.clone(),
                    cgroup_id: format!("{:#x}", hdr.cgroup_id),
                    dst: pl.dst_string(),
                    family: pl.family,
                    protocol: pl.protocol,
                };
                if let Ok(line) = serde_json::to_string(&event) {
                    subscribers.broadcast(&line);
                }
                counters.events_total.fetch_add(1, Ordering::Relaxed);
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

/// Wall-clock nanoseconds since UNIX epoch.
pub fn wall_clock_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}
