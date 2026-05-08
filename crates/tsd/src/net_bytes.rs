//! Periodic flush of the BPF `net_bytes` LRU map.
//!
//! For each non-zero entry: optionally print a `NetBytes` line on
//! stdout, and push a `NetBytesSnapshot` envelope onto the single
//! writer sink. The sink owns the DuckDB connection and per-subscriber
//! tail rendering. Map entries are NOT cleared — cumulative until
//! kernel LRU eviction.

use std::cell::RefCell;
use std::sync::atomic::Ordering;
use std::sync::mpsc::SyncSender;

use ts_bpf_sys::libbpf_rs::{MapCore, MapFlags, MapMut};
use ts_core::{decode_net_bytes_key, decode_net_bytes_value};

use crate::control::Counters;
use crate::proc_cache::ProcessCache;
use crate::sink::{EventEnvelope, NetBytesSnapshot};
use crate::wall_clock_ns;

pub fn flush(
    map: &MapMut<'_>,
    cache: &RefCell<ProcessCache>,
    events_tx: &SyncSender<EventEnvelope>,
    counters: &Counters,
    stdout: bool,
) {
    let snapshot = wall_clock_ns();
    let mut cache_mut = cache.borrow_mut();
    for raw_key in map.keys() {
        let key = match decode_net_bytes_key(&raw_key) {
            Ok(k) => k,
            Err(_) => continue,
        };
        let raw_value = match map.lookup(&raw_key, MapFlags::ANY) {
            Ok(Some(v)) => v,
            _ => continue,
        };
        let value = match decode_net_bytes_value(&raw_value) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if value.tx_bytes == 0 && value.rx_bytes == 0 {
            continue;
        }
        let cmdline = cache_mut.get_or_load(value.pid).display_cmdline();
        let comm = value.comm_str();
        if stdout {
            println!(
                "NetBytes {{ sock_cookie: {cookie:#018x}, pid: {pid}, comm: {comm:?}, cmdline: {cmdline:?}, tx: {tx}, rx: {rx}, last_ns: {ns} }}",
                cookie = key.sock_cookie,
                pid = value.pid,
                tx = value.tx_bytes,
                rx = value.rx_bytes,
                ns = value.last_ns,
            );
        }
        // Drop on full sink — Counters tracks tail-side losses; this
        // path's losses are budgeted into the same producer-side
        // backpressure semantics as the ringbuf consumer.
        let _ = events_tx.try_send(EventEnvelope::NetBytesSnapshot(NetBytesSnapshot {
            snapshot_ts_ns: snapshot,
            sock_cookie: key.sock_cookie,
            pid: value.pid,
            comm,
            cmdline,
            tx_bytes: value.tx_bytes,
            rx_bytes: value.rx_bytes,
            last_event_ns: value.last_ns,
        }));
        counters.events_total.fetch_add(1, Ordering::Relaxed);
    }
}
