//! Periodic flush of the BPF `net_bytes` LRU map.
//!
//! For each non-zero entry: optionally print a `NetBytes` line on
//! stdout, insert a row into `events_net_bytes`, broadcast a JSON
//! `NetBytes` event to tail subscribers, and bump the events_total
//! counter. Map entries are NOT cleared — cumulative until kernel LRU
//! eviction.

use std::cell::RefCell;
use std::sync::atomic::Ordering;

use tracing::warn;
use ts_bpf_sys::libbpf_rs::{MapCore, MapFlags, MapMut};
use ts_core::control::TailEvent;
use ts_core::{decode_net_bytes_key, decode_net_bytes_value};

use crate::control::{Counters, Subscribers};
use crate::proc_cache::ProcessCache;
use crate::store::Store;
use crate::wall_clock_ns;

#[allow(clippy::too_many_arguments)]
pub fn flush(
    map: &MapMut<'_>,
    cache: &RefCell<ProcessCache>,
    store: &RefCell<Store>,
    subscribers: &Subscribers,
    counters: &Counters,
    stdout: bool,
) {
    let snapshot = wall_clock_ns();
    let mut cache_mut = cache.borrow_mut();
    let store_ref = store.borrow();
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
        if let Err(e) = store_ref.insert_net_bytes(
            snapshot,
            key.sock_cookie,
            value.pid,
            &comm,
            &cmdline,
            value.tx_bytes,
            value.rx_bytes,
            value.last_ns,
        ) {
            warn!(?e, "store net_bytes");
        }
        let event = TailEvent::NetBytes {
            snapshot_ts_ns: snapshot,
            sock_cookie: format!("{:#018x}", key.sock_cookie),
            pid: value.pid,
            comm: comm.clone(),
            cmdline: cmdline.clone(),
            tx: value.tx_bytes,
            rx: value.rx_bytes,
            last_event_ns: value.last_ns,
        };
        if let Ok(line) = serde_json::to_string(&event) {
            subscribers.broadcast(&line);
        }
        counters.events_total.fetch_add(1, Ordering::Relaxed);
    }
}
