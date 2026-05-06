//! Periodic flush of the BPF `net_bytes` LRU map.
//!
//! Iterates every entry, decodes key+value, looks up comm+cmdline via
//! the proc_cache, and prints a single `NetBytes { ... }` line per
//! non-zero socket. Entries are NOT cleared — they're cumulative until
//! kernel LRU eviction. Phase 1.D will replace this with DuckDB writes.

use std::cell::RefCell;

use ts_bpf_sys::libbpf_rs::{MapCore, MapFlags, MapMut};
use ts_core::{decode_net_bytes_key, decode_net_bytes_value};

use crate::proc_cache::ProcessCache;

pub fn flush(map: &MapMut<'_>, cache: &RefCell<ProcessCache>) {
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
        let info = cache_mut.get_or_load(value.pid);
        println!(
            "NetBytes {{ sock_cookie: {cookie:#018x}, pid: {pid}, comm: {comm:?}, cmdline: {cmdline:?}, tx: {tx}, rx: {rx}, last_ns: {ns} }}",
            cookie = key.sock_cookie,
            pid = value.pid,
            comm = info.comm,
            cmdline = info.display_cmdline(),
            tx = value.tx_bytes,
            rx = value.rx_bytes,
            ns = value.last_ns,
        );
    }
}
