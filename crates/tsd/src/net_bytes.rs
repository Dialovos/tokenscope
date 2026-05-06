//! Periodic flush of the BPF `net_bytes` LRU map.
//!
//! Iterates every entry, decodes key+value, and prints a single
//! `NetBytes { ... }` line per non-zero socket. Entries are NOT
//! cleared — they're cumulative until the kernel evicts via LRU.
//! Phase 1.D will replace this with a DuckDB write.

use ts_bpf_sys::libbpf_rs::{MapCore, MapFlags, MapMut};
use ts_core::{decode_net_bytes_key, decode_net_bytes_value};

pub fn flush(map: &MapMut<'_>) {
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
        println!(
            "NetBytes {{ sock_cookie: {cookie:#018x}, pid: {pid}, tx: {tx}, rx: {rx}, last_ns: {ns} }}",
            cookie = key.sock_cookie,
            pid = value.pid,
            tx = value.tx_bytes,
            rx = value.rx_bytes,
            ns = value.last_ns,
        );
    }
}
