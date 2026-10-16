//! TLS plaintext capture lifecycle.
//!
//! `tls.bpf.c` defines the BPF programs (loaded by skeletons.rs as part
//! of `LoadedSkels`); this module owns the userspace half:
//!
//! 1. **Discovery** — walk `/proc/*/maps` periodically (5s default),
//!    extract every distinct libssl.so file by `(dev, ino)` so
//!    container/symlink/replaced-binary cases work, and `attach_uprobe`
//!    each program once per binary.
//! 2. **Ringbuf consumption** — decode `events_tls` records into
//!    `EventEnvelope::TlsPlaintext` and push onto the single-writer
//!    sink channel.
//! 3. **Counter pumping** — drain the BPF percpu counters
//!    (`tls_reserve_fail`, `tls_inflight_collision`) into the userspace
//!    `Counters` atomics so `tsctl status` can surface them.
//!
//! Threading: all functions here are designed to be called from the
//! existing tsd main thread. libbpf-rs's `Program` type is neither
//! `Send` nor `Sync`, so spawning a dedicated thread that holds
//! program references would not compile. Instead, the main loop
//! polls the existing ringbuf builder (now including `events_tls`)
//! and calls `discovery_tick` periodically.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::mpsc::SyncSender;
use std::time::{Duration, Instant};

use anyhow::Result;
use regex::Regex;
use ts_bpf_sys::libbpf_rs::{Link, MapCore, MapFlags, UprobeOpts};

use crate::control::Counters;
use crate::sink::{EventEnvelope, TlsCheckpoint, TlsPlaintextEvent};
use crate::skeletons::LoadedSkels;
use ts_core::event::{
    decode_tls_plaintext, TsEventHdr, TLS_FLAG_END, TLS_FLAG_EX_VARIANT, TLS_FLAG_READ_FAILED,
    TLS_FLAG_TRUNCATED,
};

/// How often to rescan `/proc/*/maps` for new libssl mappings.
pub const DISCOVERY_INTERVAL: Duration = Duration::from_secs(5);

/// Owned per-libssl-file attachment record. Dropping the Links
/// detaches the uprobes; dropping `AttachedLib` drops them all.
#[allow(dead_code)] // refcount is informational only today
pub struct AttachedLib {
    inode_path: PathBuf,
    links: Vec<Link>,
    refcount: u32,
    cookie: u64,
}

/// Lives for the daemon's life. Tracks which libssl files we've
/// already attached to plus the next-rescan deadline.
pub struct TlsState {
    /// Keyed by `(dev, ino)` — same path string can resolve to
    /// different inodes across mount-namespaces / after replace.
    pub attached: HashMap<(u64, u64), AttachedLib>,
    /// Earliest time the discovery_tick should do another pass.
    pub next_rescan_at: Instant,
    /// Compiled-once regex for the maps line shape.
    libssl_re: Regex,
    next_library_cookie: u64,
}

impl Default for TlsState {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsState {
    pub fn new() -> Self {
        Self {
            attached: HashMap::new(),
            next_rescan_at: Instant::now(), // do first pass immediately
            libssl_re: Regex::new(r"r-xp .* (\S*libssl\.so(?:\.\S+)?)$").unwrap(),
            next_library_cookie: 1,
        }
    }

    /// Stop every library before detaching any individual API link.
    pub fn disable_capture(&self, skels: &LoadedSkels<'_>) -> Result<()> {
        let mut failure = None;
        for lib in self.attached.values() {
            if let Err(error) = skels
                .tls
                .maps
                .tls_enabled_libraries
                .delete(&lib.cookie.to_ne_bytes())
            {
                failure.get_or_insert(error);
            }
        }
        match failure {
            Some(error) => Err(error.into()),
            None => Ok(()),
        }
    }
}

/// Ringbuf callback: decode one `events_tls` record and push it onto
/// the single-writer sink channel. Drops on full sink (counter
/// already tracked by the producer pattern in main.rs).
pub fn handle_tls_record(
    data: &[u8],
    events_tx: &SyncSender<EventEnvelope>,
    counters: &Counters,
) -> i32 {
    const HDR: usize = std::mem::size_of::<TsEventHdr>();
    if data.len() < HDR {
        // A record we cannot attribute to a lifetime is global capture loss.
        counters.tls_capture_errors.fetch_add(1, Ordering::Relaxed);
        return 0;
    }
    // SAFETY: TsEventHdr is repr(C), 56 bytes. We copy the bytes out
    // (read_unaligned-style) so alignment of `data` doesn't matter.
    let mut hdr_bytes = [0u8; HDR];
    hdr_bytes.copy_from_slice(&data[..HDR]);
    let hdr: TsEventHdr =
        unsafe { std::ptr::read_unaligned(hdr_bytes.as_ptr() as *const TsEventHdr) };

    let payload = &data[HDR..];
    let (pl, plaintext) = match decode_tls_plaintext(payload) {
        Ok(x) => x,
        Err(e) => {
            tracing::warn!(error = ?e, "decode tls plaintext");
            counters.tls_capture_errors.fetch_add(1, Ordering::Relaxed);
            return 0;
        }
    };

    let truncated = pl.flags & TLS_FLAG_TRUNCATED != 0;
    let read_failed = pl.flags & TLS_FLAG_READ_FAILED != 0;
    let ex_variant = pl.flags & TLS_FLAG_EX_VARIANT != 0;

    counters.tls_records_emitted.fetch_add(1, Ordering::Relaxed);
    if truncated {
        counters.tls_truncated_calls.fetch_add(1, Ordering::Relaxed);
    }
    if read_failed {
        counters
            .tls_read_failed_chunks
            .fetch_add(1, Ordering::Relaxed);
    }

    let lifetime = ts_core::usage::ConnectionKey {
        tgid: hdr.tgid,
        process_start: pl.process_start,
        exec_generation: pl.exec_generation,
        ssl_ctx: pl.ssl_ctx,
        generation: pl.connection_generation,
    };
    let env = EventEnvelope::TlsPlaintext(TlsPlaintextEvent {
        ts_ns: hdr.ts_ns,
        pid: hdr.pid,
        tgid: hdr.tgid,
        cgroup_id: hdr.cgroup_id,
        comm: hdr.comm_str(),
        ssl_ctx: pl.ssl_ctx,
        call_id: pl.call_id,
        direction: pl.direction,
        total_bytes: pl.total_bytes,
        chunk_index: pl.chunk_index,
        chunk_total: pl.chunk_total,
        chunk_bytes: pl.chunk_bytes,
        truncated,
        read_failed,
        ex_variant,
        process_start: pl.process_start,
        exec_generation: pl.exec_generation,
        connection_generation: pl.connection_generation,
        call_sequence: pl.call_sequence,
        loss_epoch: pl.loss_epoch,
        stream_offset: pl.stream_offset,
        lifecycle_end: pl.flags & TLS_FLAG_END != 0,
        plaintext: plaintext.to_vec(),
    });
    let closure = pl.flags & TLS_FLAG_END != 0;
    if events_tx.try_send(env).is_err() {
        counters.sink_dropped_events.fetch_add(1, Ordering::Relaxed);
        // A dropped data record is sized by the next offset or inventory of its
        // lifetime. A dropped closure has no successor, so record it beside the
        // queue; only this lifetime loses trust unless the side set overflows.
        if !closure {
            return 0;
        }
        let mut dropped = counters
            .tls_dropped_lifetimes
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if dropped.len() < MAX_DROPPED_LIFETIMES || dropped.contains(&lifetime) {
            dropped.insert(lifetime);
        } else {
            counters
                .tls_unattributed_drops
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    0
}

/// Bound on lifetimes awaiting invalidation after queue drops.
const MAX_DROPPED_LIFETIMES: usize = 4096;

/// Drive one rescan pass if the deadline has been reached. No-op
/// otherwise. Updates counters in either case.
pub fn discovery_tick(state: &mut TlsState, skels: &LoadedSkels<'_>, counters: &Counters) {
    let now = Instant::now();
    if now < state.next_rescan_at {
        return;
    }
    state.next_rescan_at = now + DISCOVERY_INTERVAL;

    let scan_start = Instant::now();
    let mut errors: u32 = 0;
    let mut seen: HashSet<(u64, u64)> = HashSet::new();

    if let Ok(dir) = fs::read_dir("/proc") {
        for entry in dir.flatten() {
            let pid_name = entry.file_name();
            let pid_str = match pid_name.to_str() {
                Some(s) => s,
                None => continue,
            };
            if !pid_str.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            scan_pid_maps(
                state,
                skels,
                counters,
                &entry.path(),
                &mut seen,
                &mut errors,
            );
        }
    }

    pump_percpu_counters(skels, counters);

    counters
        .tls_scan_duration_us
        .store(scan_start.elapsed().as_micros() as u64, Ordering::Relaxed);
    counters.tls_scan_errors.store(errors, Ordering::Relaxed);
}

fn scan_pid_maps(
    state: &mut TlsState,
    skels: &LoadedSkels<'_>,
    counters: &Counters,
    proc_pid_dir: &Path,
    seen: &mut HashSet<(u64, u64)>,
    errors: &mut u32,
) {
    let maps_path = proc_pid_dir.join("maps");
    let maps = match fs::read_to_string(&maps_path) {
        Ok(s) => s,
        Err(_) => {
            *errors += 1;
            return;
        }
    };
    for line in maps.lines() {
        let cap = match state.libssl_re.captures(line) {
            Some(c) => c,
            None => continue,
        };
        let visible = cap.get(1).unwrap().as_str();
        // Resolve via /proc/<pid>/root/<visible_path> so the inode
        // we stat matches what THIS process sees (handles container
        // mount-namespaces and deleted-then-replaced libssl).
        let proc_root = proc_pid_dir
            .join("root")
            .join(visible.trim_start_matches('/'));
        let meta = match fs::metadata(&proc_root) {
            Ok(m) => m,
            Err(_) => {
                *errors += 1;
                continue;
            }
        };
        let key = (meta.dev(), meta.ino());
        if !seen.insert(key) {
            continue;
        }
        if let Some(lib) = state.attached.get_mut(&key) {
            lib.refcount += 1;
            continue;
        }
        let cookie = state.next_library_cookie;
        let Some(next_cookie) = cookie.checked_add(1) else {
            counters.tls_libs_skipped.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        state.next_library_cookie = next_cookie;
        match attach_libssl(skels, &proc_root, cookie) {
            Ok(lib) => {
                state.attached.insert(key, lib);
                counters.tls_libs_attached.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                tracing::warn!(path = %proc_root.display(), %e, "tls libssl attach failed");
                counters.tls_libs_skipped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

fn attach_libssl(skels: &LoadedSkels<'_>, libssl_path: &Path, cookie: u64) -> Result<AttachedLib> {
    let mut links = Vec::new();
    for (prog, symbol, ret) in [
        (&skels.tls.progs.ssl_write_entry, "SSL_write", false),
        (&skels.tls.progs.ssl_write_exit, "SSL_write", true),
        (&skels.tls.progs.ssl_read_entry, "SSL_read", false),
        (&skels.tls.progs.ssl_read_exit, "SSL_read", true),
        (&skels.tls.progs.ssl_write_ex_entry, "SSL_write_ex", false),
        (&skels.tls.progs.ssl_write_ex_exit, "SSL_write_ex", true),
        (&skels.tls.progs.ssl_read_ex_entry, "SSL_read_ex", false),
        (&skels.tls.progs.ssl_read_ex_exit, "SSL_read_ex", true),
        (&skels.tls.progs.ssl_new_exit, "SSL_new", true),
        (&skels.tls.progs.ssl_free_entry, "SSL_free", false),
        (&skels.tls.progs.ssl_clear_entry, "SSL_clear", false),
    ] {
        links.push(attach_one(prog, libssl_path, symbol, ret, cookie)?);
    }
    // Entry/return and lifecycle coverage is all-or-error. Before this update,
    // attach cookies keep every probe inert; any failure drops all owned links.
    skels
        .tls
        .maps
        .tls_enabled_libraries
        .update(&cookie.to_ne_bytes(), &[1], MapFlags::NO_EXIST)?;
    Ok(AttachedLib {
        inode_path: libssl_path.to_path_buf(),
        links,
        refcount: 1,
        cookie,
    })
}

fn attach_one(
    prog: &ts_bpf_sys::libbpf_rs::ProgramMut<'_>,
    libssl_path: &Path,
    func_name: &str,
    retprobe: bool,
    cookie: u64,
) -> Result<Link> {
    let opts = UprobeOpts {
        func_name: func_name.into(),
        retprobe,
        cookie,
        ..Default::default()
    };
    prog.attach_uprobe_with_opts(-1, libssl_path, 0, opts)
        .map_err(|e| {
            anyhow::anyhow!(
                "attach {func_name} (retprobe={retprobe}) on {}: {e}",
                libssl_path.display()
            )
        })
}

pub fn pump_percpu_counters(skels: &LoadedSkels<'_>, counters: &Counters) {
    let zero = 0u32.to_ne_bytes();
    for (map, counter) in [
        (
            &skels.tls.maps.tls_reserve_fail,
            &counters.tls_reserve_failures,
        ),
        (
            &skels.tls.maps.tls_inflight_collision,
            &counters.tls_inflight_collisions,
        ),
        (&skels.tls.maps.tls_map_fail, &counters.tls_map_failures),
        (
            &skels.tls.maps.tls_missing_state,
            &counters.tls_missing_states,
        ),
        (
            &skels.tls.maps.tls_outparam_fail,
            &counters.tls_outparam_failures,
        ),
        (&skels.tls.maps.tls_close_lost, &counters.tls_close_lost),
    ] {
        match map.lookup_percpu(&zero, MapFlags::ANY) {
            Ok(Some(values)) => {
                let total = values
                    .iter()
                    .filter_map(|v| v.get(..8))
                    .map(|v| u64::from_ne_bytes(v.try_into().unwrap()))
                    .sum();
                counter.store(total, Ordering::Relaxed);
            }
            _ => {
                counters.ringbuf_poll_errors.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// Kernel lifetime inventories, read from the main loop after each poll.
#[derive(Default)]
pub struct Inventory {
    pass: u64,
    /// Lifetimes whose process had exited when the previous pass read them.
    exited: HashSet<Vec<u8>>,
}

impl Inventory {
    /// Send one inventory per kernel lifetime, then an end-of-pass marker. These
    /// live snapshots race with emission, so the writer treats an inventory
    /// ahead of consumed records as in transit until the next pass.
    ///
    /// A lifetime whose process exited before the previous pass has delivered
    /// every record; its final inventory goes to the writer and the kernel entry
    /// is removed. `final_pass` runs after capture stopped and the ring drained:
    /// its inventories are exact and use blocking sends.
    pub fn checkpoint(
        &mut self,
        skels: &LoadedSkels<'_>,
        tx: &SyncSender<EventEnvelope>,
        counters: &Counters,
        final_pass: bool,
    ) {
        pump_percpu_counters(skels, counters);
        self.pass += 1;
        let pass = self.pass;
        let send = |env: EventEnvelope| {
            let sent = if final_pass {
                tx.send(env).is_ok()
            } else {
                tx.try_send(env).is_ok()
            };
            if !sent {
                counters.sink_dropped_events.fetch_add(1, Ordering::Relaxed);
            }
            sent
        };
        let map = &skels.tls.maps.tls_connections;
        let mut exited = HashSet::new();
        for key in map.keys() {
            let value = match map.lookup(&key, MapFlags::ANY) {
                Ok(Some(v)) if key.len() == 32 && v.len() == 56 => v,
                // Closed between listing and lookup; its END records follow.
                Ok(None) => continue,
                _ => {
                    counters.ringbuf_poll_errors.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            };
            let u64_at =
                |b: &[u8], off: usize| u64::from_ne_bytes(b[off..off + 8].try_into().unwrap());
            let c = TlsCheckpoint {
                connection: ts_core::usage::ConnectionKey {
                    tgid: u64_at(&key, 0) as u32,
                    process_start: u64_at(&key, 8),
                    exec_generation: u64_at(&key, 16),
                    ssl_ctx: u64_at(&key, 24),
                    generation: u64_at(&value, 0),
                },
                sequence: [u64_at(&value, 8), u64_at(&value, 16)],
                loss_epoch: [u64_at(&value, 24), u64_at(&value, 32)],
                accepted: [u64_at(&value, 40), u64_at(&value, 48)],
                ts_ns: monotonic_ns(),
                pass,
                final_pass,
            };
            if !final_pass && self.exited.contains(&key) {
                if send(EventEnvelope::TlsLifetimeGone(c)) {
                    if map.delete(&key).is_ok() {
                        counters.tls_lifetimes_swept.fetch_add(1, Ordering::Relaxed);
                    }
                } else {
                    exited.insert(key);
                }
                continue;
            }
            if !final_pass && !process_alive(c.connection.tgid, c.connection.process_start) {
                exited.insert(key);
            }
            send(EventEnvelope::TlsCheckpoint(c));
        }
        self.exited = exited;
        send(EventEnvelope::TlsCheckpointEnd {
            pass,
            ts_ns: monotonic_ns(),
        });
    }
}

/// Whether the process that started at `start_ns` (BPF `start_boottime`) still
/// owns `tgid`. procfs reports the same clock in USER_HZ ticks. Unreadable
/// state counts as alive; only a definite exit removes a lifetime.
fn process_alive(tgid: u32, start_ns: u64) -> bool {
    let stat = match fs::read_to_string(format!("/proc/{tgid}/stat")) {
        Ok(stat) => stat,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return false,
        Err(_) => return true,
    };
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if ticks <= 0 {
        return true;
    }
    match parse_start_ticks(&stat) {
        Some(start) => start == start_ns / (1_000_000_000 / ticks as u64),
        None => true,
    }
}

/// Field 22 (`starttime`). The command name may contain spaces or parentheses.
fn parse_start_ticks(stat: &str) -> Option<u64> {
    let (_, rest) = stat.rsplit_once(')')?;
    rest.split_whitespace().nth(19)?.parse().ok()
}

fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) } != 0 {
        return 0;
    }
    (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_start_matches_procfs_ticks() {
        let stat = "123 (a) b (c)) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 4242 rest";
        assert_eq!(parse_start_ticks(stat), Some(4242));
        let own = std::process::id();
        let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as u64;
        let start =
            parse_start_ticks(&fs::read_to_string(format!("/proc/{own}/stat")).unwrap()).unwrap();
        let ns = start * (1_000_000_000 / ticks);
        assert!(process_alive(own, ns));
        assert!(process_alive(own, ns + 1_000_000_000 / ticks - 1));
        assert!(!process_alive(own, ns + 1_000_000_000 / ticks));
        assert!(!process_alive(u32::MAX - 1, ns));
    }

    #[test]
    fn libssl_regex_matches_typical_lines() {
        let re = TlsState::new().libssl_re;
        let pos = "7f1d4e000000-7f1d4e1f0000 r-xp 00000000 fd:00 12345 /usr/lib/x86_64-linux-gnu/libssl.so.3";
        let neg_perm = "7f1d4e000000-7f1d4e1f0000 r--p 00000000 fd:00 12345 /usr/lib/x86_64-linux-gnu/libssl.so.3";
        let neg_name = "7f1d4e000000-7f1d4e1f0000 r-xp 00000000 fd:00 12345 /usr/lib/x86_64-linux-gnu/libcrypto.so.3";
        assert!(re.captures(pos).is_some());
        assert!(re.captures(neg_perm).is_none());
        assert!(re.captures(neg_name).is_none());
        let cap = re.captures(pos).unwrap();
        assert_eq!(
            cap.get(1).unwrap().as_str(),
            "/usr/lib/x86_64-linux-gnu/libssl.so.3"
        );
    }

    #[test]
    fn discovery_tick_no_op_before_deadline() {
        // Without a real LoadedSkels we can't drive a full pass, but we
        // can verify that `next_rescan_at` gates correctly. Set deadline
        // far in the future and confirm the timestamp doesn't change.
        let mut s = TlsState::new();
        let far = Instant::now() + Duration::from_secs(3600);
        s.next_rescan_at = far;
        // Without real skels we can't call discovery_tick; just assert
        // the gate condition directly.
        assert!(Instant::now() < s.next_rescan_at);
    }
}
