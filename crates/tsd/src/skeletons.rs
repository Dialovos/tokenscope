//! Owns the storage and skeleton handles for every BPF program tsd loads.
//!
//! Each libbpf-rs skeleton needs its own `MaybeUninit<OpenObject>` storage
//! that outlives the loaded `Skel`. We pin both in a single struct so the
//! caller doesn't have to juggle individual lifetimes.

use std::fs::File;
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;

use anyhow::{anyhow, Context, Result};

use ts_bpf_sys::libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use ts_bpf_sys::libbpf_rs::{Link, MapCore, MapFlags, OpenObject};
use ts_bpf_sys::net::{NetSkel, NetSkelBuilder};
use ts_bpf_sys::sched_exec::{SchedExecSkel, SchedExecSkelBuilder};
use ts_bpf_sys::tls::{TlsSkel, TlsSkelBuilder};

use crate::cgroup;

/// Backing storage for every skeleton tsd loads. Must outlive the
/// loaded `Skel`s.
pub struct SkelStorage {
    pub sched: MaybeUninit<OpenObject>,
    pub net: MaybeUninit<OpenObject>,
    pub tls: MaybeUninit<OpenObject>,
}

impl SkelStorage {
    pub fn new() -> Self {
        Self {
            sched: MaybeUninit::uninit(),
            net: MaybeUninit::uninit(),
            tls: MaybeUninit::uninit(),
        }
    }
}

impl Default for SkelStorage {
    fn default() -> Self {
        Self::new()
    }
}

/// Loaded + attached skeletons. The `_cgroup_links` and `_fexit_links`
/// fields keep the BPF attachments alive (dropping them detaches).
///
/// The `tls` skeleton is LOADED but has no probes attached yet — Task 9
/// (the userspace TlsAttachManager) walks /proc and attaches per
/// libssl.so. Loading early ensures the pinned `cgroup_filter` map
/// exists in bpffs before any process tries to query it.
pub struct LoadedSkels<'obj> {
    pub sched: SchedExecSkel<'obj>,
    pub net: NetSkel<'obj>,
    pub tls: TlsSkel<'obj>,
    _cgroup_links: Vec<Link>,
    _fexit_links: Vec<Link>,
    _cgroup_root: File,
}

/// Load and attach every BPF program. Populates the pinned
/// `cgroup_filter` map with `tracked_cgroup_ids` so TLS probes (when
/// attached in Task 9) fire only for the right processes.
pub fn load_all(
    storage: &mut SkelStorage,
    cgroup_root: File,
    tracked_cgroup_ids: &[u64],
) -> Result<LoadedSkels<'_>> {
    let mut sched = SchedExecSkelBuilder::default()
        .open(&mut storage.sched)
        .context("open sched_exec skeleton")?
        .load()
        .context("load sched_exec skeleton")?;
    sched.attach().context("attach sched_exec")?;

    let net = NetSkelBuilder::default()
        .open(&mut storage.net)
        .context("open net skeleton")?
        .load()
        .context("load net skeleton")?;

    let cgroup_fd = cgroup_root.as_raw_fd();
    let link4 = net
        .progs
        .handle_connect4
        .attach_cgroup(cgroup_fd)
        .map_err(|e| anyhow!("attach cgroup/connect4: {e}"))?;
    let link6 = net
        .progs
        .handle_connect6
        .attach_cgroup(cgroup_fd)
        .map_err(|e| anyhow!("attach cgroup/connect6: {e}"))?;

    let send_link = net
        .progs
        .handle_sendmsg
        .attach()
        .map_err(|e| anyhow!("attach fexit/tcp_sendmsg: {e}"))?;
    let recv_link = net
        .progs
        .handle_recvmsg
        .attach()
        .map_err(|e| anyhow!("attach fexit/tcp_recvmsg: {e}"))?;

    // TLS skeleton: load (which honors the pinning=LIBBPF_PIN_BY_NAME
    // attribute on the cgroup_filter map and creates/reuses the bpffs
    // pin at /sys/fs/bpf/tokenscope/cgroup_filter). Probes are NOT
    // attached here — Task 9's TlsAttachManager walks /proc and
    // attaches per libssl file.
    let mut tls_open = TlsSkelBuilder::default()
        .open(&mut storage.tls)
        .context("open tls skeleton")?;
    // libbpf-rs honors per-map pin paths set on the OpenSkel side.
    // The .maps.cgroup_filter map carries pinning=LIBBPF_PIN_BY_NAME
    // from the BPF C source; we override the pin directory by setting
    // the explicit path here so it lands at our bpffs subdir rather
    // than the libbpf default `/sys/fs/bpf/<map_name>`.
    tls_open
        .maps
        .cgroup_filter
        .set_pin_path(cgroup::CGROUP_FILTER_PIN)
        .map_err(|e| anyhow!("set cgroup_filter pin path: {e}"))?;
    let tls = tls_open.load().context("load tls skeleton")?;

    // Populate the cgroup_filter map with the daemon's tracked ids.
    // Value is a single u8 sentinel (presence == "tracked").
    let value: u8 = 1;
    for cgid in tracked_cgroup_ids {
        let key_bytes = cgid.to_ne_bytes();
        tls.maps
            .cgroup_filter
            .update(&key_bytes, std::slice::from_ref(&value), MapFlags::ANY)
            .map_err(|e| anyhow!("populate cgroup_filter id={cgid}: {e}"))?;
    }

    Ok(LoadedSkels {
        sched,
        net,
        tls,
        _cgroup_links: vec![link4, link6],
        _fexit_links: vec![send_link, recv_link],
        _cgroup_root: cgroup_root,
    })
}
