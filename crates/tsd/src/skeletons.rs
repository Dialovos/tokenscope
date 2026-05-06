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
use ts_bpf_sys::libbpf_rs::{Link, OpenObject};
use ts_bpf_sys::net::{NetSkel, NetSkelBuilder};
use ts_bpf_sys::sched_exec::{SchedExecSkel, SchedExecSkelBuilder};

/// Backing storage for both skeletons. Must outlive the loaded `Skel`s.
pub struct SkelStorage {
    pub sched: MaybeUninit<OpenObject>,
    pub net: MaybeUninit<OpenObject>,
}

impl SkelStorage {
    pub fn new() -> Self {
        Self {
            sched: MaybeUninit::uninit(),
            net: MaybeUninit::uninit(),
        }
    }
}

impl Default for SkelStorage {
    fn default() -> Self {
        Self::new()
    }
}

/// Loaded + attached skeletons. The `_cgroup_links` field keeps the
/// cgroup BPF attachments alive (dropping them detaches the program).
pub struct LoadedSkels<'obj> {
    pub sched: SchedExecSkel<'obj>,
    pub net: NetSkel<'obj>,
    _cgroup_links: Vec<Link>,
    _cgroup_root: File,
}

/// Load and attach every Phase 1.A BPF program.
pub fn load_all(storage: &mut SkelStorage, cgroup_root: File) -> Result<LoadedSkels<'_>> {
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

    Ok(LoadedSkels {
        sched,
        net,
        _cgroup_links: vec![link4, link6],
        _cgroup_root: cgroup_root,
    })
}
