//! Cgroup v2 unified-hierarchy attach point.
//!
//! cgroup/connect4 and cgroup/connect6 BPF programs need a cgroup file
//! descriptor at attach time. The unified root at /sys/fs/cgroup gives
//! system-wide coverage. v1 hierarchies are not supported in Phase 1.

use std::fs::File;
use std::path::Path;

use anyhow::{Context, Result};

pub const UNIFIED_ROOT: &str = "/sys/fs/cgroup";

/// Open the cgroup v2 unified hierarchy and return an owned File.
/// Caller keeps it alive for as long as the BPF programs are attached.
pub fn open_unified_root() -> Result<File> {
    let path = Path::new(UNIFIED_ROOT);
    if !path.exists() {
        anyhow::bail!(
            "{UNIFIED_ROOT} does not exist; cgroup v2 required for cgroup/connect probes"
        );
    }
    File::open(path).with_context(|| format!("open {UNIFIED_ROOT}"))
}
