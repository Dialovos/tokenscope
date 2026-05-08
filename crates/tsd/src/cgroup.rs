//! Cgroup v2 unified-hierarchy attach point + per-cgroup filter helpers.
//!
//! `cgroup/connect4` and `cgroup/connect6` BPF programs need a cgroup file
//! descriptor at attach time. The unified root at `/sys/fs/cgroup` gives
//! system-wide coverage. v1 hierarchies are not supported.
//!
//! For Phase 2.A, the `cgroup_filter` BPF map (created by `bpf/tls.bpf.c`,
//! pinned at `/sys/fs/bpf/tokenscope/cgroup_filter`) decides which
//! processes the TLS uprobes fire for. cgroup/connect probes are not
//! migrated to use it — they remain naturally cgroup-scoped via their
//! attach point. Helpers here just resolve cgroup ids; the map-update
//! itself happens in `tls.rs` against the loaded `Map` reference.

use std::fs::File;
use std::path::Path;

use anyhow::{Context, Result};

pub const UNIFIED_ROOT: &str = "/sys/fs/cgroup";
pub const BPFFS_DIR: &str = "/sys/fs/bpf/tokenscope";
pub const CGROUP_FILTER_PIN: &str = "/sys/fs/bpf/tokenscope/cgroup_filter";

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

/// Ensure the bpffs subdirectory used by Phase 2.A pinned maps exists.
/// Created with mode 0755. Requires CAP_SYS_ADMIN to mkdir on bpffs;
/// returns an error wrapped with the path so the caller can log/skip.
pub fn ensure_bpffs_dir() -> Result<()> {
    if !Path::new(BPFFS_DIR).exists() {
        std::fs::create_dir_all(BPFFS_DIR).with_context(|| format!("mkdir {BPFFS_DIR}"))?;
    }
    Ok(())
}

/// Return the cgroup-v2 id for the calling process. The id matches
/// `bpf_get_current_cgroup_id()` (the inode of the cgroup directory).
///
/// Reads `/proc/self/cgroup` (v2 line shape `0::/path/...`), then stats
/// `/sys/fs/cgroup/<that-path>`.
pub fn own_cgroup_id() -> Result<u64> {
    let txt = std::fs::read_to_string("/proc/self/cgroup").context("read /proc/self/cgroup")?;
    let rel = txt
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .map(|p| p.trim_end().to_string())
        .ok_or_else(|| anyhow::anyhow!("no v2 cgroup line in /proc/self/cgroup"))?;
    let path = format!("{UNIFIED_ROOT}{rel}");
    cgroup_path_id(Path::new(&path))
}

/// Stat a cgroup-v2 directory and return its inode (== `bpf_get_current_cgroup_id`).
pub fn cgroup_path_id(path: &Path) -> Result<u64> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    Ok(m.ino())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_cgroup_id_returns_nonzero() {
        // CI runs in some cgroup; the id should never be 0.
        let id = own_cgroup_id().expect("own cgroup id");
        assert!(id > 0, "got cgroup id 0");
    }

    #[test]
    fn cgroup_path_id_for_unified_root() {
        let id = cgroup_path_id(Path::new(UNIFIED_ROOT)).expect("stat unified root");
        assert!(id > 0);
    }
}
