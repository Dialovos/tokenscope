//! Lazy `pid → ProcessInfo` cache populated from /proc.
//!
//! Single-threaded by design (tsd's main loop is sync). Use `RefCell`
//! at the call site for interior mutability.
//!
//! Eviction: simple FIFO at capacity. PID reuse detection (via
//! /proc/<pid>/stat start_time) is deferred to Phase 1.D when accuracy
//! starts mattering for persisted records.

use std::collections::{HashMap, VecDeque};
use std::fs;

const CAPACITY: usize = 4096;
const CMDLINE_DISPLAY_CAP: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    pub comm: String,
    pub cmdline: String,
}

impl ProcessInfo {
    /// Truncated cmdline suitable for one-line display. Falls back to
    /// the comm in brackets when cmdline is empty (kernel thread,
    /// race with exit).
    pub fn display_cmdline(&self) -> String {
        if self.cmdline.is_empty() {
            return format!("[{}]", self.comm);
        }
        if self.cmdline.len() <= CMDLINE_DISPLAY_CAP {
            return self.cmdline.clone();
        }
        let mut s = self.cmdline[..CMDLINE_DISPLAY_CAP].to_string();
        s.push('…');
        s
    }
}

pub struct ProcessCache {
    map: HashMap<u32, ProcessInfo>,
    order: VecDeque<u32>,
}

impl ProcessCache {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Lookup-or-insert. Always returns a reference — sentinel values
    /// on read failure prevent re-stating dead PIDs on every event.
    pub fn get_or_load(&mut self, pid: u32) -> &ProcessInfo {
        if !self.map.contains_key(&pid) {
            let info = read_proc(pid);
            self.insert(pid, info);
        }
        self.map.get(&pid).expect("just inserted")
    }

    fn insert(&mut self, pid: u32, info: ProcessInfo) {
        if self.map.len() >= CAPACITY {
            if let Some(evict) = self.order.pop_front() {
                self.map.remove(&evict);
            }
        }
        self.order.push_back(pid);
        self.map.insert(pid, info);
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

impl Default for ProcessCache {
    fn default() -> Self {
        Self::new()
    }
}

fn read_proc(pid: u32) -> ProcessInfo {
    let comm_path = format!("/proc/{pid}/comm");
    let cmdline_path = format!("/proc/{pid}/cmdline");

    let comm = match fs::read_to_string(&comm_path) {
        Ok(s) => s.trim_end_matches('\n').to_string(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => "<gone>".to_string(),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => "<denied>".to_string(),
        Err(_) => "<error>".to_string(),
    };

    let cmdline = match fs::read(&cmdline_path) {
        Ok(bytes) => parse_cmdline(&bytes),
        Err(_) => String::new(),
    };

    ProcessInfo { comm, cmdline }
}

fn parse_cmdline(bytes: &[u8]) -> String {
    let trimmed_end = bytes.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    let useful = &bytes[..trimmed_end];
    let parts: Vec<String> = useful
        .split(|&b| b == 0)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect();
    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cmdline_simple() {
        let bytes = b"curl\0https://example.com\0";
        assert_eq!(parse_cmdline(bytes), "curl https://example.com");
    }

    #[test]
    fn parse_cmdline_no_trailing_nul() {
        let bytes = b"sleep\01";
        assert_eq!(parse_cmdline(bytes), "sleep 1");
    }

    #[test]
    fn parse_cmdline_empty() {
        assert_eq!(parse_cmdline(b""), "");
        assert_eq!(parse_cmdline(b"\0\0\0"), "");
    }

    #[test]
    fn parse_cmdline_single_arg() {
        assert_eq!(parse_cmdline(b"sshd\0"), "sshd");
    }

    #[test]
    fn display_cmdline_falls_back_to_comm_when_empty() {
        let info = ProcessInfo {
            comm: "kworker/0:1".to_string(),
            cmdline: String::new(),
        };
        assert_eq!(info.display_cmdline(), "[kworker/0:1]");
    }

    #[test]
    fn display_cmdline_truncates() {
        let long = "x".repeat(500);
        let info = ProcessInfo {
            comm: "x".to_string(),
            cmdline: long,
        };
        let out = info.display_cmdline();
        assert_eq!(out.chars().count(), CMDLINE_DISPLAY_CAP + 1);
        assert!(out.ends_with('…'));
    }

    #[test]
    fn cache_evicts_at_capacity() {
        let mut c = ProcessCache::new();
        for pid in 1..=(CAPACITY as u32 + 10) {
            c.insert(
                pid,
                ProcessInfo {
                    comm: format!("p{pid}"),
                    cmdline: String::new(),
                },
            );
        }
        assert_eq!(c.len(), CAPACITY);
        for pid in 1..=10 {
            assert!(!c.map.contains_key(&pid));
        }
        assert!(c.map.contains_key(&(CAPACITY as u32 + 10)));
    }

    #[test]
    fn read_proc_pid_1() {
        let info = read_proc(1);
        assert!(!info.comm.is_empty());
        assert_ne!(info.comm, "<gone>");
        assert_ne!(info.comm, "<error>");
    }

    #[test]
    fn read_proc_dead_pid_is_gone() {
        let info = read_proc(0xFFFF_FFFE);
        assert_eq!(info.comm, "<gone>");
    }
}
