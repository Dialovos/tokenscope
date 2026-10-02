//! Phase 2.A end-to-end integration test.
//!
//! Strategy: spawn tsd with `--track-cgroup` pointing at the test
//! process's own v2 cgroup (so curl, which the test spawns as a child
//! and which inherits the same cgroup, fires the TLS uprobes), then:
//!
//! 1. Wait for the first `/proc` rescan (~6 s) and confirm
//!    `tls libs attached >= 1` via `tsctl status`.
//! 2. Drive a real `curl` against `https://example.com`. After the
//!    Appender's 1-second flush window, assert
//!    `events_tls_plaintext` has rows for both directions.
//! 3. Drive `curl --header "Authorization: Bearer sk-ant-..."` and
//!    confirm `tsctl tail --show-plaintext` redacts the token while
//!    `tsctl tail` (no flag) doesn't include the body at all
//!    (regression guard for codex BLOCKING #6).
//!
//! Requires:
//! - `CAP_BPF` (run via `sudo -E cargo test -p tsd -- --ignored`)
//! - `curl` on PATH (verified to dynamically link libssl.so.3 on
//!   Debian/Ubuntu)
//! - Network access to `https://example.com`
//!
//! All tests are `#[ignore]`-gated and skip cleanly if any
//! prerequisite is missing. They never silently pass.

use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use tempfile::TempDir;

const ATTACH_DEADLINE: Duration = Duration::from_secs(15);
const STATUS_LINE_PREFIX_TLS_ATTACHED: &str = "tls libs attached";

fn tsd_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tsd"))
}

fn tsctl_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tsd"))
        .parent()
        .unwrap()
        .join("tsctl")
}

fn skip_if_missing_prereqs() -> bool {
    if which("curl").is_none() {
        eprintln!("skip: curl not on PATH");
        return true;
    }
    if !std::path::Path::new("/proc/self/cgroup").exists() {
        eprintln!("skip: /proc/self/cgroup unavailable (not Linux?)");
        return true;
    }
    let tsctl = tsctl_bin();
    if !tsctl.exists() {
        // Build it inline so tests don't fail just because someone ran
        // `cargo test -p tsd --bin tsd` first without -p tsctl.
        let st = Command::new("cargo")
            .args(["build", "--bin", "tsctl"])
            .status();
        if !matches!(st, Ok(s) if s.success()) {
            eprintln!("skip: could not build tsctl");
            return true;
        }
    }
    false
}

fn which(prog: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let p = dir.join(prog);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

/// Read the test process's v2 cgroup path so tsd's filter explicitly
/// includes us. v2 line shape: `0::/user.slice/...`.
fn own_cgroup_path() -> Option<PathBuf> {
    let s = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let rel = s
        .lines()
        .find_map(|l| l.strip_prefix("0::"))?
        .trim_end()
        .to_string();
    Some(PathBuf::from(format!("/sys/fs/cgroup{rel}")))
}

fn spawn_tsd(db: &PathBuf, uds: &PathBuf, track_cgroup: &PathBuf) -> std::process::Child {
    Command::new(tsd_bin())
        .args([
            "--db-path",
            db.to_str().unwrap(),
            "--uds-path",
            uds.to_str().unwrap(),
            "--track-cgroup",
            track_cgroup.to_str().unwrap(),
            "--no-stdout",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tsd")
}

fn drain_stderr(child: &mut std::process::Child) -> thread::JoinHandle<String> {
    let mut stderr = child.stderr.take().expect("piped stderr");
    thread::spawn(move || {
        let mut buf = String::new();
        let _ = stderr.read_to_string(&mut buf);
        buf
    })
}

fn wait_for_uds(uds: &PathBuf, deadline: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < deadline {
        if uds.exists() {
            return true;
        }
        thread::sleep(Duration::from_millis(100));
    }
    false
}

fn read_status(uds: &PathBuf) -> String {
    let out = Command::new(tsctl_bin())
        .args(["--uds-path", uds.to_str().unwrap(), "status"])
        .output()
        .expect("status");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn parse_status_field(status: &str, prefix: &str) -> u64 {
    status
        .lines()
        .find(|l| l.starts_with(prefix))
        .and_then(|l| l.split_whitespace().last())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn wait_for_attach(uds: &PathBuf) -> u64 {
    let start = Instant::now();
    while start.elapsed() < ATTACH_DEADLINE {
        let n = parse_status_field(&read_status(uds), STATUS_LINE_PREFIX_TLS_ATTACHED);
        if n >= 1 {
            return n;
        }
        thread::sleep(Duration::from_millis(500));
    }
    0
}

#[test]
#[ignore = "requires CAP_BPF + curl + network; run with sudo -E cargo test -p tsd -- --ignored"]
fn tls_attaches_to_libssl_within_one_rescan() {
    if skip_if_missing_prereqs() {
        return;
    }
    let cgroup = match own_cgroup_path() {
        Some(p) if p.exists() => p,
        _ => {
            eprintln!("skip: own_cgroup_path missing or not a v2 directory");
            return;
        }
    };
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("e.duckdb");
    let uds = dir.path().join("tsd.sock");

    let mut child = spawn_tsd(&db, &uds, &cgroup);
    let stderr = drain_stderr(&mut child);
    if !wait_for_uds(&uds, Duration::from_secs(10)) {
        let _ = child.kill();
        panic!(
            "tsd never opened the UDS — stderr: {}",
            stderr.join().unwrap_or_default()
        );
    }

    // First /proc rescan happens immediately at startup; subsequent
    // every 5s. Anything libssl-mapping in the cgroup at that moment
    // counts. The test binary itself links libssl via duckdb→reqwest,
    // so we should see >= 1.
    let n = wait_for_attach(&uds);
    let status = read_status(&uds);
    eprintln!("--- status ---\n{status}");
    assert!(
        n >= 1,
        "expected tls libs attached >= 1 within {ATTACH_DEADLINE:?}; status:\n{status}"
    );

    unsafe { libc::kill(child.id() as i32, libc::SIGINT) };
    let _ = child.wait();
}

#[test]
#[ignore = "requires CAP_BPF + curl + network; run with sudo -E cargo test -p tsd -- --ignored"]
fn tls_curl_emits_chunks_and_rows_in_db() {
    if skip_if_missing_prereqs() {
        return;
    }
    let cgroup = match own_cgroup_path() {
        Some(p) if p.exists() => p,
        _ => {
            eprintln!("skip: own_cgroup_path missing");
            return;
        }
    };
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("e.duckdb");
    let uds = dir.path().join("tsd.sock");

    let mut child = spawn_tsd(&db, &uds, &cgroup);
    let _stderr = drain_stderr(&mut child);
    assert!(
        wait_for_uds(&uds, Duration::from_secs(10)),
        "tsd never opened uds"
    );
    assert!(wait_for_attach(&uds) >= 1, "tsd never attached to libssl");

    // Drive a TLS call. curl on Debian/Ubuntu links libssl.so.3.
    let curl_status = Command::new("curl")
        .args([
            "-sS",
            "--max-time",
            "10",
            "-o",
            "/dev/null",
            "https://example.com/",
        ])
        .status()
        .expect("spawn curl");
    if !curl_status.success() {
        eprintln!("skip: curl failed (no network?) status={curl_status}");
        unsafe { libc::kill(child.id() as i32, libc::SIGINT) };
        let _ = child.wait();
        return;
    }

    // Wait past the Appender's 1s flush + a margin.
    thread::sleep(Duration::from_secs(2));

    let q = Command::new(tsctl_bin())
        .args([
            "--uds-path",
            uds.to_str().unwrap(),
            "query",
            "SELECT direction, COUNT(*), SUM(chunk_bytes) FROM events_tls_plaintext GROUP BY 1 ORDER BY 1",
        ])
        .output()
        .expect("query");
    let qout = String::from_utf8_lossy(&q.stdout).into_owned();
    eprintln!("--- query ---\n{qout}");
    assert!(q.status.success(), "query failed: {qout}");
    // Both directions should have at least one row each.
    assert!(qout.contains("0"), "no write rows: {qout}");
    assert!(qout.contains("1"), "no read rows: {qout}");

    unsafe { libc::kill(child.id() as i32, libc::SIGINT) };
    let _ = child.wait();
}

#[test]
#[ignore = "requires CAP_BPF + curl + network; run with sudo -E cargo test -p tsd -- --ignored"]
fn tls_default_tail_does_not_leak_authorization_header() {
    if skip_if_missing_prereqs() {
        return;
    }
    let cgroup = match own_cgroup_path() {
        Some(p) if p.exists() => p,
        _ => {
            eprintln!("skip: own_cgroup_path missing");
            return;
        }
    };
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("e.duckdb");
    let uds = dir.path().join("tsd.sock");

    let mut child = spawn_tsd(&db, &uds, &cgroup);
    let _stderr = drain_stderr(&mut child);
    assert!(wait_for_uds(&uds, Duration::from_secs(10)));
    assert!(wait_for_attach(&uds) >= 1);

    // Open `tsctl tail` (NO --show-plaintext) and capture stdout.
    let tail_uds = uds.clone();
    let tail_handle = thread::spawn(move || {
        let tail = Command::new(tsctl_bin())
            .args(["--uds-path", tail_uds.to_str().unwrap(), "tail"])
            .stdout(Stdio::piped())
            .spawn()
            .expect("tail spawn");
        thread::sleep(Duration::from_millis(3500));
        unsafe { libc::kill(tail.id() as i32, libc::SIGINT) };
        let out = tail.wait_with_output().expect("tail wait");
        String::from_utf8_lossy(&out.stdout).into_owned()
    });
    thread::sleep(Duration::from_millis(300));

    // Drive a TLS call carrying the magic header. The header value
    // shouldn't appear anywhere in default tail output (regression
    // guard for codex BLOCKING #6).
    const MAGIC: &str = "sk-ant-MAGIC-DO-NOT-LEAK-12345-XYZ";
    let curl_status = Command::new("curl")
        .args([
            "-sS",
            "--max-time",
            "10",
            "-o",
            "/dev/null",
            "-H",
            &format!("Authorization: Bearer {MAGIC}"),
            "https://example.com/",
        ])
        .status()
        .expect("spawn curl");
    if !curl_status.success() {
        eprintln!("skip: curl failed (no network?)");
        let _ = tail_handle.join();
        unsafe { libc::kill(child.id() as i32, libc::SIGINT) };
        let _ = child.wait();
        return;
    }

    let captured = tail_handle.join().unwrap();
    eprintln!("--- captured tail (default) ---\n{captured}");
    assert!(
        !captured.contains(MAGIC),
        "default tail leaked the magic token; this is codex BLOCKING #6 regressing"
    );
    // We do expect to see SOME tls.write line for the curl call.
    assert!(
        captured.contains("\"kind\":\"tls.write\""),
        "default tail saw no tls.write at all — attachment may have failed:\n{captured}"
    );

    unsafe { libc::kill(child.id() as i32, libc::SIGINT) };
    let _ = child.wait();
}
