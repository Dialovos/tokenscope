//! End-to-end test for the Phase 1.F control plane.
//!
//! Spawns tsd with a temp DB + temp UDS, drives some loopback TCP,
//! then exercises tsctl status + tsctl tail against the running
//! daemon and asserts each returns sensible output.
//!
//! Requires CAP_BPF or root; ignored by default.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;
use tempfile::TempDir;
use ts_core::control::StatusResponse;

const PAYLOAD: &[u8] = &[b'P'; 1024];

fn target_dir() -> PathBuf {
    // CARGO_BIN_EXE_<name> only exists for the *current* test crate's
    // bins. tsd is the current crate; tsctl is a sibling — derive its
    // path from tsd's parent directory and ensure the binary exists
    // by running `cargo build -p tsctl` if needed.
    PathBuf::from(env!("CARGO_BIN_EXE_tsd"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn tsd_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tsd"))
}

fn tsctl_bin() -> PathBuf {
    let candidate = target_dir().join("tsctl");
    if !candidate.exists() {
        // Build the sibling binary on demand. Using cargo from the
        // workspace root works under both bare `cargo test` and
        // `sudo -E env "PATH=$PATH" cargo test`.
        let status = Command::new("cargo")
            .args(["build", "--bin", "tsctl"])
            .status()
            .expect("invoke cargo build for tsctl");
        assert!(status.success(), "cargo build -p tsctl failed");
    }
    candidate
}

/// Drain a child's stderr in a separate thread so a full pipe
/// doesn't deadlock the daemon. Returns a handle; the caller can
/// `.join()` after `wait()` to inspect output if needed.
fn drain_stderr(child: &mut std::process::Child) -> thread::JoinHandle<String> {
    let mut stderr = child.stderr.take().expect("piped stderr");
    thread::spawn(move || {
        let mut buf = String::new();
        let _ = stderr.read_to_string(&mut buf);
        buf
    })
}

#[test]
#[ignore = "requires CAP_BPF or root; run with --include-ignored under sudo"]
fn control_plane_status_and_tail() {
    let dir = TempDir::new().expect("tempdir");
    let db_path = dir.path().join("events.duckdb");
    let uds_path = dir.path().join("tsd.sock");

    let tsd = tsd_bin();
    let tsctl = tsctl_bin();

    let mut child = Command::new(&tsd)
        .args([
            "--db-path",
            db_path.to_str().unwrap(),
            "--uds-path",
            uds_path.to_str().unwrap(),
            "--flush-interval-ms",
            "300",
            "--no-stdout",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tsd");
    let stderr_drain = drain_stderr(&mut child);

    // Wait for the UDS file to appear (tsd opens BPF + binds the socket).
    let deadline = Instant::now() + Duration::from_secs(5);
    while !uds_path.exists() {
        if Instant::now() > deadline {
            let _ = child.kill();
            let logs = stderr_drain.join().unwrap_or_default();
            panic!(
                "tsd never created uds at {} — stderr: {}",
                uds_path.display(),
                logs
            );
        }
        thread::sleep(Duration::from_millis(100));
    }
    // Small extra grace for BPF attach to settle.
    thread::sleep(Duration::from_millis(400));

    // ---- Drive a known loopback transfer so tail/counters have data ----
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = thread::spawn(move || {
        let (mut s, _) = listener.accept().expect("accept");
        let mut buf = [0u8; 4096];
        let _ = s.read(&mut buf);
    });
    let mut client = TcpStream::connect(addr).expect("connect");
    client.write_all(PAYLOAD).expect("write");
    client.flush().ok();
    drop(client);
    let _ = server.join();
    thread::sleep(Duration::from_millis(900)); // one flush window + margin

    // ---- tsctl status ----
    let out = Command::new(&tsctl)
        .args(["--uds-path", uds_path.to_str().unwrap(), "status"])
        .output()
        .expect("run tsctl status");
    assert!(
        out.status.success(),
        "tsctl status failed (stdout={:?}, stderr={:?})",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    eprintln!("--- tsctl status ---\n{stdout}");
    assert!(stdout.contains("tsd version"), "no version line: {stdout}");
    assert!(stdout.contains("probes"), "no probes line: {stdout}");
    assert!(stdout.contains("events total"), "no events line: {stdout}");
    // Stronger assertion: events_total must be > 0 because we just
    // drove at least one connect + bytes flush. Re-issue the request
    // and parse the raw JSON to verify numerically.
    let raw_resp = raw_status_via_uds(&uds_path);
    eprintln!("raw status JSON: {raw_resp}");
    let parsed: StatusResponse = serde_json::from_str(&raw_resp).expect("StatusResponse parses");
    assert!(parsed.events_total > 0, "events_total was 0: {parsed:?}");
    assert!(
        parsed.probes_attached.contains(&"sched_exec".into()),
        "probes_attached missing sched_exec: {:?}",
        parsed.probes_attached
    );

    // ---- tsctl tail (background; capture for ~2s, then SIGINT) ----
    // Trigger more events AFTER subscribing to guarantee the
    // subscriber sees them — easier than racing pre-subscribed events.
    let mut tail = Command::new(&tsctl)
        .args(["--uds-path", uds_path.to_str().unwrap(), "tail"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn tsctl tail");
    thread::sleep(Duration::from_millis(400)); // let it subscribe
    for _ in 0..5 {
        let _ = std::process::Command::new("/bin/true").status();
    }
    thread::sleep(Duration::from_millis(1500));
    unsafe { libc::kill(tail.id() as i32, libc::SIGINT) };

    // Read tail's stdout BEFORE wait — wait may not return promptly
    // if the child holds stdio open.
    let mut tail_out = String::new();
    if let Some(mut s) = tail.stdout.take() {
        // Best-effort short read; if SIGINT closed stdin/out the
        // read returns immediately.
        let _ = s.read_to_string(&mut tail_out);
    }
    let _ = tail.wait();

    eprintln!("--- tsctl tail ---\n{tail_out}");
    let line_count = tail_out
        .lines()
        .filter(|l| serde_json::from_str::<Value>(l).is_ok())
        .count();
    assert!(
        line_count >= 1,
        "tail produced no JSON event lines (raw: {tail_out:?})"
    );

    // ---- Shutdown ----
    unsafe { libc::kill(child.id() as i32, libc::SIGINT) };
    let status = child.wait().expect("wait tsd");
    assert!(status.success(), "tsd exited non-zero: {status}");
    let _ = stderr_drain.join();

    // ---- Verify socket cleanup ----
    assert!(
        !uds_path.exists(),
        "tsd should have removed {} on shutdown",
        uds_path.display()
    );
}

/// Send a Status request directly to the daemon and return the raw
/// JSON line. Used for assertions that need the typed response.
fn raw_status_via_uds(uds_path: &std::path::Path) -> String {
    use std::io::{BufRead, BufReader};
    use std::os::unix::net::UnixStream;
    let mut s = UnixStream::connect(uds_path).expect("connect uds");
    s.write_all(b"{\"op\":\"status\"}\n")
        .expect("write request");
    let mut reader = BufReader::new(s);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read response");
    line.trim().to_string()
}
