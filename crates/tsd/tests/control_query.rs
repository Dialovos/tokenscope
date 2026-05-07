//! End-to-end test for the Phase 1.G control-plane Query path.
//!
//! Spawns tsd with a temp DB + temp UDS, drives some loopback TCP
//! so events land in DuckDB, then exercises tsctl query against
//! the daemon. Asserts:
//!   - a successful GROUP BY returns >= 1 row + correct headers
//!   - mutating SQL is rejected by the engine (read-only ATTACH)
//!   - syntactically-invalid SQL exits non-zero with "error" on stderr
//!
//! Requires CAP_BPF or root; ignored by default.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use tempfile::TempDir;

const PAYLOAD: &[u8] = &[b'P'; 1024];

fn target_dir() -> PathBuf {
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
        let status = Command::new("cargo")
            .args(["build", "--bin", "tsctl"])
            .status()
            .expect("invoke cargo build for tsctl");
        assert!(status.success(), "cargo build -p tsctl failed");
    }
    candidate
}

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
fn control_plane_query_returns_rows_and_rejects_mutations() {
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

    // Wait for UDS bind.
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
    thread::sleep(Duration::from_millis(400));

    // Drive a known loopback transfer so events_net_bytes has rows.
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
    thread::sleep(Duration::from_millis(900));

    // ---- (1) Successful GROUP BY ----
    let out = Command::new(&tsctl)
        .args([
            "--uds-path",
            uds_path.to_str().unwrap(),
            "query",
            "SELECT comm, COUNT(*) AS n FROM events_net_bytes GROUP BY 1 ORDER BY 2 DESC",
        ])
        .output()
        .expect("run tsctl query");
    assert!(
        out.status.success(),
        "tsctl query failed (stdout={:?}, stderr={:?})",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    eprintln!("--- query (1) stdout ---\n{stdout}");
    eprintln!("--- query (1) stderr ---\n{stderr}");
    assert!(stdout.contains("comm"), "no comm header: {stdout}");
    assert!(stdout.contains('n'), "no n header: {stdout}");
    let row_count_line = stderr
        .lines()
        .find(|l| l.contains("rows,"))
        .expect("summary line");
    let row_count: u64 = row_count_line
        .trim_start_matches('(')
        .split_whitespace()
        .next()
        .and_then(|s| s.parse().ok())
        .expect("parse row count");
    assert!(row_count >= 1, "expected >= 1 row, got {row_count}");

    // ---- (2) Mutating SQL must be rejected by the RO ATTACH ----
    let mut_out = Command::new(&tsctl)
        .args([
            "--uds-path",
            uds_path.to_str().unwrap(),
            "query",
            "DELETE FROM events_net_bytes",
        ])
        .output()
        .expect("run tsctl query (delete)");
    assert!(
        !mut_out.status.success(),
        "DELETE should be rejected; got stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&mut_out.stdout),
        String::from_utf8_lossy(&mut_out.stderr),
    );
    let mut_stderr = String::from_utf8_lossy(&mut_out.stderr).into_owned();
    eprintln!("--- query (2) stderr ---\n{mut_stderr}");
    assert!(
        mut_stderr.to_lowercase().contains("error"),
        "DELETE should mention error: {mut_stderr}"
    );
    // Sanity: the data should still be there.
    let count_out = Command::new(&tsctl)
        .args([
            "--uds-path",
            uds_path.to_str().unwrap(),
            "query",
            "SELECT COUNT(*) AS n FROM events_net_bytes",
        ])
        .output()
        .expect("run tsctl query (count after delete)");
    let count_stdout = String::from_utf8_lossy(&count_out.stdout).into_owned();
    eprintln!("--- post-DELETE count ---\n{count_stdout}");
    assert!(
        count_out.status.success(),
        "count after attempted DELETE failed: {count_out:?}"
    );

    // ---- (3) Invalid SQL exits non-zero ----
    let err_out = Command::new(&tsctl)
        .args([
            "--uds-path",
            uds_path.to_str().unwrap(),
            "query",
            "SLECT * FROM nope",
        ])
        .output()
        .expect("run tsctl query (bad sql)");
    assert!(
        !err_out.status.success(),
        "bad SQL should fail; got stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&err_out.stdout),
        String::from_utf8_lossy(&err_out.stderr),
    );
    let err_stderr = String::from_utf8_lossy(&err_out.stderr);
    assert!(
        err_stderr.to_lowercase().contains("error"),
        "bad SQL should mention error: {err_stderr}"
    );

    // ---- Shutdown ----
    unsafe { libc::kill(child.id() as i32, libc::SIGINT) };
    let status = child.wait().expect("wait tsd");
    assert!(status.success(), "tsd exited non-zero: {status}");
    let _ = stderr_drain.join();
    assert!(!uds_path.exists(), "tsd should remove socket on shutdown");
}
