//! Run tsd with a temp DuckDB path, generate some traffic, send SIGINT,
//! wait for tsd to exit cleanly, then open the DuckDB file from the
//! test process and assert rows landed.
//!
//! Requires CAP_BPF or root; ignored by default.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use duckdb::Connection;
use tempfile::TempDir;

const PAYLOAD: &[u8] = &[b'P'; 1024];

#[test]
#[ignore = "requires CAP_BPF or root; run with --include-ignored under sudo"]
fn round_trips_events_through_duckdb() {
    let bin = env!("CARGO_BIN_EXE_tsd");
    let dir = TempDir::new().expect("tempdir");
    let db_path = dir.path().join("events.duckdb");

    let mut child = Command::new(bin)
        .args([
            "--db-path",
            db_path.to_str().unwrap(),
            "--flush-interval-ms",
            "300",
            "--no-stdout",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tsd");

    // Let tsd attach BPF.
    thread::sleep(Duration::from_millis(900));

    // Loopback TCP pair: sender (us) writes 1024 bytes; receiver drains.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr");
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

    // Give tsd at least one flush window for net_bytes + comfortable margin.
    thread::sleep(Duration::from_millis(900));

    // SIGINT (ctrl+c) — tsd's handler flips the shutdown flag.
    unsafe { libc::kill(child.id() as i32, libc::SIGINT) };
    let status = child.wait().expect("wait");
    assert!(status.success(), "tsd exited non-zero: {status}");

    // Now open the DB ourselves and verify.
    let conn = Connection::open(&db_path).expect("open db");

    let connect_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM events_net_connect", [], |r| r.get(0))
        .unwrap();
    assert!(
        connect_count >= 1,
        "expected at least 1 connect row, got {connect_count}"
    );

    let bytes_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM events_net_bytes", [], |r| r.get(0))
        .unwrap();
    assert!(
        bytes_count >= 1,
        "expected at least 1 net_bytes row, got {bytes_count}"
    );

    let max_tx: i64 = conn
        .query_row("SELECT MAX(tx_bytes) FROM events_net_bytes", [], |r| r.get(0))
        .unwrap();
    assert!(
        max_tx >= PAYLOAD.len() as i64,
        "expected MAX(tx_bytes) >= {}, got {max_tx}",
        PAYLOAD.len()
    );

    eprintln!("connect rows: {connect_count}, bytes rows: {bytes_count}, max tx: {max_tx}");
}
