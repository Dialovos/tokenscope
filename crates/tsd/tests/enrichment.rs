//! Verify that NetConnect output contains comm metadata and omits command lines.
//! Asserts the fields' privacy contract, rather than attribution values;
//! does NOT assert their values, because the BPF→userspace pid mapping
//! has subtle TID/TGID/PID-namespace edges that make end-to-end attribution
//! inside `cargo test` flaky. Manual smoke test (sudo tsd + curl) is the
//! source of truth for value correctness; this test guards the wire format.
//!
//! Requires CAP_BPF or root; ignored by default.

use std::io::{BufRead, BufReader, Read};
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};

struct ManagedChild(Child);
impl Drop for ManagedChild {
    fn drop(&mut self) {
        if self.0.try_wait().expect("daemon state").is_none() {
            self.0.kill().expect("stop fixture daemon");
        }
        self.0.wait().expect("reap fixture daemon");
    }
}

#[test]
#[ignore = "requires CAP_BPF or root; run with --include-ignored under sudo"]
fn netconnect_line_has_metadata_without_command_line() {
    let bin = env!("CARGO_BIN_EXE_tsd");
    let dir = tempfile::TempDir::new().expect("fixture directory");
    let db = dir.path().join("private/usage.duckdb");
    let uds = dir.path().join("tsd.sock");

    let mut child = ManagedChild(
        Command::new(bin)
            .arg("--db-path")
            .arg(&db)
            .arg("--uds-path")
            .arg(&uds)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn tsd"),
    );

    let stdout = child.0.stdout.take().expect("pipe stdout");
    let mut stderr = child.0.stderr.take().expect("pipe stderr");
    let logs = thread::spawn(move || {
        let mut text = String::new();
        stderr.read_to_string(&mut text).expect("daemon logs");
        text
    });
    let (tx, rx) = mpsc::channel::<String>();
    thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });

    let startup_deadline = Instant::now() + Duration::from_secs(10);
    while !uds.exists() {
        assert!(
            child.0.try_wait().expect("daemon state").is_none(),
            "daemon exited at startup"
        );
        assert!(
            Instant::now() < startup_deadline,
            "daemon did not create control socket"
        );
        thread::sleep(Duration::from_millis(100));
    }

    let socket =
        Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).expect("create socket");
    socket.set_nonblocking(true).expect("nonblocking socket");
    let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let _ = socket.connect(&addr.into());

    let deadline = Instant::now() + Duration::from_secs(4);
    let mut saw_event = false;
    loop {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        match rx.recv_timeout(remaining) {
            Ok(line)
                if line.contains("kind: NetConnect")
                    && line.contains("dst: 127.0.0.1:1")
                    && line.contains("comm:") =>
            {
                assert!(!line.contains("cmdline:"), "stdout must omit command lines");
                saw_event = true;
                eprintln!("captured: {}", line.trim());
                break;
            }
            Ok(_) => continue,
            Err(_) => break,
        }
    }

    unsafe { libc::kill(child.0.id() as i32, libc::SIGINT) };
    let status = child.0.wait().expect("daemon exit");
    let logs = logs.join().expect("daemon logs thread");
    assert!(status.success(), "daemon failed: {logs}");

    assert!(
        saw_event,
        "tsd produced no NetConnect line with comm metadata within 4s; {logs}"
    );
}
