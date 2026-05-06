//! Spawn `tsd`, then deliberately connect a TCP socket to 127.0.0.1:1
//! (RST'd immediately, but the connect() syscall fires the cgroup hook).
//! Assert tsd prints a `kind: NetConnect, dst: 127.0.0.1:1` line.
//!
//! Requires CAP_BPF or root. `#[ignore]`d so unprivileged `cargo test`
//! still passes; CI runs with `--include-ignored` under sudo.

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};

#[test]
#[ignore = "requires CAP_BPF or root; run with --include-ignored under sudo"]
fn captures_cgroup_connect_v4() {
    let bin = env!("CARGO_BIN_EXE_tsd");

    let mut child = Command::new(bin)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tsd");

    let stdout = child.stdout.take().expect("pipe stdout");
    let mut reader = BufReader::new(stdout);

    // Wait for tsd to attach BPF programs.
    std::thread::sleep(Duration::from_millis(700));

    // Trigger: connect to 127.0.0.1:1 — kernel will refuse, but the
    // connect() syscall reaches cgroup/connect4 BEFORE the refusal.
    let socket =
        Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).expect("create socket");
    socket.set_nonblocking(true).ok();
    let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let _ = socket.connect(&addr.into()); // ignore EINPROGRESS / ECONNREFUSED

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut saw_event = false;
    let mut line = String::new();
    while Instant::now() < deadline {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) if line.contains("kind: NetConnect") && line.contains("dst: 127.0.0.1:1") => {
                saw_event = true;
                eprintln!("captured: {}", line.trim());
                break;
            }
            Ok(_) => continue,
            Err(_) => break,
        }
    }

    let _ = child.kill();
    let _ = child.wait();

    assert!(
        saw_event,
        "tsd produced no NetConnect line for 127.0.0.1:1 within 5s"
    );
}
