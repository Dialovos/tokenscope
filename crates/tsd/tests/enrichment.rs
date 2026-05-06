//! Verify that tsd's NetConnect lines now include `comm:` and `cmdline:`
//! fields. Asserts only that the FIELDS are present (the format is right);
//! does NOT assert their values, because the BPF→userspace pid mapping
//! has subtle TID/TGID/PID-namespace edges that make end-to-end attribution
//! inside `cargo test` flaky. Manual smoke test (sudo tsd + curl) is the
//! source of truth for value correctness; this test guards the wire format.
//!
//! Requires CAP_BPF or root; ignored by default.

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};

#[test]
#[ignore = "requires CAP_BPF or root; run with --include-ignored under sudo"]
fn netconnect_line_has_enrichment_fields() {
    let bin = env!("CARGO_BIN_EXE_tsd");

    let mut child = Command::new(bin)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tsd");

    let stdout = child.stdout.take().expect("pipe stdout");
    let (tx, rx) = mpsc::channel::<String>();
    thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });

    thread::sleep(Duration::from_millis(700));

    let socket =
        Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).expect("create socket");
    socket.set_nonblocking(true).ok();
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
                    && line.contains("comm:")
                    && line.contains("cmdline:") =>
            {
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
        "tsd produced no NetConnect line with comm: and cmdline: fields within 4s"
    );
}
