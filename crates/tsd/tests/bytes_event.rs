//! Stand up a loopback TCP listener+connector pair, send 1024 bytes,
//! and assert tsd's stdout shows a `NetBytes` line with tx >= 1024
//! within ~3s (one flush interval at 500ms + buffer for jitter).
//!
//! Requires CAP_BPF or root; ignored by default.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const PAYLOAD: &[u8] = &[b'T'; 1024];

#[test]
#[ignore = "requires CAP_BPF or root; run with --include-ignored under sudo"]
fn captures_tcp_byte_counts() {
    let bin = env!("CARGO_BIN_EXE_tsd");

    let mut child = Command::new(bin)
        .args(["--flush-interval-ms", "500"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tsd");

    let stdout = child.stdout.take().expect("pipe stdout");
    let mut stderr = child.stderr.take().expect("pipe stderr");
    // Read both pipes on their own threads: a blocking read_line can't honor
    // the deadline below, and an undrained stderr pipe stalls tsd once full.
    let (lines_tx, lines_rx) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if lines_tx.send(line).is_err() {
                break;
            }
        }
    });
    let stderr_reader = thread::spawn(move || {
        let mut buf = String::new();
        let _ = stderr.read_to_string(&mut buf);
        buf
    });

    thread::sleep(Duration::from_millis(700));

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut buf = vec![0u8; 4096];
        let _ = stream.read(&mut buf);
    });

    let mut client = TcpStream::connect(addr).expect("connect");
    client.write_all(PAYLOAD).expect("write payload");
    client.flush().ok();
    drop(client);
    let _ = server.join();

    let deadline = Instant::now() + Duration::from_secs(3);
    let mut saw_event = false;
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        match lines_rx.recv_timeout(left) {
            Ok(line) if line.contains("NetBytes") => {
                if let Some(tx) = parse_field_u64(&line, "tx: ") {
                    if tx >= PAYLOAD.len() as u64 {
                        saw_event = true;
                        eprintln!("captured: {}", line.trim());
                        break;
                    }
                }
            }
            Ok(_) => continue,
            // Timed out, or tsd closed stdout.
            Err(_) => break,
        }
    }

    let _ = child.kill();
    let _ = child.wait();
    let tsd_stderr = stderr_reader.join().unwrap_or_default();

    assert!(
        saw_event,
        "tsd produced no NetBytes line with tx >= {} within 3s; tsd stderr:\n{}",
        PAYLOAD.len(),
        tsd_stderr
    );
}

fn parse_field_u64(line: &str, prefix: &str) -> Option<u64> {
    let start = line.find(prefix)? + prefix.len();
    let rest = &line[start..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}
