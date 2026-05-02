//! Spawn `tsd`, then exec a child process, and assert that tsd's stdout
//! contains a `TsEventHdr` line.
//!
//! Requires CAP_BPF (or root). Marked `#[ignore]` so unprivileged
//! `cargo test` doesn't fail; CI runs with `--include-ignored` under sudo.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
#[ignore = "requires CAP_BPF or root; run with --include-ignored under sudo"]
fn captures_exec_event_for_child() {
    let bin = env!("CARGO_BIN_EXE_tsd");

    let mut child = Command::new(bin)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tsd");

    let stdout = child.stdout.take().expect("pipe stdout");
    let mut reader = BufReader::new(stdout);

    // Give tsd a moment to attach the BPF program before triggering exec.
    std::thread::sleep(Duration::from_millis(500));

    let triggered = Command::new("/bin/true")
        .status()
        .expect("trigger /bin/true");
    assert!(triggered.success());

    // Read tsd's stdout for up to 5 seconds, looking for any TsEventHdr line.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut saw_event = false;
    let mut line = String::new();
    while Instant::now() < deadline {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) if line.contains("TsEventHdr") => {
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
        "tsd produced no TsEventHdr lines within 5s after triggering /bin/true"
    );
}
