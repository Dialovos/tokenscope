//! Privileged OpenSSL qualification with synthetic loopback traffic only.
//! Build tsd and tsctl first; select this suite inside a dedicated test cgroup.
//! Selecting an ignored test with missing prerequisites fails explicitly.

use duckdb::Connection;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

const SENTINELS: [&str; 3] = [
    "PRIVATE-HEADER-SENTINEL",
    "PRIVATE-PROMPT-SENTINEL",
    "PRIVATE-RESPONSE-SENTINEL",
];
const SERVER: &str = r#"
import http.server, json, ssl, sys
class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def do_POST(self):
        body = self.rfile.read(int(self.headers['Content-Length']))
        assert self.path == '/v1/chat/completions'
        assert body == b'{"prompt":"PRIVATE-PROMPT-SENTINEL"}'
        assert self.headers['Authorization'] == 'Bearer PRIVATE-HEADER-SENTINEL'
        payload = json.dumps({'choices':[{'content':'PRIVATE-RESPONSE-SENTINEL'}],
          'usage':{'prompt_tokens':5,'completion_tokens':3,'total_tokens':8}}).encode()
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(payload)))
        self.send_header('Connection','close')
        self.end_headers()
        self.wfile.write(payload)
    def log_message(self,*args): pass
server = http.server.HTTPServer(('127.0.0.1',0),Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(sys.argv[1],sys.argv[2])
context.set_alpn_protocols(['http/1.1'])
server.socket = context.wrap_socket(server.socket,server_side=True)
print(server.server_port,flush=True)
server.serve_forever()
"#;

struct ManagedChild(Child);
impl Drop for ManagedChild {
    fn drop(&mut self) {
        if self.0.try_wait().expect("check child").is_none() {
            self.0.kill().expect("stop owned child");
        }
        self.0.wait().expect("reap owned child");
    }
}
fn binary(name: &str) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_BIN_EXE_tsd"))
        .parent()
        .unwrap()
        .join(name);
    assert!(
        path.is_file(),
        "build {name} before privileged qualification"
    );
    path
}
fn cgroup() -> PathBuf {
    let text = std::fs::read_to_string("/proc/self/cgroup").expect("read own cgroup");
    let relative = text
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .expect("cgroup v2");
    let path = PathBuf::from("/sys/fs/cgroup").join(relative.trim_start_matches('/'));
    assert!(path.is_dir(), "own cgroup must be visible");
    path
}
fn status(uds: &Path) -> String {
    let out = Command::new(binary("tsctl"))
        .arg("--uds-path")
        .arg(uds)
        .arg("status")
        .output()
        .expect("status command");
    assert!(
        out.status.success(),
        "status failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("UTF-8 status")
}
fn field(text: &str, prefix: &str) -> u64 {
    text.lines()
        .find(|line| line.starts_with(prefix))
        .expect("required status field")
        .split_whitespace()
        .last()
        .unwrap()
        .parse()
        .expect("numeric status field")
}
fn wait_until(mut condition: impl FnMut() -> bool, message: &str) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !condition() {
        assert!(Instant::now() < deadline, "{message}");
        thread::sleep(Duration::from_millis(100));
    }
}
struct Fixture {
    _server: ManagedChild,
    _directory: TempDir,
    port: u16,
    certificate: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let directory = TempDir::new().expect("fixture directory");
        let certificate = directory.path().join("fixture.pem");
        let key = directory.path().join("fixture-key.pem");
        let out = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
            ])
            .arg("-keyout")
            .arg(&key)
            .arg("-out")
            .arg(&certificate)
            .output()
            .expect("openssl prerequisite");
        assert!(
            out.status.success(),
            "fixture certificate generation failed"
        );
        let mut server = ManagedChild(
            Command::new("python3")
                .args(["-u", "-c", SERVER])
                .arg(&certificate)
                .arg(&key)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("Python TLS fixture"),
        );
        let stdout = server.0.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut line = String::new();
            BufReader::new(stdout)
                .read_line(&mut line)
                .expect("fixture port");
            tx.send(line).expect("fixture receiver");
        });
        let port = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("fixture startup deadline")
            .trim()
            .parse()
            .expect("numeric port");
        Self {
            _server: server,
            _directory: directory,
            port,
            certificate,
        }
    }
    fn request(&self) -> u32 {
        // No DNS or provider request: both TLS endpoints are on loopback.
        let child = Command::new("curl")
            .args([
                "--silent",
                "--show-error",
                "--http1.1",
                "--noproxy",
                "*",
                "--max-time",
                "10",
            ])
            .arg("--cacert")
            .arg(&self.certificate)
            .arg("--resolve")
            .arg(format!("localhost:{}:127.0.0.1", self.port))
            .args([
                "-H",
                "Host: api.openai.com",
                "-H",
                "Authorization: Bearer PRIVATE-HEADER-SENTINEL",
                "-H",
                "Content-Type: application/json",
                "--data-binary",
                r#"{"prompt":"PRIVATE-PROMPT-SENTINEL"}"#,
            ])
            .arg(format!(
                "https://localhost:{}/v1/chat/completions",
                self.port
            ))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("curl prerequisite");
        let pid = child.id();
        let out = child.wait_with_output().expect("fixture request");
        assert!(
            out.status.success(),
            "loopback request failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let body: serde_json::Value = serde_json::from_slice(&out.stdout).expect("fixture JSON");
        assert_eq!(body["usage"]["total_tokens"], 8);
        assert_eq!(body["choices"][0]["content"], SENTINELS[2]);
        pid
    }
}
struct Daemon {
    child: ManagedChild,
    _directory: TempDir,
    db: PathBuf,
    uds: PathBuf,
    logs: Option<thread::JoinHandle<String>>,
}
impl Daemon {
    fn new() -> Self {
        let directory = TempDir::new().expect("daemon directory");
        let db = directory.path().join("private/usage.duckdb");
        let uds = directory.path().join("tsd.sock");
        let mut child = ManagedChild(
            Command::new(binary("tsd"))
                .arg("--db-path")
                .arg(&db)
                .arg("--uds-path")
                .arg(&uds)
                .arg("--track-cgroup")
                .arg(cgroup())
                .arg("--no-stdout")
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn daemon"),
        );
        let mut stderr = child.0.stderr.take().unwrap();
        let logs = thread::spawn(move || {
            let mut text = String::new();
            stderr.read_to_string(&mut text).expect("daemon logs");
            text
        });
        let mut exited = None;
        wait_until(
            || {
                exited = child.0.try_wait().expect("daemon state");
                exited.is_some() || uds.exists()
            },
            "daemon did not create control socket",
        );
        if let Some(status) = exited {
            let text = logs.join().unwrap_or_default();
            panic!("daemon exited before qualification ({status}):\n{text}");
        }
        wait_until(
            || field(&status(&uds), "tls libs attached") > 0,
            "libssl attachment did not qualify",
        );
        Self {
            child,
            _directory: directory,
            db,
            uds,
            logs: Some(logs),
        }
    }
    fn stop(&mut self) -> String {
        assert_eq!(
            unsafe { libc::kill(self.child.0.id() as i32, libc::SIGINT) },
            0
        );
        let mut exit = None;
        wait_until(
            || {
                exit = self.child.0.try_wait().expect("daemon shutdown");
                exit.is_some()
            },
            "daemon did not drain and stop",
        );
        let logs = self.logs.take().unwrap().join().expect("daemon log reader");
        assert!(exit.unwrap().success(), "daemon shutdown failed: {logs}");
        logs
    }
}
/// Metadata-only view of what the daemon stored: usage states and reasons, and
/// TLS call counts per process and direction. No content or headers.
fn capture_summary(conn: &Connection) -> String {
    let mut out = String::from("events_usage (tgid, ordinal, state, integrity, reason):\n");
    let mut rows = conn
        .prepare(
            "SELECT tgid, request_ordinal, usage_state, capture_integrity, coalesce(reason, '') \
             FROM events_usage ORDER BY ts_ns",
        )
        .unwrap();
    let usage = rows
        .query_map([], |r| {
            Ok(format!(
                "  {} {:?} {} {} {}",
                r.get::<_, u32>(0)?,
                r.get::<_, Option<u64>>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?
            ))
        })
        .unwrap();
    for line in usage {
        out.push_str(&line.unwrap());
        out.push('\n');
    }
    out.push_str("events_tls_metadata (tgid, direction, chunks, max sequence, loss, ends):\n");
    let mut rows = conn
        .prepare(
            "SELECT tgid, direction, count(*), max(call_sequence), max(loss_epoch), \
             count(*) FILTER (WHERE lifecycle_end) FROM events_tls_metadata \
             GROUP BY tgid, direction ORDER BY tgid, direction",
        )
        .unwrap();
    let calls = rows
        .query_map([], |r| {
            Ok(format!(
                "  {} {} {} {} {} {}",
                r.get::<_, u32>(0)?,
                r.get::<_, u8>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, u64>(3)?,
                r.get::<_, u64>(4)?,
                r.get::<_, i64>(5)?
            ))
        })
        .unwrap();
    for line in calls {
        out.push_str(&line.unwrap());
        out.push('\n');
    }
    out
}
fn assert_private(text: &[u8]) {
    for sentinel in SENTINELS {
        assert!(
            !text
                .windows(sentinel.len())
                .any(|w| w == sentinel.as_bytes()),
            "persistent/export surface leaked a sentinel"
        );
    }
}
#[test]
#[ignore = "requires root, curl, OpenSSL, Python and a dedicated test cgroup"]
fn tls_attaches_to_libssl_within_one_rescan() {
    let _fixture = Fixture::new();
    let mut daemon = Daemon::new();
    assert!(field(&status(&daemon.uds), "tls libs attached") >= 1);
    assert_private(daemon.stop().as_bytes());
}
#[test]
#[ignore = "requires root, curl, OpenSSL, Python and a dedicated test cgroup"]
fn tls_curl_emits_metadata_and_exact_reported_usage() {
    let fixture = Fixture::new();
    let mut daemon = Daemon::new();
    let pid = fixture.request();
    wait_until(
        || field(&status(&daemon.uds), "rows flushed") > 0,
        "fixture rows were not flushed",
    );
    let logs = daemon.stop();
    assert_private(logs.as_bytes());
    let conn = Connection::open(&daemon.db).expect("inspect fixture database");
    let reports: String = match conn.query_row(
        "SELECT reports_json FROM events_usage WHERE tgid=? AND usage_state='reported' AND request_ordinal=1",
        [pid],
        |r| r.get(0),
    ) {
        Ok(reports) => reports,
        Err(e) => panic!(
            "exact client usage must qualify ({e}); curl pid {pid}\n{}\ndaemon log:\n{logs}",
            capture_summary(&conn)
        ),
    };
    let counts: serde_json::Value = serde_json::from_str(&reports).unwrap();
    assert_eq!(counts[0]["input"], 5);
    assert_eq!(counts[0]["output"], 3);
    assert_eq!(counts[0]["total"], 8);
    for direction in [0, 1] {
        let n: i64 = conn
            .query_row(
                "SELECT count(*) FROM events_tls_metadata WHERE tgid=? AND direction=?",
                duckdb::params![pid, direction],
                |r| r.get(0),
            )
            .unwrap();
        assert!(n > 0, "missing client TLS direction {direction}");
    }
    let raw:i64=conn.query_row("SELECT count(*) FROM information_schema.tables WHERE table_name='events_tls_plaintext'",[],|r|r.get(0)).unwrap();
    assert_eq!(raw, 0);
    drop(conn);
    assert_private(&std::fs::read(&daemon.db).unwrap());
}
#[test]
#[ignore = "requires root, curl, OpenSSL, Python and a dedicated test cgroup"]
fn tls_default_tail_is_private_and_plaintext_requests_are_refused() {
    let fixture = Fixture::new();
    let mut daemon = Daemon::new();
    let refused = Command::new(binary("tsctl"))
        .arg("--uds-path")
        .arg(&daemon.uds)
        .args(["tail", "--show-plaintext"])
        .output()
        .expect("plaintext request");
    assert!(
        !refused.status.success(),
        "plaintext export must be refused"
    );
    let mut tail = ManagedChild(
        Command::new(binary("tsctl"))
            .arg("--uds-path")
            .arg(&daemon.uds)
            .arg("tail")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("tail"),
    );
    let mut stdout = tail.0.stdout.take().unwrap();
    let reader = thread::spawn(move || {
        let mut text = Vec::new();
        stdout.read_to_end(&mut text).expect("tail output");
        text
    });
    wait_until(
        || field(&status(&daemon.uds), "tail subscribers") >= 1,
        "tail did not register",
    );
    fixture.request();
    thread::sleep(Duration::from_millis(500));
    assert_eq!(unsafe { libc::kill(tail.0.id() as i32, libc::SIGINT) }, 0);
    let captured = reader.join().expect("tail reader");
    assert_private(&captured);
    let text = String::from_utf8(captured).unwrap();
    assert!(
        text.contains("\"kind\":\"tls.write\""),
        "no positive TLS tail control"
    );
    assert!(!text.contains("\"plaintext\"") && !text.contains("\"cmdline\""));
    assert_private(daemon.stop().as_bytes());
}
