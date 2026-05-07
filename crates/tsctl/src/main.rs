//! TokenScope CLI (Phase 1.F).
//!
//! Two commands today:
//!   tsctl status               # one-shot daemon snapshot
//!   tsctl tail                 # live JSON event stream until Ctrl-C
//!
//! Both talk to tsd over a Unix domain socket. `tsctl query` lands in
//! Phase 1.G — DuckDB does not allow concurrent reader+writer across
//! processes, so query has to be routed through the daemon's own
//! connection.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};

use ts_core::control::{ErrorResponse, Request, StatusResponse};

#[derive(Parser, Debug)]
#[command(name = "tsctl", version, about = "TokenScope CLI")]
struct Args {
    /// Path to the daemon's Unix domain socket.
    #[arg(long, default_value_os_t = default_uds_path(), global = true)]
    uds_path: PathBuf,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Print build info and exit.
    Version,
    /// One-shot daemon status snapshot.
    Status,
    /// Live event stream from tsd. Exits on SIGINT.
    Tail,
    /// Run an ad-hoc SQL query against the daemon's DuckDB (executed
    /// server-side via in-memory primary + ATTACH READ_ONLY).
    Query {
        /// The SQL statement.
        sql: String,
    },
}

fn default_uds_path() -> PathBuf {
    if let Some(rt) = std::env::var_os("XDG_RUNTIME_DIR") {
        if !rt.is_empty() {
            return PathBuf::from(rt).join("tokenscope").join("tsd.sock");
        }
    }
    PathBuf::from("/run/tokenscope/tsd.sock")
}

fn main() -> Result<()> {
    let args = Args::parse();
    match args.cmd {
        Cmd::Version => {
            println!("tsctl {}", env!("CARGO_PKG_VERSION"));
        }
        Cmd::Status => cmd_status(&args.uds_path)?,
        Cmd::Tail => cmd_tail(&args.uds_path)?,
        Cmd::Query { sql } => cmd_query(&args.uds_path, &sql)?,
    }
    Ok(())
}

fn connect(uds_path: &PathBuf) -> Result<UnixStream> {
    UnixStream::connect(uds_path)
        .with_context(|| format!("connect to tsd at {}", uds_path.display()))
}

fn cmd_status(uds_path: &PathBuf) -> Result<()> {
    let mut stream = connect(uds_path)?;
    let req = serde_json::to_string(&Request::Status)?;
    writeln!(stream, "{req}").context("write request")?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).context("read response")?;

    // The daemon may reply with an ErrorResponse on bad requests.
    if let Ok(err) = serde_json::from_str::<ErrorResponse>(line.trim()) {
        return Err(anyhow!("tsd error: {}", err.error));
    }
    let resp: StatusResponse =
        serde_json::from_str(line.trim()).context("decode StatusResponse")?;

    println!("tsd version            {}", resp.version);
    println!("protocol version       {}", resp.protocol_version);
    println!("uptime (s)             {}", resp.uptime_s);
    println!("db path                {}", resp.db_path);
    println!("uds path               {}", resp.uds_path);
    println!("probes                 {}", resp.probes_attached.join(", "));
    println!("events total           {}", resp.events_total);
    println!("ringbuf poll errors    {}", resp.ringbuf_poll_errors);
    println!("tail subscribers       {}", resp.tail_subscribers_active);
    Ok(())
}

fn cmd_tail(uds_path: &PathBuf) -> Result<()> {
    let mut stream = connect(uds_path)?;
    let req = serde_json::to_string(&Request::Tail)?;
    writeln!(stream, "{req}").context("write request")?;

    // SIGINT shuts down by closing the read side; the loop sees EOF.
    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let s = shutdown.clone();
        ctrlc::set_handler(move || s.store(true, Ordering::SeqCst))
            .context("install signal handler")?;
    }
    // Read with a short timeout so we can poll the shutdown flag.
    stream
        .set_read_timeout(Some(Duration::from_millis(300)))
        .ok();
    let reader = BufReader::new(stream);
    for line in reader.lines() {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        match line {
            Ok(l) => {
                println!("{l}");
                std::io::stdout().flush().ok();
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => return Err(anyhow!("read tail: {e}")),
        }
    }
    Ok(())
}

fn cmd_query(uds_path: &PathBuf, sql: &str) -> Result<()> {
    use tabled::{builder::Builder, settings::Style};
    use ts_core::control::QueryFrame;

    let mut stream = connect(uds_path)?;
    let req = serde_json::to_string(&Request::Query { sql: sql.into() })?;
    writeln!(stream, "{req}").context("write request")?;

    let reader = BufReader::new(stream);
    let mut builder = Builder::default();
    let mut have_header = false;
    let mut row_count: u64 = 0;
    let mut elapsed_ms: u64 = 0;
    let mut saw_terminator = false;

    for line in reader.lines() {
        let line = line.context("read frame")?;
        // First try QueryFrame; if that fails, try ErrorResponse so a
        // new tsctl talking to an old tsd that doesn't know `Query`
        // surfaces the daemon's typed error instead of "missing kind".
        match serde_json::from_str::<QueryFrame>(&line) {
            Ok(QueryFrame::Header { columns }) => {
                builder.push_record(&columns);
                have_header = true;
            }
            Ok(QueryFrame::Row { values }) => {
                builder.push_record(&values);
            }
            Ok(QueryFrame::End {
                row_count: n,
                elapsed_ms: ms,
            }) => {
                row_count = n;
                elapsed_ms = ms;
                saw_terminator = true;
                break;
            }
            Ok(QueryFrame::Error { message }) => {
                return Err(anyhow!("query error: {message}"));
            }
            Err(_) => {
                if let Ok(err) = serde_json::from_str::<ErrorResponse>(&line) {
                    return Err(anyhow!("tsd error: {}", err.error));
                }
                return Err(anyhow!("unparseable frame: {line}"));
            }
        }
    }

    if !saw_terminator {
        return Err(anyhow!(
            "stream ended before End/Error frame (daemon disconnect?)"
        ));
    }
    if have_header {
        println!("{}", builder.build().with(Style::sharp()));
    }
    eprintln!("({row_count} rows, {elapsed_ms} ms)");
    Ok(())
}
