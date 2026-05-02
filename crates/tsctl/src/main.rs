//! TokenScope CLI. Phase 0: `--version` only. Phases 1+ add status, tail,
//! query, etc. — see SPEC.md §6.

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "tsctl", version, about = "TokenScope CLI")]
struct Args {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Print build info and exit (Phase 0 has nothing else).
    Version,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    match args.cmd.unwrap_or(Cmd::Version) {
        Cmd::Version => {
            println!("tsctl {}", env!("CARGO_PKG_VERSION"));
        }
    }
    Ok(())
}
