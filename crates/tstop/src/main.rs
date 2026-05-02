//! TokenScope TUI. Phase 0: stub that prints a "coming in Phase 2" notice
//! and exits cleanly. The real ratatui dashboard lands in Phase 2.

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "tstop", version, about = "TokenScope live dashboard (stub)")]
struct Args {}

fn main() -> anyhow::Result<()> {
    let _ = Args::parse();
    eprintln!(
        "tstop is a Phase 2 deliverable. For Phase 0, run `sudo tsd` and read the lines on stdout."
    );
    Ok(())
}
