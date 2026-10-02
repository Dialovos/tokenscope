#!/usr/bin/env python3
"""Inspect or stop specifically named study jobs, preserving their evidence."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import signal
import subprocess


ROOT = Path(__file__).resolve().parent.parent


def command(pid):
    try:
        return Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")[:-1]
    except FileNotFoundError:
        return []


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, action="append", required=True)
    parser.add_argument("--stop", action="store_true")
    parser.add_argument("--reason", choices=("overlapping_jobs", "user_requested_stop"), default="overlapping_jobs")
    args = parser.parse_args()
    if Path.cwd().resolve() != ROOT:
        parser.error("Run from the project root")
    if args.stop and os.geteuid() != 0:
        parser.error("Stopping root study jobs requires sudo")
    rows = {}
    listing = subprocess.check_output(["ps", "-eo", "pid=,ppid="], text=True)
    for line in listing.splitlines():
        pid, parent = map(int, line.split())
        rows[pid] = parent
    targets, units, runs = {}, set(), []
    for requested in args.run:
        run = requested.resolve()
        if run.parent != ROOT / "experiments/runs" or not run.is_dir():
            parser.error("Each run must be an existing immediate experiments/runs directory")
        relative = run.relative_to(ROOT).as_posix().encode()
        found = []
        for pid in rows:
            cmd = command(pid)
            if (b"experiments/run-study.py" in cmd and b"--output" in cmd
                    and cmd[cmd.index(b"--output") + 1] == relative):
                found.append(pid)
        for pid in found:
            descendants = {pid}
            while True:
                more = {child for child, parent in rows.items() if parent in descendants}
                if more <= descendants:
                    break
                descendants |= more
            parent = rows[pid]
            parent_cmd = command(parent)
            # Stop the enclosing confirmation shell so it cannot launch the next runtime.
            if (parent_cmd and parent_cmd[0] == b"bash" and b"-c" in parent_cmd
                    and b"STUDY_GO_MAIN" in b" ".join(parent_cmd)
                    and b"experiments/run-study.py" in b" ".join(parent_cmd)):
                descendants.add(parent)
            for child in descendants:
                cmd = command(child)
                if not cmd:
                    continue
                targets[child] = cmd
                for item in cmd:
                    if item.startswith(b"--unit=accounting-observer-"):
                        unit = item.split(b"=", 1)[1].decode()
                        if not re.fullmatch(r"accounting-observer-[0-9a-f]{12}", unit):
                            raise RuntimeError("Unexpected observer unit")
                        units.add(unit)
        print(f"{run.name}: runner PIDs {found or 'none'}", flush=True)
        runs.append(run)
    print(f"Specific process PIDs: {sorted(targets)}; observer units: {sorted(units)}", flush=True)
    if not args.stop:
        print("Inspection only; pass --stop with sudo to stop these jobs.")
        return
    # Freeze the captured process tree before stopping its services. Recheck
    # command lines to avoid acting on a PID reused since inspection.
    for pid, expected in targets.items():
        if command(pid) == expected:
            try:
                os.kill(pid, signal.SIGSTOP)
            except ProcessLookupError:
                pass
    try:
        for unit in sorted(units):
            subprocess.run(["systemctl", "stop", unit], check=True, timeout=25)
    finally:
        for pid, expected in targets.items():
            if command(pid) == expected:
                try:
                    os.kill(pid, signal.SIGTERM)
                    os.kill(pid, signal.SIGCONT)
                except ProcessLookupError:
                    pass
    for run in runs:
        note = {"reviewed_at_utc": datetime.now(timezone.utc).isoformat(),
                "decision": "excluded_from_confirmation",
                "reason": args.reason,
                "process_pids": sorted(targets), "observer_units": sorted(units)}
        (run / "execution-review.json").write_text(json.dumps(note, indent=2) + "\n", encoding="utf-8")
        (run / "fixture.key").unlink(missing_ok=True)  # Generated disposable fixture key.
        if "SUDO_UID" in os.environ and "SUDO_GID" in os.environ:
            uid, gid = int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])
            for path in [run, *run.rglob("*")]:
                if not path.is_symlink():
                    os.chown(path, uid, gid)
    print("Selected study jobs stopped; research evidence retained.")


if __name__ == "__main__":
    main()
