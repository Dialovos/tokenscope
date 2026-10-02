#!/usr/bin/env bash
# Qualify Go HTTP/2, then collect ten-seed matrices sequentially.
set -euo pipefail
if [[ $EUID -ne 0 ]]; then
  echo 'Run with sudo from the prepared project root.' >&2
  exit 1
fi
if [[ ! -x .venv/bin/python || ! -x experiments/.cache/accounting-client ]]; then
  echo 'The Python environment and compiled Go fixture must be prepared first.' >&2
  exit 1
fi
mkdir -p experiments/runs
study_stamp=$(date -u +%Y-%m-%dT%H-%M-%SZ)
study_log="experiments/runs/${study_stamp}-confirmation.log"
study_go_screen="experiments/runs/${study_stamp}-go-screen"
study_go_main="experiments/runs/${study_stamp}-go-main"
study_python_main="experiments/runs/${study_stamp}-python-main"
export STUDY_GO_SCREEN="$study_go_screen"
export STUDY_GO_MAIN="$study_go_main"
export STUDY_PYTHON_MAIN="$study_python_main"
set -o noclobber
nohup systemd-inhibit --what=sleep:idle:handle-lid-switch \
  --why='Local ten-seed accounting study' bash -c '
    set -euo pipefail
    exec 9>experiments/runs/.observer-job.lock
    flock -n 9 || { echo "Another observer job holds the study lock; exiting." >&2; exit 1; }
    .venv/bin/python experiments/run-study.py --mode screen --runtime go \
      --observers control obi --output "$STUDY_GO_SCREEN"
    .venv/bin/python - <<"PY"
import json, os
from pathlib import Path
root = Path(os.environ["STUDY_GO_SCREEN"])
for protocol in ("http1", "http2"):
    report = json.loads((root / ("obi-" + protocol + "-000") / "score.json").read_text())
    control = next(t for t in report["trials"] if t["parameters"]["scenario"] == "complete"
                   and t["parameters"]["concurrency"] == 1 and t["parameters"]["seed"] == 0)
    if report["status"] != "ok" or control["summary"]["exact_attempts"] != 1:
        raise SystemExit("Go " + protocol + " usage not qualified; retain diagnostics and stop")
print("Go HTTP/1.1 and HTTP/2 clean usage capture qualified", flush=True)
PY
    .venv/bin/python experiments/run-study.py --mode main --runtime go \
      --observers control obi --output "$STUDY_GO_MAIN"
    .venv/bin/python experiments/run-study.py --mode main --runtime python \
      --protocols http1 --observers control obi --output "$STUDY_PYTHON_MAIN"
    echo "Confirmation matrices finished; inspect and analyze before publication."
  ' >"$study_log" 2>&1 </dev/null &
study_pid=$!
if [[ -n ${SUDO_UID:-} && -n ${SUDO_GID:-} ]]; then
  chown "$SUDO_UID:$SUDO_GID" "$study_log"
fi
echo "Study PID: $study_pid"
echo "Log: $study_log"
echo "Go qualification: $study_go_screen"
echo "Go confirmation: $study_go_main"
echo "Python confirmation: $study_python_main"
