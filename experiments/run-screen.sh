#!/usr/bin/env bash
# Run from the project root after reviewing the study protocol and runner.
set -euo pipefail
if [[ $EUID -ne 0 ]]; then
  echo 'Run with sudo; only the fixture client PID is selected for capture.' >&2
  exit 1
fi
if [[ ! -f experiments/baselines.json || ! -x .venv/bin/python ]]; then
  echo 'Run from the prepared project root.' >&2
  exit 1
fi
study_runtime=${1:-python}
study_mode=${2:-screen}
case "$study_runtime" in python|go) ;; *) echo 'Runtime must be python or go.' >&2; exit 1 ;; esac
case "$study_mode" in screen|main) ;; *) echo 'Mode must be screen or main.' >&2; exit 1 ;; esac
mkdir -p experiments/runs
study_stamp=$(date -u +%Y-%m-%dT%H-%M-%SZ)
study_log="experiments/runs/${study_stamp}-${study_runtime}-${study_mode}.log"
study_output="experiments/runs/${study_stamp}-${study_runtime}-${study_mode}"
set -o noclobber
nohup systemd-inhibit --what=sleep:idle:handle-lid-switch \
  --why='Local TLS accounting research screen' \
  flock -n experiments/runs/.observer-job.lock \
  .venv/bin/python experiments/run-study.py --mode "$study_mode" --runtime "$study_runtime" \
  --observers control obi --output "$study_output" \
  >"$study_log" 2>&1 </dev/null &
study_pid=$!
if [[ -n ${SUDO_UID:-} && -n ${SUDO_GID:-} ]]; then
  chown "$SUDO_UID:$SUDO_GID" "$study_log"
fi
echo "Study PID: $study_pid"
echo "Log: $study_log"
echo "Evidence: $study_output"
