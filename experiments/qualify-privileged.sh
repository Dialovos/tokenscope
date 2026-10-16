#!/usr/bin/env bash
# Every privileged tsd integration test, run as root one binary at a time in a
# dedicated loopback-only scope. Run as the normal user from anywhere: it builds
# without root and asks sudo only to run the test binaries. Synthetic loopback
# traffic only; no provider calls. Logs and exit codes go to
# target/implementation-checks/. Requires exclusive use of the pinned filter.
set -euo pipefail
cd "$(dirname "$0")/.."
checks=target/implementation-checks
mkdir -p "$checks"
pin=/sys/fs/bpf/tokenscope/cgroup_filter

sudo -v
if sudo test -e "$pin"; then
    echo "Refusing: $pin already exists." >&2
    echo "Another observer or an earlier run owns it; inspect it before removing." >&2
    exit 2
fi

# Optional machine-local toolchain selection (ignored by Git).
if [[ -f "$checks/env.sh" ]]; then
    source "$checks/env.sh"
fi
cargo build --workspace --all-targets --locked --offline
cargo test -p tsd --tests --no-run --locked --offline \
    --message-format=json > "$checks/privileged-build.jsonl"
mapfile -t binaries < <(python3 - "$checks/privileged-build.jsonl" <<'PY'
import json, sys
from pathlib import Path
for line in Path(sys.argv[1]).read_text().splitlines():
    obj = json.loads(line)
    target = obj.get('target', {})
    if (obj.get('reason') == 'compiler-artifact' and obj.get('executable')
            and target.get('kind') == ['test']):
        print(target['name'], obj['executable'])
PY
)

overall=0
summary=()
for entry in "${binaries[@]}"; do
    name=${entry%% *}
    binary=${entry#* }
    log="$checks/privileged-$name.log"
    if sudo systemd-run --scope -p IPAddressDeny=any -p IPAddressAllow=localhost \
        systemd-inhibit --what=sleep:idle:handle-lid-switch \
        --why='Synthetic TokenScope qualification' \
        "$binary" --ignored --test-threads=1 --nocapture > "$log" 2>&1; then
        status=0
    else
        status=$?
        overall=1
    fi
    printf '%s\n' "$status" > "$checks/privileged-$name.exit"
    summary+=("$(printf '%-16s exit %-3s %s' "$name" "$status" "$(grep -E '^test result' "$log" | tail -n 1)")")
done

echo "--- results (logs: $checks/privileged-<name>.log)"
printf '%s\n' "${summary[@]}"
# The pin was absent at the start, so this run's daemons created it.
if sudo test -e "$pin"; then
    sudo rm "$pin"
    echo "Removed the cgroup_filter pin this run created."
fi
exit "$overall"
