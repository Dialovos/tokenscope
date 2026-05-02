#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Fetch a vmlinux BTF dump for the running kernel from BTFHub when
# /sys/kernel/btf/vmlinux is not available (e.g., kernels built without
# CONFIG_DEBUG_INFO_BTF). Writes bpf/vmlinux.h to stdout-friendly C format.
#
# Usage:
#   ./vmlinux/fetch-btf.sh                  # auto-detect distro + kernel
#   ./vmlinux/fetch-btf.sh ubuntu 22.04 5.15.0-91-generic
#
# Exit codes:
#   0 success
#   1 BTF could not be located on BTFHub for this kernel
#   2 missing required tool (curl, tar, bpftool)

set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${REPO_ROOT}/bpf/vmlinux.h"
CACHE="${REPO_ROOT}/vmlinux/btf-cache"
mkdir -p "$CACHE"

require() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "missing required tool: $1" >&2
        exit 2
    fi
}
require curl
require tar
require bpftool

# 1. Fast path: kernel exposes BTF directly.
if [[ -r /sys/kernel/btf/vmlinux ]]; then
    echo "kernel exposes BTF; dumping directly" >&2
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$OUT"
    echo "wrote $OUT" >&2
    exit 0
fi

# 2. Otherwise, look up BTFHub.
DISTRO="${1:-}"
RELEASE="${2:-}"
KERNEL="${3:-$(uname -r)}"
ARCH="$(uname -m)"

if [[ -z "$DISTRO" || -z "$RELEASE" ]]; then
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        DISTRO="${ID:-unknown}"
        RELEASE="${VERSION_ID:-unknown}"
    else
        echo "cannot detect distro; pass DISTRO RELEASE as args" >&2
        exit 1
    fi
fi

URL="https://github.com/aquasecurity/btfhub-archive/raw/main/${DISTRO}/${RELEASE}/${ARCH}/${KERNEL}.btf.tar.xz"
TARBALL="${CACHE}/${KERNEL}.btf.tar.xz"

echo "fetching ${URL}" >&2
if ! curl -fLo "$TARBALL" "$URL"; then
    echo "no BTF on BTFHub for ${DISTRO} ${RELEASE} ${KERNEL} ${ARCH}" >&2
    exit 1
fi

tar -xJf "$TARBALL" -C "$CACHE"
BTF_FILE="${CACHE}/${KERNEL}.btf"

if [[ ! -r "$BTF_FILE" ]]; then
    echo "extracted archive missing ${BTF_FILE}" >&2
    exit 1
fi

bpftool btf dump file "$BTF_FILE" format c > "$OUT"
echo "wrote $OUT" >&2
