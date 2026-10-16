#!/usr/bin/env python3
"""Execute actual TLS probe C functions with mocked helpers; no verifier claim."""
import argparse
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cc', default='cc')
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    source = (root / 'bpf/tls.bpf.c').read_text(encoding='utf-8')
    for include in ['"vmlinux.h"', '<bpf/bpf_helpers.h>', '<bpf/bpf_tracing.h>', '<bpf/bpf_core_read.h>']:
        line = '#include ' + include + '\n'
        if source.count(line) != 1:
            raise RuntimeError('Unexpected kernel includes in TLS probe')
        source = source.replace(line, '')
    scratch = root / 'target/implementation-checks'
    scratch.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='tls-inflight-', dir=scratch) as directory:
        directory = Path(directory)
        (directory / 'tls-probe-under-test.c').write_text(source, encoding='utf-8')
        executable = directory / 'fixture'
        subprocess.run([args.cc, '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                        '-Wno-unused-parameter', '-Wno-unknown-pragmas',
                        '-I', str(directory), '-I', str(root / 'bpf'),
                        str(root / 'experiments/tls-inflight-fixture.c'),
                        '-o', str(executable)], check=True)
        subprocess.run([str(executable)], check=True)


if __name__ == '__main__':
    main()
