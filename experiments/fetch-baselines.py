#!/usr/bin/env python3
"""Fetch pinned public baseline binaries, verify hashes, and save provenance."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tarfile
from urllib.request import Request, urlopen


BASELINES = {
    "obi": ("open-telemetry/opentelemetry-ebpf-instrumentation", "v0.13.0",
            "obi-v0.13.0-linux-amd64.tar.gz"),
    "agtap": ("zhebrak/agtap", "v0.1.0", "agtap-v0.1.0-linux-x86_64.tar.gz"),
}


def request(url):
    return urlopen(Request(url, headers={"User-Agent": "research-artifact-fetcher"}),
                   timeout=120)


def api(path):
    with request("https://api.github.com/repos/" + path) as response:
        return json.load(response)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=Path("experiments/.cache/baselines"))
    parser.add_argument("--manifest", type=Path, default=Path("experiments/baselines.json"))
    args = parser.parse_args()
    manifest = {"schema_version": 1, "fetched_at_utc": datetime.now(timezone.utc).isoformat(),
                "hash_verification": "GitHub release asset digest; no Sigstore signature claim",
                "baselines": {}}
    for name, (repo, tag, filename) in BASELINES.items():
        release = api(repo + "/releases/tags/" + tag)
        commit = api(repo + "/commits/" + tag)["sha"]
        asset = next(a for a in release["assets"] if a["name"] == filename)
        expected = asset.get("digest", "")
        if not expected.startswith("sha256:"):
            raise RuntimeError("Release asset has no SHA256 digest: " + filename)
        directory = args.cache / name
        directory.mkdir(parents=True, exist_ok=True)
        archive = directory / filename
        if not archive.exists():
            partial = archive.with_suffix(archive.suffix + ".part")
            with request(asset["browser_download_url"]) as response, partial.open("wb") as out:
                while chunk := response.read(1024 * 1024):
                    out.write(chunk)
            partial.replace(archive)
        with archive.open("rb") as source:
            digest = hashlib.file_digest(source, "sha256").hexdigest()
        if digest != expected.removeprefix("sha256:"):
            raise RuntimeError("Release asset checksum mismatch: " + filename)
        # Extract just the executable, without accepting archive paths/symlinks.
        with tarfile.open(archive) as bundle:
            member = next(m for m in bundle.getmembers()
                          if Path(m.name).name == name and m.isfile())
            source = bundle.extractfile(member)
            binary = directory / name
            with binary.open("wb") as out:
                while chunk := source.read(1024 * 1024):
                    out.write(chunk)
        binary.chmod(0o755)
        with binary.open("rb") as source:
            binary_hash = hashlib.file_digest(source, "sha256").hexdigest()
        manifest["baselines"][name] = {
            "repository": "https://github.com/" + repo, "tag": tag,
            "source_commit": commit, "asset": filename,
            "asset_url": asset["browser_download_url"], "archive_sha256": digest,
            "binary_sha256": binary_hash, "binary": binary.as_posix(),
        }
        print(name, tag, "checksum verified", flush=True)
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
