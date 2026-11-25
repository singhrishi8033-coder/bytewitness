"""Offline evidence collection for static file triage."""
import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import re
import stat
import sys

LIMIT = 16 * 1024 * 1024
WINDOW = 4096
MAX_EVIDENCE = 32
URL = re.compile(rb"""https?://[^\s\x00-\x20\x7f-\xff"'<>]{1,512}""", re.I)
EXECUTABLE_SUFFIXES = {".exe", ".dll", ".sys", ".scr", ".ocx", ".efi"}


def identify(data):
    if data.startswith(b"MZ") and len(data) >= 64:
        offset = int.from_bytes(data[60:64], "little")
        if 64 <= offset <= len(data) - 24 and data[offset:offset + 4] == b"PE\0\0":
            return "PE signature"
    for signature, label in [(b"\x7fELF", "ELF signature"), (b"MZ", "MZ prefix"),
                             (b"%PDF-", "PDF signature"), (b"PK\x03\x04", "ZIP signature")]:
        if data.startswith(signature):
            return label
    return "unrecognized"


def entropy(block):
    return -sum((n / len(block)) * math.log2(n / len(block))
                for n in Counter(block).values())


def collect(name, data, known):
    digest = hashlib.sha256(data).hexdigest()
    kind = identify(data)
    findings = []
    if digest in known:
        findings.append({"rule": "local_hash_match", "sha256": digest})
    if kind == "PE signature" and Path(name).suffix.lower() not in EXECUTABLE_SUFFIXES:
        findings.append({"rule": "unexpected_pe_extension", "offset": 0})
    urls = []
    count = 0
    for match in URL.finditer(data):
        count += 1
        if len(urls) < MAX_EVIDENCE:
            urls.append({"offset": match.start(), "text": match[0].decode("ascii")})
    regions = []
    region_count = 0
    for start in range(0, len(data) - WINDOW + 1, WINDOW):
        value = entropy(data[start:start + WINDOW])
        if value >= 7.5:
            region_count += 1
            if len(regions) < MAX_EVIDENCE:
                regions.append({"offset": start, "length": WINDOW,
                                "bits_per_byte": round(value, 4)})
    return {"file": name, "bytes": len(data), "sha256": digest, "format": kind,
            "findings": findings, "url_count": count, "urls": urls,
            "high_entropy_window_count": region_count, "high_entropy_windows": regions}


def read_regular(path):
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError(f"{path} is not a regular file")
    if path.stat().st_size > LIMIT:
        raise ValueError(f"{path} exceeds the 16 MiB limit")
    with path.open("rb") as stream:
        data = stream.read(LIMIT + 1)
    if len(data) > LIMIT:
        raise ValueError(f"{path} exceeds the 16 MiB limit")
    return data


def read_hashes(path):
    hashes = set()
    for number, line in enumerate(read_regular(path).decode("ascii").splitlines(), 1):
        value = line.partition("#")[0].strip().lower()
        if value and not re.fullmatch(r"[a-f0-9]{64}", value):
            raise ValueError(f"{path}, line {number}: expected a SHA-256 digest")
        if value:
            hashes.add(value)
    return hashes


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", type=Path, nargs="+")
    parser.add_argument("--watchlist", type=Path, help="one SHA-256 per line")
    args = parser.parse_args(argv)
    try:
        known = read_hashes(args.watchlist) if args.watchlist else set()
    except (OSError, ValueError) as exc:
        parser.exit(2, f"Invalid watchlist: {exc}\n")
    errors = []
    reports = []
    for path in args.files:
        try:
            reports.append(collect(str(path), read_regular(path), known))
        except (OSError, ValueError) as exc:
            errors.append({"file": str(path), "error": str(exc)})
    print(json.dumps({"schema_version": 1, "reports": reports, "errors": errors}, indent=2))
    return int(bool(errors))


if __name__ == "__main__":
    sys.exit(main())
