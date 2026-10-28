#!/usr/bin/env python3
"""Build data/blocklist.bin for the ESP32 sinkhole.

Usage:
  python3 build_blocklist.py                 # uses default list below
  python3 build_blocklist.py URL_OR_FILE ... # hosts-format or plain-domain lists
"""
import os
import struct
import sys
import urllib.request

DEFAULT_SOURCES = [
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
]
SKIP = {"localhost", "localhost.localdomain", "local", "broadcasthost",
        "ip6-localhost", "ip6-loopback", "0.0.0.0"}


def fnv1a64(s: str) -> int:
    h = 0xcbf29ce484222325
    for b in s.lower().encode():
        h ^= b
        h = (h * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
    return h


def read_source(src: str) -> str:
    if src.startswith("http"):
        with urllib.request.urlopen(src) as r:
            return r.read().decode("utf-8", "ignore")
    with open(src, encoding="utf-8", errors="ignore") as f:
        return f.read()


def domains(text: str):
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        d = parts[1] if len(parts) > 1 else parts[0]   # hosts format or bare domain
        d = d.strip(".").lower()
        if "." in d and d not in SKIP:
            yield d


def main():
    sources = sys.argv[1:] or list(DEFAULT_SOURCES)
    if os.path.exists("custom.txt") and "custom.txt" not in sources:
        sources.append("custom.txt")   # your own extra domains, one per line
    names = set()
    for s in sources:
        print(f"reading {s}")
        names.update(domains(read_source(s)))

    hashes = sorted({fnv1a64(d) for d in names})
    os.makedirs("data", exist_ok=True)
    with open("data/blocklist.bin", "wb") as f:
        for h in hashes:
            f.write(struct.pack("<Q", h))
    print(f"{len(hashes)} domains -> data/blocklist.bin "
          f"({len(hashes) * 8 / 1024:.0f} KB)")


if __name__ == "__main__":
    main()
