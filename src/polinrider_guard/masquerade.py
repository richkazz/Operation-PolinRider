from __future__ import annotations

import argparse
import json
import math
import re
import sys
from pathlib import Path

from .models import Finding
from .walk import iter_files, read_prefix

BINARY_DISGUISE_EXTENSIONS = {
    ".woff",
    ".woff2",
    ".ttf",
    ".otf",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".wasm",
}
MAGIC_BYTES = {
    ".woff": (b"wOFF",),
    ".woff2": (b"wOF2",),
    ".ttf": (b"\x00\x01\x00\x00", b"true", b"typ1"),
    ".otf": (b"OTTO",),
    ".png": (b"\x89PNG\r\n\x1a\n",),
    ".jpg": (b"\xff\xd8\xff",),
    ".jpeg": (b"\xff\xd8\xff",),
    ".gif": (b"GIF87a", b"GIF89a"),
    ".ico": (b"\x00\x00\x01\x00",),
    ".wasm": (b"\x00asm",),
}
SCRIPT_MARKERS = re.compile(
    rb"(function\s*\(|!function\s*\(|=>\s*\{|require\s*\(|import\s+|eval\s*\(|global\s*\[|"
    rb"process\.|exec\(|subprocess\.|os\.system|Buffer\.from\s*\(|atob\s*\(|"
    rb"String\.fromCharCode\s*\(|var\s+_0x)"
)
C2_MARKERS = re.compile(
    rb"(trongrid\.io|aptoslabs\.com|bsc-dataseed|solana|MemoSq4gq|aptos-mainnet\.nodereal)", re.I
)
IOC_MARKERS = re.compile(
    rb"(rmcej.{0,5}otb|global\[.{0,3}_V.{0,3}\]\s*=\s*.{0,3}8-(st\d{1,3}|\d{3,4}))"
)


def printable_ratio(data: bytes) -> float:
    if not data:
        return 1.0
    printable = sum(byte in b"\t\n\r" or 32 <= byte <= 126 for byte in data)
    return printable / len(data)


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = {byte: data.count(byte) for byte in set(data)}
    return -sum((count / len(data)) * math.log2(count / len(data)) for count in counts.values())


def scan_file(path: Path) -> list[Finding]:
    ext = path.suffix.lower()
    if ext not in BINARY_DISGUISE_EXTENSIONS:
        return []
    try:
        if path.stat().st_mode & 0o444 == 0:
            return [
                Finding("file.read_error", "low", "file has no read permission bits", path=path)
            ]
        data = read_prefix(path, 64 * 1024)
    except OSError as exc:
        return [Finding("file.read_error", "low", str(exc), path=path)]
    expected = MAGIC_BYTES.get(ext, ())
    has_valid_magic = any(data.startswith(magic) for magic in expected)
    ratio = printable_ratio(data)
    file_entropy = entropy(data)
    findings: list[Finding] = []
    if not has_valid_magic and ratio > 0.75 and SCRIPT_MARKERS.search(data):
        findings.append(
            Finding(
                "masquerade.binary_extension_contains_script",
                "critical",
                f"{ext} file looks like script text instead of its declared binary format",
                path=path,
                evidence="script marker in high-printable binary-extension file",
                metadata={"printable_ratio": round(ratio, 3), "entropy": round(file_entropy, 3)},
            )
        )
    if C2_MARKERS.search(data):
        findings.append(
            Finding(
                "ioc.blockchain_or_known_endpoint_marker",
                "high",
                "Known endpoint or blockchain C2 marker appears in disguised file",
                path=path,
                evidence="endpoint marker",
                metadata={"printable_ratio": round(ratio, 3), "entropy": round(file_entropy, 3)},
            )
        )
    if IOC_MARKERS.search(data):
        findings.append(
            Finding(
                "ioc.polinrider_version_or_marker",
                "critical",
                "Known PolinRider version tag or marker appears in file",
                path=path,
                evidence="PolinRider IOC marker",
                metadata={"printable_ratio": round(ratio, 3), "entropy": round(file_entropy, 3)},
            )
        )
    return findings


def scan_path(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in iter_files(root):
        findings.extend(scan_file(path))
    return findings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Detect script payloads hidden behind binary extensions."
    )
    parser.add_argument("path", nargs="?", default=".", help="File or directory to scan.")
    parser.add_argument("--json", action="store_true", help="Emit JSON findings.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.path).resolve()
    findings = scan_path(root)
    if args.json:
        print(json.dumps([finding.to_dict(root) for finding in findings], indent=2, sort_keys=True))
    else:
        for finding in findings:
            print(f"{finding.path}: {finding.message}")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
