from __future__ import annotations

import argparse
import json
import sys
import unicodedata
from pathlib import Path

from .models import Finding
from .walk import iter_files

SUSPICIOUS_RANGES = (
    (0x200B, 0x200F, "zero-width/bidi formatting character"),
    (0x202A, 0x202E, "bidirectional override/embedding character"),
    (0x2060, 0x206F, "invisible formatting character"),
    (0xFE00, 0xFE0F, "variation selector"),
    (0xE000, 0xF8FF, "private-use character"),
)
TEXT_EXTENSIONS = {
    ".bat", ".c", ".cc", ".cpp", ".cs", ".css", ".go", ".h", ".hpp", ".html",
    ".java", ".js", ".jsx", ".json", ".kt", ".md", ".mjs", ".php", ".ps1",
    ".py", ".rb", ".rs", ".sh", ".sql", ".swift", ".ts", ".tsx", ".txt",
    ".yaml", ".yml",
}


def suspicious_codepoint(character: str) -> str | None:
    codepoint = ord(character)
    for start, end, label in SUSPICIOUS_RANGES:
        if start <= codepoint <= end:
            return label
    return None


def scan_text(text: str, path: Path | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for column, character in enumerate(line, start=1):
            label = suspicious_codepoint(character)
            if label is None:
                continue
            codepoint = f"U+{ord(character):04X}"
            name = unicodedata.name(character, "UNKNOWN")
            findings.append(
                Finding(
                    rule_id="unicode.invisible_or_private_use",
                    severity="high",
                    message=f"Suspicious {label}: {codepoint} {name}",
                    path=path,
                    line=line_number,
                    column=column,
                    evidence=codepoint,
                    metadata={"unicode_name": name, "category": unicodedata.category(character)},
                )
            )
    return findings


def scan_file(path: Path) -> list[Finding]:
    if path.suffix.lower() not in TEXT_EXTENSIONS:
        return []
    try:
        if path.stat().st_mode & 0o444 == 0:
            return [
                Finding("file.read_error", "low", "file has no read permission bits", path=path)
            ]
        data = path.read_bytes()
    except OSError as exc:
        return [Finding("file.read_error", "low", str(exc), path=path)]
    if b"\x00" in data[:4096]:
        return []
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return []
    return scan_text(text, path)


def scan_path(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in iter_files(root):
        findings.extend(scan_file(path))
    return findings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan source files for invisible Unicode indicators."
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
            location = finding.path or root
            print(f"{location}:{finding.line}:{finding.column}: {finding.message}")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
