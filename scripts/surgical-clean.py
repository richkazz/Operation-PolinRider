#!/usr/bin/env python3
# surgical-clean.py - surgically remove PolinRider payload from git history
#
# Usage:
#   python3 surgical-clean.py                (run from repo directory)
#   python3 surgical-clean.py --dry-run      (preview, no changes)
#
# Requires: git-filter-repo (pip install git-filter-repo)
# IMPORTANT: Run from a MIRROR CLONE, not your original repo directory.

import argparse
import re
import subprocess
import sys

# IOC patterns compiled against raw byte content.
RAW_IOC_PATTERNS = [
    rb"global\[.{0,5}_V.{0,5}\]\s*=\s*.{0,5}8-",
    rb"rmcej.{0,5}otb",
    rb"eval\s*\(\s*Buffer\.from",
    rb"eval\s*\(\s*atob\s*\(",
    rb"trongrid\.io",
    rb"fullnode\.mainnet\.aptoslabs\.com",
    rb"bsc-dataseed",
    rb"aptos-mainnet\.nodereal",
    rb"String\.fromCharCode\((?:\d+,\s*){15,}",
    rb"\.split\(..\)\.map.*XOR.*eval",
]

# Invisible/suspicious Unicode ranges
UNICODE_IOC_RANGES = (
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0xFE00, 0xFE0F),
    (0xE000, 0xF8FF),
)

class SurgicalCleaner:
    def __init__(self, dry_run=False, verbose=False):
        self.dry_run = dry_run
        self.verbose = verbose
        self.compiled_patterns = [re.compile(p, re.IGNORECASE) for p in RAW_IOC_PATTERNS]
        self.blobs_cleaned = 0
        self.lines_removed = 0
        self.blobs_scanned = 0

    def clean_line(self, line):
        """
        Surgically remove only the malicious parts of a line if possible,
        or return None to drop line.
        """
        # 1. Regex patterns - usually whole line injections
        for pattern in self.compiled_patterns:
            if pattern.search(line):
                return None

        # 2. Invisible Unicode - often appended to legitimate lines
        try:
            text = line.decode('utf-8')
            has_ioc = False
            for start, end in UNICODE_IOC_RANGES:
                # Build regex for these characters
                pattern = f"[{chr(start)}-{chr(end)}]"
                if re.search(pattern, text):
                    text = re.sub(pattern, "", text)
                    has_ioc = True
            if has_ioc:
                return text.encode('utf-8')
        except UnicodeDecodeError:
            pass

        return line

    def clean_blob(self, blob, metadata=None):
        """
        Callback for git-filter-repo.
        Note: API varies between git-filter-repo versions on whether metadata is passed.
        We handle both by using an optional argument.
        """
        self.blobs_scanned += 1

        lines = blob.data.split(b'\n')
        new_lines = []
        changed = False
        removed_count = 0

        for line in lines:
            cleaned = self.clean_line(line)
            if cleaned != line:
                changed = True
                if cleaned is None:
                    removed_count += 1
                else:
                    new_lines.append(cleaned)
            else:
                new_lines.append(line)

        if not changed:
            return

        self.blobs_cleaned += 1
        self.lines_removed += removed_count

        if self.verbose or self.dry_run:
            # We don't have filename in blob_callback unfortunately
            print(f"  Blob {blob.original_id.decode()[:8]}... - Cleaned")

        if not self.dry_run:
            blob.data = b'\n'.join(new_lines)

    def print_summary(self):
        mode = "DRY RUN - " if self.dry_run else ""
        print(f"\n{'='*60}")
        print(f"{mode}SURGICAL CLEAN SUMMARY")
        print(f"{'='*60}")
        print(f"  Blobs scanned:  {self.blobs_scanned}")
        print(f"  Blobs cleaned:  {self.blobs_cleaned}")
        print(f"  Lines removed:  {self.lines_removed}")
        if self.blobs_cleaned == 0:
            print("\n  Repository appears CLEAN - no IOC patterns found.")
        print(f"{'='*60}\n")

def main():
    parser = argparse.ArgumentParser(
        description='Surgically remove PolinRider payload from git history')
    parser.add_argument('--dry-run', action='store_true', help='Preview changes')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    args = parser.parse_args()

    # In a bare repository (mirror clone), there is no .git directory.
    # We check if we are in a git repository at all.
    try:
        subprocess.run(['git', 'rev-parse', '--is-inside-git-dir'],
                       check=True, capture_output=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Error: not a git repository.")
        sys.exit(1)

    try:
        import git_filter_repo as fr
    except ImportError:
        print("Error: git-filter-repo not installed.")
        sys.exit(1)

    cleaner = SurgicalCleaner(dry_run=args.dry_run, verbose=args.verbose)
    filter_args = fr.FilteringOptions.default_options()
    filter_args.force = True
    filter_args.prune_empty = 'never'

    repo_filter = fr.RepoFilter(
        filter_args,
        blob_callback=cleaner.clean_blob
    )
    repo_filter.run()
    cleaner.print_summary()
    return 0 if cleaner.blobs_cleaned == 0 else 1

if __name__ == '__main__':
    sys.exit(main())
