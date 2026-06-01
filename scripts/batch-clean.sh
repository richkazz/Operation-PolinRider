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

# Get absolute path to the surgical-clean.py script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLEAN_SCRIPT="$SCRIPT_DIR/surgical-clean.py"

while IFS=$'\t' read -r repo status inject_hash inject_date email files commits ioc notes; do
    [[ "$repo" == "repo" ]] && continue
    [[ "$status" == "CLEAN" ]] && { ((SKIP_COUNT++)); continue; }
    [[ -z "$repo" ]] && continue

    echo "========================================"
    echo "Processing: $repo [$status]"

    REPO_DIR="./$repo"
    if [[ ! -d "$REPO_DIR" ]]; then
        echo "  SKIP: directory not found"
        ((SKIP_COUNT++))
        continue
    fi

    # Verify it is a git repo (handles both normal and bare/mirror clones)
    if ! (cd "$REPO_DIR" && git rev-parse --is-inside-git-dir >/dev/null 2>&1); then
        echo "  SKIP: not a git repository"
        ((SKIP_COUNT++))
        continue
    fi

    SNAPSHOT="forensic-${repo}-$(date +%s).tar.gz"
    tar -czf "$SNAPSHOT" "$REPO_DIR/" 2>/dev/null
    echo "  Snapshot: $SNAPSHOT"

    # Save remotes because git-filter-repo might remove them
    REMOTES=$(cd "$REPO_DIR" && git remote -v | grep '(push)' | awk '{print $1 " " $2}')

    (cd "$REPO_DIR" && python3 "$CLEAN_SCRIPT" 2>&1) | head -20

    # Restore remotes if they were removed
    while read -r name url; do
        if [[ -n "$name" ]]; then
            (cd "$REPO_DIR" && git remote add "$name" "$url" 2>/dev/null || git remote set-url "$name" "$url")
        fi
    done <<< "$REMOTES"

    # Verify - no IOC anywhere in full history
    # Using 'git log --all -p' to check history, not just current files
    IOC_REMAINING=$(cd "$REPO_DIR" && git log --all -p \
        -- '*.js' '*.mjs' '*.ts' 2>/dev/null | \
        grep -cE \
        "global\[.{0,5}_V.{0,5}\].*8-|eval\s*\(\s*Buffer\.from|trongrid\.io|bsc-dataseed" \
        || true)

    # Unicode check in history
    UNICODE_REMAINING=$(cd "$REPO_DIR" && git log --all -p \
        -- '*.js' '*.mjs' 2>/dev/null | \
        grep -cP '[\x{200B}-\x{200F}\x{FE00}-\x{FE0F}]' || true)

    if [[ "$IOC_REMAINING" -gt 0 || "$UNICODE_REMAINING" -gt 0 ]]; then
        echo "  FAIL: IOC still present ($IOC_REMAINING IOCs, $UNICODE_REMAINING Unicode) - moving to manual-review/"
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
