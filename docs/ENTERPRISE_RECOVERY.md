# Part 3: Programmatic Enterprise Recovery and CI Hardening

For platform engineers and repository administrators. Goal: surgically clean many repositories that have accumulated legitimate commits on top of malicious ones, harden all repositories against future injection, and build a CI pipeline that detects any recurrence automatically.

## The Challenge of Cleaning History with Commits On Top

The naive approach to removing a malicious commit is `git revert`. This works perfectly when the bad commit is at the HEAD of the branch — you simply add a new commit that undoes the changes. But when legitimate developer work has accumulated on top of the injection, a revert will partially undo that work (because the diff conflicts) or leave behind a messy three-way merge that is hard to audit.

The second naive approach is `git filter-branch` or `git filter-repo --path --invert-paths`, which removes an entire file from history. But PolinRider only appended a few lines to the end of existing legitimate files — removing the entire file would destroy months of legitimate development.

The correct approach is what we call a surgical clean: use `git filter-repo`'s blob callback API to rewrite every historical snapshot of every affected file, removing only the malicious lines while leaving all legitimate content intact. The result is a history that looks exactly as it would have if the injection had never happened, with every legitimate commit preserved in its correct position.

### 3.1 — Setting Up git-filter-repo

```bash
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
```

### 3.2 — The Surgical Clean Engine

The key insight of this script is that `git filter-repo`'s blob callback receives every single file snapshot that has ever existed across every commit in the entire history. By scanning each blob for IOC patterns and stripping only the matching lines, we rewrite the repository's object database so that the payload never appears anywhere in any historical state, while all other content remains exactly unchanged.

See `scripts/surgical-clean.py` for the implementation.

### 3.3 — Batch Clean Across Many Repositories

For organizations managing dozens or hundreds of repositories, manual cleaning is not viable.

See `scripts/batch-clean.sh` for an automated recovery script that handles forensic snapshots, surgical cleaning, verification, and force-pushing across multiple repositories flagged in a triage report.
