from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

DEFAULT_EXCLUDES = {
    ".git",
    ".hg",
    ".svn",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    "node_modules",
    "dist",
    "build",
    ".venv",
    "venv",
}


def iter_files(root: Path, excludes: set[str] | None = None) -> Iterator[Path]:
    """Yield files below *root* while pruning noisy/generated directories."""
    excludes = DEFAULT_EXCLUDES if excludes is None else excludes
    root = root.resolve()
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in excludes]
        for filename in filenames:
            yield Path(dirpath) / filename


def read_prefix(path: Path, limit: int = 8192) -> bytes:
    with path.open("rb") as handle:
        return handle.read(limit)
