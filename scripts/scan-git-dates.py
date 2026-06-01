#!/usr/bin/env python3
"""Cross-platform wrapper for git author/committer date skew scanning."""
import importlib
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC = PROJECT_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


def _main() -> int:
    module = importlib.import_module("polinrider_guard.git_dates")
    return module.main()


if __name__ == "__main__":
    raise SystemExit(_main())
