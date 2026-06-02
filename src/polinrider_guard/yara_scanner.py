from __future__ import annotations

import logging
from pathlib import Path

from .models import Finding
from .walk import iter_files

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False

RULES_PATH = Path(__file__).parent / "rules" / "polinrider.yar"


def scan_path(root: Path) -> list[Finding]:
    if not HAS_YARA:
        return []

    if not RULES_PATH.exists():
        logging.warning(f"YARA rules not found at {RULES_PATH}")
        return []

    try:
        rules = yara.compile(filepath=str(RULES_PATH), externals={"filename": ""})
    except yara.Error as exc:
        logging.error(f"Failed to compile YARA rules: {exc}")
        return []

    findings: list[Finding] = []
    for path in iter_files(root):
        try:
            matches = rules.match(str(path), externals={"filename": path.name})
            for match in matches:
                evidence = None
                if match.strings:
                    try:
                        s = match.strings[0]
                        evidence = str(getattr(s, "instances", [s])[0].matched_data)
                    except (IndexError, AttributeError):
                        evidence = str(match.strings[0])

                findings.append(
                    Finding(
                        rule_id=f"yara.{match.rule}",
                        severity=match.meta.get("severity", "high"),
                        message=match.meta.get("description", "YARA match"),
                        path=path,
                        evidence=evidence,
                        metadata={
                            "campaign": match.meta.get("campaign"),
                            "tags": match.tags,
                        },
                    )
                )
        except (yara.Error, OSError):
            continue

    return findings
