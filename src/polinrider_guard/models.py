from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Finding:
    """A normalized scanner finding."""

    rule_id: str
    severity: str
    message: str
    path: Path | None = None
    line: int | None = None
    column: int | None = None
    evidence: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self, root: Path | None = None) -> dict[str, Any]:
        path_value: str | None = None
        if self.path is not None:
            try:
                path_value = str(self.path.relative_to(root)) if root else str(self.path)
            except ValueError:
                path_value = str(self.path)
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "path": path_value,
            "line": self.line,
            "column": self.column,
            "evidence": self.evidence,
            "metadata": self.metadata,
        }
