"""What every reporter is given, and helpers they share."""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path

from scanner.judge.judge import JudgeResult
from scanner.models import Finding, ServerSnapshot, Severity

TOOL_NAME = "mcp-poison-scanner"


def tool_version() -> str:
    try:
        return metadata.version(TOOL_NAME)
    except metadata.PackageNotFoundError:
        return "0.0.0"


@dataclass
class ScanReport:
    """Everything one scan produced."""

    snapshots: Sequence[ServerSnapshot]
    findings: Sequence[Finding]
    judge: JudgeResult | None = None
    """The judge's run summary, when ``--judge`` was used."""
    notes: Sequence[str] = ()
    """Remarks that are not findings (for example, a server that is not pinned). Safe to print."""
    sources: dict[str, Path] = field(default_factory=dict)
    """Server name -> the snapshot file it was read from, for servers that came from a file."""

    def severity_counts(self) -> dict[str, int]:
        counts = Counter(f.severity for f in self.findings)
        return {s.value: counts[s] for s in sorted(Severity, key=lambda s: -s.rank)}
