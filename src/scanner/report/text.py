"""Plain-text report for the terminal.

Every piece of server-controlled text (server names, item names, pointers) goes
through ``visible`` before printing, so a hostile server cannot inject terminal
escape codes or reorder the report with direction overrides. Finding evidence is
already escaped when the finding is created.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence

from scanner.judge.judge import JudgeResult
from scanner.models import Finding, ServerSnapshot, Severity
from scanner.report.common import ScanReport
from scanner.textutil import visible

_KIND_LABEL = {
    "server": "server",
    "tool": "tool",
    "prompt": "prompt",
    "resource": "resource",
    "resource_template": "resource template",
}


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


def _inventory(snapshot: ServerSnapshot) -> str:
    return ", ".join(
        [
            _plural(len(snapshot.tools), "tool"),
            _plural(len(snapshot.prompts), "prompt"),
            _plural(len(snapshot.resources), "resource"),
            _plural(len(snapshot.resource_templates), "resource template"),
        ]
    )


def _severity_counts(findings: Sequence[Finding]) -> str:
    counts = Counter(f.severity for f in findings)
    parts = [f"{counts[s]} {s.value}" for s in sorted(Severity, key=lambda s: -s.rank) if counts[s]]
    return ", ".join(parts)


def _judge_lines(judge: JudgeResult) -> list[str]:
    models = ", ".join(sorted(judge.models)) or "no model answered"
    lines = [
        f"Judge: {_plural(judge.judged, 'item')} classified by {visible(models)} "
        f"({judge.input_tokens:,} input and {judge.output_tokens:,} output tokens)."
    ]
    if judge.errors:
        lines.append(f"  warning: {_plural(len(judge.errors), 'item')} could not be judged and may still be unsafe:")
        lines.extend(f"    {err}" for err in judge.errors)
    return lines


def render_text(report: ScanReport) -> str:
    snapshots, findings, judge = report.snapshots, report.findings, report.judge
    lines: list[str] = []
    for snapshot in snapshots:
        mine = [f for f in findings if f.server == snapshot.server_name]
        status = f"{_plural(len(mine), 'finding')} ({_severity_counts(mine)})" if mine else "no findings"
        lines.append(f"{visible(snapshot.server_name)}: {_inventory(snapshot)} - {status}")
        for err in snapshot.errors:
            lines.append(f"  warning: collection problem: {visible(err)}")
        for f in mine:
            where = f"{_KIND_LABEL[f.item_kind]} {visible(f.item_name)}"
            lines.append("")
            lines.append(f"  {f.severity.value.upper():<6} {f.rule_id}  {f.title}")
            lines.append(f"         where:    {where}  {visible(f.pointer)}")
            lines.append(f"         what:     {f.message}")
            lines.append(f"         evidence: {f.evidence}")
            lines.append(f"         fix:      {f.remediation}")
        lines.append("")

    lines.extend(f"note: {note}" for note in report.notes)
    if judge is not None:
        lines.extend(_judge_lines(judge))
    total = len(findings)
    scanned = _plural(len(snapshots), "server")
    if total:
        lines.append(f"Summary: {_plural(total, 'finding')} ({_severity_counts(findings)}) across {scanned}.")
    else:
        checks = "Static rules and LLM judge" if judge is not None else "Static rules only"
        lines.append(f"Summary: no findings across {scanned}. {checks}; this does not prove a server is safe.")
    return "\n".join(lines) + "\n"
