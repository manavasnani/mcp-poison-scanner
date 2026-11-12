"""JSON report: the same content as the text report, for other programs to read.

Names and pointers are given as the server sent them (JSON escaping keeps control
and non-ASCII characters inert in the file). A program that prints them to a
terminal must escape them itself; ``message`` and ``evidence`` are already safe.
"""

from __future__ import annotations

import json
from typing import Any

from scanner.report.common import TOOL_NAME, ScanReport, tool_version

SCHEMA_VERSION = 1


def render_json(report: ScanReport) -> str:
    judge: dict[str, Any] | None = None
    if report.judge is not None:
        judge = {
            "items_judged": report.judge.judged,
            "not_judged": list(report.judge.errors),
            "models": sorted(report.judge.models),
            "input_tokens": report.judge.input_tokens,
            "output_tokens": report.judge.output_tokens,
        }
    document = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": tool_version()},
        "servers": [
            {
                "name": s.server_name,
                "source": s.source,
                "tools": len(s.tools),
                "prompts": len(s.prompts),
                "resources": len(s.resources),
                "resource_templates": len(s.resource_templates),
                "collection_errors": list(s.errors),
            }
            for s in report.snapshots
        ],
        "findings": [f.model_dump(mode="json") for f in report.findings],
        "judge": judge,
        "notes": list(report.notes),
        "summary": {"findings": len(report.findings), "by_severity": report.severity_counts()},
    }
    return json.dumps(document, indent=2, ensure_ascii=True) + "\n"
