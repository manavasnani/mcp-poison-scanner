"""SARIF 2.1.0 report, the format code-scanning tools (GitHub and others) ingest.

A finding lives in a server's metadata, not at a line of a file, so each result
carries a *logical* location (server, item, JSON pointer). When the server was read
from a snapshot file, that file is also given as the physical location, which is
what GitHub needs to show a result. Servers scanned live have no file to point at.

Only plain-text ``message.text`` is used, never markdown, so text from a server
cannot become formatting or links in a viewer.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from scanner import pin
from scanner.judge.judge import REMEDIATION as JUDGE_REMEDIATION
from scanner.judge.judge import RULE_ID as JUDGE_RULE_ID
from scanner.models import Finding, Severity
from scanner.report.common import TOOL_NAME, ScanReport, tool_version
from scanner.rules import STATIC_RULES
from scanner.textutil import visible

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_LEVEL = {Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "note"}
# GitHub sorts security results by this 0-10 score.
_SCORE = {Severity.HIGH: "8.0", Severity.MEDIUM: "5.0", Severity.LOW: "2.0"}

# id -> (short description, default severity, help text)
RULES: dict[str, tuple[str, Severity, str]] = {r.id: (r.title, r.severity, r.remediation) for r in STATIC_RULES}
RULES[pin.RULE_ID] = (pin.TITLE, Severity.MEDIUM, pin.REMEDIATION)
RULES[JUDGE_RULE_ID] = ("LLM judge verdict", Severity.HIGH, JUDGE_REMEDIATION)


def _uri(path: Path) -> str:
    """Relative to the working directory when possible, as code-scanning tools expect."""
    resolved = path.resolve()
    try:
        return resolved.relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return resolved.as_uri()


def _fingerprint(finding: Finding) -> str:
    """Stable across runs and across an item moving position in its list."""
    inside = finding.pointer if finding.item_kind == "server" else "/".join(finding.pointer.split("/")[3:])
    key = "\x00".join([finding.rule_id, finding.server, finding.item_kind, finding.item_name, inside])
    return hashlib.sha256(key.encode("utf-8", "surrogatepass")).hexdigest()[:32]


def _result(finding: Finding, rule_index: dict[str, int], sources: dict[str, Path]) -> dict[str, Any]:
    where = f"{visible(finding.server)} {finding.item_kind.replace('_', ' ')} {visible(finding.item_name)}"
    location: dict[str, Any] = {
        "logicalLocations": [
            {
                "name": visible(finding.item_name),
                "fullyQualifiedName": f"{visible(finding.server)}{visible(finding.pointer)}",
                "kind": finding.item_kind,
            }
        ]
    }
    source = sources.get(finding.server)
    if source is not None:
        location["physicalLocation"] = {"artifactLocation": {"uri": _uri(source)}, "region": {"startLine": 1}}
    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "level": _LEVEL[finding.severity],
        "message": {"text": f"{where}: {finding.message} Evidence: {finding.evidence}"},
        "locations": [location],
        "partialFingerprints": {"mcpPoisonScanner/v1": _fingerprint(finding)},
        "properties": {
            "server": finding.server,
            "itemKind": finding.item_kind,
            "itemName": finding.item_name,
            "pointer": finding.pointer,
            "severity": finding.severity.value,
            "evidence": finding.evidence,
        },
    }
    if finding.rule_id in rule_index:
        result["ruleIndex"] = rule_index[finding.rule_id]
    return result


def render_sarif(report: ScanReport) -> str:
    rules = [
        {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": title},
            "help": {"text": help_text},
            "defaultConfiguration": {"level": _LEVEL[severity]},
            "properties": {"security-severity": _SCORE[severity], "tags": ["security", "mcp"]},
        }
        for rule_id, (title, severity, help_text) in RULES.items()
    ]
    rule_index = {rule["id"]: i for i, rule in enumerate(rules)}
    run: dict[str, Any] = {
        "tool": {"driver": {"name": TOOL_NAME, "version": tool_version(), "rules": rules}},
        "results": [_result(f, rule_index, report.sources) for f in report.findings],
    }
    notifications = [*report.notes]
    if report.judge is not None:
        notifications += report.judge.errors
    notifications += [
        f"{visible(s.server_name)}: collection problem: {visible(e)}" for s in report.snapshots for e in s.errors
    ]
    if notifications:
        run["invocations"] = [
            {
                "executionSuccessful": True,
                "toolExecutionNotifications": [{"level": "warning", "message": {"text": n}} for n in notifications],
            }
        ]
    document = {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}
    return json.dumps(document, indent=2, ensure_ascii=True) + "\n"
