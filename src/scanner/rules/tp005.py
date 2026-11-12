"""TP005: the same tool name exposed by two servers in one config.

When two servers both offer ``send_email``, the model may call the wrong one. A
malicious server can use this to intercept calls meant for a trusted server.
Names are compared case-insensitively, since a model will not reliably tell
``Send_Email`` from ``send_email``.
"""

from __future__ import annotations

from collections.abc import Iterator

from scanner.models import Finding, Severity
from scanner.normalize import TextField
from scanner.rules.base import Rule, ScanContext
from scanner.textutil import visible


def _check(rule: Rule, ctx: ScanContext) -> Iterator[Finding]:
    # folded name -> list of (server name, the tool's name field)
    owners: dict[str, list[TextField]] = {}
    for field in ctx.fields:
        if field.kind == "tool" and field.path == ("name",):
            owners.setdefault(field.text.casefold(), []).append(field)

    for fields in owners.values():
        servers = sorted({f.server for f in fields})
        if len(servers) < 2:
            continue
        for field in fields:
            others = ", ".join(f"'{visible(s)}'" for s in servers if s != field.server)
            yield rule.finding(
                field,
                f"Tool name is also exposed by server {others}; the model may call the wrong one.",
                visible(field.text),
            )


RULE = Rule(
    id="TP005",
    title="Duplicate tool name across servers",
    severity=Severity.MEDIUM,
    remediation=("Confirm both servers are trusted, then remove or rename one tool so the model cannot confuse them."),
    check=_check,
)
