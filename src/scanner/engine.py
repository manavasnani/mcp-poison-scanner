"""Run the rules over one or more server snapshots.

All snapshots passed to one call are treated as one client config, which is what
lets cross-server rules (shadowing, duplicate tool names) see every server at once.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from scanner.models import Finding, ServerSnapshot
from scanner.normalize import normalize
from scanner.rules import STATIC_RULES, Rule, ScanContext


def scan(snapshots: Sequence[ServerSnapshot], rules: Iterable[Rule] = STATIC_RULES) -> list[Finding]:
    """Return every finding, ordered by server, then severity (highest first), then location."""
    ctx = ScanContext(tuple(normalize(s) for s in snapshots))
    server_order = [server.name for server in ctx.servers]
    return sort_findings([finding for rule in rules for finding in rule.run(ctx)], list(server_order))


def sort_findings(findings: Iterable[Finding], server_names: Sequence[str]) -> list[Finding]:
    """Order findings by server (in the order given), then severity (highest first), then location."""
    order = {name: i for i, name in reversed(list(enumerate(server_names)))}
    return sorted(findings, key=lambda f: (order.get(f.server, 0), -f.severity.rank, f.pointer, f.rule_id))
