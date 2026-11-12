"""CAP001: a toxic combination of capabilities in one config.

An agent is exposed when, across all its servers, it can (1) read private data,
(2) take in content written by strangers, and (3) send data out. Any text arriving
through (2) can tell the model to fetch something through (1) and leak it through
(3). No single tool has to be malicious for this to work.

One finding is reported for the whole config, anchored on a tool that sends data
out, since removing or gating that leg is usually the cheapest fix.
"""

from __future__ import annotations

from collections.abc import Iterator

from scanner.capabilities import Capability, ToolProfile, profile_server
from scanner.models import Finding, Severity
from scanner.rules.base import Rule, ScanContext
from scanner.textutil import visible

_LEGS = (Capability.READS_PRIVATE, Capability.UNTRUSTED_INPUT, Capability.SENDS_OUT)
MAX_EXAMPLES = 3


def _names(tools: list[ToolProfile]) -> str:
    shown = ", ".join(f"{visible(t.server)}/{visible(t.name)}" for t in tools[:MAX_EXAMPLES])
    extra = len(tools) - MAX_EXAMPLES
    return f"{shown} and {extra} more" if extra > 0 else shown


def _check(rule: Rule, ctx: ScanContext) -> Iterator[Finding]:
    profiles = [p for server in ctx.servers for p in profile_server(server)]
    legs = {leg: [p for p in profiles if leg in p.capabilities] for leg in _LEGS}
    if not all(legs.values()):
        return

    anchor = legs[Capability.SENDS_OUT][0]
    parts = "; ".join(f"{leg.value}: {_names(tools)}" for leg, tools in legs.items())
    yield rule.finding_at(
        anchor.server,
        "tool",
        anchor.name,
        anchor.pointer,
        "Together, the tools in this config can read private data, take in untrusted content and send data out. "
        "Text arriving through any untrusted source can steer the model into leaking the private data.",
        parts,
    )


RULE = Rule(
    id="CAP001",
    title="Toxic capability combination",
    severity=Severity.HIGH,
    remediation=(
        "Remove one of the three legs from this config, or require user approval for every tool that sends data out."
    ),
    check=_check,
)
