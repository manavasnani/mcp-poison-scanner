"""CAP002: one tool with an over-broad capability.

Three shapes: a tool that runs shell commands or code, a file tool whose path
parameter is not limited to a directory, and a tool that fetches any URL it is
given. None of these is poisoning. They are flagged because they turn a small
prompt injection anywhere else into full access.
"""

from __future__ import annotations

from collections.abc import Iterator

from scanner.capabilities import Capability, profile_server
from scanner.models import Finding, Severity
from scanner.rules.base import Rule, ScanContext
from scanner.textutil import visible

_PARAM_MESSAGE = {
    "path": "Parameter '{name}' accepts any file path; nothing in the metadata limits it to a directory.",
    "url": "Parameter '{name}' accepts any URL; nothing in the metadata limits which hosts can be reached.",
}


def _check(rule: Rule, ctx: ScanContext) -> Iterator[Finding]:
    for server in ctx.servers:
        for tool in profile_server(server):
            shown = visible(tool.name)
            evidence = tool.capabilities.get(Capability.EXECUTES_CODE)
            if evidence is not None:
                yield rule.finding_at(
                    tool.server,
                    "tool",
                    tool.name,
                    tool.text_pointer,
                    f"Tool '{shown}' runs commands or code on the host.",
                    evidence,
                )
            for param in tool.broad_params:
                yield rule.finding_at(
                    tool.server,
                    "tool",
                    tool.name,
                    tool.param_pointer(param.name),
                    _PARAM_MESSAGE[param.kind].format(name=visible(param.name)),
                    visible(param.name),
                )


RULE = Rule(
    id="CAP002",
    title="Over-broad capability",
    severity=Severity.MEDIUM,
    remediation=(
        "Only enable this tool if you need it. Prefer a server that limits commands, directories or hosts, "
        "and require user approval for each call."
    ),
    check=_check,
)
