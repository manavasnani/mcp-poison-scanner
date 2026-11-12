"""TP004: cross-tool instructions (shadowing).

One item's metadata tells the model how to use a *different* tool, typically one
on another, trusted server: "when send_email is used, also bcc ...". The attacker's
tool never has to be called for this to work.

References to tools on the same server are ignored: "call list_tables first" is
normal workflow guidance from a server about its own tools. A finding needs both a
reference to a tool that is not on this server and directive wording.

Servers often give every tool a shared prefix (``notion-restore-pages``) and then refer to
one by its short name (``restore_pages``). Those count as the server's own tools too, but
only when most of the server's tools carry the prefix, and never when the short name is
the exact name of a tool on another server in the config.

One same-server case is reported: a tool whose text sets conditions on the use of a
*different* tool ("before using read_file, call set_config", "when calling search, set
the query to ..."). A description that explains its own tool has no reason to govern
another one, and an attacker who adds a tool to a server does exactly this.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass

from scanner.models import Finding, Severity
from scanner.normalize import NormalizedServer, Path, TextField
from scanner.rules.base import Rule, ScanContext
from scanner.textutil import excerpt

_IDENT = r"[A-Za-z][A-Za-z0-9]*(?:[_.-][A-Za-z0-9]+)+|[a-z]+[A-Z][A-Za-z0-9]*"
"""Looks like a tool identifier: has an underscore, dot or hyphen inside, or is camelCase."""

_QUOTE = "[`'\"]"

# `send_email` tool / the send_email tool / tool named send_email
_NAMED_TOOL = re.compile(
    rf"({_QUOTE}?)\b({_IDENT})\b{_QUOTE}?\s+(?:tool|function)\b"
    rf"|\b(?:tool|function)\s+(?:called|named)\s+({_QUOTE}?)({_IDENT})\b"
)
_OTHER_TOOLS = re.compile(r"\b(any|all|every|each)\s+other\s+tools?\b|\bother\s+tools\b", re.IGNORECASE)
_DIRECTIVE = re.compile(
    r"\b(always|never|must|instead|whenever|when|before|after|first|do not|don't|should|ensure|make sure|"
    r"required|need to|have to)\b",
    re.IGNORECASE,
)


_WHO = r"(?:(?:you|the\s+user|a\s+user|users|the\s+model|the\s+assistant)\s+)?"
_USES = (
    r"(?:(?:are|is)\s+)?(?:use[sd]?|using|call(?:s|ed|ing)?|invok(?:e[sd]?|ing)|run(?:s|ning)?|"
    r"execut(?:e[sd]?|ing)|requests?\s+to\s+use)"
)
_NAME = r"([`'\"]?)([A-Za-z][\w.-]{1,80}?)[`'\"]?(?![\w-])"
# "before using X", "when you call the tool X", "any request to X", "any X request"
_GOVERNS = re.compile(
    # Only at the start of a clause: "confirm before calling X" is this tool's own follow-up step.
    rf"(?:^|[.!?:;,)*]\s+|\band\s+)(?:when(?:ever)?|before|if|every\s+time)\s+{_WHO}{_USES}\s+(?:the\s+)?(?:tool\s+)?{_NAME}(\s+tool\b)?"
    rf"|\bany\s+(?:requests?|calls?)\s+(?:to|for)\s+(?:the\s+)?{_NAME}(\s+tool\b)?"
    rf"|\b(?:any|all|every)\s+{_NAME}\s+(?:requests?|calls?|quer(?:y|ies))\b",
    re.IGNORECASE,
)


def _plain(name: str) -> str:
    return name.lower().replace("-", "_").replace(".", "_")


@dataclass(frozen=True)
class _Own:
    """How a server's own tools may be written in its text."""

    aliases: dict[str, str]
    """Plain spelling (hyphen for underscore, shared prefix dropped) -> the tool's real name."""
    prefix: str | None
    """The prefix most of the server's tools share, if there is one."""

    def is_own(self, name: str) -> bool:
        plain = _plain(name)
        # A name carrying the server's own prefix is one of its tools even if the listing
        # does not show it (a tool that is switched off, or cut from a long list).
        return plain in self.aliases or (self.prefix is not None and plain.startswith(self.prefix + "_"))


def _own_names(own: NormalizedServer) -> _Own:
    aliases = {_plain(name): name for name in own.tool_names}
    counts: dict[str, int] = {}
    for plain in list(aliases):
        head, sep, _rest = plain.partition("_")
        if sep:
            counts[head] = counts.get(head, 0) + 1
    shared = next((p for p, n in counts.items() if n >= 2 and n * 2 > len(aliases)), None)
    if shared:
        for plain, name in list(aliases.items()):
            if plain.startswith(shared + "_"):
                aliases.setdefault(plain[len(shared) + 1 :], name)
    return _Own(aliases, shared)


def _governed_tool(field: TextField, own: _Own) -> tuple[str, int, int] | None:
    """A different tool on this server whose use the text sets conditions on, if any."""
    for match in _GOVERNS.finditer(field.canonical):
        # Groups per alternative: (quote, name, "tool") twice, then (quote, name).
        base = next(i for i in (1, 4, 7) if match.group(i + 1))
        quote, name = match.group(base), match.group(base + 1)
        said_tool = base < 7 and match.group(base + 2)
        real = own.aliases.get(_plain(name))
        if real is None or real == field.item or _plain(name) == _plain(field.item):
            continue
        # A bare everyday word ("search", "fetch") only counts when quoted or followed by "tool".
        looks_like_a_name = bool(re.search(r"[_.-]|[a-z][A-Z]", name))
        if looks_like_a_name or quote or said_tool:
            return real, match.start(), match.end()
    return None


def _known_elsewhere(ctx: ScanContext, own: NormalizedServer) -> dict[str, str]:
    """Tool name -> server name, for tools on every server except ``own``."""
    known: dict[str, str] = {}
    for server in ctx.servers:
        if server is own:
            continue
        for name in server.tool_names:
            known.setdefault(name, server.name)
    return known


def _references(text: str, elsewhere: dict[str, str]) -> Iterator[tuple[str, int, int]]:
    """Yield (tool name, start, end) for each apparent reference to a tool."""
    for match in _NAMED_TOOL.finditer(text):
        quote = match.group(1) or match.group(3)
        name = match.group(2) or match.group(4)
        # "command-line tool" and "built-in tool" are English, not tool names: a name whose
        # only separator is a hyphen must be quoted, or be a known tool, to count.
        if "-" in name and "_" not in name and not quote and name not in elsewhere:
            continue
        yield name, match.start(), match.end()
    # Exact names of tools on other servers, even when written without "tool" or quotes.
    for name in elsewhere:
        if len(name) < 4:
            continue
        for match in re.finditer(rf"(?<![\w.-]){re.escape(name)}(?![\w-])", text):
            yield name, match.start(), match.end()


def _check_field(
    rule: Rule,
    field: TextField,
    own: NormalizedServer,
    own_params: frozenset[str],
    elsewhere: dict[str, str],
    names: _Own,
) -> Finding | None:
    if field.is_key or field.leaf in ("name", "uri", "uriTemplate"):
        return None
    text = field.canonical
    if not _DIRECTIVE.search(text):
        return None

    if field.kind != "server":  # server instructions may say how the server's tools fit together
        governed = _governed_tool(field, names)
        if governed:
            name, start, end = governed
            return rule.finding(
                field,
                f"Text sets conditions on the use of a different tool on this server, '{name}'.",
                excerpt(text, start, end),
                severity=Severity.HIGH,
            )

    for name, start, end in _references(text, elsewhere):
        if name in own.tool_names or name == field.item or name in own_params:
            continue
        if names.is_own(name) and name not in elsewhere:
            continue
        where = f"on server '{elsewhere[name]}'" if name in elsewhere else "not defined by this server"
        return rule.finding(
            field,
            f"Text gives instructions about another tool, '{name}', which is {where}.",
            excerpt(text, start, end),
        )

    generic = _OTHER_TOOLS.search(text)
    if generic:
        return rule.finding(
            field, "Text gives instructions that apply to other tools.", excerpt(text, generic.start(), generic.end())
        )
    return None


def _check(rule: Rule, ctx: ScanContext) -> Iterator[Finding]:
    for server in ctx.servers:
        elsewhere = _known_elsewhere(ctx, server)
        names = _own_names(server)
        params: dict[Path, set[str]] = {}
        for field in server.fields:
            if field.param:
                params.setdefault(field.item_path, set()).add(field.param)
        for field in server.fields:
            own_params = frozenset(params.get(field.item_path, ()))
            finding = _check_field(rule, field, server, own_params, elsewhere, names)
            if finding:
                yield finding


RULE = Rule(
    id="TP004",
    title="Cross-tool instructions",
    severity=Severity.MEDIUM,
    remediation=(
        "A server should only describe its own tools. Check whether this text changes how the model uses a "
        "tool from another server, and remove the server if it does."
    ),
    check=_check,
)
