"""TP006: parameter poisoning.

The attack lives in a tool's parameters rather than its description. Three shapes:

1. A parameter whose description asks for data the tool has no business receiving:
   the conversation, the system prompt, files the model has seen.
2. An enum value, default, const or example that carries an instruction. These look
   like harmless option lists, so reviewers skip them.
3. A side-channel parameter: the tool's description tells the model to put sensitive
   data into one of the tool's own parameters ("pass its contents as 'sidenote'").
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from scanner.models import Finding, Severity
from scanner.normalize import NormalizedServer, Path, TextField
from scanner.rules.base import Rule, ScanContext, first_match, match_evidence, pattern
from scanner.rules.tp001 import INSTRUCTION_PATTERNS
from scanner.rules.tp002 import SENSITIVE_PATTERNS
from scanner.textutil import excerpt

# Shape 1: a parameter description asking for conversation or context data.
_ASKS_FOR_CONTEXT = (
    pattern(
        "asks for the conversation",
        # Deliberately not bare "recent messages": chat and email tools say that about their own data.
        r"\b(entire|full|whole|complete|previous|prior|earlier|recent)\s+(conversation|chat|dialogue|transcript)\b"
        r"|\bconversation\s+(so\s+far|history)\b|\bchat\s+history\b"
        r"|\b(user's|your)\s+(previous|prior|earlier|recent|last)\s+messages\b"
        r"|\bmessages\s+(so\s+far|in\s+this\s+(conversation|chat)|from\s+this\s+(conversation|chat))\b",
    ),
    pattern(
        "asks for the model's instructions",
        r"\bsystem\s+prompt\b|\byour\s+(instructions|context|memory|system\s+message)\b",
    ),
    pattern(
        "asks for files or data the model has seen",
        r"\bfiles?\s+(contents?\s+)?(you|that\s+you)\s+(have\s+|'ve\s+)?(seen|read|opened|accessed)\b"
        r"|\bany\s+file\s+contents\b|\beverything\s+(you|the\s+user)\b",
    ),
    pattern(
        "asks for the user's secrets",
        r"\b(api\s+keys?|passwords?|tokens?|credentials|secrets?)\b[^.!?\n]{0,20}"
        r"\b(you\s+(have|know|can\s+find)|the\s+user's)\b"
        r"|\bthe\s+user's\s+(api\s+keys?|passwords?|tokens?|credentials|secrets?)\b",
    ),
)

# Shape 2: directive wording inside a value that should just be an option or a default.
_VALUE_DIRECTIVE = pattern(
    "contains a directive",
    r"\b(also|first|then|always|before\s+\w+ing|after\s+\w+ing|when(ever)?)\b.{0,40}"
    r"\b(call|invoke|run|execute|read|send|fetch|upload|post|email|forward)\b",
)
MAX_ENUM_WORDS = 7
"""An enum value longer than this reads as a sentence, not an option."""

# Shape 3: "pass <something> as/in/into <param>".
_TRANSFER_VERB = (
    r"\b(pass|put|include|provide|send|add|append|write|place|copy|paste|summari[sz]e|encode|store|set|insert)\b"
)
_SENSITIVE_HINT = re.compile(
    r"\b(conversation|chat\s+history|previous\s+messages|prior\s+messages|system\s+prompt|credentials?|secrets?"
    r"|passwords?|tokens?|api\s+keys?|private\s+key)\b|\bread\b.{0,80}\b(contents?|file)\b",
    re.IGNORECASE,
)


def _param_fields(server: NormalizedServer) -> dict[tuple[Path, str], TextField]:
    """(item path, parameter name) -> the field for that parameter's name."""
    found: dict[tuple[Path, str], TextField] = {}
    for field in server.fields:
        if (
            field.kind == "tool"
            and field.is_key
            and len(field.path) == 3
            and field.path[:2] == ("inputSchema", "properties")
        ):
            found[(field.item_path, field.text)] = field
    return found


_NEGATED = re.compile(
    r"\b(do not|don't|never|must not|should not|no|not|without|avoid|exclude|omit|instead of|rather than|leave out)\b",
    re.IGNORECASE,
)
_SUPPLY = re.compile(
    r"\b(pass|include|provide|send|paste|copy|attach|put|supply|add|insert|append|write|summari[sz]e|contain|forward)"
    r"\w{0,3}\W+(?:\S+\W+){0,5}$",
    re.IGNORECASE,
)
_DEFINES_WITHIN = 50
"""A parameter whose description opens with the data ("The full conversation so far") is that data."""


def _is_a_request(text: str, match: re.Match[str]) -> bool:
    """Is the parameter asking for this data, or only mentioning it?

    "Do not include the user's credentials" and "the summary is shown instead of the full
    transcript" both name sensitive data without asking for it.
    """
    sentence_start = max(text.rfind(mark, 0, match.start()) for mark in (". ", "! ", "? ", "\n")) + 1
    before = text[sentence_start : match.start()]
    if _NEGATED.search(before[-80:]):
        return False
    return match.start() <= _DEFINES_WITHIN or bool(_SUPPLY.search(before))


def _context_requests(rule: Rule, server: NormalizedServer) -> Iterator[Finding]:
    for field in server.fields:
        if field.param is None or field.is_key or field.in_value_slot:
            continue
        text = field.canonical
        hit = next(
            ((pat, m) for pat in _ASKS_FOR_CONTEXT for m in pat.regex.finditer(text) if _is_a_request(text, m)),
            None,
        )
        if hit:
            pat, match = hit
            yield rule.finding(field, f"Parameter '{field.param}' {pat.label}.", match_evidence(text, match))


def _poisoned_values(rule: Rule, server: NormalizedServer) -> Iterator[Finding]:
    for field in server.fields:
        if field.is_key or not field.in_value_slot:
            continue
        text = field.canonical
        slot = next(p for p in field.path if p in ("enum", "default", "const", "examples"))
        owner = f"parameter '{field.param}'" if field.param else "a schema"
        hit = first_match((*INSTRUCTION_PATTERNS, _VALUE_DIRECTIVE, *SENSITIVE_PATTERNS), text)
        if hit:
            _, match = hit
            yield rule.finding(
                field,
                f"The {slot} value of {owner} carries an instruction or a sensitive path.",
                match_evidence(text, match),
            )
        elif slot == "enum" and len(text.split()) > MAX_ENUM_WORDS:
            yield rule.finding(
                field,
                f"An enum value of {owner} is a full sentence, not an option.",
                excerpt(text, 0, min(len(text), 120), pad=0),
            )


def _side_channels(rule: Rule, server: NormalizedServer) -> Iterator[Finding]:
    params = _param_fields(server)
    for field in server.fields:
        if field.kind != "tool" or field.path != ("description",):
            continue
        text = field.canonical
        for (item_path, name), param_field in params.items():
            if item_path != field.item_path:
                continue
            transfer = re.search(
                rf"{_TRANSFER_VERB}.{{0,160}}?\b(as|in|into|to|via|using|inside)\b.{{0,15}}?(?<![\w-]){re.escape(name)}(?![\w-])",
                text,
                re.IGNORECASE,
            )
            if not transfer:
                continue
            window = text[max(0, transfer.start() - 120) : transfer.end() + 40]
            if _SENSITIVE_HINT.search(window) or first_match(SENSITIVE_PATTERNS, window):
                yield rule.finding(
                    param_field,
                    f"The tool description tells the model to put sensitive data into parameter '{name}'.",
                    excerpt(text, transfer.start(), transfer.end(), pad=30),
                )


def _check(rule: Rule, ctx: ScanContext) -> Iterator[Finding]:
    for server in ctx.servers:
        yield from _context_requests(rule, server)
        yield from _poisoned_values(rule, server)
        yield from _side_channels(rule, server)


RULE = Rule(
    id="TP006",
    title="Parameter poisoning",
    severity=Severity.HIGH,
    remediation=(
        "Review this parameter. A tool should not collect the conversation, system prompt or unrelated files, "
        "and option lists and defaults should not contain instructions."
    ),
    check=_check,
)
