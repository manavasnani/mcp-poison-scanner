"""Work out what each tool can *do*, from its name, description and parameters.

The TP rules look for hostile text. The CAP rules ask a different question: if the
model were steered wrong, how much damage could these tools do? That depends on
capabilities, and a perfectly honest server can have dangerous ones.

Classification is keyword matching on what the server says about itself, so it is
a best-effort guess: a server that describes its tools vaguely will be under-counted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from scanner.normalize import NormalizedServer, to_pointer
from scanner.textutil import canonicalize, excerpt

MAX_TEXT = 20_000
"""Only this much of a tool's text is classified; capability keywords appear early or not at all."""


class Capability(StrEnum):
    EXECUTES_CODE = "runs commands or code"
    READS_PRIVATE = "reads private data"
    UNTRUSTED_INPUT = "takes in untrusted content"
    SENDS_OUT = "sends data out"


def _rx(regex: str) -> re.Pattern[str]:
    return re.compile(regex, re.IGNORECASE)


_READ = r"(?:read|get|list|search|quer(?:y|ie)|retrieve|fetch|export|load|open|return|show|view|find|look ?up)(?:s|es)?"
_PRIVATE_NOUN = (
    r"(?:files?|director(?:y|ies)|folders?|documents?|databases?|tables?|rows|records|e-?mails?|inbox|mailbox"
    r"|messages|conversations?|chats?|notes?|calendars?|contacts?|repositor(?:y|ies)|source code|secrets?"
    r"|credentials?|passwords?|environment variables?|clipboard|histor(?:y|ies)|logs?|issues|pull requests"
    r"|tickets|customers?|accounts?|transactions?|drive)"
)
_WEB_NOUN = r"(?:urls?|web ?pages?|web ?sites?|the web|the internet|html|links?|https?)"
_AUTHORED_NOUN = (
    r"(?:e-?mails?|inbox|mailbox|issues?|pull requests?|comments?|tickets?|channels?|messages|reviews|posts|tweets"
    r"|feeds?|rss)"
)

_PATTERNS: dict[Capability, tuple[re.Pattern[str], ...]] = {
    Capability.EXECUTES_CODE: (
        _rx(
            r"\b(?:run|execute|spawn|launch|evaluate)s?\s(?:(?:an?|any|the|arbitrary|given|your)\s){0,3}"
            r"(?:(?:shell|bash|terminal|system|python|javascript|powershell|command[- ]line)\s){0,2}"
            r"(?:commands?|code|scripts?|programs?|process(?:es)?)\b"
        ),
        _rx(r"\barbitrary (?:code|commands?|scripts?)\b"),
        _rx(r"\b(?:shell|bash|powershell|terminal) (?:command|session|access)s?\b"),
    ),
    Capability.READS_PRIVATE: (
        _rx(rf"\b{_READ}\b.{{0,60}}?\b{_PRIVATE_NOUN}\b"),
        _rx(r"\b(?:select|sql) quer(?:y|ies)\b"),
    ),
    Capability.UNTRUSTED_INPUT: (
        _rx(
            rf"\b(?:fetch|download|scrape|crawl|browse|navigate|open|load|retrieve|get|read|visit)(?:s|es)?\b"
            rf".{{0,40}}?\b{_WEB_NOUN}\b"
        ),
        _rx(r"\bweb search\b|\bsearch(?:es)? (?:the )?(?:web|internet)\b|\bsearch engine\b"),
        _rx(rf"\b(?:read|get|list|fetch|search|retrieve)(?:s|es)?\b.{{0,40}}?\b{_AUTHORED_NOUN}\b"),
    ),
    Capability.SENDS_OUT: (
        _rx(
            r"\b(?:send|post|publish|upload|share|forward|e-?mail|notify|tweet|submit|push)(?:s|es)?\b.{0,40}?"
            r"\b(?:e-?mails?|messages?|sms|texts?|notifications?|webhooks?|requests?|channels?|comments?|files?|data"
            r"|replies|reply)\b"
        ),
        _rx(
            r"\b(?:create|add|open|update|write)s?\b.{0,30}?"
            r"\b(?:issues?|pull requests?|comments?|gists?|posts?|tickets?)\b"
        ),
        _rx(r"\bhttp (?:request|post|put)s?\b|\bmakes? (?:an? )?(?:http|api|web) requests?\b|\bwebhooks?\b"),
    ),
}

_URL_PARAM = re.compile(r"^(?:url|uri|link|href|endpoint|website|webpage|\w{1,40}_ur[li])$", re.IGNORECASE)
_URL_ACTION = _rx(r"\b(?:fetch|download|scrape|crawl|browse|navigate|open|load|retrieve|get|read|visit|request)")
_URL_LIMIT = _rx(
    r"\ballow[- ]?list|\ballowed (?:domains?|hosts?|urls?|sites?)|\brestricted to\b|\bwhitelist"
    r"|\bonly (?:from|to|on|for|allowed)\b|\bsame[- ]origin\b|\bmust (?:be|start with|begin with)\b"
)

_PATH_PARAM = re.compile(
    r"^(?:path|paths|file|files|filepath|filename|dir|directory|folder|\w{1,40}_(?:path|file|dir|directory))$",
    re.IGNORECASE,
)
_FILE_ACTION = _rx(
    r"\b(?:read|write|create|delete|remove|move|copy|edit|list|open|overwrite|append|load|save)s?\b.{0,40}?"
    r"\b(?:files?|director(?:y|ies)|folders?)\b"
)
_PATH_LIMIT = _rx(
    r"\ballowed (?:director|path|folder)|\bwithin (?:the |an? )?(?:allowed|workspace|project|sandbox|root|base)"
    r"|\bsandbox|\bworkspace\b|\brelative to\b|\brestricted to\b|\bonly (?:works )?(?:within|inside|under)\b"
    r"|\bbase director|\bproject root\b"
)


@dataclass(frozen=True)
class BroadParam:
    """A parameter that accepts any file path or any URL."""

    name: str
    kind: str  # "path" or "url"


@dataclass(frozen=True)
class ToolProfile:
    server: str
    index: int
    name: str
    has_description: bool
    capabilities: dict[Capability, str] = field(default_factory=dict)
    """Each capability the tool appears to have, with the text that showed it."""
    broad_params: tuple[BroadParam, ...] = ()

    @property
    def pointer(self) -> str:
        return to_pointer(("tools", self.index))

    @property
    def text_pointer(self) -> str:
        return to_pointer(("tools", self.index, "description" if self.has_description else "name"))

    def param_pointer(self, name: str) -> str:
        return to_pointer(("tools", self.index, "inputSchema", "properties", name))


def _words(name: str) -> str:
    """``send_email`` and ``sendEmail`` both become ``send email``, so name and prose match alike."""
    return re.sub(r"[_\-.]+|(?<=[a-z])(?=[A-Z])", " ", name)


def _is_open_string(schema: Any) -> bool:
    """True when a parameter takes free text: no enum, const or pattern narrows it."""
    if not isinstance(schema, dict):
        return True
    if schema.get("type") not in (None, "string", "array"):
        return False
    return not any(key in schema for key in ("enum", "const", "pattern"))


def profile_tool(server: str, index: int, tool: dict[str, Any]) -> ToolProfile:
    name = tool.get("name") if isinstance(tool.get("name"), str) else f"#{index}"
    description = tool.get("description") if isinstance(tool.get("description"), str) else ""
    text = canonicalize(f"{_words(name)}. {description}"[:MAX_TEXT])

    capabilities: dict[Capability, str] = {}
    for capability, patterns in _PATTERNS.items():
        for regex in patterns:
            match = regex.search(text)
            if match:
                capabilities[capability] = excerpt(text, match.start(), match.end(), pad=20)
                break

    schema = tool.get("inputSchema")
    props = schema.get("properties") if isinstance(schema, dict) else None
    broad: list[BroadParam] = []
    for param, param_schema in props.items() if isinstance(props, dict) else ():
        param = str(param)
        if not _is_open_string(param_schema):
            continue
        param_text = param_schema.get("description") if isinstance(param_schema, dict) else None
        scope = text + " " + canonicalize(param_text[:MAX_TEXT]) if isinstance(param_text, str) else text
        if _URL_PARAM.match(param) and _URL_ACTION.search(text):
            # Any URL the model is talked into visiting can carry data out in its query string.
            capabilities.setdefault(Capability.UNTRUSTED_INPUT, f"parameter '{param}' takes a URL")
            capabilities.setdefault(Capability.SENDS_OUT, f"parameter '{param}' takes a URL")
            if not _URL_LIMIT.search(scope):
                broad.append(BroadParam(param, "url"))
        elif _PATH_PARAM.match(param) and _FILE_ACTION.search(text) and not _PATH_LIMIT.search(scope):
            broad.append(BroadParam(param, "path"))

    return ToolProfile(server, index, name, bool(description), capabilities, tuple(broad))


def profile_server(server: NormalizedServer) -> list[ToolProfile]:
    return [
        profile_tool(server.name, index, tool)
        for index, tool in enumerate(server.snapshot.tools)
        if isinstance(tool, dict)
    ]
