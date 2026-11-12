"""Pinning: remember what a server looked like when you approved it, and explain what changed.

A "rug pull" is a server that behaves until it is approved and then changes its
metadata. A hash of each tool would show *that* something changed. The lockfile
here stores the full definitions instead, so RP001 can say *what* changed and how
much riskier it made the server:

- high:   the change added text that the poisoning rules flag (new instructions);
- medium: the change added a tool, a parameter or a capability;
- low:    anything else (rewording, removals, non-text schema changes).

The lockfile holds server-written text, so it is as untrusted as a snapshot. It is
written with non-ASCII characters escaped, like snapshots are.
"""

from __future__ import annotations

import difflib
import json
from collections.abc import Iterator, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from scanner.capabilities import profile_tool
from scanner.engine import scan
from scanner.models import Finding, ItemKind, ServerSnapshot, Severity
from scanner.normalize import MAX_DEPTH, to_pointer
from scanner.rules import POISONING_RULES
from scanner.textutil import canonicalize, redact, visible

RULE_ID = "RP001"
TITLE = "Pinned server changed"
REMEDIATION = (
    "Review the change. If you accept it, pin the server again with the 'pin' command; "
    "if not, remove the server or roll it back."
)
LOCK_VERSION = 1
DEFAULT_LOCKFILE = "mcp-poison.lock.json"
MAX_LOCK_BYTES = 50 * 1024 * 1024
MAX_DIFF_WORDS = 2000
MAX_EVIDENCE = 200

Path_ = tuple[str | int, ...]

# (snapshot attribute, pointer segment, kind, label, fields that identify an item)
_SECTIONS: tuple[tuple[str, str, ItemKind, str, tuple[str, ...]], ...] = (
    ("tools", "tools", "tool", "Tool", ("name",)),
    ("prompts", "prompts", "prompt", "Prompt", ("name",)),
    ("resources", "resources", "resource", "Resource", ("uri", "name")),
    ("resource_templates", "resourceTemplates", "resource_template", "Resource template", ("uriTemplate", "name")),
)


class LockError(RuntimeError):
    """The lockfile is missing, unreadable or not a lockfile."""


class PinEntry(BaseModel):
    pinned_at: str
    snapshot: ServerSnapshot


class LockFile(BaseModel):
    lockfile_version: int = LOCK_VERSION
    servers: dict[str, PinEntry] = Field(default_factory=dict)


# --- reading and writing ----------------------------------------------------------------------


def load_lock(path: Path) -> LockFile:
    try:
        if path.stat().st_size > MAX_LOCK_BYTES:
            raise LockError(f"{path}: lockfile is larger than {MAX_LOCK_BYTES // (1024 * 1024)} MB")
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except FileNotFoundError as exc:
        raise LockError(f"{path}: no lockfile here. Create one with the 'pin' command.") from exc
    except OSError as exc:
        raise LockError(f"{path}: cannot read lockfile: {exc.strerror or exc}") from exc
    except (ValueError, RecursionError) as exc:
        raise LockError(f"{path}: lockfile is not valid JSON") from exc
    try:
        lock = LockFile.model_validate(data)
    except ValidationError as exc:
        raise LockError(f"{path}: not a lockfile ({exc.error_count()} problems)") from exc
    if lock.lockfile_version != LOCK_VERSION:
        raise LockError(f"{path}: lockfile version {lock.lockfile_version} is not supported")
    return lock


def save_lock(lock: LockFile, path: Path) -> None:
    lock.servers = dict(sorted(lock.servers.items()))
    text = json.dumps(lock.model_dump(mode="json"), indent=2, ensure_ascii=True) + "\n"
    path.write_text(text, encoding="utf-8")


def pin(lock: LockFile, snapshots: Sequence[ServerSnapshot], now: datetime | None = None) -> LockFile:
    """Record each snapshot as the approved state of its server, replacing any earlier pin."""
    stamp = (now or datetime.now(UTC)).isoformat(timespec="seconds")
    for snapshot in snapshots:
        stored = snapshot.model_copy(update={"errors": []})
        lock.servers[snapshot.server_name] = PinEntry(pinned_at=stamp, snapshot=stored)
    return lock


# --- diff helpers -----------------------------------------------------------------------------


def _leaves(value: Any) -> dict[Path_, Any]:
    """Every scalar (and empty container) in ``value``, keyed by its path."""
    out: dict[Path_, Any] = {}
    stack: list[tuple[Any, Path_]] = [(value, ())]
    while stack:
        current, path = stack.pop()
        if len(path) > MAX_DEPTH:
            continue
        if isinstance(current, dict) and current:
            stack.extend((child, (*path, str(key))) for key, child in current.items())
        elif isinstance(current, list) and current:
            stack.extend((child, (*path, i)) for i, child in enumerate(current))
        else:
            out[path] = current
    return out


def _index(items: list[Any], keys: tuple[str, ...]) -> dict[str, tuple[int, dict[str, Any]]]:
    """Items by identity (tool name, resource URI). The first of any duplicates wins."""
    found: dict[str, tuple[int, dict[str, Any]]] = {}
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        name = next((item[k] for k in keys if isinstance(item.get(k), str)), f"#{index}")
        found.setdefault(name, (index, item))
    return found


def _params(kind: ItemKind, item: dict[str, Any]) -> set[str]:
    if kind == "tool":
        schema = item.get("inputSchema")
        props = schema.get("properties") if isinstance(schema, dict) else None
        return {str(k) for k in props} if isinstance(props, dict) else set()
    if kind == "prompt":
        args = item.get("arguments")
        if isinstance(args, list):
            return {a["name"] for a in args if isinstance(a, dict) and isinstance(a.get("name"), str)}
    return set()


def _param_of(kind: ItemKind, item: dict[str, Any], path: Path_) -> str | None:
    if kind == "tool" and len(path) >= 3 and path[:2] == ("inputSchema", "properties"):
        return str(path[2])
    if kind == "prompt" and len(path) >= 2 and path[0] == "arguments" and isinstance(path[1], int):
        args = item.get("arguments")
        if isinstance(args, list) and path[1] < len(args) and isinstance(args[path[1]], dict):
            name = args[path[1]].get("name")
            return name if isinstance(name, str) else None
    return None


def _clip(text: str) -> str:
    shown = visible(redact(text))
    return shown if len(shown) <= MAX_EVIDENCE else shown[: MAX_EVIDENCE - 3] + "..."


def added_text(old: str, new: str) -> str:
    """The words present in ``new`` but not in ``old``, in order."""
    before = canonicalize(old).split()[:MAX_DIFF_WORDS]
    after = canonicalize(new).split()[:MAX_DIFF_WORDS]
    matcher = difflib.SequenceMatcher(a=before, b=after, autojunk=False)
    parts = [" ".join(after[j1:j2]) for tag, _i1, _i2, j1, j2 in matcher.get_opcodes() if tag in ("insert", "replace")]
    return " ... ".join(parts)


def _quoted(names: Sequence[str]) -> str:
    return ", ".join(f"'{visible(n)}'" for n in names)


def _new_poison(old: ServerSnapshot, new: ServerSnapshot) -> dict[tuple[str, str], list[Finding]]:
    """Poisoning findings present now that were not there when pinned, grouped by (kind, item name)."""

    def key(f: Finding) -> tuple[str, str, str, str]:
        # Drop "/tools/3" from the pointer: an item's position may shift between versions.
        inside = f.pointer if f.item_kind == "server" else "/" + "/".join(f.pointer.split("/")[3:])
        return f.rule_id, f.item_kind, f.item_name, inside

    known = {key(f) for f in scan([old], rules=POISONING_RULES)}
    grouped: dict[tuple[str, str], list[Finding]] = {}
    for finding in scan([new], rules=POISONING_RULES):
        if key(finding) not in known:
            grouped.setdefault((finding.item_kind, finding.item_name), []).append(finding)
    return grouped


def _finding(
    server: str, kind: ItemKind, name: str, pointer: str, severity: Severity, message: str, evidence: str
) -> Finding:
    return Finding(
        rule_id=RULE_ID,
        severity=severity,
        title=TITLE,
        server=server,
        item_kind=kind,
        item_name=name,
        pointer=pointer,
        message=message,
        evidence=evidence,
        remediation=REMEDIATION,
    )


def _risk(poison: list[Finding], gained: list[str], structural: bool) -> tuple[Severity, str]:
    """Severity of a change, and the sentence that explains it."""
    notes = ""
    if gained:
        notes += f" New capability: {', '.join(gained)}."
    if poison:
        rules = ", ".join(sorted({f.rule_id for f in poison}))
        severity = max((f.severity for f in poison), key=lambda s: s.rank)
        return severity, f" The change added text flagged by {rules}.{notes}"
    return (Severity.MEDIUM if gained or structural else Severity.LOW), notes


def _gained_capabilities(old: dict[str, Any] | None, new: dict[str, Any]) -> list[str]:
    before = profile_tool("", 0, old) if old is not None else None
    after = profile_tool("", 0, new)
    gained = [c.value for c in after.capabilities if before is None or c not in before.capabilities]
    had = {(p.name, p.kind) for p in before.broad_params} if before else set()
    gained += [
        f"parameter '{visible(p.name)}' takes any {p.kind}" for p in after.broad_params if (p.name, p.kind) not in had
    ]
    return gained


def _describe_change(kind: ItemKind, old: dict[str, Any], new: dict[str, Any]) -> tuple[list[str], bool, str]:
    """What changed inside one item: phrases for the message, whether structure grew, and a text excerpt."""
    before, after = _leaves(old), _leaves(new)
    differing = sorted(
        (p for p in before.keys() | after.keys() if before.get(p, _MISSING) != after.get(p, _MISSING)),
        key=to_pointer,
    )
    params_added = sorted(_params(kind, new) - _params(kind, old))
    params_removed = sorted(_params(kind, old) - _params(kind, new))

    phrases: list[str] = []
    params_changed: set[str] = set()
    other: list[str] = []
    for path in differing:
        param = _param_of(kind, new, path) or _param_of(kind, old, path)
        if path in (("description",), ("title",)):
            phrases.append(f"{path[0]} changed")
        elif param is not None:
            if param not in params_added and param not in params_removed:
                params_changed.add(param)
        else:
            other.append(visible(to_pointer(path)))
    if params_added:
        phrases.append(f"parameter {_quoted(params_added)} added")
    if params_changed:
        phrases.append(f"parameter {_quoted(sorted(params_changed))} changed")
    if params_removed:
        phrases.append(f"parameter {_quoted(params_removed)} removed")
    if other:
        more = f" and {len(other) - 3} more" if len(other) > 3 else ""
        phrases.append(f"other fields changed ({', '.join(other[:3])}{more})")

    excerpt = ""
    for path in differing:
        value = after.get(path)
        if isinstance(value, str):
            previous = before.get(path)
            excerpt = added_text(previous if isinstance(previous, str) else "", value)
            if excerpt:
                excerpt = f"added at {visible(to_pointer(path))}: {excerpt}"
                break
    return phrases, bool(params_added), excerpt


_MISSING = object()


# --- the diff ---------------------------------------------------------------------------------


def diff_server(old: ServerSnapshot, new: ServerSnapshot) -> Iterator[Finding]:
    """RP001 findings for everything in ``new`` that differs from the pinned ``old``."""
    server = new.server_name
    poison = _new_poison(old, new)

    was, now = old.instructions or "", new.instructions or ""
    if was != now:
        flagged = poison.get(("server", server), [])
        severity, why = _risk(flagged, [], False)
        verb = "added" if not was else "removed" if not now else "changed"
        evidence = flagged[0].evidence if flagged else added_text(was, now) or "(text removed)"
        yield _finding(
            server,
            "server",
            server,
            "/instructions",
            severity,
            f"Server instructions were {verb} since the server was pinned.{why}",
            _clip(evidence),
        )

    for attr, segment, kind, label, keys in _SECTIONS:
        before, after = _index(getattr(old, attr), keys), _index(getattr(new, attr), keys)
        for name, (index, item) in after.items():
            pointer = to_pointer((segment, index))
            flagged = poison.get((kind, name), [])
            if name not in before:
                gained = _gained_capabilities(None, item) if kind == "tool" else []
                severity, why = _risk(flagged, gained, kind == "tool")
                description = item.get("description")
                evidence = flagged[0].evidence if flagged else description if isinstance(description, str) else name
                yield _finding(
                    server,
                    kind,
                    name,
                    pointer,
                    severity,
                    f"{label} was added after the server was pinned.{why}",
                    _clip(evidence),
                )
                continue
            previous = before[name][1]
            if previous == item:
                continue
            phrases, grew, excerpt = _describe_change(kind, previous, item)
            gained = _gained_capabilities(previous, item) if kind == "tool" else []
            severity, why = _risk(flagged, gained, grew)
            evidence = f"{flagged[0].rule_id}: {flagged[0].evidence}" if flagged else _clip(excerpt)
            yield _finding(
                server,
                kind,
                name,
                pointer,
                severity,
                f"{label} changed since the server was pinned: {'; '.join(phrases) or 'definition changed'}.{why}",
                evidence or "(no text was added)",
            )
        for name in before.keys() - after.keys():
            yield _finding(
                server,
                kind,
                name,
                "/" + segment,
                Severity.LOW,
                f"{label} was removed since the server was pinned.",
                visible(name),
            )


def check_pins(lock: LockFile, snapshots: Sequence[ServerSnapshot]) -> tuple[list[Finding], list[str]]:
    """Compare each scanned server with its pin. Returns findings, and notes about unpinned servers."""
    findings: list[Finding] = []
    notes: list[str] = []
    for snapshot in snapshots:
        entry = lock.servers.get(snapshot.server_name)
        if entry is None:
            notes.append(f"server '{visible(snapshot.server_name)}' is not pinned, so changes to it cannot be detected")
            continue
        findings.extend(diff_server(entry.snapshot, snapshot))
    return findings, notes
