"""Flatten a server snapshot into (JSON pointer, text) pairs.

Poisoning can sit in any string the model reads, not just the top-level
description, so every string value becomes a ``TextField``: descriptions, titles,
enum values, defaults, examples, server instructions and so on. Parameter names
are dictionary *keys* in a JSON schema, so those are emitted as fields too.

Rules then work on a flat list and never need to know the shape of a schema.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from functools import cached_property
from typing import Any

from scanner.models import ItemKind, ServerSnapshot
from scanner.textutil import canonicalize

MAX_DEPTH = 64
"""Nesting deeper than this inside one item is ignored, so a hostile schema can't stall the walk."""

# (snapshot attribute, pointer segment, item kind)
_SECTIONS: tuple[tuple[str, str, ItemKind], ...] = (
    ("tools", "tools", "tool"),
    ("prompts", "prompts", "prompt"),
    ("resources", "resources", "resource"),
    ("resource_templates", "resourceTemplates", "resource_template"),
)

# Schema keywords whose dictionary keys are names the model sees (parameter and type names).
_NAMED_CHILDREN = frozenset({"properties", "$defs", "definitions", "patternProperties"})

# Schema keywords that hold example or fixed *values* rather than prose.
_VALUE_SLOTS = frozenset({"enum", "default", "const", "examples"})

Path = tuple[str | int, ...]


def escape_token(token: str | int) -> str:
    """Escape one JSON pointer reference token (RFC 6901)."""
    return str(token).replace("~", "~0").replace("/", "~1")


def to_pointer(path: Path) -> str:
    return "".join("/" + escape_token(p) for p in path)


@dataclass(frozen=True)
class TextField:
    """One string the model can see, with where it came from."""

    server: str
    kind: ItemKind
    item: str
    """Tool or prompt name, resource URI, or the server name for server-level fields."""
    item_path: Path
    """Path of the owning item inside the snapshot, e.g. ``("tools", 3)``; empty for server-level fields."""
    path: Path
    """Path of this field inside the item, e.g. ``("inputSchema", "properties", "notes", "description")``."""
    text: str
    is_key: bool = False
    """True when the text is a dictionary key (a parameter name), not a value."""
    param: str | None = None
    """Name of the top-level parameter this field belongs to, if any."""

    @property
    def pointer(self) -> str:
        return to_pointer(self.item_path + self.path)

    @property
    def item_pointer(self) -> str:
        return to_pointer(self.item_path)

    @property
    def leaf(self) -> str | int | None:
        return self.path[-1] if self.path else None

    @property
    def in_value_slot(self) -> bool:
        """True for enum values, defaults, consts and examples."""
        return any(p in _VALUE_SLOTS for p in self.path if isinstance(p, str))

    @cached_property
    def canonical(self) -> str:
        """De-obfuscated single-line view of the text, for word-based rules."""
        return canonicalize(self.text)


@dataclass(frozen=True)
class NormalizedServer:
    name: str
    snapshot: ServerSnapshot
    fields: tuple[TextField, ...]

    @cached_property
    def tool_names(self) -> frozenset[str]:
        return frozenset(t["name"] for t in self.snapshot.tools if isinstance(t.get("name"), str))


def walk_strings(value: Any, base: Path) -> Iterator[tuple[Path, str, bool]]:
    """Yield (path, text, is_key) for every string under ``value``, in document order."""
    stack: list[tuple[Any, Path]] = [(value, base)]
    while stack:
        current, path = stack.pop()
        if len(path) - len(base) > MAX_DEPTH:
            continue
        if isinstance(current, str):
            yield path, current, False
        elif isinstance(current, dict):
            names_are_visible = bool(path) and path[-1] in _NAMED_CHILDREN
            children: list[tuple[Any, Path]] = []
            for key, child in current.items():
                key = str(key)
                if key == "required" and isinstance(child, list):
                    continue  # repeats parameter names already emitted as keys
                if names_are_visible:
                    yield (*path, key), key, True
                children.append((child, (*path, key)))
            stack.extend(reversed(children))
        elif isinstance(current, list):
            stack.extend(reversed([(child, (*path, i)) for i, child in enumerate(current)]))


def _param_for(kind: ItemKind, item: dict[str, Any], path: Path) -> str | None:
    """Which top-level parameter a field belongs to, if any."""
    if kind == "tool" and len(path) >= 3 and path[0] == "inputSchema" and path[1] == "properties":
        return str(path[2])
    if kind == "prompt" and len(path) >= 2 and path[0] == "arguments" and isinstance(path[1], int):
        args = item.get("arguments")
        if isinstance(args, list) and path[1] < len(args) and isinstance(args[path[1]], dict):
            name = args[path[1]].get("name")
            return name if isinstance(name, str) else None
    return None


def _item_name(item: dict[str, Any], index: int) -> str:
    for key in ("name", "uri", "uriTemplate"):
        if isinstance(item.get(key), str):
            return item[key]
    return f"#{index}"


def normalize(snapshot: ServerSnapshot) -> NormalizedServer:
    """Flatten every model-visible string in ``snapshot`` into ``TextField`` records."""
    server = snapshot.server_name
    fields: list[TextField] = []

    if snapshot.instructions:
        fields.append(TextField(server, "server", server, (), ("instructions",), snapshot.instructions))
    if snapshot.server_info:
        for path, text, is_key in walk_strings(snapshot.server_info, ("serverInfo",)):
            fields.append(TextField(server, "server", server, (), path, text, is_key))

    for attr, segment, kind in _SECTIONS:
        for index, item in enumerate(getattr(snapshot, attr)):
            if not isinstance(item, dict):
                continue
            name = _item_name(item, index)
            for path, text, is_key in walk_strings(item, ()):
                fields.append(
                    TextField(server, kind, name, (segment, index), path, text, is_key, _param_for(kind, item, path))
                )

    return NormalizedServer(server, snapshot, tuple(fields))
