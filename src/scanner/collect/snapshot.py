"""Snapshot mode: read a saved server listing from disk. Runs no server code.

Accepted shapes, detected in this order:

1. A ``ServerSnapshot`` written by this tool (has ``format_version``).
2. A JSON-RPC response wrapping a list result: ``{"jsonrpc": "2.0", "result": {...}}``.
3. A bare list result: ``{"tools": [...], "prompts": [...], "resources": [...]}``,
   e.g. the saved output of ``tools/list``. Any subset of the keys is fine.
4. A bare JSON array of tool objects.

The file content is attacker-controlled, so it is size-capped and shape-checked,
and nothing in it is ever executed or interpreted beyond JSON parsing.
"""

from __future__ import annotations

import codecs
import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from scanner.models import SNAPSHOT_FORMAT_VERSION, ServerSnapshot

MAX_SNAPSHOT_BYTES = 20 * 1024 * 1024

_LIST_KEYS = {
    "tools": "tools",
    "prompts": "prompts",
    "resources": "resources",
    "resourceTemplates": "resource_templates",
}


class SnapshotError(ValueError):
    """The snapshot file is unreadable or not a recognised shape."""


def _check_items(value: Any, key: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise SnapshotError(f"'{key}' must be a JSON array")
    for i, item in enumerate(value):
        if not isinstance(item, dict):
            raise SnapshotError(f"'{key}[{i}]' must be a JSON object")
        # Resources are identified by uri, everything else by name; require some identifier.
        if not any(isinstance(item.get(k), str) for k in ("name", "uri", "uriTemplate")):
            raise SnapshotError(f"'{key}[{i}]' has no string 'name', 'uri' or 'uriTemplate'")
    return value


def parse_snapshot(data: Any, default_name: str) -> ServerSnapshot:
    """Turn parsed JSON into a ``ServerSnapshot``. Raises ``SnapshotError``."""
    if isinstance(data, dict) and "format_version" in data:
        if data["format_version"] != SNAPSHOT_FORMAT_VERSION:
            raise SnapshotError(
                f"unsupported snapshot format_version {data['format_version']!r}; "
                f"this version reads {SNAPSHOT_FORMAT_VERSION}"
            )
        try:
            snap = ServerSnapshot.model_validate(data)
        except ValidationError as exc:
            raise SnapshotError(f"invalid snapshot: {exc.error_count()} validation error(s)") from exc
        for key in ("tools", "prompts", "resources", "resource_templates"):
            _check_items(getattr(snap, key), key)
        return snap

    if isinstance(data, list):
        return ServerSnapshot(server_name=default_name, source="snapshot", tools=_check_items(data, "tools"))

    if not isinstance(data, dict):
        raise SnapshotError("snapshot must be a JSON object or array")

    if "jsonrpc" in data:
        if "result" not in data:
            raise SnapshotError("JSON-RPC message has no 'result'")
        data = data["result"]
        if not isinstance(data, dict):
            raise SnapshotError("JSON-RPC 'result' must be an object")

    found = {field: _check_items(data[key], key) for key, field in _LIST_KEYS.items() if key in data}
    if not found:
        raise SnapshotError("no 'tools', 'prompts', 'resources' or 'resourceTemplates' key found")

    return ServerSnapshot(server_name=default_name, source="snapshot", **found)


def _decode(raw: bytes) -> str:
    """Decode UTF-8 (with or without a BOM) or BOM-marked UTF-16.

    Windows PowerShell 5.1 writes ``>`` redirects as UTF-16 with a BOM, so a
    listing saved that way is a common real-world input.
    """
    if raw.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return raw.decode("utf-16")
    return raw.decode("utf-8-sig")


def load_snapshot(path: Path, server_name: str | None = None) -> ServerSnapshot:
    """Load a snapshot file. ``server_name`` overrides the name for raw listings."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise SnapshotError(f"cannot read {path}: {exc.strerror}") from exc
    if size > MAX_SNAPSHOT_BYTES:
        raise SnapshotError(f"{path} is {size} bytes; limit is {MAX_SNAPSHOT_BYTES}")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise SnapshotError(f"cannot read {path}: {exc.strerror}") from exc
    try:
        data = json.loads(_decode(raw))
    except UnicodeDecodeError as exc:
        raise SnapshotError(f"{path} is not valid UTF-8 or UTF-16") from exc
    except json.JSONDecodeError as exc:
        raise SnapshotError(f"{path} is not valid JSON: {exc.msg} (line {exc.lineno})") from exc
    except RecursionError as exc:
        raise SnapshotError(f"{path} is nested too deeply to parse") from exc
    return parse_snapshot(data, server_name or path.stem)


def save_snapshot(snapshot: ServerSnapshot, path: Path) -> None:
    # ensure_ascii keeps zero-width and bidi characters visible as \u escapes in the file.
    text = json.dumps(snapshot.model_dump(mode="json"), indent=2, ensure_ascii=True)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text + "\n", encoding="utf-8")
