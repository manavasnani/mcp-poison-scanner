"""Core data models.

A ``ServerSnapshot`` is everything a server exposes to the model, stored as plain
JSON dicts in MCP wire format (camelCase keys, e.g. ``inputSchema``). Keeping raw
dicts rather than SDK models means no field the server sent is dropped or renamed,
which matters because poisoning can hide in any field.

Everything inside a snapshot is untrusted, attacker-controlled data.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field

SNAPSHOT_FORMAT_VERSION = 1

SourceKind = Literal["snapshot", "stdio", "http", "docker", "in_process"]


class ServerSnapshot(BaseModel):
    """The listed metadata of one MCP server at one point in time."""

    format_version: int = SNAPSHOT_FORMAT_VERSION
    server_name: str
    """Name from the client config, CLI, or the server's own serverInfo."""
    source: SourceKind
    server_info: dict[str, Any] | None = None
    instructions: str | None = None
    """Server-level instructions sent at initialize; also reaches the model."""
    tools: list[dict[str, Any]] = Field(default_factory=list)
    prompts: list[dict[str, Any]] = Field(default_factory=list)
    resources: list[dict[str, Any]] = Field(default_factory=list)
    resource_templates: list[dict[str, Any]] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    """Non-fatal problems hit while collecting (e.g. a list call that failed)."""


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3}

ItemKind = Literal["server", "tool", "prompt", "resource", "resource_template"]


class Finding(BaseModel):
    """One problem found in one field of one server's metadata."""

    rule_id: str
    severity: Severity
    title: str
    """Short name of the rule, e.g. 'Hidden or obfuscated text'."""
    server: str
    item_kind: ItemKind
    item_name: str
    """Tool or prompt name, resource URI, or the server name for server-level fields."""
    pointer: str
    """JSON pointer to the exact field inside the server's snapshot,
    e.g. ``/tools/3/inputSchema/properties/notes/description``."""
    message: str
    """What was found, in one sentence."""
    evidence: str
    """Matched text with context: secrets redacted, invisible characters escaped, length-capped."""
    remediation: str
