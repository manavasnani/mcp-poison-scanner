"""Rule plumbing: what a rule is and how it reports a finding."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass

from scanner.models import Finding, ItemKind, Severity
from scanner.normalize import NormalizedServer, TextField
from scanner.textutil import excerpt


@dataclass(frozen=True)
class ScanContext:
    """Everything a rule may look at: all servers in one scan (one client config)."""

    servers: tuple[NormalizedServer, ...]

    @property
    def fields(self) -> Iterator[TextField]:
        for server in self.servers:
            yield from server.fields


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    remediation: str
    check: Callable[[Rule, ScanContext], Iterable[Finding]]

    def run(self, ctx: ScanContext) -> list[Finding]:
        return list(self.check(self, ctx))

    def finding(
        self,
        field: TextField,
        message: str,
        evidence: str,
        pointer: str | None = None,
        *,
        severity: Severity | None = None,
        remediation: str | None = None,
    ) -> Finding:
        """A finding on one field. ``severity`` and ``remediation`` replace the rule's own when given."""
        found = self.finding_at(
            field.server, field.kind, field.item, pointer if pointer is not None else field.pointer, message, evidence
        )
        changes = {"severity": severity, "remediation": remediation}
        return found.model_copy(update={k: v for k, v in changes.items() if v is not None})

    def finding_at(
        self, server: str, item_kind: ItemKind, item_name: str, pointer: str, message: str, evidence: str
    ) -> Finding:
        """A finding about an item as a whole, for rules that do not work field by field."""
        return Finding(
            rule_id=self.id,
            severity=self.severity,
            title=self.title,
            server=server,
            item_kind=item_kind,
            item_name=item_name,
            pointer=pointer,
            message=message,
            evidence=evidence,
            remediation=self.remediation,
        )


@dataclass(frozen=True)
class Pattern:
    """A labelled regular expression. All quantifiers must be bounded to keep matching linear."""

    label: str
    regex: re.Pattern[str]
    weak: bool = False
    """True when honest servers write this too, so a match alone is not evidence of an attack."""


def pattern(label: str, regex: str, *, case_sensitive: bool = False, weak: bool = False) -> Pattern:
    return Pattern(label, re.compile(regex, 0 if case_sensitive else re.IGNORECASE), weak)


def first_match(patterns: Iterable[Pattern], text: str) -> tuple[Pattern, re.Match[str]] | None:
    for pat in patterns:
        match = pat.regex.search(text)
        if match:
            return pat, match
    return None


def all_matches(patterns: Iterable[Pattern], text: str) -> list[tuple[Pattern, re.Match[str]]]:
    """The first match of each pattern that matches, in pattern order."""
    found = []
    for pat in patterns:
        match = pat.regex.search(text)
        if match:
            found.append((pat, match))
    return found


def match_evidence(text: str, match: re.Match[str]) -> str:
    return excerpt(text, match.start(), match.end())
