"""TP003: hidden or obfuscated text.

Text the user cannot see in a client's approval dialog but the model still reads:
invisible characters, direction overrides, HTML comments, encoded blobs, and
padding that pushes text out of view. This rule looks at the raw text, since the
obfuscation itself is the signal.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from collections.abc import Iterator

from scanner.models import Finding, Severity
from scanner.normalize import TextField
from scanner.rules.base import Rule, ScanContext
from scanner.textutil import BIDI_CONTROLS, VARIATION_SELECTORS, ZERO_WIDTH, ZWJ, decode_tags, excerpt, is_tag_char

_HTML_COMMENT = re.compile(r"<!--.{0,2000}?(-->|$)", re.DOTALL)
_BASE64_RUN = re.compile(r"[A-Za-z0-9+/_-]{40,}={0,2}")
# A long run of blanks, or many blank lines, with more text after it.
_PADDING = re.compile(r"(?:[ \t\xa0]{30,}|(?:[ \t]*\r?\n){8,})(?=\S)")

MIN_DECODED_PRINTABLE = 0.9


def _is_emoji_like(ch: str) -> bool:
    return unicodedata.category(ch) == "So" or ord(ch) in VARIATION_SELECTORS or ord(ch) >= 0x1F000


def _first_index(text: str, predicate) -> int:
    return next((i for i, ch in enumerate(text) if predicate(ch)), -1)


def _span_evidence(text: str, index: int) -> str:
    return excerpt(text, index, index + 1, pad=30)


def decode_base64_text(blob: str) -> str | None:
    """Return the decoded text if ``blob`` is base64 of readable text, else None.

    Hashes, IDs and binary data also look like base64 but decode to noise, so only
    blobs that decode to mostly printable text are treated as hidden instructions.
    """
    candidate = blob.replace("-", "+").replace("_", "/").rstrip("=")
    candidate += "=" * (-len(candidate) % 4)
    try:
        raw = base64.b64decode(candidate, validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(decoded) < 16 or " " not in decoded:
        return None
    printable = sum(ch.isprintable() or ch in "\n\t" for ch in decoded)
    return decoded if printable / len(decoded) >= MIN_DECODED_PRINTABLE else None


def _zero_width_index(text: str) -> int:
    """Index of the first suspicious zero-width character, or -1.

    A zero-width joiner between emoji is how family and flag emoji are built, so it
    is only reported when it does not sit next to an emoji.
    """
    for i, ch in enumerate(text):
        cp = ord(ch)
        if cp in ZERO_WIDTH:
            return i
        if cp == ZWJ:
            before = text[i - 1] if i > 0 else ""
            after = text[i + 1] if i + 1 < len(text) else ""
            if not (before and after and _is_emoji_like(before) and _is_emoji_like(after)):
                return i
    return -1


def find_hidden(field: TextField) -> Iterator[tuple[str, str]]:
    """Yield (message, evidence) for each kind of hidden text in the field."""
    text = field.text

    hidden = decode_tags(text)
    if any(is_tag_char(ch) for ch in text):
        i = _first_index(text, is_tag_char)
        count = sum(is_tag_char(ch) for ch in text)
        shown = excerpt(hidden, 0, min(len(hidden), 120), pad=0) if hidden.strip() else _span_evidence(text, i)
        yield f"Contains {count} invisible Unicode tag characters that spell out hidden text.", shown

    i = _zero_width_index(text)
    if i >= 0:
        message = "Contains zero-width characters, which can split words to dodge filters or hide text."
        yield message, _span_evidence(text, i)

    i = _first_index(text, lambda ch: ord(ch) in BIDI_CONTROLS)
    if i >= 0:
        message = "Contains text-direction control characters, which make text display differently from what is read."
        yield message, _span_evidence(text, i)

    i = _first_index(text, lambda ch: unicodedata.category(ch) == "Cc" and ch not in "\n\r\t")
    if i >= 0:
        yield "Contains control characters, such as terminal escape codes.", _span_evidence(text, i)

    comment = _HTML_COMMENT.search(text)
    if comment:
        message = "Contains an HTML comment, which most clients do not display."
        yield message, excerpt(text, comment.start(), comment.end(), pad=0)

    for blob in _BASE64_RUN.finditer(text):
        decoded = decode_base64_text(blob.group(0))
        if decoded is not None:
            message = f"Contains a base64 blob ({len(blob.group(0))} characters) that decodes to readable text."
            yield message, excerpt(decoded, 0, min(len(decoded), 120), pad=0)
            break

    padding = _PADDING.search(text)
    if padding:
        size = padding.end() - padding.start()
        message = f"Contains {size} characters of blank padding before more text, which can push it out of view."
        yield message, excerpt(text, padding.end(), min(len(text), padding.end() + 80), pad=0)


def _check(rule: Rule, ctx: ScanContext) -> Iterator[Finding]:
    for field in ctx.fields:
        for message, evidence in find_hidden(field):
            yield rule.finding(field, message, evidence)


RULE = Rule(
    id="TP003",
    title="Hidden or obfuscated text",
    severity=Severity.HIGH,
    remediation=(
        "Honest metadata has no reason to hide text. Inspect the raw field shown in the evidence and do not "
        "connect the server unless the hidden content is explained."
    ),
    check=_check,
)
