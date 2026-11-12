"""Text helpers shared by the normalizer, the rules and the reporters.

Three jobs:

- ``canonicalize``: undo cheap obfuscation so word-based rules still match.
- ``visible``: make attacker-controlled text safe and readable to print.
- ``redact`` / ``excerpt``: build the short evidence string shown in a finding.

Invisible characters are referred to by code point (``chr(0x200B)``) throughout,
never pasted literally, so this file stays reviewable.
"""

from __future__ import annotations

import re
import unicodedata

ZERO_WIDTH = frozenset({0x200B, 0x200C, 0x2060, 0xFEFF, 0x180E, 0x00AD})
"""Zero-width space, non-joiner, word joiner, BOM, Mongolian vowel separator, soft hyphen."""

ZWJ = 0x200D
"""Zero-width joiner: legitimate inside emoji sequences, suspicious elsewhere."""

BIDI_CONTROLS = frozenset({0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069, 0x200E, 0x200F})
"""Embedding, override, isolate and mark characters that reorder displayed text."""

TAG_BLOCK = range(0xE0000, 0xE0080)
"""Unicode tag characters: invisible copies of ASCII, offset by 0xE0000."""

VARIATION_SELECTORS = range(0xFE00, 0xFE10)

_WS_RUN = re.compile(r"\s+")


def is_tag_char(ch: str) -> bool:
    return ord(ch) in TAG_BLOCK


def decode_tags(text: str) -> str:
    """Return the ASCII text hidden in Unicode tag characters, or '' if there is none."""
    return "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E)


def canonicalize(text: str) -> str:
    """A de-obfuscated, single-line view of ``text`` for word-based matching.

    Tag characters become the ASCII they encode, other invisible format characters
    are dropped (so a word split by zero-width spaces is whole again), compatibility
    forms are folded (NFKC: fullwidth letters and the like), and whitespace runs
    collapse to one space. Offsets do not map back to the original text.
    """
    out: list[str] = []
    for ch in text:
        cp = ord(ch)
        if 0xE0020 <= cp <= 0xE007E:
            out.append(chr(cp - 0xE0000))
        elif cp in TAG_BLOCK or unicodedata.category(ch) == "Cf":
            continue
        else:
            out.append(ch)
    folded = unicodedata.normalize("NFKC", "".join(out))
    return _WS_RUN.sub(" ", folded).strip()


def visible(text: str) -> str:
    """Escape everything that is not plainly printable.

    Finding evidence is attacker-controlled and ends up in a terminal or a report,
    so control characters, invisible characters and direction overrides are shown as
    ``\\uXXXX`` escapes instead of being emitted raw.
    """
    out: list[str] = []
    for ch in text:
        cp = ord(ch)
        if ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif ch == " " or (ch.isprintable() and unicodedata.category(ch) not in ("Cf", "Co", "Cn", "Zs", "Zl", "Zp")):
            out.append(ch)
        elif cp > 0xFFFF:
            out.append(f"\\U{cp:08x}")
        else:
            out.append(f"\\u{cp:04x}")
    return "".join(out)


_SECRET_TOKEN = re.compile(
    r"\b(sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{30,})"
)
_LONG_BLOB = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")


def _looks_like_key_material(blob: str) -> bool:
    if blob.count("/") > len(blob) / 12:  # a long file path, not an encoded blob
        return False
    return any(c.isdigit() for c in blob) and any(c.islower() for c in blob) and any(c.isupper() for c in blob)


def redact(text: str) -> str:
    """Mask secrets so a report never repeats a credential it found."""

    def mask(match: re.Match[str]) -> str:
        value = match.group(0)
        return f"{value[:6]}...[{len(value)} chars redacted]"

    text = _SECRET_TOKEN.sub(mask, text)
    return _LONG_BLOB.sub(lambda m: mask(m) if _looks_like_key_material(m.group(0)) else m.group(0), text)


MAX_EVIDENCE = 200


def excerpt(text: str, start: int, end: int, pad: int = 50) -> str:
    """The matched span with some context, redacted, escaped and length-capped."""
    lo, hi = max(0, start - pad), min(len(text), end + pad)
    snippet = redact(text[lo:hi])
    shown = visible(snippet)
    if len(shown) > MAX_EVIDENCE:
        shown = shown[: MAX_EVIDENCE - 3] + "..."
    return ("..." if lo > 0 else "") + shown + ("..." if hi < len(text) else "")
