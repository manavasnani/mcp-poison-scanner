"""Awkward snapshot files: encodings, hostile shapes, and saved-fixture freshness."""

import codecs
import json
import unicodedata
from pathlib import Path

import pytest

from scanner.collect import SnapshotError, collect_in_process, load_snapshot
from tests.conftest import ROOT, load_fixture_module

LISTING = {"tools": [{"name": "t", "description": "d"}]}


def test_utf8_with_bom_is_accepted(tmp_path):
    p = tmp_path / "bom.json"
    p.write_bytes(codecs.BOM_UTF8 + json.dumps(LISTING).encode("utf-8"))
    assert load_snapshot(p).tools == LISTING["tools"]


@pytest.mark.parametrize("encoding", ["utf-16", "utf-16-le", "utf-16-be"])
def test_utf16_with_bom_is_accepted(tmp_path, encoding):
    # Windows PowerShell 5.1 saves `>` redirects as UTF-16 with a BOM.
    bom = {"utf-16-le": codecs.BOM_UTF16_LE, "utf-16-be": codecs.BOM_UTF16_BE}.get(encoding, b"")
    p = tmp_path / "ps.json"
    p.write_bytes(bom + json.dumps(LISTING).encode(encoding))
    assert load_snapshot(p).tools == LISTING["tools"]


def test_deeply_nested_json_is_rejected_not_crashed(tmp_path):
    p = tmp_path / "deep.json"
    p.write_text("[" * 200_000 + "]" * 200_000, encoding="utf-8")
    with pytest.raises(SnapshotError, match="nested too deeply"):
        load_snapshot(p)


def test_directory_path_is_rejected(tmp_path):
    with pytest.raises(SnapshotError, match="cannot read"):
        load_snapshot(tmp_path)


def test_unsupported_format_version_is_rejected(tmp_path):
    p = tmp_path / "future.json"
    p.write_text(json.dumps({"format_version": 99, "server_name": "x", "source": "snapshot"}), encoding="utf-8")
    with pytest.raises(SnapshotError, match="unsupported snapshot format_version 99"):
        load_snapshot(p)


@pytest.mark.anyio
@pytest.mark.parametrize("name", ["clean", "poisoned", "rugpull_v1", "rugpull_v2"])
async def test_saved_fixture_snapshots_match_their_servers(name):
    """fixtures/snapshots/*.json must be regenerated whenever a fixture server changes."""
    saved = load_snapshot(ROOT / "fixtures" / "snapshots" / f"{name}.json")
    live = await collect_in_process(load_fixture_module(name).server)
    for field in ("instructions", "tools", "prompts", "resources", "resource_templates"):
        assert getattr(saved, field) == getattr(live, field), f"{name}.json is stale in '{field}'"


def test_source_files_contain_no_literal_invisible_characters():
    """Invisible and bidi characters must be written as escapes, never pasted into source.

    A literal right-to-left override in code is itself an attack (Trojan Source), and
    makes the fixtures impossible to review by eye.
    """
    offenders = []
    for folder in ("src", "tests", "fixtures/servers"):
        for path in Path(ROOT, folder).rglob("*.py"):
            for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                bad = {f"U+{ord(c):04X}" for c in line if unicodedata.category(c) in ("Cf", "Co", "Cn")}
                if bad:
                    offenders.append(f"{path.relative_to(ROOT)}:{lineno} {sorted(bad)}")
    assert offenders == []
