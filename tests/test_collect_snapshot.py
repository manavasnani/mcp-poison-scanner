"""Snapshot mode: parsing saved listings. Runs no server code."""

import json

import pytest

from scanner.collect import SnapshotError, collect_in_process, load_snapshot, parse_snapshot, save_snapshot
from scanner.collect import snapshot as snapshot_mod
from tests.conftest import load_fixture_module

TOOL = {"name": "echo", "description": "Echo text.", "inputSchema": {"type": "object"}}


def test_bare_tools_list_result():
    snap = parse_snapshot({"tools": [TOOL]}, "srv")
    assert snap.server_name == "srv"
    assert snap.source == "snapshot"
    assert snap.tools == [TOOL]
    assert snap.prompts == []


def test_jsonrpc_response_is_unwrapped():
    snap = parse_snapshot({"jsonrpc": "2.0", "id": 1, "result": {"tools": [TOOL]}}, "srv")
    assert snap.tools == [TOOL]


def test_bare_array_of_tools():
    assert parse_snapshot([TOOL], "srv").tools == [TOOL]


def test_all_list_kinds_and_camelcase_templates():
    data = {
        "tools": [TOOL],
        "prompts": [{"name": "p", "description": "d"}],
        "resources": [{"uri": "file:///x", "name": "x"}],
        "resourceTemplates": [{"uriTemplate": "file:///{p}", "name": "t"}],
    }
    snap = parse_snapshot(data, "srv")
    assert len(snap.prompts) == len(snap.resources) == len(snap.resource_templates) == 1


def test_unknown_fields_are_preserved():
    tool = {**TOOL, "x-vendor-note": "hidden text the model might see"}
    assert parse_snapshot({"tools": [tool]}, "srv").tools[0]["x-vendor-note"].startswith("hidden")


@pytest.mark.parametrize(
    "data, message",
    [
        ("just a string", "JSON object or array"),
        ({}, "no 'tools'"),
        ({"jsonrpc": "2.0", "error": {"code": -1}}, "no 'result'"),
        ({"jsonrpc": "2.0", "result": []}, "'result' must be an object"),
        ({"tools": {"name": "x"}}, "must be a JSON array"),
        ({"tools": ["x"]}, "must be a JSON object"),
        ({"tools": [{"description": "no name"}]}, "no string 'name'"),
        ([{"name": 5}], "no string 'name'"),
    ],
)
def test_bad_shapes_are_rejected(data, message):
    with pytest.raises(SnapshotError, match=message):
        parse_snapshot(data, "srv")


def test_invalid_json_file(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(SnapshotError, match="not valid JSON"):
        load_snapshot(p)


def test_non_utf8_file(tmp_path):
    p = tmp_path / "bad.json"
    p.write_bytes(bytes([0x80, 0x81]) + b"{}")  # invalid as UTF-8, and no UTF-16 BOM
    with pytest.raises(SnapshotError, match="UTF-8"):
        load_snapshot(p)


def test_missing_file(tmp_path):
    with pytest.raises(SnapshotError, match="cannot read"):
        load_snapshot(tmp_path / "nope.json")


def test_oversized_file_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(snapshot_mod, "MAX_SNAPSHOT_BYTES", 10)
    p = tmp_path / "big.json"
    p.write_text(json.dumps({"tools": [TOOL]}), encoding="utf-8")
    with pytest.raises(SnapshotError, match="limit is 10"):
        load_snapshot(p)


def test_file_stem_is_default_name_and_override_wins(tmp_path):
    p = tmp_path / "github-server.json"
    p.write_text(json.dumps({"tools": [TOOL]}), encoding="utf-8")
    assert load_snapshot(p).server_name == "github-server"
    assert load_snapshot(p, "gh").server_name == "gh"


@pytest.mark.anyio
async def test_save_then_load_round_trips_hidden_unicode(tmp_path):
    original = await collect_in_process(load_fixture_module("poisoned").server)
    path = tmp_path / "poisoned.json"
    save_snapshot(original, path)

    # Saved file is pure ASCII: invisible characters show up as \u escapes on inspection.
    raw = path.read_bytes()
    assert raw.isascii()
    assert b"\\u200b" in raw

    loaded = load_snapshot(path)
    assert loaded == original


def test_save_creates_the_folder_it_is_asked_to_write_into(tmp_path):
    from scanner.models import ServerSnapshot

    target = tmp_path / "new" / "folder" / "server.json"
    save_snapshot(ServerSnapshot(server_name="s", source="snapshot"), target)
    assert load_snapshot(target).server_name == "s"
