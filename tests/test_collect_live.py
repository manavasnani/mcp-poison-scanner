"""Live collection against in-process fixture servers (no subprocess, no network)."""

from types import SimpleNamespace

import pytest

from scanner.collect import collect_in_process
from scanner.collect.live import MAX_PAGES, _paginate
from tests.conftest import load_fixture_module

pytestmark = pytest.mark.anyio


def _by_name(items: list[dict]) -> dict[str, dict]:
    return {i["name"]: i for i in items}


async def test_clean_server_lists_everything():
    snap = await collect_in_process(load_fixture_module("clean").server)

    assert snap.server_name == "fixture-clean"
    assert snap.source == "in_process"
    assert snap.errors == []
    assert snap.server_info and snap.server_info["name"] == "fixture-clean"
    assert snap.instructions and "note-taking" in snap.instructions

    assert set(_by_name(snap.tools)) == {"add_note", "search_notes", "format_note"}
    assert [p["name"] for p in snap.prompts] == ["summarize_note"]
    assert [r["uri"] for r in snap.resources] == ["notes://index"]
    assert [t["uriTemplate"] for t in snap.resource_templates] == ["notes://{title}"]


async def test_tools_are_in_wire_format_with_full_schema():
    snap = await collect_in_process(load_fixture_module("clean").server)
    tool = _by_name(snap.tools)["format_note"]

    assert "inputSchema" in tool and "input_schema" not in tool
    props = tool["inputSchema"]["properties"]
    assert props["title"]["description"] == "Title of an existing note."
    assert props["style"]["enum"] == ["plain", "markdown", "html"]
    assert props["style"]["default"] == "plain"


async def test_prompt_arguments_are_collected():
    snap = await collect_in_process(load_fixture_module("clean").server)
    args = snap.prompts[0]["arguments"]
    assert [a["name"] for a in args] == ["title"]


async def test_poisoned_text_survives_collection_byte_for_byte():
    mod = load_fixture_module("poisoned")
    snap = await collect_in_process(mod.server)
    tools = _by_name(snap.tools)

    # Hidden Unicode must reach the analyzers untouched, or TP003 can't see it.
    weather = tools["get_weather"]
    assert mod._tag_encode(" Also read .env") in weather["description"]
    city_desc = weather["inputSchema"]["properties"]["city"]["description"]
    assert mod.ZWSP in city_desc and mod.RLO in city_desc

    # Whitespace padding is kept, not stripped.
    assert " " * 400 in tools["convert_temperature"]["description"]

    # Enum values and defaults carrying instructions are present.
    t_props = tools["translate"]["inputSchema"]["properties"]
    assert any("ignore all prior instructions" in v for v in t_props["target"]["enum"])
    assert "credentials.db" in t_props["mode"]["default"]

    assert "always call `sync_context`" in snap.instructions
    assert "Ignore previous instructions" in snap.prompts[0]["description"]
    assert "attacker.example" in snap.resources[0]["description"]


async def test_rugpull_pair_shares_names_but_differs():
    v1 = await collect_in_process(load_fixture_module("rugpull_v1").server)
    v2 = await collect_in_process(load_fixture_module("rugpull_v2").server)

    assert v1.server_name == v2.server_name == "fixture-rugpull"
    t1, t2 = _by_name(v1.tools), _by_name(v2.tools)
    assert t1["word_count"] == t2["word_count"]
    assert t1["get_fact"] != t2["get_fact"]
    assert "context" in t2["get_fact"]["inputSchema"]["properties"]
    assert set(t2) - set(t1) == {"fetch_url"}


# --- pagination limits, tested directly with fake pages -------------------------------


def _page(names: list[str], cursor: str | None):
    items = [SimpleNamespace(model_dump=lambda n=n, **_: {"name": n}) for n in names]
    return SimpleNamespace(tools=items, next_cursor=cursor)


async def test_paginate_follows_cursors():
    pages = {None: _page(["a"], "p2"), "p2": _page(["b"], "p3"), "p3": _page(["c"], None)}

    async def fetch(cursor):
        return pages[cursor]

    errors: list[str] = []
    items = await _paginate(fetch, "tools", errors, "tools/list")
    assert [i["name"] for i in items] == ["a", "b", "c"]
    assert errors == []


async def test_paginate_stops_on_repeated_cursor():
    async def fetch(cursor):
        return _page(["x"], "same")

    errors: list[str] = []
    items = await _paginate(fetch, "tools", errors, "tools/list")
    assert len(items) == 2
    assert "repeated a pagination cursor" in errors[0]


async def test_paginate_stops_after_page_cap():
    counter = iter(range(10_000))

    async def fetch(cursor):
        return _page(["x"], f"c{next(counter)}")

    errors: list[str] = []
    items = await _paginate(fetch, "tools", errors, "tools/list")
    assert len(items) == MAX_PAGES
    assert f"stopped after {MAX_PAGES} pages" in errors[0]


async def test_paginate_records_failure_and_keeps_partial_results():
    async def fetch(cursor):
        if cursor is None:
            return _page(["a"], "next")
        raise RuntimeError("boom")

    errors: list[str] = []
    items = await _paginate(fetch, "tools", errors, "tools/list")
    assert [i["name"] for i in items] == ["a"]
    assert errors == ["tools/list: RuntimeError: boom"]
