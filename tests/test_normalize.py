"""Normalizer: every model-visible string becomes a (pointer, text) field."""

from scanner.models import ServerSnapshot
from scanner.normalize import MAX_DEPTH, escape_token, normalize
from scanner.textutil import canonicalize, redact, visible
from tests.conftest import ROOT
from tests.helpers import server, tool


def by_pointer(snap: ServerSnapshot) -> dict[str, str]:
    return {f.pointer: f.text for f in normalize(snap).fields}


def test_flattens_every_string_in_a_tool():
    snap = server(
        "srv",
        {
            "name": "translate",
            "title": "Translate",
            "description": "Translate text.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Language.",
                        "enum": ["fr", "de"],
                        "default": "fr",
                        "examples": ["es"],
                    }
                },
                "required": ["target"],
            },
            "annotations": {"title": "Annotated title"},
            "_meta": {"vendor": {"note": "meta text"}},
        },
    )
    fields = by_pointer(snap)
    base = "/tools/0/inputSchema/properties/target"
    assert fields["/tools/0/name"] == "translate"
    assert fields["/tools/0/title"] == "Translate"
    assert fields["/tools/0/description"] == "Translate text."
    assert fields[base] == "target"  # the parameter name itself
    assert fields[f"{base}/description"] == "Language."
    assert fields[f"{base}/enum/0"] == "fr" and fields[f"{base}/enum/1"] == "de"
    assert fields[f"{base}/default"] == "fr"
    assert fields[f"{base}/examples/0"] == "es"
    assert fields["/tools/0/annotations/title"] == "Annotated title"
    assert fields["/tools/0/_meta/vendor/note"] == "meta text"
    assert not any("/required/" in p for p in fields)  # duplicates of parameter names


def test_covers_instructions_prompts_resources_and_templates():
    snap = ServerSnapshot(
        server_name="srv",
        source="snapshot",
        instructions="Server instructions.",
        server_info={"name": "srv-impl", "version": "1.0"},
        prompts=[{"name": "p", "description": "Prompt.", "arguments": [{"name": "topic", "description": "Topic."}]}],
        resources=[{"uri": "x://y", "name": "y", "description": "Resource."}],
        resource_templates=[{"uriTemplate": "x://{id}", "name": "t", "description": "Template."}],
    )
    fields = by_pointer(snap)
    assert fields["/instructions"] == "Server instructions."
    assert fields["/serverInfo/name"] == "srv-impl"
    assert fields["/prompts/0/arguments/0/description"] == "Topic."
    assert fields["/resources/0/description"] == "Resource."
    assert fields["/resourceTemplates/0/description"] == "Template."


def test_field_metadata():
    snap = server("srv", tool("t", "D.", notes={"type": "string", "description": "N.", "enum": ["a"]}))
    fields = {f.pointer: f for f in normalize(snap).fields}

    name = fields["/tools/0/inputSchema/properties/notes"]
    assert name.is_key and name.param == "notes" and name.kind == "tool" and name.item == "t"

    desc = fields["/tools/0/inputSchema/properties/notes/description"]
    assert not desc.is_key and desc.param == "notes" and not desc.in_value_slot and desc.leaf == "description"

    enum = fields["/tools/0/inputSchema/properties/notes/enum/0"]
    assert enum.in_value_slot and enum.param == "notes"

    top = fields["/tools/0/description"]
    assert top.param is None and top.item_pointer == "/tools/0"


def test_prompt_argument_fields_know_their_parameter():
    snap = ServerSnapshot(
        server_name="s",
        source="snapshot",
        prompts=[{"name": "p", "arguments": [{"name": "topic", "description": "T"}]}],
    )
    field = next(f for f in normalize(snap).fields if f.pointer == "/prompts/0/arguments/0/description")
    assert field.param == "topic" and field.kind == "prompt"


def test_resources_are_named_by_name_then_uri():
    snap = ServerSnapshot(server_name="s", source="snapshot", resources=[{"uri": "x://only-uri", "description": "d"}])
    assert {f.item for f in normalize(snap).fields} == {"x://only-uri"}


def test_pointer_tokens_are_escaped():
    assert escape_token("a/b~c") == "a~1b~0c"
    snap = server("srv", tool("t", "D.", **{"we/ird~name": "Odd."}))
    assert "/tools/0/inputSchema/properties/we~1ird~0name/description" in by_pointer(snap)


def test_nested_and_unknown_structures_are_walked():
    schema = {
        "type": "object",
        "properties": {"outer": {"type": "object", "properties": {"inner": {"description": "Deep."}}}},
        "$defs": {"Shape": {"description": "A def."}},
        "x-vendor": ["loose", {"k": "nested"}],
    }
    fields = by_pointer(server("srv", {"name": "t", "inputSchema": schema}))
    assert fields["/tools/0/inputSchema/properties/outer/properties/inner/description"] == "Deep."
    assert fields["/tools/0/inputSchema/properties/outer/properties/inner"] == "inner"
    assert fields["/tools/0/inputSchema/$defs/Shape"] == "Shape"
    assert fields["/tools/0/inputSchema/x-vendor/0"] == "loose"
    assert fields["/tools/0/inputSchema/x-vendor/1/k"] == "nested"


def test_non_string_values_and_bad_items_are_skipped():
    snap = ServerSnapshot(
        server_name="s",
        source="snapshot",
        tools=[{"name": "t", "inputSchema": {"properties": {"n": {"default": 5, "minimum": 1.5, "nullable": None}}}}],
    )
    assert set(by_pointer(snap)) == {"/tools/0/name", "/tools/0/inputSchema/properties/n"}


def test_very_deep_nesting_is_cut_off_without_error():
    deep: dict = {"description": "bottom"}
    for _ in range(MAX_DEPTH * 3):
        deep = {"x": deep}
    fields = by_pointer(server("srv", {"name": "t", "inputSchema": deep}))
    assert "bottom" not in fields.values()
    assert fields["/tools/0/name"] == "t"


def test_fields_come_out_in_document_order():
    snap = server("srv", tool("first", "A."), tool("second", "B."))
    pointers = [f.pointer for f in normalize(snap).fields]
    assert pointers.index("/tools/0/description") < pointers.index("/tools/1/name")
    assert pointers == sorted(pointers, key=lambda p: int(p.split("/")[2]))


def test_fixture_snapshot_has_a_field_for_every_poisoned_location():
    from scanner.collect import load_snapshot
    from tests.conftest import load_fixture_module

    snap = load_snapshot(ROOT / "fixtures" / "snapshots" / "poisoned.json")
    pointers = [f.pointer for f in normalize(snap).fields]
    for kind, _name, path, _rule in load_fixture_module("poisoned").POISONED_LOCATIONS:
        if kind == "server":
            assert path in pointers
        else:
            assert any(p.endswith(path) or f"{path}/" in p for p in pointers), path


# --- text helpers ---------------------------------------------------------------------------


def test_canonicalize_undoes_cheap_obfuscation():
    zwsp, rlo = chr(0x200B), chr(0x202E)
    tagged = "".join(chr(0xE0000 + ord(c)) for c in "hidden")
    assert canonicalize(f"ig{zwsp}nore  this\n\n  {rlo}now") == "ignore this now"
    assert canonicalize("see " + tagged) == "see hidden"
    assert canonicalize(chr(0xFF49) + chr(0xFF47) + "nore") == "ignore"  # fullwidth letters


def test_visible_escapes_everything_unprintable():
    out = visible("a" + chr(0x200B) + "b" + chr(0x1B) + "[0m\n" + chr(0xE0041) + chr(0x202E))
    assert out == "a\\u200bb\\u001b[0m\\n\\U000e0041\\u202e"
    assert visible("plain caf" + chr(0xE9)) == "plain caf" + chr(0xE9)


def test_redact_masks_tokens_and_long_blobs_but_not_paths():
    assert "redacted" in redact("key sk-abcdefghijklmnopqrstuvwx here")
    blob = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5YWJjZGVm"
    assert blob not in redact(f"data {blob} end")
    path = "/usr/local/share/applications/vendor/product/resources/config"
    assert redact(path) == path
