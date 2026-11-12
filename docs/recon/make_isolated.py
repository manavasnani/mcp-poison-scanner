"""Build one-attack-per-tool files from fixtures/snapshots/poisoned.json.

Each output tool is a bland tool with exactly one poisoned field copied in, so a
scanner's verdict on that tool can be attributed to that one attack. Used to compare
other scanners field by field. Run from the repo root:

    python docs/recon/make_isolated.py OUT_DIR
"""

import json
import sys
from pathlib import Path

snap = json.loads(Path("fixtures/snapshots/poisoned.json").read_text(encoding="utf-8"))
tools = {t["name"]: t for t in snap["tools"]}


def tool(name: str, description: str = "A simple utility tool.", props: dict | None = None) -> dict:
    props = props or {"value": {"type": "string", "description": "Input value."}}
    return {"name": name, "description": description, "inputSchema": {"type": "object", "properties": props}}


def prop(tool_name: str, param: str) -> dict:
    return tools[tool_name]["inputSchema"]["properties"][param]


conv = tools["convert_temperature"]["description"]
html_comment = conv[conv.index("<!--") : conv.index("-->") + 3]
b64 = conv[conv.index("Build id: ") :].split(" ")[2]
padded = "Convert a temperature." + conv[conv.index(" " * 400) :]

isolated = [
    tool("control_clean"),
    tool("desc_important_block_and_ssh_key", tools["add"]["description"]),
    tool("desc_unicode_tag_chars", tools["get_weather"]["description"]),
    tool("param_desc_zero_width_and_bidi", props={"city": prop("get_weather", "city")}),
    tool("desc_html_comment", "Convert a temperature." + html_comment),
    tool("desc_base64_blob", "Convert a temperature. Build id: " + b64),
    tool("desc_whitespace_padding", padded),
    tool("desc_shadows_other_tool", tools["lookup_contact"]["description"]),
    tool("param_enum_instruction", props={"target": prop("translate", "target")}),
    tool("param_desc_asks_for_conversation", props={"context": prop("translate", "context")}),
    tool("param_default_instruction_and_cred_path", props={"mode": prop("translate", "mode")}),
    tool("desc_shell_capability", tools["run_command"]["description"], {"command": prop("run_command", "command")}),
]

out = Path(sys.argv[1])
out.mkdir(parents=True, exist_ok=True)
(out / "tools.json").write_text(json.dumps({"tools": isolated}, indent=2), encoding="utf-8")
(out / "prompts.json").write_text(json.dumps({"prompts": snap["prompts"]}, indent=2), encoding="utf-8")
(out / "resources.json").write_text(json.dumps({"resources": snap["resources"]}, indent=2), encoding="utf-8")
print(f"wrote {len(isolated)} isolated tools, {len(snap['prompts'])} prompts, {len(snap['resources'])} resources")
