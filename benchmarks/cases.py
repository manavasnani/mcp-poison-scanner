"""Benchmark cases and the loaders that build them.

A case is one item (usually one tool) with a known label, inside the server it would
be seen in. Scanners are judged on whether they flag that one item:

- ``mcptox``: MCPTox's poisoned tools (positives), each added to its real server's
  clean tool list, and those clean tools themselves (negatives).
- ``own``: handcrafted cases covering what MCPTox lacks (poison outside the
  description, hidden text, rug pulls) plus benign cases written to look suspicious.
- ``clean_servers``: tool lists collected from widely used real servers (negatives).
- ``signed_in``: the full listings of commercial servers, collected while signed in to
  an account (negatives). Their descriptions are longer and far more forceful.

MCPTox is split by server into a ``dev`` half and a ``held-out`` half (``mcptox_part``).
Rules may be tuned by looking at dev cases only; the held-out half is never inspected.

MCPTox has no license, so it is read from a local clone and never copied into this
repository. Nothing here runs or follows any text from a dataset.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scanner.collect import load_snapshot
from scanner.models import ItemKind, ServerSnapshot

HERE = Path(__file__).resolve().parent
MCPTOX_FILE = HERE / "datasets" / "raw" / "mcptox" / "response_all.json"
OWN_FILE = HERE / "datasets" / "own" / "cases.json"
CLEAN_SERVERS_DIR = HERE / "datasets" / "clean_servers"
SIGNED_IN_DIR = HERE / "datasets" / "signed_in_servers"

DEV, HELD_OUT = "dev", "held-out"


def mcptox_part(case_or_server: Case | str) -> str | None:
    """Which half of MCPTox a server (or a case) belongs to. None for other datasets.

    Decided by a hash of the server's name, so it never changes and nobody chose it.
    """
    if isinstance(case_or_server, str):
        server = case_or_server
    elif case_or_server.dataset != "mcptox":
        return None
    else:
        server = case_or_server.snapshot.server_name
    return DEV if hashlib.sha256(server.encode()).digest()[0] % 2 == 0 else HELD_OUT


POISONED, CLEAN = "poisoned", "clean"
NEWLINE = chr(10)
ESCAPED_NEWLINE = chr(92) + "n"


@dataclass(frozen=True)
class Case:
    id: str
    dataset: str
    label: str
    """``poisoned`` or ``clean``."""
    category: str
    """MCPTox: the security risk. Own cases: the technique family. Clean servers: the server."""
    subcategory: str
    snapshot: ServerSnapshot
    """The server the item is seen in. Shared between cases of the same server."""
    target_kind: ItemKind
    target_name: str
    """The item being judged: tool or prompt name, resource URI, or the server name."""
    pinned: ServerSnapshot | None = None
    """Rug-pull cases only: the server as it was when approved."""

    def target_item(self) -> dict[str, Any] | None:
        """The raw definition of the target item (None for a server-level target)."""
        section = {
            "tool": self.snapshot.tools,
            "prompt": self.snapshot.prompts,
            "resource": self.snapshot.resources,
            "resource_template": self.snapshot.resource_templates,
        }.get(self.target_kind)
        for item in section or []:
            if self.target_name in (item.get("name"), item.get("uri"), item.get("uriTemplate")):
                return item
        return None


class DatasetMissing(RuntimeError):
    """A dataset's files are not on this machine."""


# --- MCPTox -------------------------------------------------------------------------------------

_TOOL_START = re.compile(r"^Tool:[ \t]*", re.M)
_ARG_LINE = re.compile(r"^-[ \t]*([^:\n]{1,200}):[ \t]*(.*)$")
_REQUIRED = re.compile(r"[ \t]*\(required\)[ \t]*$")


def parse_tool_text(block: str) -> dict[str, Any]:
    """Turn MCPTox's ``name / Description: / Arguments:`` text into a tool definition.

    ``block`` starts right after ``Tool:``. Text that does not fit the format stays in
    the description, so nothing a model would have read is dropped.
    """
    name, _, rest = block.partition("\n")
    description, args_text = rest, ""
    marker = rest.rfind("\nArguments:")
    if rest.startswith("Arguments:"):
        description, args_text = "", rest[len("Arguments:") :]
    elif marker != -1:
        description, args_text = rest[:marker], rest[marker + len("\nArguments:") :]
    if description.startswith("Description:"):
        description = description[len("Description:") :]

    properties: dict[str, Any] = {}
    required: list[str] = []
    leftover: list[str] = []
    for line in args_text.splitlines():
        if not line.strip():
            continue
        if line.strip().lower() in ("- no arguments", "no arguments", "none"):
            continue
        match = _ARG_LINE.match(line.strip())
        if not match:
            leftover.append(line)
            continue
        arg, text = match.group(1).strip(), match.group(2)
        if _REQUIRED.search(text):
            required.append(arg)
            text = _REQUIRED.sub("", text)
        prop: dict[str, Any] = {"type": "string"}
        if text.strip() and text.strip() != "No description":
            prop["description"] = text.strip()
        properties[arg] = prop
    if leftover:
        description = description.rstrip() + "\n" + "\n".join(leftover)

    schema: dict[str, Any] = {"type": "object", "properties": properties}
    if required:
        schema["required"] = required
    return {"name": name.strip(), "description": description.strip(), "inputSchema": schema}


def split_tool_blocks(text: str) -> list[str]:
    """Each ``Tool:`` block in ``text``, without the leading marker."""
    starts = [m.end() for m in _TOOL_START.finditer(text)]
    begins = [m.start() for m in _TOOL_START.finditer(text)]
    return [text[start:end].rstrip() for start, end in zip(starts, [*begins[1:], len(text)], strict=True)]


def _clean_tools(prompt: str) -> list[dict[str, Any]]:
    blocks = split_tool_blocks(prompt)
    if blocks:
        # The last block runs into the prompt's closing instructions; cut at the first blank-line gap.
        blocks[-1] = re.split(r"\n\s*\n", blocks[-1], maxsplit=1)[0]
    return [parse_tool_text(block) for block in blocks]


def load_mcptox(path: Path = MCPTOX_FILE) -> list[Case]:
    if not path.exists():
        raise DatasetMissing(f"MCPTox not found at {path}. Fetch it with: python -m benchmarks.fetch_mcptox")
    data = json.loads(path.read_text(encoding="utf-8"))
    cases: list[Case] = []
    for server_name, server in data["servers"].items():
        clean = _clean_tools(server["clean_system_promot"])
        base = ServerSnapshot(server_name=server_name, source="snapshot", tools=clean)
        for tool in clean:
            cases.append(
                Case(
                    f"mcptox/{server_name}/clean/{tool['name']}",
                    "mcptox",
                    CLEAN,
                    "clean tool",
                    "",
                    base,
                    "tool",
                    tool["name"],
                )
            )
        for index, instance in enumerate(server["malicious_instance"]):
            if instance.get("wrong_data") != 0:
                continue  # marked invalid by the dataset's authors
            text = instance["poisoned_tool"]
            if NEWLINE not in text:
                # About half the instances store their line breaks as a literal backslash and "n".
                text = text.replace(ESCAPED_NEWLINE, NEWLINE)
            blocks = split_tool_blocks(text)
            if len(blocks) != 1:
                continue
            poisoned = parse_tool_text(blocks[0])
            # The attack adds a tool to the server; if it reuses a name, it replaces that tool.
            tools = [t for t in clean if t["name"] != poisoned["name"]] + [poisoned]
            meta = instance.get("metadata", {})
            cases.append(
                Case(
                    f"mcptox/{server_name}/poisoned/{index}",
                    "mcptox",
                    POISONED,
                    str(meta.get("security risk", "unknown")),
                    str(meta.get("paradigm", "unknown")),
                    ServerSnapshot(server_name=server_name, source="snapshot", tools=tools),
                    "tool",
                    poisoned["name"],
                )
            )
    return cases


# --- our own cases ------------------------------------------------------------------------------


def _snapshot(data: dict[str, Any]) -> ServerSnapshot:
    return ServerSnapshot(
        server_name=str(data.get("server_name", "server")),
        source="snapshot",
        instructions=data.get("instructions"),
        tools=list(data.get("tools", [])),
        prompts=list(data.get("prompts", [])),
        resources=list(data.get("resources", [])),
        resource_templates=list(data.get("resource_templates", [])),
    )


def load_own(path: Path = OWN_FILE) -> list[Case]:
    if not path.exists():
        raise DatasetMissing(
            f"own cases not found at {path}. Build them with: python {path.with_name('build_cases.py')}"
        )
    cases: list[Case] = []
    for raw in json.loads(path.read_text(encoding="utf-8")):
        snapshot = _snapshot(raw["snapshot"])
        target = raw["target"]
        name = snapshot.server_name if target["kind"] == "server" else target["name"]
        cases.append(
            Case(
                raw["id"],
                "own",
                raw["label"],
                raw["category"],
                raw.get("technique", ""),
                snapshot,
                target["kind"],
                name,
                _snapshot(raw["pinned"]) if raw.get("pinned") else None,
            )
        )
    return cases


# --- clean real servers -------------------------------------------------------------------------


def load_clean_servers(directory: Path = CLEAN_SERVERS_DIR, dataset: str = "clean_servers") -> list[Case]:
    files = sorted(directory.glob("*.json")) if directory.is_dir() else []
    if not files:
        raise DatasetMissing(
            f"no server snapshots in {directory}. Collect them with: python -m benchmarks.collect_clean"
            if dataset == "clean_servers"
            else f"no server snapshots in {directory}. Save some with: scanner collect --url ADDRESS --sign-in -o FILE"
        )
    cases: list[Case] = []
    for file in files:
        snapshot = load_snapshot(file).model_copy(update={"server_name": file.stem})
        sections: list[tuple[ItemKind, list[dict[str, Any]], tuple[str, ...]]] = [
            ("tool", snapshot.tools, ("name",)),
            ("prompt", snapshot.prompts, ("name",)),
            ("resource", snapshot.resources, ("uri", "name")),
            ("resource_template", snapshot.resource_templates, ("uriTemplate", "name")),
        ]
        if (snapshot.instructions or "").strip():
            # Server instructions reach the model too, so they are a clean item like any other.
            cases.append(
                Case(
                    f"{dataset}/{file.stem}/server",
                    dataset,
                    CLEAN,
                    file.stem,
                    "server",
                    snapshot,
                    "server",
                    file.stem,
                )
            )
        for kind, items, keys in sections:
            for item in items:
                name = next((item[k] for k in keys if isinstance(item.get(k), str)), None)
                if name is not None:
                    cases.append(
                        Case(
                            f"{dataset}/{file.stem}/{kind}/{name}",
                            dataset,
                            CLEAN,
                            file.stem,
                            kind,
                            snapshot,
                            kind,
                            name,
                        )
                    )
    return cases


def load_signed_in(directory: Path = SIGNED_IN_DIR) -> list[Case]:
    return load_clean_servers(directory, "signed_in")


LOADERS = {
    "mcptox": load_mcptox,
    "own": load_own,
    "clean_servers": load_clean_servers,
    "signed_in": load_signed_in,
}
ALL_DATASETS = list(LOADERS)


def load_cases(datasets: list[str]) -> tuple[list[Case], list[str]]:
    """Cases from the named datasets, plus a note for each dataset that is not available."""
    cases: list[Case] = []
    missing: list[str] = []
    for name in datasets:
        try:
            cases.extend(LOADERS[name]())
        except DatasetMissing as exc:
            missing.append(str(exc))
    return cases, missing
