"""Zip the agent skill for upload to a skill marketplace.

    uv run python scripts/package_skill.py

Writes ``dist/mcp-poison-scanner-skill.zip`` with one top-level folder, ``mcp-poison-scanner/``.
Refuses to package anything a marketplace would reject: a missing ``name`` or ``description``, a
version that differs from ``pyproject.toml``, a binary file, or a bundled dependency folder.
"""

from __future__ import annotations

import sys
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILL = ROOT / "skill" / "mcp-poison-scanner"
OUTPUT = ROOT / "dist" / "mcp-poison-scanner-skill.zip"

SKIPPED_NAMES = {".DS_Store", "Thumbs.db"}
SKIPPED_FOLDERS = {"__pycache__", ".git"}
REFUSED_FOLDERS = {"node_modules", "site-packages", ".venv", "venv"}
REFUSED_SUFFIXES = {".exe", ".dll", ".so", ".dylib", ".bin", ".jar", ".wasm", ".pyc", ".pyd", ".class", ".zip"}
MAX_SCRIPT_BYTES = 20_000


def frontmatter(text: str) -> dict[str, str]:
    """The top-level ``key: value`` pairs of a SKILL.md's frontmatter. Lists and folded text keep their key only."""
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        raise SystemExit("SKILL.md must start with a '---' frontmatter block")
    fields: dict[str, str] = {}
    for line in lines[1:]:
        if line.strip() == "---":
            return fields
        if line[:1].isalpha() and ":" in line:
            key, _, value = line.partition(":")
            fields[key.strip()] = value.strip()
    raise SystemExit("SKILL.md frontmatter is not closed with '---'")


def files_to_package(folder: Path) -> list[Path]:
    problems: list[str] = []
    chosen: list[Path] = []
    for path in sorted(folder.rglob("*")):
        parts = set(path.relative_to(folder).parts)
        if parts & SKIPPED_FOLDERS or path.name in SKIPPED_NAMES or path.is_dir():
            if path.is_dir() and path.name in REFUSED_FOLDERS:
                problems.append(f"{path.relative_to(folder)}: bundled dependency folder")
            continue
        if parts & REFUSED_FOLDERS:
            continue
        if path.suffix.lower() in REFUSED_SUFFIXES:
            problems.append(f"{path.relative_to(folder)}: binary or archive file")
            continue
        try:
            path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            problems.append(f"{path.relative_to(folder)}: not a text file")
            continue
        if path.suffix.lower() in {".py", ".sh", ".ps1", ".js"} and path.stat().st_size > MAX_SCRIPT_BYTES:
            problems.append(f"{path.relative_to(folder)}: script larger than {MAX_SCRIPT_BYTES} bytes")
        chosen.append(path)
    if problems:
        raise SystemExit("cannot package the skill:\n  " + "\n  ".join(problems))
    return chosen


def check(folder: Path = SKILL, pyproject: Path = ROOT / "pyproject.toml") -> dict[str, str]:
    skill_file = folder / "SKILL.md"
    if not skill_file.is_file():
        raise SystemExit(f"{skill_file} is missing")
    fields = frontmatter(skill_file.read_text(encoding="utf-8"))
    for required in ("name", "description"):
        if required not in fields:
            raise SystemExit(f"SKILL.md frontmatter has no '{required}'")
    if fields["name"] != folder.name:
        raise SystemExit(f"skill name {fields['name']!r} does not match its folder {folder.name!r}")
    version = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]["version"]
    if fields.get("version") != version:
        raise SystemExit(f"SKILL.md version {fields.get('version')!r} does not match pyproject {version!r}")
    return fields


def package(folder: Path = SKILL, output: Path = OUTPUT) -> list[str]:
    """Write the zip and return the names inside it."""
    check(folder)
    files = files_to_package(folder)
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in files:
            archive.write(path, f"{folder.name}/{path.relative_to(folder).as_posix()}")
        return archive.namelist()


def main() -> None:
    names = package()
    print(f"wrote {OUTPUT} ({OUTPUT.stat().st_size:,} bytes)")
    for name in names:
        print(f"  {name}")


if __name__ == "__main__":
    sys.exit(main())
