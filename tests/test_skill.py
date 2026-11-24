"""The agent skill in skill/: it must describe the real command line, and package cleanly."""

import importlib.util
import re
import tomllib
import zipfile

import pytest
import typer

from scanner.cli import app
from tests.conftest import ROOT

SKILL_FILE = ROOT / "skill" / "mcp-poison-scanner" / "SKILL.md"

# Flags in the skill that belong to other programs (uvx, pip), not to the scanner.
OTHER_PROGRAMS_FLAGS = {"--from", "--no-cache-dir"}


def load_packager():
    spec = importlib.util.spec_from_file_location("package_skill", ROOT / "scripts" / "package_skill.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def cli_surface() -> tuple[set[str], set[str]]:
    """Every subcommand and every option the real command line accepts."""
    group = typer.main.get_command(app)
    flags = {"--help"}
    for command in group.commands.values():
        for param in command.params:
            flags.update(opt for opt in (*param.opts, *param.secondary_opts) if opt.startswith("--"))
    return set(group.commands), flags


def test_every_flag_the_skill_mentions_exists():
    _commands, flags = cli_surface()
    text = SKILL_FILE.read_text(encoding="utf-8")
    mentioned = set(re.findall(r"(?<![\w-])--[a-z][a-z-]+", text))
    assert mentioned - flags - OTHER_PROGRAMS_FLAGS == set()


def test_every_subcommand_the_skill_runs_exists():
    commands, _flags = cli_surface()
    text = SKILL_FILE.read_text(encoding="utf-8")
    used = set(re.findall(r"(?:^\s*|`)mcp-poison-scanner ([a-z][a-z-]+)", text, re.MULTILINE))
    assert used and used <= commands
    assert {"discover", "scan", "pin", "collect", "sign-out"} <= used


def test_skill_names_every_rule_the_scanner_reports():
    from scanner.rules import STATIC_RULES

    text = SKILL_FILE.read_text(encoding="utf-8")
    for rule_id in [rule.id for rule in STATIC_RULES] + ["RP001", "LLM001"]:
        assert f"| {rule_id} |" in text


def test_frontmatter_matches_the_project():
    fields = load_packager().check()
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert fields["name"] == "mcp-poison-scanner" == project["name"]
    assert fields["version"] == project["version"]
    assert fields["docs_url"] == "https://github.com/manavasnani/mcp-poison-scanner"
    assert project["scripts"]["mcp-poison-scanner"] == "scanner.cli:app"


def test_install_commands_are_pinned_to_the_released_tag():
    version = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    for file in (SKILL_FILE, ROOT / "README.md"):
        text = file.read_text(encoding="utf-8")
        sources = re.findall(r"git\+https://github\.com/manavasnani/mcp-poison-scanner([^\s`]*)", text)
        assert sources and set(sources) == {f"@v{version}"}, file.name


def test_sandbox_example_uses_the_locked_mcp_version():
    lock = (ROOT / "uv.lock").read_text(encoding="utf-8")
    locked = re.search(r'name = "mcp"\r?\nversion = "([^"]+)"', lock).group(1)
    assert f'"mcp=={locked}"' in SKILL_FILE.read_text(encoding="utf-8")
    assert f'"mcp=={locked}"' in (ROOT / "docker" / "python-mcp.Dockerfile").read_text(encoding="utf-8")


def test_package_has_one_top_level_folder_and_only_text(tmp_path):
    names = load_packager().package(output=tmp_path / "skill.zip")
    assert "mcp-poison-scanner/SKILL.md" in names
    assert {name.split("/")[0] for name in names} == {"mcp-poison-scanner"}
    with zipfile.ZipFile(tmp_path / "skill.zip") as archive:
        for name in names:
            archive.read(name).decode("utf-8")  # every file is text


def test_packager_refuses_binaries_and_dependency_folders(tmp_path):
    packager = load_packager()
    folder = tmp_path / "mcp-poison-scanner"
    (folder / "node_modules" / "x").mkdir(parents=True)
    (folder / "node_modules" / "x" / "index.js").write_text("x", encoding="utf-8")
    (folder / "tool.exe").write_bytes(b"MZ\x00\x01")
    (folder / "__pycache__").mkdir()
    (folder / "__pycache__" / "junk.txt").write_text("skipped quietly", encoding="utf-8")
    (folder / "SKILL.md").write_text("---\nname: x\n---\n", encoding="utf-8")
    with pytest.raises(SystemExit) as refused:
        packager.files_to_package(folder)
    assert "node_modules" in str(refused.value) and "tool.exe" in str(refused.value)
    assert "junk.txt" not in str(refused.value)
