"""Finding servers in Claude's settings files. Nothing here reads the real user's settings."""

import json
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from scanner import cli
from scanner.cli import app
from scanner.discover import (
    CODE,
    DESKTOP,
    PLACEHOLDER,
    ConfigFile,
    DiscoverError,
    discover,
    read_config,
    standard_locations,
)
from tests.conftest import FIXTURE_SERVERS

runner = CliRunner()


def write(path: Path, data) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


# --- where the files are --------------------------------------------------------------------------


def test_windows_locations_include_the_store_install(tmp_path):
    home = tmp_path / "home"
    local = tmp_path / "local"
    (local / "Packages" / "Claude_abc123").mkdir(parents=True)
    env = {"APPDATA": str(tmp_path / "roaming"), "LOCALAPPDATA": str(local)}
    files = standard_locations("win32", env, home, tmp_path / "project")
    paths = [f.path for f in files]
    assert paths == [
        tmp_path / "roaming" / "Claude" / "claude_desktop_config.json",
        local / "Packages" / "Claude_abc123" / "LocalCache" / "Roaming" / "Claude" / "claude_desktop_config.json",
        home / ".claude.json",
        tmp_path / "project" / ".mcp.json",
    ]
    assert [f.client for f in files] == [DESKTOP, DESKTOP, CODE, CODE]


def test_mac_and_linux_locations(tmp_path):
    mac = [f.path for f in standard_locations("darwin", {}, tmp_path, tmp_path)]
    assert mac[0] == tmp_path / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    linux = [
        f.path for f in standard_locations("linux", {"CLAUDE_CONFIG_DIR": str(tmp_path / "cc")}, tmp_path, tmp_path)
    ]
    assert linux[0] == tmp_path / ".config" / "Claude" / "claude_desktop_config.json"
    assert tmp_path / "cc" / ".claude.json" in linux


# --- reading entries ------------------------------------------------------------------------------


def test_desktop_entry_is_taken_as_written(tmp_path):
    path = write(
        tmp_path / "claude_desktop_config.json",
        {"mcpServers": {"files": {"command": "npx", "args": ["-y", "pkg", "${HOME}"], "env": {"KEY": "abc"}}}},
    )
    (server,) = read_config(ConfigFile(DESKTOP, path), env={"HOME": "/h"})
    assert server.transport == "stdio" and server.scope == "app"
    assert server.command == ("npx", "-y", "pkg", "${HOME}")  # Claude Desktop does not expand variables
    assert dict(server.env) == {"KEY": "abc"}
    assert server.placeholder_env() == {"KEY": PLACEHOLDER}


def test_claude_code_scopes_and_expansion(tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    path = write(
        tmp_path / ".claude.json",
        {
            "mcpServers": {"mine": {"type": "http", "url": "https://a.example/mcp", "headers": {"X": "Bearer ${TOK}"}}},
            "projects": {
                str(project).replace("\\", "/"): {"mcpServers": {"here": {"command": "run-${WHO:-nobody}"}}},
                "/somewhere/else": {"mcpServers": {"elsewhere": {"command": "x"}}},
            },
        },
    )
    servers = {s.name: s for s in read_config(ConfigFile(CODE, path), cwd=project, env={"TOK": "t0k"})}
    assert set(servers) == {"mine", "here"}  # another project's servers are not this folder's
    assert servers["mine"].scope == "user" and dict(servers["mine"].headers) == {"X": "Bearer t0k"}
    assert servers["here"].scope == "local" and servers["here"].command == ("run-nobody",)


def test_unset_and_blocked_variables(tmp_path):
    path = write(
        tmp_path / ".mcp.json",
        {
            "mcpServers": {
                "leaky": {"type": "http", "url": "https://x.example/mcp", "headers": {"K": "${ANTHROPIC_API_KEY}"}},
                "unset": {"command": "tool", "args": ["${MISSING_ONE}"]},
            }
        },
    )
    servers = {s.name: s for s in read_config(ConfigFile(CODE, path), env={"ANTHROPIC_API_KEY": "sk-real"})}
    # A project file must not be able to pull this machine's Claude key into a request.
    assert dict(servers["leaky"].headers) == {"K": ""}
    assert "never passes that on" in servers["leaky"].remarks[0]
    assert servers["unset"].command == ("tool", "${MISSING_ONE}")
    assert "MISSING_ONE" in servers["unset"].remarks[0]


def test_entries_that_cannot_be_scanned(tmp_path):
    path = write(
        tmp_path / ".mcp.json",
        {
            "mcpServers": {
                "old": {"type": "sse", "url": "https://x.example/sse"},
                "socket": {"type": "ws", "url": "wss://x.example"},
                "empty": {},
                "wrong": "not an object",
                "helper": {"type": "http", "url": "https://x.example/mcp", "headersHelper": "get-token.sh"},
            }
        },
    )
    servers = {s.name: s for s in read_config(ConfigFile(CODE, path), env={})}
    assert "SSE" in servers["old"].problem and "not supported" in servers["socket"].problem
    assert servers["empty"].problem and servers["wrong"].problem
    assert servers["helper"].problem is None and "does not run it" in servers["helper"].remarks[0]


def test_description_never_shows_a_secret(tmp_path):
    path = write(
        tmp_path / ".mcp.json",
        {
            "mcpServers": {
                "db": {
                    "command": "pg-server",
                    "args": ["postgres://admin:hunter2secret@db.example/app", "--key", "sk-abcdefghijklmnopqrstuvwx"],
                    "env": {"DB_PASSWORD": "another-secret"},
                },
                "api": {
                    "type": "http",
                    "url": "https://api.example/mcp?token=querysecret",
                    "headers": {"Authorization": "Bearer headersecret"},
                },
            }
        },
    )
    text = " ".join(s.describe() for s in read_config(ConfigFile(CODE, path), env={}))
    for secret in ("hunter2secret", "abcdefghijklmnopqrstuvwx", "another-secret", "querysecret", "headersecret"):
        assert secret not in text
    assert "DB_PASSWORD" in text and "Authorization" in text and "https://api.example/mcp" in text


def test_bad_files(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(DiscoverError, match="not valid JSON"):
        read_config(ConfigFile(CODE, bad))
    with pytest.raises(DiscoverError, match="no such file"):
        discover([tmp_path / "missing.json"])


# --- combining files ------------------------------------------------------------------------------


def test_standard_discovery_precedence_and_cross_app_names(tmp_path):
    home, project = tmp_path / "home", tmp_path / "proj"
    project.mkdir(parents=True)
    write(
        home / ".config" / "Claude" / "claude_desktop_config.json",
        {"mcpServers": {"notes": {"command": "desktop-notes"}, "same": {"command": "shared"}}},
    )
    write(
        home / ".claude.json",
        {
            "mcpServers": {"notes": {"command": "user-notes"}, "same": {"command": "shared"}},
            "projects": {str(project): {"mcpServers": {"notes": {"command": "local-notes"}}}},
        },
    )
    write(project / ".mcp.json", {"mcpServers": {"notes": {"command": "project-notes"}}})
    broken = home / ".broken"
    broken.mkdir()

    found = discover(platform="linux", env={}, home=home, cwd=project)
    by_name = {s.name: s.command for s in found.servers}
    # Inside Claude Code the local definition wins; Claude Desktop's different server keeps a distinct name.
    assert by_name == {
        "notes": ("local-notes",),
        f"notes ({DESKTOP})": ("desktop-notes",),
        "same": ("shared",),
    }
    assert [status.split(",")[0] for _file, status in found.checked] == ["found", "found", "found"]
    assert any("also defined" in note for note in found.notes)


def test_a_missing_or_broken_standard_file_is_only_noted(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    (home / ".claude.json").write_text("{broken", encoding="utf-8")
    found = discover(platform="linux", env={}, home=home, cwd=tmp_path)
    assert found.servers == []
    statuses = [status for _file, status in found.checked]
    assert statuses[0] == "not there" and "could not be read" in statuses[1]


# --- the command line -----------------------------------------------------------------------------


def fixture_config(tmp_path: Path, **extra) -> Path:
    clean = {
        "command": sys.executable,
        "args": [str(FIXTURE_SERVERS / "clean.py")],
        "env": {"DEMO_KEY": "s3cr3t-value"},
    }
    return write(tmp_path / "settings.json", {"mcpServers": {"clean": clean, **extra}})


def test_discover_command_lists_without_launching_or_leaking(tmp_path):
    config = fixture_config(tmp_path)
    result = runner.invoke(app, ["discover", "--config", str(config)])
    assert result.exit_code == 0, result.output
    assert "Servers found: 1" in result.stdout and "clean" in result.stdout and "DEMO_KEY" in result.stdout
    assert "s3cr3t-value" not in result.output


def test_scan_discover_needs_a_choice_before_running_local_servers(tmp_path):
    result = runner.invoke(app, ["scan", "--config", str(fixture_config(tmp_path))])
    assert result.exit_code == 2
    assert "--unsafe-local" in result.stderr and "none of the servers found could be scanned" in result.stderr


def test_scan_discover_runs_local_servers_and_reports_the_ones_it_could_not(tmp_path):
    config = fixture_config(tmp_path, old={"type": "sse", "url": "https://x.example/sse"})
    result = runner.invoke(app, ["scan", "--config", str(config), "--unsafe-local"])
    assert "clean: 3 tools" in result.stdout
    assert "note: not scanned: old" in result.stdout and "SSE" in result.stdout
    # One server was left unscanned, so the scan does not pass.
    assert result.exit_code == 1
    assert "launching 1 local server(s)" in result.stderr and "s3cr3t-value" not in result.output

    relaxed = runner.invoke(app, ["scan", "--config", str(config), "--unsafe-local", "--fail-on", "none"])
    assert relaxed.exit_code == 0


def test_scan_discover_passes_when_everything_was_scanned_and_clean(tmp_path):
    # --fail-on high: the clean fixture has capability findings below that level only.
    result = runner.invoke(app, ["scan", "--config", str(fixture_config(tmp_path)), "--unsafe-local"])
    assert result.exit_code == 0, result.output


def test_discovered_environment_goes_to_a_direct_launch_but_not_into_the_sandbox(tmp_path, monkeypatch):
    seen = {}

    async def fake_stdio(command, args, **kwargs):
        seen["direct"] = kwargs["env"]
        raise cli.CollectError("stop here")

    async def fake_docker(image, command, **kwargs):
        seen["sandbox"] = kwargs["env"]
        raise cli.CollectError("stop here")

    monkeypatch.setattr(cli, "collect_stdio", fake_stdio)
    monkeypatch.setattr(cli, "collect_docker", fake_docker)
    config = fixture_config(tmp_path)
    runner.invoke(app, ["scan", "--config", str(config), "--unsafe-local"])
    runner.invoke(app, ["scan", "--config", str(config), "--sandbox-image", "img"])
    assert seen["direct"] == {"DEMO_KEY": "s3cr3t-value"}
    assert seen["sandbox"] == {"DEMO_KEY": PLACEHOLDER}


def test_discover_cannot_be_mixed_with_a_single_server(tmp_path):
    config = str(fixture_config(tmp_path))
    assert runner.invoke(app, ["scan", "--config", config, "--url", "https://x.example/mcp"]).exit_code == 2
    assert runner.invoke(app, ["scan", "--config", config, "--name", "n", "--unsafe-local"]).exit_code == 2


def test_pin_discover_records_what_it_could_collect(tmp_path):
    lock = tmp_path / "lock.json"
    config = fixture_config(tmp_path)
    result = runner.invoke(app, ["pin", "--config", str(config), "--unsafe-local", "--lock", str(lock)])
    assert result.exit_code == 0, result.output
    assert "clean" in json.loads(lock.read_text(encoding="utf-8"))["servers"]
