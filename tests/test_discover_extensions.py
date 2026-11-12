"""Claude Desktop extensions: reading their manifests and running them. Uses made-up folders only."""

import contextlib
import json
import sys
from pathlib import Path

from typer.testing import CliRunner

from scanner import cli
from scanner.cli import app
from scanner.discover import PLACEHOLDER, desktop_data_folders, discover, read_extensions
from tests.conftest import FIXTURE_SERVERS

runner = CliRunner()


def install(
    data: Path, ext_id: str, server: dict, user_config: dict | None = None, settings: dict | None = None
) -> Path:
    folder = data / "Claude Extensions" / ext_id
    folder.mkdir(parents=True)
    manifest = {"name": ext_id.split(".")[-1], "server": server, "user_config": user_config or {}}
    (folder / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    if settings is not None:
        (data / "Claude Extensions Settings").mkdir(exist_ok=True)
        (data / "Claude Extensions Settings" / f"{ext_id}.json").write_text(json.dumps(settings), encoding="utf-8")
    return folder


def test_windows_store_data_folder_is_checked(tmp_path):
    local = tmp_path / "local"
    (local / "Claude-Data" / "claude_abc").mkdir(parents=True)
    folders = desktop_data_folders(
        "win32", {"APPDATA": str(tmp_path / "roaming"), "LOCALAPPDATA": str(local)}, tmp_path
    )
    assert folders == [tmp_path / "roaming" / "Claude", local / "Claude-Data" / "claude_abc"]


def test_extension_command_settings_and_sandbox_form(tmp_path):
    folder = install(
        tmp_path,
        "vendor.notes",
        {
            "type": "node",
            "mcp_config": {
                "command": "node",
                "args": ["${__dirname}/dist/main.js", "--mode", "${user_config.mode}", "${user_config.folders}"],
                "env": {"NOTES_TOKEN": "${user_config.token}"},
            },
        },
        user_config={"token": {"sensitive": True}, "mode": {"default": "fast"}, "folders": {}},
        settings={"isEnabled": True, "userConfig": {"token": "real-secret", "folders": ["/a", "/b"]}},
    )
    (server,), notes = read_extensions(tmp_path, home=tmp_path / "home", platform="linux")
    assert notes == [] and server.name == "notes" and server.origin == "Claude Desktop, extension"
    # A saved setting wins, a default fills a gap, and a list becomes several arguments.
    assert server.command == ("node", f"{folder}/dist/main.js", "--mode", "fast", "/a", "/b")
    assert dict(server.env) == {"NOTES_TOKEN": "real-secret"}
    # In the sandbox the extension's folder is mounted under /work.
    assert server.mount == folder and server.sandbox_command[1] == "/work/vendor.notes/dist/main.js"
    assert "real-secret" not in server.describe()


def test_sensitive_setting_used_as_an_argument_is_replaced_in_the_sandbox(tmp_path):
    install(
        tmp_path,
        "vendor.cli",
        {"mcp_config": {"command": "tool", "args": ["--key", "${user_config.key}"]}},
        user_config={"key": {"sensitive": True}},
        settings={"userConfig": {"key": "real-secret"}},
    )
    (server,), _notes = read_extensions(tmp_path, home=tmp_path, platform="linux")
    assert server.command == ("tool", "--key", "real-secret")
    assert server.sandbox_command == ("tool", "--key", PLACEHOLDER)


def test_disabled_broken_and_platform_specific_extensions(tmp_path):
    install(tmp_path, "a.off", {"mcp_config": {"command": "x"}}, settings={"isEnabled": False})
    install(tmp_path, "b.nothing", {"type": "node"})
    install(
        tmp_path,
        "c.win",
        {"mcp_config": {"command": "run.sh", "platform_overrides": {"win32": {"command": "run.cmd"}}}},
    )
    (tmp_path / "Claude Extensions" / "d.bad").mkdir()
    (tmp_path / "Claude Extensions" / "d.bad" / "manifest.json").write_text("{nope", encoding="utf-8")

    servers, notes = read_extensions(tmp_path, home=tmp_path, platform="win32")
    by_name = {s.name: s for s in servers}
    assert set(by_name) == {"nothing", "win"}
    assert by_name["nothing"].problem and by_name["win"].command == ("run.cmd",)
    assert any("switched off" in n for n in notes) and any("could not be read" in n for n in notes)


def test_standard_discovery_includes_extensions(tmp_path):
    data = tmp_path / ".config" / "Claude"
    install(data, "vendor.ext", {"mcp_config": {"command": "tool"}})
    found = discover(platform="linux", env={}, home=tmp_path, cwd=tmp_path)
    assert [s.name for s in found.servers] == ["ext"]
    assert any("1 extension" in status for _file, status in found.checked)


def test_sandbox_run_mounts_the_extension_and_hides_its_secrets(tmp_path, monkeypatch):
    folder = install(
        tmp_path / "data",
        "vendor.ext",
        {"mcp_config": {"command": "node", "args": ["${__dirname}/main.js"], "env": {"TOKEN": "${user_config.t}"}}},
        user_config={"t": {"sensitive": True}},
        settings={"userConfig": {"t": "real-secret"}},
    )
    (server,), _notes = read_extensions(tmp_path / "data", home=tmp_path, platform="linux")
    seen = {}

    async def fake_docker(image, command, **kwargs):
        seen.update(command=command, **kwargs)
        raise cli.CollectError("stop here")

    monkeypatch.setattr(cli, "collect_docker", fake_docker)
    live = cli.Live([], None, [], None, None, False, "img", [], 5.0, False)
    with contextlib.suppress(cli._Unreachable):
        cli._collect_discovered(server, live)
    assert seen["command"] == ["node", "/work/vendor.ext/main.js"]
    assert seen["mounts"] == [folder] and seen["env"] == {"TOKEN": PLACEHOLDER}


def test_missing_program_is_explained_not_crashed(tmp_path, monkeypatch):
    install(tmp_path, "vendor.ext", {"mcp_config": {"command": "no-such-program-xyz", "args": []}})
    servers, _notes = read_extensions(tmp_path, home=tmp_path, platform="linux")
    assert servers[0].missing_program() == "no-such-program-xyz"

    from scanner import discover as discover_module

    monkeypatch.setattr(cli, "find_servers", lambda configs: discover_module.Discovery(servers=servers))
    result = runner.invoke(app, ["scan", "--discover", "--unsafe-local"])
    assert result.exit_code == 2
    assert "not installed on this computer" in result.stderr and "built-in copy" in result.stderr


def test_an_extension_can_be_scanned_end_to_end(tmp_path, monkeypatch):
    install(
        tmp_path,
        "vendor.clean",
        {"mcp_config": {"command": sys.executable, "args": [str(FIXTURE_SERVERS / "clean.py")]}},
    )
    servers, _notes = read_extensions(tmp_path, home=tmp_path, platform=sys.platform)

    from scanner import discover as discover_module

    monkeypatch.setattr(cli, "find_servers", lambda configs: discover_module.Discovery(servers=servers))
    result = runner.invoke(app, ["scan", "--discover", "--unsafe-local"])
    assert result.exit_code == 0, result.output
    assert "clean: 3 tools" in result.stdout
