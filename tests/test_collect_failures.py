"""Failure handling and legacy-protocol compatibility for live stdio collection."""

import json
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from scanner.cli import app
from scanner.collect import CollectError, collect_stdio

LEGACY_SERVER = str(Path(__file__).parent / "legacy_server.py")


@pytest.mark.anyio
async def test_server_that_exits_immediately_raises_collect_error():
    with pytest.raises(CollectError, match="server connection failed"):
        await collect_stdio(sys.executable, ["-c", "raise SystemExit(1)"], unsafe_local=True, timeout_s=20)


@pytest.mark.anyio
async def test_missing_command_raises_oserror():
    with pytest.raises(OSError):
        await collect_stdio("definitely-not-a-real-command-xyz", [], unsafe_local=True, timeout_s=20)


@pytest.mark.anyio
async def test_legacy_handshake_server_is_collected():
    snap = await collect_stdio(sys.executable, [LEGACY_SERVER], unsafe_local=True, timeout_s=30)

    assert snap.errors == []
    assert snap.server_info == {"name": "raw-legacy", "version": "0"}
    assert snap.instructions == "RAW_INSTRUCTIONS"
    assert snap.prompts == [] and snap.resources == []  # not advertised, so never requested

    text = json.dumps(snap.tools)
    # Everything inside the JSON schema survives, including unknown keywords and explicit nulls.
    for kept in ("UNKNOWN_IN_SCHEMA", "UNKNOWN_IN_PROP", "EXAMPLE_TEXT", "ANNOT_TITLE", "META_TEXT"):
        assert kept in text
    assert snap.tools[0]["inputSchema"]["properties"]["p"]["default"] is None


@pytest.mark.anyio
async def test_sdk_drops_unknown_fields_outside_the_schema():
    """Documents a known limit of live mode (see CLAUDE.md gotchas).

    The SDK parses tools into typed models and discards keys it doesn't know, at the
    tool's top level and inside ``annotations``. An SDK-based client never sees these
    either. If this test starts failing, the SDK now keeps them: update the docs.
    """
    snap = await collect_stdio(sys.executable, [LEGACY_SERVER], unsafe_local=True, timeout_s=30)
    text = json.dumps(snap.tools)
    assert "UNKNOWN_TOP_LEVEL" not in text
    assert "UNKNOWN_IN_ANNOT" not in text


@pytest.mark.anyio
async def test_server_stderr_is_not_passed_through_by_default(capfd):
    await collect_stdio(sys.executable, [LEGACY_SERVER], unsafe_local=True, timeout_s=30)
    assert "SERVER_STDERR_NOISE" not in capfd.readouterr().err


def test_cli_reports_crashed_server_cleanly():
    result = CliRunner().invoke(app, ["collect", "--unsafe-local", "--", sys.executable, "-c", "raise SystemExit(1)"])
    assert result.exit_code == 2
    assert "error: server connection failed" in result.stderr
    assert "Traceback" not in result.output


def test_cli_reports_missing_command_cleanly():
    result = CliRunner().invoke(app, ["collect", "--unsafe-local", "--", "definitely-not-a-real-command-xyz"])
    assert result.exit_code == 2
    assert "could not launch server" in result.stderr
