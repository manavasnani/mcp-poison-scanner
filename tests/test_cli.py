import json
import sys

from typer.testing import CliRunner

from scanner.cli import app
from tests.conftest import FIXTURE_SERVERS

runner = CliRunner()


def test_collect_from_snapshot_to_stdout(tmp_path):
    p = tmp_path / "srv.json"
    p.write_text(json.dumps({"tools": [{"name": "echo", "inputSchema": {"type": "object"}}]}), encoding="utf-8")
    result = runner.invoke(app, ["collect", "--snapshot", str(p)])
    assert result.exit_code == 0, result.output
    out = json.loads(result.stdout)
    assert out["server_name"] == "srv"
    assert out["tools"][0]["name"] == "echo"


def test_collect_requires_exactly_one_input():
    assert runner.invoke(app, ["collect"]).exit_code != 0


def test_collect_bad_snapshot_exits_2(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("[]x", encoding="utf-8")
    result = runner.invoke(app, ["collect", "-s", str(p)])
    assert result.exit_code == 2
    assert "not valid JSON" in result.stderr


def test_collect_command_without_unsafe_flag_is_refused(tmp_path):
    marker = tmp_path / "ran"
    code = f"open({str(marker)!r}, 'w').close()"
    result = runner.invoke(app, ["collect", "--", sys.executable, "-c", code])
    assert result.exit_code == 2
    assert "--unsafe-local" in result.stderr
    assert not marker.exists()


def test_collect_command_with_unsafe_flag_writes_file(tmp_path):
    out = tmp_path / "clean.json"
    result = runner.invoke(
        app,
        [
            "collect",
            "--unsafe-local",
            "-n",
            "clean",
            "-o",
            str(out),
            "--",
            sys.executable,
            str(FIXTURE_SERVERS / "clean.py"),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "launching untrusted server" in result.stderr
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["server_name"] == "clean"
    assert len(data["tools"]) == 3
