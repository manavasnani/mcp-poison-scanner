"""Docker sandbox. The command line and the refusals are tested without Docker.

The last test runs a real container. It is skipped unless Docker is running and the
image from ``docker/python-mcp.Dockerfile`` has been built as ``mcp-scan-python``,
and it launches only this repo's own fixture server.
"""

import shutil
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

import scanner.collect.docker as sandbox
from scanner.cli import app
from scanner.collect import SandboxError, collect_docker, collect_in_process
from tests.conftest import FIXTURE_SERVERS, load_fixture_module

IMAGE = "mcp-scan-python"


def args_for(command=("python", "server.py"), mounts=(), image=IMAGE) -> list[str]:
    return sandbox.build_run_args(image, list(command), list(mounts), "scan-test")


def value_after(args: list[str], flag: str) -> str:
    return args[args.index(flag) + 1]


# --- the docker command line --------------------------------------------------------------------


def test_container_is_locked_down():
    args = args_for()
    assert args[0] == "run" and "--rm" in args and "--interactive" in args
    assert value_after(args, "--network") == "none"
    assert "--read-only" in args
    assert value_after(args, "--cap-drop") == "ALL"
    assert value_after(args, "--security-opt") == "no-new-privileges"
    assert value_after(args, "--user") == "65534:65534"
    assert value_after(args, "--pull") == "never"
    assert "noexec" in value_after(args, "--tmpfs")
    for limit in ("--memory", "--cpus", "--pids-limit"):
        assert limit in args
    for forbidden in ("--privileged", "-v", "--volume", "--env-file", "--pid", "--cap-add", "--device"):
        assert forbidden not in args


def test_no_host_environment_or_files_reach_the_container(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-secret")
    args = args_for()
    assert not any("sk-test-secret" in a or "ANTHROPIC" in a for a in args)
    envs = [args[i + 1] for i, a in enumerate(args) if a == "--env"]
    assert envs == ["HOME=/tmp", "PYTHONDONTWRITEBYTECODE=1"]
    assert "--mount" not in args


def test_server_command_comes_after_the_image_untouched():
    command = ["python", "-c", "print('--network host')", "--privileged"]
    args = args_for(command)
    assert args[args.index(IMAGE) :] == [IMAGE, *command]
    assert value_after(args, "--network") == "none"  # options inside the command do not count


def test_mounts_are_read_only_under_work(tmp_path):
    folder = tmp_path / "servers"
    folder.mkdir()
    args = args_for(mounts=[folder])
    assert value_after(args, "--mount") == f"type=bind,source={folder.resolve()},target=/work/servers,readonly"


@pytest.mark.parametrize("bad", [Path.home(), Path.home().parent, Path(Path.home().anchor)])
def test_refuses_to_mount_home_or_anything_above_it(bad):
    with pytest.raises(SandboxError, match="refusing to mount"):
        args_for(mounts=[bad])


def test_refuses_bad_mounts(tmp_path):
    with pytest.raises(SandboxError, match="not a directory"):
        args_for(mounts=[tmp_path / "missing"])
    (tmp_path / "a" / "x").mkdir(parents=True)
    (tmp_path / "b" / "x").mkdir(parents=True)
    with pytest.raises(SandboxError, match="both appear"):
        args_for(mounts=[tmp_path / "a" / "x", tmp_path / "b" / "x"])


@pytest.mark.parametrize("image", ["", "--privileged", "-v", "name with space"])
def test_refuses_an_image_name_that_could_be_an_option(image):
    with pytest.raises(SandboxError, match="not a valid image"):
        args_for(image=image)


def test_refuses_an_empty_command():
    with pytest.raises(SandboxError, match="no server command"):
        args_for(command=())


# --- preflight ----------------------------------------------------------------------------------


def fake_docker(monkeypatch, returncodes: dict[str, int]):
    monkeypatch.setattr(sandbox.shutil, "which", lambda name: "docker")

    def run(argv, **kwargs):
        return subprocess.CompletedProcess(argv, returncodes.get(argv[1], 0), "", "")

    monkeypatch.setattr(sandbox.subprocess, "run", run)


def test_preflight_reports_missing_docker(monkeypatch):
    monkeypatch.setattr(sandbox.shutil, "which", lambda name: None)
    with pytest.raises(SandboxError, match="not installed"):
        sandbox.check_docker(IMAGE)


def test_preflight_reports_stopped_daemon(monkeypatch):
    fake_docker(monkeypatch, {"version": 1})
    with pytest.raises(SandboxError, match="daemon is not running"):
        sandbox.check_docker(IMAGE)


def test_preflight_reports_missing_image_and_never_pulls(monkeypatch):
    fake_docker(monkeypatch, {"image": 1})
    with pytest.raises(SandboxError, match="never downloads"):
        sandbox.check_docker(IMAGE)


def test_preflight_reports_a_hung_docker(monkeypatch):
    monkeypatch.setattr(sandbox.shutil, "which", lambda name: "docker")

    def run(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, 1)

    monkeypatch.setattr(sandbox.subprocess, "run", run)
    with pytest.raises(SandboxError, match="did not answer"):
        sandbox.check_docker(IMAGE)


# --- CLI ----------------------------------------------------------------------------------------

runner = CliRunner()


def test_cli_rejects_sandbox_and_unsafe_together():
    result = runner.invoke(app, ["scan", "--sandbox-image", IMAGE, "--unsafe-local", "--", "python", "x.py"])
    assert result.exit_code != 0 and "not both" in result.output


def test_cli_rejects_mount_without_sandbox(tmp_path):
    result = runner.invoke(app, ["scan", "--mount", str(tmp_path), "--unsafe-local", "--", "python", "x.py"])
    assert result.exit_code != 0 and "--sandbox-image" in result.output


def test_cli_reports_sandbox_problems(monkeypatch):
    monkeypatch.setattr(sandbox.shutil, "which", lambda name: None)
    result = runner.invoke(app, ["scan", "--sandbox-image", IMAGE, "--", "python", "x.py"])
    assert result.exit_code == 2
    assert "Docker is not installed" in result.stderr


def test_cli_refusal_points_to_the_sandbox():
    result = runner.invoke(app, ["scan", "--", "python", "-c", "pass"])
    assert result.exit_code == 2
    assert "--sandbox-image" in result.stderr and "--unsafe-local" in result.stderr


# --- a real container ---------------------------------------------------------------------------


def docker_ready() -> bool:
    docker = shutil.which("docker")
    if docker is None:
        return False
    try:
        probe = subprocess.run([docker, "image", "inspect", IMAGE], capture_output=True, timeout=20, check=False)
    except (OSError, subprocess.SubprocessError):
        return False
    return probe.returncode == 0


@pytest.mark.anyio
@pytest.mark.skipif(not docker_ready(), reason=f"needs a running Docker with the {IMAGE} image built")
async def test_sandboxed_collection_matches_in_process_listing():
    snap = await collect_docker(IMAGE, ["python", "/work/servers/poisoned.py"], mounts=[FIXTURE_SERVERS], timeout_s=120)
    in_proc = await collect_in_process(load_fixture_module("poisoned").server)
    assert snap.source == "docker" and snap.errors == []
    assert snap.tools == in_proc.tools
    assert snap.prompts == in_proc.prompts
    assert snap.resources == in_proc.resources
    assert snap.instructions == in_proc.instructions
