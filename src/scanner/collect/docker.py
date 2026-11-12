"""Docker sandbox: run a stdio server inside a locked-down container.

Scanning a stdio server means running its code. In the sandbox that code gets:

- no network (``--network none``), so it cannot download a payload or send anything out;
- a read-only root filesystem, plus a small in-memory ``/tmp`` that cannot run programs;
- no Linux capabilities, no privilege escalation, an unprivileged user;
- limits on memory, CPU and process count;
- none of the host's environment variables, and no host files except folders the
  user mounts on purpose, which are always read-only. The home directory, anything
  above it, and a drive root are refused.

The image must already be on this machine (``--pull never``): a scan never
downloads anything. Because there is no network, the image has to contain the
server and its dependencies; see ``docker/python-mcp.Dockerfile``.

This lowers the risk of running an untrusted server; it does not remove it. A
container shares the host kernel, so a kernel or Docker escape bug would defeat it.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import uuid
from contextlib import suppress
from pathlib import Path, PurePosixPath

from mcp import StdioServerParameters
from mcp.client.stdio import get_default_environment

from scanner.collect.live import DEFAULT_TIMEOUT_S
from scanner.collect.stdio import run_server
from scanner.models import ServerSnapshot

MOUNT_ROOT = PurePosixPath("/work")
CONTAINER_USER = "65534:65534"  # "nobody" on most images
MEMORY_LIMIT = "512m"
CPU_LIMIT = "1"
PIDS_LIMIT = "128"
DOCKER_CHECK_TIMEOUT_S = 20

# Docker's own settings, so the docker CLI can find the daemon. Nothing else from the
# host environment is passed on, and none of it reaches the container.
_DOCKER_ENV = ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH")


_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,100}$")


class SandboxError(RuntimeError):
    """The sandbox could not be set up (Docker missing, daemon down, bad image or mount)."""


def _check_mount(path: Path) -> Path:
    resolved = path.expanduser().resolve()
    if not resolved.is_dir():
        raise SandboxError(f"mount is not a directory: {path}")
    home = Path.home().resolve()
    if resolved.parent == resolved:
        raise SandboxError(f"refusing to mount a filesystem root: {resolved}")
    if resolved == home or home.is_relative_to(resolved):
        raise SandboxError(f"refusing to mount the home directory or a folder that contains it: {resolved}")
    if "," in str(resolved):
        raise SandboxError(f"mount path may not contain a comma: {resolved}")
    return resolved


def mount_targets(mounts: list[Path]) -> list[tuple[Path, str]]:
    """Pair each host folder with where it appears in the container: ``/work/<folder name>``."""
    pairs: list[tuple[Path, str]] = []
    seen: set[str] = set()
    for mount in mounts:
        source = _check_mount(mount)
        target = str(MOUNT_ROOT / source.name)
        if target in seen:
            raise SandboxError(f"two mounts would both appear as {target}; rename one folder")
        seen.add(target)
        pairs.append((source, target))
    return pairs


def build_run_args(
    image: str, command: list[str], mounts: list[Path], container_name: str, env: dict[str, str] | None = None
) -> list[str]:
    """Arguments for ``docker`` that start ``command`` inside the sandbox.

    ``env`` adds variables the caller spells out (a placeholder key a server insists on, say).
    The host's own environment is never passed on.
    """
    if not image or image.startswith("-") or any(c.isspace() for c in image):
        raise SandboxError(f"not a valid image name: {image!r}")
    if not command:
        raise SandboxError("no server command given")

    args = [
        "run",
        "--rm",
        "--interactive",
        "--name",
        container_name,
        "--pull",
        "never",
        "--network",
        "none",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=64m",  # noqa: S108 - a path inside the container, not on the host
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--user",
        CONTAINER_USER,
        "--memory",
        MEMORY_LIMIT,
        "--cpus",
        CPU_LIMIT,
        "--pids-limit",
        PIDS_LIMIT,
        "--env",
        "HOME=/tmp",
        "--env",
        "PYTHONDONTWRITEBYTECODE=1",
    ]
    for key, value in (env or {}).items():
        if not _ENV_NAME.match(key) or chr(0) in value:
            raise SandboxError(f"not a valid environment variable: {key!r}")
        args += ["--env", f"{key}={value}"]
    for source, target in mount_targets(mounts):
        args += ["--mount", f"type=bind,source={source},target={target},readonly"]
    # Everything after the image is the server's own command line; docker stops reading options here.
    return [*args, image, *command]


def _docker_env() -> dict[str, str]:
    env = get_default_environment()
    env.update({key: os.environ[key] for key in _DOCKER_ENV if key in os.environ})
    return env


def _docker(docker: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        [docker, *args],
        capture_output=True,
        text=True,
        errors="replace",
        timeout=DOCKER_CHECK_TIMEOUT_S,
        env=_docker_env(),
        check=False,
    )


def check_docker(image: str) -> str:
    """Return the path of a working ``docker``, or raise ``SandboxError`` saying what is missing."""
    docker = shutil.which("docker")
    if docker is None:
        raise SandboxError("Docker is not installed or not on PATH. Install Docker, or scan a snapshot instead.")
    try:
        if _docker(docker, "version", "--format", "{{.Server.Version}}").returncode != 0:
            raise SandboxError("Docker is installed but its daemon is not running. Start Docker and try again.")
        if _docker(docker, "image", "inspect", "--format", "{{.Id}}", image).returncode != 0:
            raise SandboxError(
                f"image {image!r} is not on this machine. Build or pull it first; a scan never downloads images."
            )
    except subprocess.TimeoutExpired as exc:
        raise SandboxError("Docker did not answer in time.") from exc
    except OSError as exc:
        raise SandboxError(f"could not run Docker: {exc}") from exc
    return docker


def _remove_container(docker: str, name: str) -> None:
    """Best effort: make sure nothing keeps running after a timeout or a crash."""
    with suppress(OSError, subprocess.SubprocessError):
        _docker(docker, "rm", "--force", name)


async def collect_docker(
    image: str,
    command: list[str],
    *,
    mounts: list[Path] | None = None,
    server_name: str | None = None,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    show_stderr: bool = False,
    env: dict[str, str] | None = None,
) -> ServerSnapshot:
    """Run ``command`` inside a sandboxed container of ``image`` and collect its listings."""
    container_name = f"mcp-poison-scan-{uuid.uuid4().hex[:12]}"
    args = build_run_args(image, command, list(mounts or []), container_name, env)
    docker = check_docker(image)
    params = StdioServerParameters(command=docker, args=args, env=_docker_env())
    name = server_name or command[0]
    try:
        if show_stderr:
            return await run_server(params, sys.stderr, name, timeout_s, "docker")
        with open(os.devnull, "w", encoding="utf-8") as devnull:
            return await run_server(params, devnull, name, timeout_s, "docker")
    finally:
        _remove_container(docker, container_name)
