"""Collect tool lists from widely used real MCP servers, for the clean (false-positive) set.

Each server is started inside the scanner's own sandbox (no network, read-only
filesystem, unprivileged user) from the image built by ``clean_servers/Dockerfile``:

    docker build -t mcp-bench-servers benchmarks/clean_servers     # downloads third-party packages
    uv run python -m benchmarks.collect_clean

Snapshots are written to ``datasets/clean_servers/``. A server that will not start
without a real account or network is skipped and listed at the end. Placeholder
values stand in for API keys: with no network, no server can use them.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import anyio

from scanner.collect import CollectError, SandboxError, collect_docker, save_snapshot

IMAGE = "mcp-bench-servers"
OUT = Path(__file__).resolve().parent / "datasets" / "clean_servers"
FAKE = "placeholder-not-a-real-key"

# name -> (command inside the image, placeholder environment)
SERVERS: dict[str, tuple[list[str], dict[str, str]]] = {
    "filesystem": (["mcp-server-filesystem", "/tmp"], {}),  # noqa: S108 - a path inside the container
    "memory": (["mcp-server-memory"], {"MEMORY_FILE_PATH": "/tmp/memory.json"}),  # noqa: S108
    "sequential-thinking": (["mcp-server-sequential-thinking"], {}),
    "everything": (["mcp-server-everything"], {}),
    "github": (["mcp-server-github"], {"GITHUB_PERSONAL_ACCESS_TOKEN": FAKE}),
    "gitlab": (["mcp-server-gitlab"], {"GITLAB_PERSONAL_ACCESS_TOKEN": FAKE}),
    "postgres": (["mcp-server-postgres", "postgresql://localhost/none"], {}),
    "brave-search": (["mcp-server-brave-search"], {"BRAVE_API_KEY": FAKE}),
    "slack": (["mcp-server-slack"], {"SLACK_BOT_TOKEN": FAKE, "SLACK_TEAM_ID": "T00000000"}),
    "google-maps": (["mcp-server-google-maps"], {"GOOGLE_MAPS_API_KEY": FAKE}),
    "redis": (["mcp-server-redis", "redis://localhost:6379"], {}),
    "puppeteer": (["mcp-server-puppeteer"], {}),
    "playwright": (["mcp-server-playwright"], {}),
    "context7": (["context7-mcp"], {}),
    "notion": (["notion-mcp-server"], {"NOTION_TOKEN": FAKE}),
    "firecrawl": (["firecrawl-mcp"], {"FIRECRAWL_API_KEY": FAKE}),
    "tavily": (["tavily-mcp"], {"TAVILY_API_KEY": FAKE}),
    "exa": (["exa-mcp-server"], {"EXA_API_KEY": FAKE}),
    "fetch": (["mcp-server-fetch"], {}),
    "git": (["mcp-server-git"], {}),
    "time": (["mcp-server-time"], {}),
    "sqlite": (["mcp-server-sqlite", "--db-path", "/tmp/bench.db"], {}),  # noqa: S108
}


async def collect_all() -> tuple[list[str], list[str]]:
    OUT.mkdir(parents=True, exist_ok=True)
    collected, skipped = [], []
    for name, (command, env) in SERVERS.items():
        try:
            snapshot = await collect_docker(IMAGE, command, server_name=name, timeout_s=60, env=env)
        except (CollectError, TimeoutError) as exc:
            skipped.append(f"{name}: {type(exc).__name__}: {exc}"[:200])
            continue
        if not (snapshot.tools or snapshot.prompts or snapshot.resources):
            skipped.append(f"{name}: started but listed nothing")
            continue
        save_snapshot(snapshot, OUT / f"{name}.json")
        collected.append(f"{name}: {len(snapshot.tools)} tools, {len(snapshot.prompts)} prompts")
    return collected, skipped


def record_versions() -> None:
    """Save which package versions the image holds, so the set can be described exactly."""
    result = subprocess.run(  # noqa: S603 - fixed argv
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            IMAGE,
            "cat",
            "/installed-versions.txt",
            "/install-failures.txt",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    (OUT / "VERSIONS.txt").write_text(result.stdout, encoding="utf-8")


def main() -> None:
    try:
        collected, skipped = anyio.run(collect_all)
    except SandboxError as exc:
        sys.exit(f"error: {exc}")
    record_versions()
    print(f"collected {len(collected)} servers into {OUT}:")
    for line in collected:
        print(f"  {line}")
    if skipped:
        print(f"skipped {len(skipped)}:")
        for line in skipped:
            print(f"  {line}")


if __name__ == "__main__":
    main()
