"""Stdio collection: launch a server command and list its metadata.

Launching a server runs untrusted code on this machine with the user's privileges.
This module refuses to do that unless the caller passes ``unsafe_local=True``,
which the CLI only sets from an explicit ``--unsafe-local`` flag. The safer way
to run a stdio server is the Docker sandbox in ``scanner.collect.docker``.
"""

from __future__ import annotations

import os
import sys
from typing import TextIO

from mcp import Client, StdioServerParameters
from mcp.client.stdio import stdio_client

from scanner.collect.live import DEFAULT_TIMEOUT_S, collect_with_timeout
from scanner.models import ServerSnapshot, SourceKind


class UnsafeLaunchRefused(RuntimeError):
    """Raised when asked to launch a server without explicit consent."""


async def collect_stdio(
    command: str,
    args: list[str] | None = None,
    *,
    server_name: str | None = None,
    env: dict[str, str] | None = None,
    unsafe_local: bool = False,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    show_stderr: bool = False,
) -> ServerSnapshot:
    """Launch ``command`` directly on the host and collect its listings.

    ``env`` is merged over the SDK's minimal default environment (PATH, HOME and
    similar), so the user's API keys and tokens are not passed to the server.

    The server's stderr is discarded unless ``show_stderr`` is set: it is untrusted
    output and would otherwise be written straight to the user's terminal.
    """
    if not unsafe_local:
        raise UnsafeLaunchRefused(
            "Refusing to launch a server on the host: it would run untrusted code. "
            "Use a snapshot, or pass --unsafe-local if you trust this server."
        )
    params = StdioServerParameters(command=command, args=list(args or []), env=env)
    name = server_name or command
    if show_stderr:
        return await run_server(params, sys.stderr, name, timeout_s)
    with open(os.devnull, "w", encoding="utf-8") as devnull:
        return await run_server(params, devnull, name, timeout_s)


async def run_server(
    params: StdioServerParameters, errlog: TextIO, name: str, timeout_s: float, source: SourceKind = "stdio"
) -> ServerSnapshot:
    """Start the process described by ``params``, speak MCP over its stdio, and collect its listings."""
    client = Client(stdio_client(params, errlog=errlog), cache=None, mode="auto")
    return await collect_with_timeout(client, name, source, timeout_s)
