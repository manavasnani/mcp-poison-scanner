"""Walk a connected MCP client and record everything the server lists.

Shared by every live transport (stdio now; HTTP and Docker later), and by tests,
which pass an in-process server so no subprocess or network is needed.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import anyio
from mcp import Client
from mcp.server.mcpserver import MCPServer
from mcp.shared.exceptions import MCPError
from mcp.types import ServerCapabilities

from scanner.models import ServerSnapshot, SourceKind

MAX_PAGES = 50
"""Cap on pages per list call, so a server that never stops paginating can't hang a scan."""

MAX_ITEMS = 5_000
"""Cap on items per list call, so a hostile server can't exhaust memory."""

DEFAULT_TIMEOUT_S = 30.0


class CollectError(RuntimeError):
    """The server could not be connected to, crashed, or broke the protocol."""


def _leaf(exc: BaseException) -> BaseException:
    """First non-group exception inside nested exception groups."""
    while isinstance(exc, BaseExceptionGroup) and exc.exceptions:
        exc = exc.exceptions[0]
    return exc


def _describe(exc: BaseException) -> str:
    # The message may contain server-controlled text: keep it short and escape control characters.
    text = str(exc).strip()[:200].encode("unicode_escape").decode("ascii")
    return f"{type(exc).__name__}: {text}" if text else type(exc).__name__


def _dump(item: Any) -> dict[str, Any]:
    """SDK model -> MCP wire-format dict, keeping every field the server sent."""
    return item.model_dump(mode="json", by_alias=True, exclude_none=True)


async def _paginate(
    fetch: Callable[[str | None], Awaitable[Any]],
    attr: str,
    errors: list[str],
    label: str,
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    cursor: str | None = None
    seen_cursors: set[str] = set()
    for _ in range(MAX_PAGES):
        try:
            page = await fetch(cursor)
        except Exception as exc:  # a failing list call must not abort the whole scan
            errors.append(f"{label}: {type(exc).__name__}: {exc}")
            return items
        items.extend(_dump(i) for i in getattr(page, attr))
        if len(items) >= MAX_ITEMS:
            errors.append(f"{label}: truncated at {MAX_ITEMS} items")
            return items[:MAX_ITEMS]
        cursor = page.next_cursor
        if cursor is None:
            return items
        if cursor in seen_cursors:
            errors.append(f"{label}: server repeated a pagination cursor; stopped")
            return items
        seen_cursors.add(cursor)
    errors.append(f"{label}: stopped after {MAX_PAGES} pages")
    return items


async def collect_from_client(client: Client, server_name: str, source: SourceKind) -> ServerSnapshot:
    """Record tools, prompts, resources and resource templates from an open client."""
    errors: list[str] = []
    caps: ServerCapabilities = client.server_capabilities
    info = client.server_info

    tools: list[dict[str, Any]] = []
    prompts: list[dict[str, Any]] = []
    resources: list[dict[str, Any]] = []
    templates: list[dict[str, Any]] = []

    # Only call list methods the server advertises; calling others is a protocol error.
    if caps.tools is not None:
        tools = await _paginate(lambda c: client.list_tools(cursor=c), "tools", errors, "tools/list")
    if caps.prompts is not None:
        prompts = await _paginate(lambda c: client.list_prompts(cursor=c), "prompts", errors, "prompts/list")
    if caps.resources is not None:
        resources = await _paginate(lambda c: client.list_resources(cursor=c), "resources", errors, "resources/list")
        templates = await _paginate(
            lambda c: client.list_resource_templates(cursor=c),
            "resource_templates",
            errors,
            "resources/templates/list",
        )

    return ServerSnapshot(
        server_name=server_name,
        source=source,
        server_info=_dump(info) if info is not None else None,
        instructions=client.instructions,
        tools=tools,
        prompts=prompts,
        resources=resources,
        resource_templates=templates,
        errors=errors,
    )


async def collect_in_process(server: MCPServer, server_name: str | None = None) -> ServerSnapshot:
    """Collect from an in-process server. Test helper: no subprocess, no network."""
    async with Client(server, cache=None) as client:
        return await collect_from_client(client, server_name or server.name, "in_process")


async def collect_with_timeout(
    client: Client, server_name: str, source: SourceKind, timeout_s: float = DEFAULT_TIMEOUT_S
) -> ServerSnapshot:
    """Connect, collect and disconnect, all within ``timeout_s``.

    Raises ``TimeoutError`` if the server is too slow, and ``CollectError`` if it
    exits, crashes or answers the handshake with an error.
    """
    try:
        with anyio.fail_after(timeout_s):
            async with client:
                return await collect_from_client(client, server_name, source)
    except MCPError as exc:
        raise CollectError(f"server rejected the connection: {_describe(exc)}") from exc
    except ExceptionGroup as group:
        # The SDK runs the connection in task groups, so a dead server surfaces as a group.
        leaf = _leaf(group)
        if isinstance(leaf, TimeoutError):
            raise TimeoutError() from group
        raise CollectError(f"server connection failed: {_describe(leaf)}") from group
