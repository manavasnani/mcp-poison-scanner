"""Streamable HTTP collection.

No sockets are opened: the fixture server runs as an in-memory ASGI app and the
collector's network layer is replaced with a transport that calls it directly.
"""

from contextlib import asynccontextmanager

import httpx2
import pytest
from typer.testing import CliRunner

import scanner.cli as cli
from scanner.collect import CollectError, HttpTargetError, collect_http, collect_in_process, parse_header
from scanner.collect.http import check_target
from tests.conftest import load_fixture_module

URL = "http://127.0.0.1:8000/mcp"


class Recording(httpx2.AsyncBaseTransport):
    """Passes requests to an ASGI app and remembers their headers."""

    def __init__(self, app) -> None:
        self.inner = httpx2.ASGITransport(app=app)
        self.headers: list[httpx2.Headers] = []

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        self.headers.append(request.headers)
        return await self.inner.handle_async_request(request)


@asynccontextmanager
async def served(fixture: str):
    """The fixture server as an in-memory HTTP app, plus the in-process server for comparison."""
    server = load_fixture_module(fixture).server
    app = server.streamable_http_app()
    async with app.router.lifespan_context(app):
        yield Recording(app), server


# --- collection ---------------------------------------------------------------------------------


@pytest.mark.anyio
async def test_http_matches_in_process_listing():
    async with served("poisoned") as (transport, server):
        snap = await collect_http(URL, transport=transport, timeout_s=30)
        in_proc = await collect_in_process(server)
    assert snap.source == "http" and snap.server_name == "127.0.0.1" and snap.errors == []
    assert snap.tools == in_proc.tools
    assert snap.prompts == in_proc.prompts
    assert snap.resources == in_proc.resources
    assert snap.instructions == in_proc.instructions


@pytest.mark.anyio
async def test_headers_are_sent_with_every_request():
    async with served("clean") as (transport, _server):
        await collect_http(URL, headers={"Authorization": "Bearer tok", "X-Team": "sec"}, transport=transport)
    assert transport.headers
    assert all(h["authorization"] == "Bearer tok" and h["x-team"] == "sec" for h in transport.headers)


@pytest.mark.anyio
async def test_a_non_mcp_endpoint_is_a_collect_error():
    def not_found(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(404, text="nope")

    with pytest.raises(CollectError):
        await collect_http(URL, transport=httpx2.MockTransport(not_found), timeout_s=10)


@pytest.mark.anyio
async def test_connection_failure_never_echoes_the_token():
    def refuse(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError(f"refused {request.headers['authorization']}", request=request)

    with pytest.raises(CollectError) as caught:
        await collect_http(URL, headers={"Authorization": "Bearer s3cret"}, transport=httpx2.MockTransport(refuse))
    assert "s3cret" not in str(caught.value)


# --- what the scanner refuses to connect with ---------------------------------------------------


@pytest.mark.parametrize(
    "url, headers, expected",
    [
        ("ftp://example.com/mcp", {}, "http:// or https://"),
        ("file:///etc/passwd", {}, "http:// or https://"),
        ("example.com/mcp", {}, "http:// or https://"),
        ("https://", {}, "name a host"),
        ("https://user:pw@example.com/mcp", {}, "not in the URL"),
        ("http://example.com/mcp", {"Authorization": "Bearer t"}, "plain http"),
        ("http://10.0.0.5/mcp", {"X-Key": "k"}, "plain http"),
    ],
)
def test_bad_targets_are_refused(url, headers, expected):
    with pytest.raises(HttpTargetError, match=expected):
        check_target(url, headers)


@pytest.mark.parametrize(
    "url, headers",
    [
        ("https://example.com/mcp", {"Authorization": "Bearer t"}),
        ("http://example.com/mcp", {}),  # no secret to leak
        ("http://localhost:8000/mcp", {"Authorization": "Bearer t"}),
        ("http://127.0.0.1:8000/mcp", {"Authorization": "Bearer t"}),
        ("http://[::1]:8000/mcp", {"Authorization": "Bearer t"}),
    ],
)
def test_good_targets_are_accepted(url, headers):
    assert check_target(url, headers)


def test_parse_header():
    assert parse_header("Authorization: Bearer a:b") == ("Authorization", "Bearer a:b")
    assert parse_header("  X-Team :  sec ") == ("X-Team", "sec")
    for bad in ("no-colon", ": value", "Name:", "Bad Name: x", "X: a\r\nInjected: y"):
        with pytest.raises(HttpTargetError):
            parse_header(bad)


# --- CLI ----------------------------------------------------------------------------------------

runner = CliRunner()


@pytest.fixture
def captured(monkeypatch):
    """Replace the HTTP collector and record what the CLI passes to it."""
    calls: list[dict] = []

    async def fake(url, **kwargs):
        calls.append({"url": url, **kwargs})
        from tests.helpers import server, tool

        return server(kwargs.get("server_name") or "remote", tool("t", "Fine."))

    monkeypatch.setattr(cli, "collect_http", fake)
    return calls


def test_cli_scan_url_with_bearer_token_from_the_environment(captured, monkeypatch):
    monkeypatch.setenv("MY_TOKEN", "tok-123")
    result = runner.invoke(
        cli.app, ["scan", "--url", "https://mcp.example/mcp", "--bearer-env", "MY_TOKEN", "--header", "X-Team: sec"]
    )
    assert result.exit_code == 0, result.output
    assert captured[0]["url"] == "https://mcp.example/mcp"
    assert captured[0]["headers"] == {"X-Team": "sec", "Authorization": "Bearer tok-123"}
    assert "tok-123" not in result.output


def test_cli_missing_token_variable_is_an_error(captured, monkeypatch):
    monkeypatch.delenv("NOPE_TOKEN", raising=False)
    result = runner.invoke(cli.app, ["scan", "--url", "https://mcp.example/mcp", "--bearer-env", "NOPE_TOKEN"])
    assert result.exit_code == 2 and "NOPE_TOKEN is not set" in result.stderr and captured == []


def test_cli_reports_a_refused_target():
    result = runner.invoke(cli.app, ["scan", "--url", "http://mcp.example/mcp", "--header", "Authorization: Bearer t"])
    assert result.exit_code == 2 and "plain http" in result.stderr


@pytest.mark.parametrize(
    "args",
    [
        ["scan", "--url", "https://a.example/mcp", "--", "python", "x.py"],
        ["scan", "--header", "X: y", "-s", "whatever.json"],
        ["scan", "--url", "https://a.example/mcp", "--unsafe-local"],
        ["collect", "--url", "https://a.example/mcp", "-s", "whatever.json"],
    ],
)
def test_cli_rejects_mixed_up_options(args):
    assert runner.invoke(cli.app, args).exit_code == 2


def test_cli_collect_and_pin_accept_a_url(captured, tmp_path):
    out = tmp_path / "snap.json"
    assert runner.invoke(cli.app, ["collect", "--url", "https://a.example/mcp", "-o", str(out)]).exit_code == 0
    assert out.exists()
    lock = tmp_path / "lock.json"
    pinned = runner.invoke(cli.app, ["pin", "--url", "https://a.example/mcp", "--name", "remote", "--lock", str(lock)])
    assert pinned.exit_code == 0 and "pinned remote" in pinned.stderr
