"""Streamable HTTP collection: list the metadata of a remote MCP server.

Nothing from the server runs on this machine, so no sandbox or ``--unsafe-local``
is needed. The risks are different ones:

- Credentials. Extra headers (a bearer token) are sent only to the URL's own
  origin: the SDK refuses redirects that leave it. A header is never sent over
  plain ``http`` except to this machine, and header values never appear in errors.
- A hostile or broken server. The same page, item and time limits apply as for
  every other transport.

A server that wants a browser sign-in (OAuth) is handled by ``signin.py`` when the caller
passes a ``SignIn``. The sign-in service's addresses come from the server, so with a sign-in
every request must be ``https`` (or to this machine), not only the first one.
"""

from __future__ import annotations

import ipaddress
import math
import re
from urllib.parse import urlsplit

import anyio
import httpx2
from mcp import Client
from mcp.client.auth import OAuthFlowError, OAuthRegistrationError
from mcp.client.streamable_http import streamable_http_client

from scanner.collect.live import DEFAULT_TIMEOUT_S, CollectError, _leaf, collect_with_timeout
from scanner.collect.signin import SignIn, SignInError
from scanner.models import ServerSnapshot
from scanner.textutil import visible

_HEADER_NAME = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,100}$")
CONNECT_TIMEOUT_S = 15.0


class HttpTargetError(ValueError):
    """The URL or headers are not something the scanner will connect with."""


def _is_local(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class SignInNeeded(CollectError):
    """The server answered 401: it wants a sign-in or a token that was not given."""


def _scrub(text: str, headers: dict[str, str], extra: frozenset[str] | set[str] = frozenset()) -> str:
    """Remove header values (and their parts, such as the token after 'Bearer') from ``text``."""
    secrets = {value for value in headers.values()} | set(extra)
    secrets |= {part for value in headers.values() for part in value.split() if len(part) >= 6}
    for secret in sorted(secrets, key=len, reverse=True):
        text = text.replace(secret, "[redacted]")
    return text


def parse_header(line: str) -> tuple[str, str]:
    """Split a ``Name: value`` header given on the command line."""
    name, sep, value = line.partition(":")
    name, value = name.strip(), value.strip()
    if not sep or not _HEADER_NAME.match(name) or not value:
        raise HttpTargetError("a header must look like 'Name: value'")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        raise HttpTargetError(f"header {name} contains a control character")
    return name, value


def check_target(url: str, headers: dict[str, str]) -> str:
    """Validate the URL and return its host. Raises ``HttpTargetError`` with a reason."""
    try:
        parts = urlsplit(url)
        host = parts.hostname
    except ValueError as exc:
        raise HttpTargetError("not a valid URL") from exc
    if parts.scheme not in ("http", "https") or not host:
        raise HttpTargetError("the URL must start with http:// or https:// and name a host")
    if parts.username is not None or parts.password is not None:
        raise HttpTargetError("put credentials in a header, not in the URL")
    if headers and parts.scheme == "http" and not _is_local(host):
        raise HttpTargetError("refusing to send headers over plain http to another machine; use https")
    return host


async def collect_http(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    server_name: str | None = None,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    transport: httpx2.AsyncBaseTransport | None = None,
    sign_in: SignIn | None = None,
) -> ServerSnapshot:
    """Connect to the streamable HTTP endpoint at ``url`` and collect its listings.

    ``transport`` replaces the network layer; tests use it to talk to an in-memory server.
    ``sign_in`` lets the server ask for a browser sign-in; without it a server that wants
    one fails with ``SignInNeeded``.
    """
    headers = dict(headers or {})
    host = check_target(url, headers)
    if sign_in is not None:
        if any(name.lower() == "authorization" for name in headers):
            raise HttpTargetError("give a token or a browser sign-in, not both")
        if urlsplit(url).scheme == "http" and not _is_local(host):
            raise HttpTargetError("refusing to sign in over plain http to another machine; use https")
    timeout = httpx2.Timeout(min(CONNECT_TIMEOUT_S, timeout_s), read=timeout_s)
    refused: list[int] = []

    async def watch(response: httpx2.Response) -> None:
        if response.status_code == 401:
            refused.append(401)

    async def https_only(request: httpx2.Request) -> None:
        # With a sign-in, the server names other addresses to talk to. Hold them to the same rule.
        if request.url.scheme != "https" and not _is_local(request.url.host):
            raise HttpTargetError("the server pointed the sign-in at an address that is not https")

    hooks = {"response": [watch], "request": [https_only] if sign_in is not None else []}
    try:
        async with httpx2.AsyncClient(headers=headers, timeout=timeout, transport=transport, event_hooks=hooks) as http:
            if sign_in is None:
                client = Client(streamable_http_client(url, http_client=http), cache=None, mode="auto")
                return await collect_with_timeout(client, server_name or host, "http", timeout_s)
            # The time limit is held here, not inside, so that the sign-in can pause it.
            with anyio.fail_after(timeout_s) as scope:
                async with sign_in.session(url, scope, timeout_s) as auth:
                    http.auth = auth
                    client = Client(streamable_http_client(url, http_client=http), cache=None, mode="auto")
                    return await collect_with_timeout(client, server_name or host, "http", math.inf)
    except httpx2.HTTPError as exc:
        # Only the error's type: its text can quote the request, and requests carry the headers.
        raise CollectError(f"could not reach the server: {type(exc).__name__}") from None
    except CollectError as exc:
        secrets = sign_in.secrets(url) if sign_in is not None else set()
        cause = _leaf(exc.__cause__) if exc.__cause__ is not None else exc
        if isinstance(cause, SignInError | HttpTargetError):
            raise type(cause)(_scrub(str(cause), headers, secrets)) from None
        if isinstance(cause, OAuthRegistrationError):
            raise SignInError(
                "this server does not let a new app register itself for sign-in, so the scanner cannot "
                "sign in to it. If the service gives out API tokens, pass one with --bearer-env"
            ) from None
        if isinstance(cause, OAuthFlowError):
            text = visible(str(cause).strip()[:200])
            raise SignInError(_scrub(f"sign-in failed: {text}", headers, secrets)) from None
        if refused and sign_in is None:
            raise SignInNeeded("the server wants a sign-in or a token (it answered 401)") from None
        # The underlying error text may quote a request. Never let a header value out in a message.
        raise CollectError(_scrub(str(exc), headers, secrets)) from None
