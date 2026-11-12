"""Browser sign-in (OAuth) for remote servers that will not answer without one.

The protocol itself (finding the sign-in service, registering as an app, PKCE, swapping
the code for a token, refreshing) is the MCP SDK's ``OAuthClientProvider``. This module
supplies what the SDK leaves to the application:

- opening the browser, after checking the address the server gave us;
- a listener on this machine (127.0.0.1 only) that catches the browser coming back;
- a file that remembers sign-ins between runs;
- a time limit that pauses while a person is signing in.

Everything the server says here is untrusted. The sign-in address comes from the server,
so it must be ``https`` (or this machine) before a browser is pointed at it. Nothing the
server sends is echoed into the page shown in the browser. Tokens are never printed.

A token lets its holder act as the user on that service. The scanner uses it only to list
what the server offers; it never calls a tool.
"""

from __future__ import annotations

import contextlib
import json
import logging
import math
import os
import time
import webbrowser
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import anyio
from anyio.abc import SocketAttribute, SocketStream
from mcp.client.auth import OAuthClientProvider
from mcp.shared.auth import AuthorizationCodeResult, OAuthClientInformationFull, OAuthClientMetadata, OAuthToken
from pydantic import AnyUrl, ValidationError

from scanner.collect.live import CollectError
from scanner.textutil import visible

SIGN_IN_TIMEOUT_S = 300.0
"""How long to wait for a person to finish signing in."""

CLIENT_NAME = "MCP Poison Scanner"
CALLBACK_PATH = "/callback"
_MAX_REQUEST_BYTES = 16_384
_CONNECTION_TIMEOUT_S = 5.0
_MAX_STORE_BYTES = 2_000_000

# The SDK logs a failed sign-in with a traceback; the scanner reports it in one line instead.
logging.getLogger("mcp.client.auth").addHandler(logging.NullHandler())
logging.getLogger("mcp.client.auth").propagate = False


class SignInError(CollectError):
    """Signing in did not work. The message is safe to print."""


def default_store_path() -> Path:
    return Path.home() / ".mcp-poison-scanner" / "sign-ins.json"


def server_key(url: str) -> str:
    """The name a server's sign-in is saved under: its address without query or fragment."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if ":" in host:
        host = f"[{host}]"
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme.lower()}://{host}{port}{parts.path or '/'}"


def _is_local(host: str | None) -> bool:
    return host in ("127.0.0.1", "localhost", "::1")


def check_sign_in_address(url: str) -> str:
    """Refuse a sign-in address a browser should not be sent to. Returns its host."""
    try:
        parts = urlsplit(url)
        host = parts.hostname
    except ValueError:
        raise SignInError("the server gave a sign-in address that is not a valid URL") from None
    if not host or parts.username is not None or parts.password is not None:
        raise SignInError("the server gave a sign-in address that is not a plain web address")
    if parts.scheme != "https" and not (parts.scheme == "http" and _is_local(host)):
        raise SignInError("the server gave a sign-in address that is not https; refusing to open it")
    return host


class SignInStore:
    """Sign-ins remembered between runs, in one JSON file. ``path=None`` keeps them in memory only."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self._memory: dict[str, dict[str, Any]] = {}

    def _read(self) -> dict[str, dict[str, Any]]:
        if self.path is None:
            return self._memory
        try:
            if self.path.stat().st_size > _MAX_STORE_BYTES:
                return {}
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        servers = data.get("servers") if isinstance(data, dict) else None
        if not isinstance(servers, dict):
            return {}
        return {key: value for key, value in servers.items() if isinstance(value, dict)}

    def _write(self, servers: dict[str, dict[str, Any]]) -> None:
        if self.path is None:
            self._memory = servers
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        text = json.dumps({"version": 1, "servers": servers}, indent=2)
        # Created readable by the owner only (on Windows the user's profile folder already is).
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)

    def get(self, key: str) -> dict[str, Any]:
        return dict(self._read().get(key, {}))

    def put(self, key: str, entry: dict[str, Any]) -> None:
        servers = self._read()
        servers[key] = entry
        self._write(servers)

    def keys(self) -> list[str]:
        return sorted(self._read())

    def forget(self, key: str | None = None) -> list[str]:
        """Delete one saved sign-in, or all of them. Returns the addresses removed."""
        servers = self._read()
        gone = sorted(servers) if key is None else [k for k in servers if k == key]
        if gone:
            self._write({k: v for k, v in servers.items() if k not in gone})
        return gone


class _ServerStorage:
    """What the SDK reads and writes for one server."""

    def __init__(self, store: SignInStore, key: str, redirect_uri: str) -> None:
        self._store, self._key, self._redirect_uri = store, key, redirect_uri

    def expires_at(self) -> float | None:
        value = self._store.get(self._key).get("expires_at")
        return float(value) if isinstance(value, int | float) else None

    async def get_tokens(self) -> OAuthToken | None:
        try:
            return OAuthToken.model_validate(self._store.get(self._key).get("tokens"))
        except ValidationError:
            return None

    async def set_tokens(self, tokens: OAuthToken) -> None:
        entry = self._store.get(self._key)
        entry["tokens"] = tokens.model_dump(mode="json", exclude_none=True)
        entry["expires_at"] = time.time() + int(tokens.expires_in) if tokens.expires_in is not None else None
        self._store.put(self._key, entry)

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        try:
            info = OAuthClientInformationFull.model_validate(self._store.get(self._key).get("client"))
        except ValidationError:
            return None
        # A registration is tied to the return address it was made with. If this run listens
        # somewhere else, it cannot be used to sign in again, so register afresh.
        if self._redirect_uri not in [str(uri) for uri in info.redirect_uris or []]:
            return None
        return info

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        entry = self._store.get(self._key)
        entry["client"] = client_info.model_dump(mode="json", exclude_none=True)
        self._store.put(self._key, entry)


class _Provider(OAuthClientProvider):
    """The SDK's provider, plus remembering when a saved token runs out.

    The SDK only learns a token's expiry when the token is issued. Without this, a saved token
    that has expired would be sent, rejected, and followed by a full browser sign-in instead
    of a silent refresh.
    """

    def __init__(self, storage: _ServerStorage, **kwargs: Any) -> None:
        super().__init__(storage=storage, **kwargs)
        self._saved = storage

    async def _initialize(self) -> None:
        await super()._initialize()
        if self.context.current_tokens is not None:
            self.context.token_expiry_time = self._saved.expires_at()


_PAGE = (
    "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {length}\r\n"
    "Cache-Control: no-store\r\nConnection: close\r\n\r\n"
)
_DONE = "Sign-in finished. You can close this tab and go back to the scanner."
_FAILED = "Sign-in was not completed. Go back to the scanner for details."
_NOT_EXPECTED = "This is not the sign-in the scanner is waiting for."


def _page(status: str, message: str) -> bytes:
    # Fixed text only: nothing from the request or the server is ever put in this page.
    body = f"<!doctype html><title>{CLIENT_NAME}</title><p>{message}</p>".encode()
    return _PAGE.format(status=status, length=len(body)).encode() + body


class _Callback:
    """One sign-in in progress: the local listener, and the time limit it pauses."""

    def __init__(self, signin: SignIn, server_host: str, listener: Any, scope: anyio.CancelScope, timeout_s: float):
        self.signin, self.server_host, self.listener = signin, server_host, listener
        self.scope, self.timeout_s = scope, timeout_s
        self.port: int = listener.extra(SocketAttribute.local_port)  # noqa: S610 - anyio, not Django
        self.redirect_uri = f"http://127.0.0.1:{self.port}{CALLBACK_PATH}"
        self.state: str | None = None
        self.signed_in = False

    async def open_browser(self, url: str) -> None:
        """The SDK's redirect handler: check the address, then send the person's browser to it."""
        host = check_sign_in_address(url)
        self.state = (parse_qs(urlsplit(url).query).get("state") or [None])[0]
        self.scope.deadline = math.inf  # the collection time limit does not run while a person signs in
        say = self.signin.announce
        say(f"sign-in needed for {visible(self.server_host)}: opening your browser at {visible(host)}")
        say("  the page will ask you to let 'MCP Poison Scanner' connect. It only lists the server's tools.")
        say(f"  if no browser opens, paste this address into one:\n  {visible(url)}")
        with contextlib.suppress(Exception):
            self.signin.open_browser(url)

    async def wait(self) -> AuthorizationCodeResult:
        """The SDK's callback handler: wait for the browser to come back to this machine."""
        outcome: list[AuthorizationCodeResult | SignInError] = []

        async def handle(stream: SocketStream) -> None:
            async with stream:
                with anyio.move_on_after(_CONNECTION_TIMEOUT_S):
                    answer = self._read(await _request_target(stream))
                    if answer is None:
                        await stream.send(_page("404 Not Found", _NOT_EXPECTED))
                        return
                    ok = isinstance(answer, AuthorizationCodeResult)
                    await stream.send(_page("200 OK", _DONE if ok else _FAILED))
                    outcome.append(answer)
                    group.cancel_scope.cancel()

        with anyio.move_on_after(self.signin.wait_s):
            async with anyio.create_task_group() as group:
                while True:
                    group.start_soon(handle, await self.listener.accept())
        self.scope.deadline = anyio.current_time() + self.timeout_s
        if not outcome:
            minutes = max(1, round(self.signin.wait_s / 60))
            raise SignInError(f"nobody finished signing in within {minutes} minutes")
        if isinstance(outcome[0], SignInError):
            raise outcome[0]
        self.signed_in = True
        return outcome[0]

    def _read(self, target: str | None) -> AuthorizationCodeResult | SignInError | None:
        """Turn a request to the listener into an answer, or None if it is not the one awaited."""
        if target is None:
            return None
        parts = urlsplit(target)
        query = {key: values[0] for key, values in parse_qs(parts.query).items()}
        # Any page in the browser can make requests to this port. Only the one carrying the
        # random value sent with this sign-in counts.
        if parts.path != CALLBACK_PATH or not self.state or query.get("state") != self.state:
            return None
        if "error" in query:
            detail = query.get("error_description") or query["error"]
            return SignInError(f"the sign-in page reported: {visible(detail[:200])}")
        if not query.get("code"):
            return None
        return AuthorizationCodeResult(code=query["code"], state=query["state"], iss=query.get("iss"))


async def _request_target(stream: SocketStream) -> str | None:
    """The path and query of a GET request, or None for anything else."""
    data = b""
    while b"\r\n" not in data:
        if len(data) > _MAX_REQUEST_BYTES:
            return None
        try:
            data += await stream.receive(4096)
        except (anyio.EndOfStream, anyio.BrokenResourceError):
            return None
    words = data.split(b"\r\n", 1)[0].decode("latin-1").split(" ")
    return words[1] if len(words) == 3 and words[0] == "GET" else None


class SignIn:
    """How to sign in through a browser. One object serves every server in a run.

    ``open_browser`` and ``announce`` are replaceable so tests need no browser.
    """

    def __init__(
        self,
        store: SignInStore | None = None,
        *,
        open_browser: Callable[[str], object] | None = None,
        announce: Callable[[str], None] = lambda _line: None,
        wait_s: float = SIGN_IN_TIMEOUT_S,
    ) -> None:
        self.store = store or SignInStore()
        self.open_browser = open_browser or webbrowser.open
        self.announce = announce
        self.wait_s = wait_s

    def secrets(self, url: str) -> set[str]:
        """Token values saved for ``url``, so error messages can be scrubbed of them."""
        tokens = self.store.get(server_key(url)).get("tokens") or {}
        return {str(tokens[k]) for k in ("access_token", "refresh_token") if tokens.get(k)}

    def _saved_port(self, key: str) -> int | None:
        for uri in (self.store.get(key).get("client") or {}).get("redirect_uris") or []:
            parts = urlsplit(str(uri))
            if parts.hostname == "127.0.0.1" and parts.port:
                return parts.port
        return None

    @contextlib.asynccontextmanager
    async def session(self, url: str, scope: anyio.CancelScope, timeout_s: float) -> AsyncIterator[OAuthClientProvider]:
        """An ``httpx2`` auth object for ``url``. ``scope`` is the time limit to pause during sign-in."""
        key = server_key(url)
        listener = None
        # Listen where the saved registration expects the browser to return, if that port is free.
        for port in [p for p in (self._saved_port(key), 0) if p is not None]:
            try:
                listener = (await anyio.create_tcp_listener(local_host="127.0.0.1", local_port=port)).listeners[0]
                break
            except OSError:
                continue
        if listener is None:
            raise SignInError("could not open a port on this machine for the browser to return to")
        try:
            callback = _Callback(self, urlsplit(url).hostname or "", listener, scope, timeout_s)
            provider = _Provider(
                _ServerStorage(self.store, key, callback.redirect_uri),
                server_url=url,
                client_metadata=OAuthClientMetadata(
                    client_name=CLIENT_NAME,
                    redirect_uris=[AnyUrl(callback.redirect_uri)],
                    token_endpoint_auth_method="none",  # noqa: S106 - a public client: it has no secret
                ),
                redirect_handler=callback.open_browser,
                callback_handler=callback.wait,
            )
            yield provider
            if callback.signed_in:
                where = f"; saved in {self.store.path}" if self.store.path else ""
                self.announce(f"signed in to {visible(callback.server_host)}{where}")
        finally:
            await listener.aclose()
