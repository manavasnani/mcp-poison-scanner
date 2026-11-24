"""Browser sign-in for remote servers.

Nothing leaves this machine and no browser opens. The server, and the sign-in service in
front of it, are one in-memory app. The "browser" is a function that reads the address it
was sent to and calls back the scanner's own listener on 127.0.0.1, as a real one would.
"""

import json
import threading
import time
import urllib.error
import urllib.request
from contextlib import asynccontextmanager
from urllib.parse import parse_qs, urlsplit

import httpx2
import pytest
from typer.testing import CliRunner

import scanner.cli as cli
from scanner.collect import (
    CollectError,
    HttpTargetError,
    SignIn,
    SignInError,
    SignInNeeded,
    SignInStore,
    collect_http,
    collect_in_process,
    server_key,
)
from scanner.collect.signin import check_sign_in_address
from tests.conftest import load_fixture_module

BASE = "http://127.0.0.1:8000"
URL = f"{BASE}/mcp"
runner = CliRunner()


class Protected:
    """The clean fixture server behind a made-up sign-in service."""

    def __init__(self, inner, *, registration=True, authorize=f"{BASE}/authorize", token=f"{BASE}/token"):
        self.inner, self.registration, self.authorize, self.token = inner, registration, authorize, token
        self.valid: set[str] = set()
        self.issued = 0
        self.registrations = 0
        self.grants: list[str] = []

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.inner(scope, receive, send)
        path = scope["path"]
        if path == "/mcp":
            headers = {k.decode().lower(): v.decode() for k, v in scope["headers"]}
            if headers.get("authorization", "").removeprefix("Bearer ") in self.valid:
                return await self.inner(scope, receive, send)
            challenge = f'Bearer resource_metadata="{BASE}/.well-known/oauth-protected-resource/mcp"'
            return await self._json(send, 401, {"error": "sign in"}, {"www-authenticate": challenge})
        if path == "/.well-known/oauth-protected-resource/mcp":
            return await self._json(send, 200, {"resource": URL, "authorization_servers": [BASE]})
        if path == "/.well-known/oauth-authorization-server":
            return await self._json(
                send,
                200,
                {
                    "issuer": BASE,
                    "authorization_endpoint": self.authorize,
                    "token_endpoint": self.token,
                    "registration_endpoint": f"{BASE}/register",
                    "response_types_supported": ["code"],
                    "code_challenge_methods_supported": ["S256"],
                },
            )
        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body"):
                break
        if path == "/register":
            if not self.registration:
                return await self._json(send, 403, {"error": "registration is closed"})
            self.registrations += 1
            asked = json.loads(body)
            return await self._json(
                send,
                201,
                {
                    "client_id": "client-1",
                    "token_endpoint_auth_method": "none",
                    "redirect_uris": asked["redirect_uris"],
                },
            )
        if path == "/token":
            form = {k: v[0] for k, v in parse_qs(body.decode()).items()}
            self.grants.append(form["grant_type"])
            good = form.get("code") == "the-code" or form.get("refresh_token", "").startswith("refresh-secret-")
            if not good:
                return await self._json(send, 400, {"error": "invalid_grant"})
            self.issued += 1
            access = f"access-secret-{self.issued}"
            self.valid = {access}
            return await self._json(
                send,
                200,
                {
                    "access_token": access,
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "refresh_token": f"refresh-secret-{self.issued}",
                },
            )
        return await self._json(send, 404, {})

    @staticmethod
    async def _json(send, status, data, headers=None):
        raw = [(b"content-type", b"application/json")]
        raw += [(k.encode(), v.encode()) for k, v in (headers or {}).items()]
        await send({"type": "http.response.start", "status": status, "headers": raw})
        await send({"type": "http.response.body", "body": json.dumps(data).encode()})


@asynccontextmanager
async def protected(**options):
    server = load_fixture_module("clean").server
    app = server.streamable_http_app()
    async with app.router.lifespan_context(app):
        service = Protected(app, **options)
        yield httpx2.ASGITransport(app=service), service, server


class Browser:
    """Stands in for the person and their browser."""

    def __init__(self, answer="code=the-code", first_try_wrong_state=False, comes_back=True):
        self.answer, self.first_try_wrong_state, self.comes_back = answer, first_try_wrong_state, comes_back
        self.opened: list[str] = []
        self._pages: list[tuple[int, str]] = []
        self._thread: threading.Thread | None = None

    def __call__(self, url: str) -> None:
        self.opened.append(url)
        if self.comes_back:
            self._thread = threading.Thread(target=self._return, args=(url,), daemon=True)
            self._thread.start()

    @property
    def pages(self) -> list[tuple[int, str]]:
        """What the browser was shown. Waits for it to finish reading: the scan can return first."""
        if self._thread is not None:
            self._thread.join(timeout=10)
        return self._pages

    def _get(self, address: str) -> None:
        try:
            with urllib.request.urlopen(address, timeout=10) as response:  # noqa: S310 - our own 127.0.0.1 listener
                self._pages.append((response.status, response.read().decode()))
        except urllib.error.HTTPError as exc:
            self._pages.append((exc.code, exc.read().decode()))

    def _return(self, url: str) -> None:
        query = {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}
        assert query["redirect_uri"].startswith("http://127.0.0.1:")
        if self.first_try_wrong_state:
            self._get(f"{query['redirect_uri']}?code=stolen&state=not-the-state")
        self._get(f"{query['redirect_uri']}?{self.answer}&state={query['state']}")


def never(url: str) -> None:
    raise AssertionError("the browser must not be opened")


# --- signing in -----------------------------------------------------------------------------------


@pytest.mark.anyio
async def test_a_server_that_wants_a_sign_in_says_so_without_one():
    async with protected() as (transport, _service, _server):
        with pytest.raises(SignInNeeded, match="401"):
            await collect_http(URL, transport=transport)


@pytest.mark.anyio
async def test_sign_in_collects_the_server_and_saves_the_sign_in(tmp_path):
    browser, said = Browser(), []
    store = SignInStore(tmp_path / "deep" / "sign-ins.json")
    async with protected() as (transport, service, server):
        snap = await collect_http(
            URL, transport=transport, sign_in=SignIn(store, open_browser=browser, announce=said.append)
        )
        assert snap.tools == (await collect_in_process(server)).tools and snap.errors == []
    assert len(browser.opened) == 1 and browser.opened[0].startswith(f"{BASE}/authorize?")
    assert "code_challenge_method=S256" in browser.opened[0]
    assert browser.pages == [(200, browser.pages[0][1])] and "Sign-in finished" in browser.pages[0][1]
    saved = store.get(server_key(URL))
    assert saved["tokens"]["access_token"] == "access-secret-1" and saved["client"]["client_id"] == "client-1"
    # The person is told where they are being sent, and is never shown a token.
    told = "\n".join(said)
    assert "opening your browser at 127.0.0.1" in told and "signed in to 127.0.0.1" in told
    assert "access-secret" not in told and "refresh-secret" not in told
    assert service.grants == ["authorization_code"]


@pytest.mark.anyio
async def test_a_saved_sign_in_is_reused_without_a_browser(tmp_path):
    store = SignInStore(tmp_path / "sign-ins.json")
    async with protected() as (transport, service, _server):
        await collect_http(URL, transport=transport, sign_in=SignIn(store, open_browser=Browser()))
        again = await collect_http(URL, transport=transport, sign_in=SignIn(store, open_browser=never))
        assert len(again.tools) == 3 and service.registrations == 1 and service.issued == 1


@pytest.mark.anyio
async def test_an_expired_saved_token_is_renewed_without_a_browser(tmp_path):
    store = SignInStore(tmp_path / "sign-ins.json")
    key = server_key(URL)
    async with protected() as (transport, service, _server):
        await collect_http(URL, transport=transport, sign_in=SignIn(store, open_browser=Browser()))
        store.put(key, {**store.get(key), "expires_at": time.time() - 60})
        service.valid.clear()  # the service no longer accepts the old token either
        again = await collect_http(URL, transport=transport, sign_in=SignIn(store, open_browser=never))
        assert len(again.tools) == 3 and service.grants == ["authorization_code", "refresh_token"]
    assert store.get(key)["tokens"]["access_token"] == "access-secret-2"


@pytest.mark.anyio
async def test_memory_only_store_writes_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr("scanner.collect.signin.default_store_path", lambda: tmp_path / "never.json")
    async with protected() as (transport, _service, _server):
        await collect_http(URL, transport=transport, sign_in=SignIn(open_browser=Browser()))
    assert list(tmp_path.iterdir()) == []


@pytest.mark.anyio
async def test_a_request_with_the_wrong_state_is_ignored(tmp_path):
    browser = Browser(first_try_wrong_state=True)
    async with protected() as (transport, _service, _server):
        snap = await collect_http(URL, transport=transport, sign_in=SignIn(open_browser=browser))
    assert len(snap.tools) == 3
    assert [status for status, _page in browser.pages] == [404, 200]


# --- when it goes wrong -----------------------------------------------------------------------------


@pytest.mark.anyio
async def test_saying_no_in_the_browser_is_reported_and_nothing_is_saved(tmp_path):
    store = SignInStore(tmp_path / "sign-ins.json")
    browser = Browser(answer="error=access_denied&error_description=%3Cb%3Eno%1b%5B31m")
    async with protected() as (transport, _service, _server):
        with pytest.raises(SignInError, match="the sign-in page reported") as caught:
            await collect_http(URL, transport=transport, sign_in=SignIn(store, open_browser=browser))
    assert "\x1b" not in str(caught.value)
    assert "tokens" not in store.get(server_key(URL))
    # The page shown in the browser is fixed text: nothing from the request is echoed into it.
    assert "<b>" not in browser.pages[0][1] and "not completed" in browser.pages[0][1]


@pytest.mark.anyio
async def test_nobody_signing_in_times_out_with_a_clear_message():
    async with protected() as (transport, _service, _server):
        with pytest.raises(SignInError, match="nobody finished signing in"):
            await collect_http(
                URL, transport=transport, sign_in=SignIn(open_browser=Browser(comes_back=False), wait_s=0.3)
            )


@pytest.mark.anyio
async def test_waiting_for_a_person_does_not_use_up_the_collection_time_limit():
    class Slow(Browser):
        def _return(self, url):
            time.sleep(1.0)
            super()._return(url)

    async with protected() as (transport, _service, _server):
        snap = await collect_http(URL, transport=transport, timeout_s=0.5, sign_in=SignIn(open_browser=Slow()))
    assert len(snap.tools) == 3


@pytest.mark.anyio
async def test_a_sign_in_address_that_is_not_https_is_never_opened():
    browser = Browser()
    async with protected(authorize="http://sign-in.example/authorize") as (transport, _service, _server):
        with pytest.raises(SignInError, match="not https"):
            await collect_http(URL, transport=transport, sign_in=SignIn(open_browser=browser))
    assert browser.opened == []


@pytest.mark.anyio
async def test_a_token_address_that_is_not_https_is_never_contacted():
    async with protected(token="http://tokens.example/token") as (transport, _service, _server):
        with pytest.raises(HttpTargetError, match="not https"):
            await collect_http(URL, transport=transport, sign_in=SignIn(open_browser=Browser()))


@pytest.mark.anyio
async def test_a_server_that_does_not_register_new_apps_is_explained():
    async with protected(registration=False) as (transport, _service, _server):
        with pytest.raises(SignInError, match="does not let a new app register"):
            await collect_http(URL, transport=transport, sign_in=SignIn(open_browser=never))


@pytest.mark.anyio
async def test_sign_in_is_refused_with_a_token_or_over_plain_http():
    with pytest.raises(HttpTargetError, match="not both"):
        await collect_http("https://a.example/mcp", headers={"authorization": "Bearer t"}, sign_in=SignIn())
    with pytest.raises(HttpTargetError, match="plain http"):
        await collect_http("http://a.example/mcp", sign_in=SignIn())


@pytest.mark.parametrize(
    "address",
    [
        "http://sign-in.example/a",
        "file:///C:/Windows/system32/calc.exe",
        "javascript:alert(1)",
        "https://u:p@x.example/",
    ],
)
def test_addresses_a_browser_is_not_sent_to(address):
    with pytest.raises(SignInError):
        check_sign_in_address(address)


def test_addresses_a_browser_may_be_sent_to():
    assert check_sign_in_address("https://sign-in.example/authorize?x=1") == "sign-in.example"
    assert check_sign_in_address("http://localhost:9000/authorize") == "localhost"


# --- the saved file -----------------------------------------------------------------------------------


def test_store_survives_a_damaged_file_and_forgets_on_request(tmp_path):
    path = tmp_path / "sign-ins.json"
    path.write_text("{not json", encoding="utf-8")
    store = SignInStore(path)
    assert store.keys() == []
    store.put("https://a.example/mcp", {"tokens": {"access_token": "t"}})
    store.put("https://b.example/mcp", {"tokens": {"access_token": "u"}})
    assert store.forget("https://a.example/mcp") == ["https://a.example/mcp"]
    assert store.forget("https://nope.example/") == []
    assert store.forget() == ["https://b.example/mcp"] and store.keys() == []


def test_server_key_ignores_case_query_and_fragment():
    assert server_key("HTTPS://MCP.Example.com/mcp?x=1#y") == "https://mcp.example.com/mcp"
    assert server_key("https://mcp.example.com:8443") == "https://mcp.example.com:8443/"


# --- command line -------------------------------------------------------------------------------------


@pytest.fixture
def cli_service(monkeypatch, tmp_path):
    """Route the command line's HTTP collection to the in-memory service, with a stand-in browser."""
    browser = Browser()
    monkeypatch.setattr("scanner.collect.signin.webbrowser.open", browser)
    monkeypatch.setattr(cli, "default_store_path", lambda: tmp_path / "sign-ins.json")

    async def routed(url, **kwargs):
        failure = None
        async with protected() as (transport, _service, _server):
            try:
                return await collect_http(URL, transport=transport, **kwargs)
            except (CollectError, HttpTargetError) as exc:
                failure = exc  # raised outside, so the app's task group does not wrap it
        raise failure

    monkeypatch.setattr(cli, "collect_http", routed)
    return browser, tmp_path / "sign-ins.json"


def test_cli_explains_how_to_sign_in(cli_service):
    result = runner.invoke(cli.app, ["scan", "--url", URL])
    assert result.exit_code == 2
    assert "--sign-in" in result.stderr and "--bearer-env" in result.stderr


def test_cli_sign_in_scans_saves_and_signs_out(cli_service):
    browser, saved = cli_service
    result = runner.invoke(cli.app, ["scan", "--url", URL, "--sign-in", "--name", "notes"])
    assert result.exit_code == 0, result.output
    assert "notes: 3 tools" in result.stdout and len(browser.opened) == 1
    assert "sign-in needed for 127.0.0.1" in result.stderr and str(saved) in result.stderr
    assert "access-secret" not in result.output and "refresh-secret" not in result.output
    assert "access-secret-1" in saved.read_text(encoding="utf-8")

    out = runner.invoke(cli.app, ["sign-out", URL])
    assert out.exit_code == 0 and f"signed out of {URL}" in out.stdout
    assert "access-secret" not in saved.read_text(encoding="utf-8")
    assert "no saved sign-ins" in runner.invoke(cli.app, ["sign-out"]).stdout


def test_cli_no_save_keeps_the_sign_in_out_of_the_file(cli_service):
    _browser, saved = cli_service
    result = runner.invoke(cli.app, ["collect", "--url", URL, "--sign-in", "--no-save-sign-in"])
    assert result.exit_code == 0, result.output
    assert not saved.exists()


@pytest.mark.parametrize(
    "args",
    [
        ["scan", "--sign-in", "--unsafe-local", "--", "python", "x.py"],
        ["scan", "--sign-in", "--url", "https://a.example/mcp", "--bearer-env", "T"],
        ["scan", "--sign-in", "-s", "fixtures/snapshots/clean.json"],
    ],
)
def test_cli_sign_in_only_goes_with_a_url_or_discovery(args):
    assert runner.invoke(cli.app, args).exit_code == 2


def test_cli_discovered_remote_server_can_sign_in(cli_service, tmp_path):
    config = tmp_path / ".mcp.json"
    config.write_text(json.dumps({"mcpServers": {"notes": {"type": "http", "url": URL}}}), encoding="utf-8")
    without = runner.invoke(cli.app, ["scan", "--config", str(config)])
    assert without.exit_code == 2 and "--sign-in" in without.stderr
    result = runner.invoke(cli.app, ["scan", "--config", str(config), "--sign-in"])
    assert result.exit_code == 0, result.output
    assert "notes: 3 tools" in result.stdout


def test_no_test_can_open_a_real_browser():
    import webbrowser

    with pytest.raises(AssertionError):
        webbrowser.open("https://example.com")
