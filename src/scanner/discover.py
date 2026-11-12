"""Find the MCP servers a user's Claude apps are configured to use.

Claude Desktop and Claude Code keep their server lists in JSON settings files at
known places. This module finds those files, reads the server entries and turns
each into a ``DiscoveredServer`` the CLI can scan. It only reads files: nothing is
launched and nothing is contacted here.

Where the files are (checked against the apps' documentation, November 2026):

- Claude Desktop: ``claude_desktop_config.json`` in ``%APPDATA%\\Claude`` (Windows),
  ``~/Library/Application Support/Claude`` (macOS) or ``~/.config/Claude`` (Linux).
  A Windows Store install keeps its data elsewhere: ``%LOCALAPPDATA%\\Claude-Data\\<id>``
  was seen on a real install; the package folder is also checked. Neither is documented.
- Claude Desktop extensions (installed from its Extensions page): each has a folder
  under ``Claude Extensions`` in the same data folder, with a ``manifest.json`` whose
  ``server.mcp_config`` says how to start it, and the user's settings for it in
  ``Claude Extensions Settings``.
- Claude Code: ``~/.claude.json`` holds user-scope servers at the top level and
  local-scope servers under ``projects[<project path>]``; a project can also carry
  a shared ``.mcp.json`` in its root.

Not found here, because no local file lists them: connectors switched on at
claude.ai, servers bundled with plugins, and an organisation's managed servers.

A settings file is input like any other. A ``.mcp.json`` comes with whatever project
was cloned, so its entries are treated as untrusted: values are escaped before
printing, a helper command named in an entry is never run, and the variables that
hold this machine's own Claude and package-registry credentials are never expanded
into a server's command line, address or headers.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from scanner.textutil import redact, visible

DESKTOP = "Claude Desktop"
CODE = "Claude Code"
GIVEN = "given file"

Transport = Literal["stdio", "http", "unsupported"]

MAX_CONFIG_BYTES = 20_000_000
PLACEHOLDER = "placeholder-not-a-real-value"

# Never expanded into a server entry: a project file could otherwise ask for them and
# have them sent to a server of its choosing. Claude Code blanks the first three itself.
BLOCKED_VARIABLES = frozenset(
    {
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "NPM_TOKEN",
        "CLAUDE_CODE_OAUTH_TOKEN",
        "MCP_SCANNER_LLM_API_KEY",
    }
)

_VARIABLE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]{0,100})(?::-([^}]{0,2000}))?\}")
_HTTP_TYPES = {"http", "streamable-http", "streamable_http", "streamablehttp"}
_SCOPE_RANK = {"local": 0, "project": 1, "user": 2}


class DiscoverError(RuntimeError):
    """A settings file named by the user could not be read."""


@dataclass(frozen=True)
class ConfigFile:
    client: str
    path: Path


@dataclass(frozen=True)
class DiscoveredServer:
    name: str
    client: str
    scope: str
    """``user``, ``local`` or ``project`` for Claude Code; ``app`` for Claude Desktop; ``file`` otherwise."""
    config_path: Path
    transport: Transport
    command: tuple[str, ...] = ()
    env: Mapping[str, str] = field(default_factory=dict)
    url: str | None = None
    headers: Mapping[str, str] = field(default_factory=dict)
    problem: str | None = None
    """Why this entry cannot be scanned as written, if it cannot."""
    remarks: tuple[str, ...] = ()
    """Things the user should know about the entry (an unset variable, a helper that was not run)."""
    sandbox_command: tuple[str, ...] = ()
    """The command to use inside the sandbox, when it differs (paths under ``mount`` become ``/work/...``)."""
    mount: Path | None = None
    """A folder the server's own files live in, to show the sandbox read-only."""

    @property
    def origin(self) -> str:
        if self.scope == "extension":
            return f"{self.client}, extension"
        return f"{self.client}, {self.config_path.name}" + ("" if self.scope in ("app", "file") else f", {self.scope}")

    def missing_program(self) -> str | None:
        """The program a local server needs, if this computer does not have it."""
        if self.transport != "stdio" or not self.command:
            return None
        program = self.command[0]
        return None if shutil.which(program) or Path(program).is_file() else program

    def placeholder_env(self) -> dict[str, str]:
        """The same variable names with stand-in values, for running the server in the sandbox."""
        return dict.fromkeys(self.env, PLACEHOLDER)

    def describe(self) -> str:
        """One printable line saying how the server is reached. Never includes a secret value."""
        if self.transport == "stdio":
            shown = " ".join(visible(redact(_mask_url_secrets(part))) for part in self.command)
            names = ", ".join(visible(name) for name in sorted(self.env))
            return f"runs: {shown}" + (f"  (sets: {names})" if names else "")
        if self.transport == "http":
            names = ", ".join(visible(name) for name in sorted(self.headers))
            return f"connects to: {visible(_bare_url(self.url or ''))}" + (
                f"  (sends headers: {names})" if names else ""
            )
        return "not scannable"


@dataclass
class Discovery:
    checked: list[tuple[ConfigFile, str]] = field(default_factory=list)
    """Every file looked for, with what happened: ``found``, ``not there``, or an error."""
    servers: list[DiscoveredServer] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    """Printable remarks: a duplicate that was dropped, a file that could not be parsed."""


# --- where the files are --------------------------------------------------------------------------


def desktop_data_folders(
    platform: str | None = None, env: Mapping[str, str] | None = None, home: Path | None = None
) -> list[Path]:
    """Folders Claude Desktop may keep its settings and extensions in, whether or not they exist."""
    platform = platform or sys.platform
    env = os.environ if env is None else env
    home = home or Path.home()
    if platform == "darwin":
        return [home / "Library" / "Application Support" / "Claude"]
    if platform != "win32":
        base = Path(env["XDG_CONFIG_HOME"]) if env.get("XDG_CONFIG_HOME") else home / ".config"
        return [base / "Claude"]
    appdata = Path(env["APPDATA"]) if env.get("APPDATA") else home / "AppData" / "Roaming"
    local = Path(env["LOCALAPPDATA"]) if env.get("LOCALAPPDATA") else home / "AppData" / "Local"
    folders = [appdata / "Claude"]
    # Store installs do not use %APPDATA%. Seen on a real install: Claude-Data\<package id>.
    if (local / "Claude-Data").is_dir():
        folders += sorted(p for p in (local / "Claude-Data").iterdir() if p.is_dir())
    if (local / "Packages").is_dir():
        folders += [p / "LocalCache" / "Roaming" / "Claude" for p in sorted((local / "Packages").glob("Claude_*"))]
    return folders


def standard_locations(
    platform: str | None = None,
    env: Mapping[str, str] | None = None,
    home: Path | None = None,
    cwd: Path | None = None,
) -> list[ConfigFile]:
    """Every settings file worth checking on this machine, whether or not it exists."""
    env = os.environ if env is None else env
    home = home or Path.home()
    cwd = cwd or Path.cwd()
    files = [
        ConfigFile(DESKTOP, folder / "claude_desktop_config.json")
        for folder in desktop_data_folders(platform, env, home)
    ]
    files.append(ConfigFile(CODE, home / ".claude.json"))
    if env.get("CLAUDE_CONFIG_DIR"):
        files.append(ConfigFile(CODE, Path(env["CLAUDE_CONFIG_DIR"]) / ".claude.json"))
    files.append(ConfigFile(CODE, cwd / ".mcp.json"))

    unique: dict[str, ConfigFile] = {}
    for file in files:
        unique.setdefault(os.path.normcase(str(file.path)), file)
    return list(unique.values())


# --- reading one file -----------------------------------------------------------------------------


def _mask_url_secrets(text: str) -> str:
    """Hide a password inside a URL-shaped argument (``postgres://user:secret@host``)."""
    return re.sub(r"(://[^/\s:@]{0,200}):[^/\s@]{1,500}@", r"\1:[redacted]@", text)


def _bare_url(url: str) -> str:
    """The address without its query string, which can carry a token."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return "(not a valid address)"
    if not parts.scheme or not parts.hostname:
        return "(not a valid address)"
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme}://{parts.hostname}{port}{parts.path}" + ("?[query hidden]" if parts.query else "")


class _Expander:
    """Expands ``${VAR}`` and ``${VAR:-default}`` the way Claude Code does, and records what it could not."""

    def __init__(self, env: Mapping[str, str], enabled: bool) -> None:
        self.env = env
        self.enabled = enabled
        self.unset: set[str] = set()
        self.blocked: set[str] = set()

    def __call__(self, text: str) -> str:
        if not self.enabled:
            return text

        def replace(match: re.Match[str]) -> str:
            name, default = match.group(1), match.group(2)
            if name in BLOCKED_VARIABLES:
                self.blocked.add(name)
                return ""
            if name in self.env:  # set, even to an empty string, counts as set
                return self.env[name]
            if default is not None:
                return default
            self.unset.add(name)
            return match.group(0)

        return _VARIABLE.sub(replace, text)


def _strings(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(k): str(v) for k, v in value.items() if isinstance(v, str | int | float) and not isinstance(v, bool)}


def _entry(
    name: str, spec: Any, file: ConfigFile, scope: str, env: Mapping[str, str], expand: bool
) -> DiscoveredServer:
    def unusable(problem: str) -> DiscoveredServer:
        return DiscoveredServer(name, file.client, scope, file.path, "unsupported", problem=problem)

    if not isinstance(spec, dict):
        return unusable("the entry is not an object")
    expander = _Expander(env, expand)
    kind = str(spec.get("type") or "").lower()
    remarks: list[str] = []
    if spec.get("headersHelper"):
        remarks.append("the entry names a helper command for its headers; the scanner does not run it")

    server: DiscoveredServer
    if kind in ("", "stdio") and isinstance(spec.get("command"), str) and spec["command"].strip():
        args = [expander(str(a)) for a in spec.get("args") or [] if isinstance(a, str | int | float)]
        values = {key: expander(value) for key, value in _strings(spec.get("env")).items()}
        server = DiscoveredServer(
            name, file.client, scope, file.path, "stdio", command=(expander(spec["command"]), *args), env=values
        )
    elif (kind in _HTTP_TYPES or kind == "") and isinstance(spec.get("url"), str):
        headers = {key: expander(value) for key, value in _strings(spec.get("headers")).items()}
        server = DiscoveredServer(
            name, file.client, scope, file.path, "http", url=expander(spec["url"]), headers=headers
        )
    elif kind == "sse":
        return unusable("it uses the older SSE transport, which the scanner does not support")
    elif kind:
        return unusable(f"transport type {visible(kind)[:40]!r} is not supported")
    else:
        return unusable("the entry has neither a command nor an address")

    if expander.blocked:
        names = ", ".join(sorted(expander.blocked))
        remarks.append(f"the entry asks for {names}; the scanner never passes that on, so it was left empty")
    if expander.unset:
        remarks.append(f"environment variable not set: {', '.join(sorted(expander.unset))}")
    return replace(server, remarks=tuple(remarks))


def _same_folder(a: str, b: Path) -> bool:
    try:
        left, right = Path(a).resolve(), b.resolve()
    except (OSError, ValueError):
        return False
    return os.path.normcase(str(left)) == os.path.normcase(str(right))


def read_config(
    file: ConfigFile, *, cwd: Path | None = None, env: Mapping[str, str] | None = None
) -> list[DiscoveredServer]:
    """The server entries in one settings file. Raises ``DiscoverError`` when it cannot be read."""
    env = os.environ if env is None else env
    cwd = cwd or Path.cwd()
    try:
        if file.path.stat().st_size > MAX_CONFIG_BYTES:
            raise DiscoverError("the file is too large to be a settings file")
        data = json.loads(file.path.read_text(encoding="utf-8-sig"))
    except OSError as exc:
        raise DiscoverError(f"cannot read it: {exc.strerror or type(exc).__name__}") from exc
    except (ValueError, RecursionError) as exc:
        raise DiscoverError("it is not valid JSON") from exc
    if not isinstance(data, dict):
        raise DiscoverError("it does not contain a settings object")

    # Claude Code expands ${VAR}; Claude Desktop is not documented to, so its entries are taken as written.
    expand = file.client != DESKTOP
    is_code_home = file.client == CODE and file.path.name == ".claude.json"
    top_scope = "app" if file.client == DESKTOP else "file" if file.client == GIVEN else "project"
    if is_code_home:
        top_scope = "user"

    groups: list[tuple[str, Any]] = [(top_scope, data.get("mcpServers"))]
    projects = data.get("projects")
    if isinstance(projects, dict) and file.client != DESKTOP:
        for folder, project in projects.items():
            if isinstance(project, dict) and _same_folder(str(folder), cwd):
                groups.append(("local", project.get("mcpServers")))

    servers: list[DiscoveredServer] = []
    for scope, entries in groups:
        if isinstance(entries, dict):
            servers += [_entry(str(name), spec, file, scope, env, expand) for name, spec in entries.items()]
    return servers


# --- Claude Desktop extensions --------------------------------------------------------------------

_EXTENSION_VARIABLE = re.compile(r"\$\{([A-Za-z_/][A-Za-z0-9_.]{0,100}|/)\}")
SANDBOX_ROOT = "/work"
"""Where the scanner's sandbox shows a mounted folder (``collect/docker.py``)."""


def _load_json(path: Path) -> Any:
    if path.stat().st_size > MAX_CONFIG_BYTES:
        raise ValueError("too large")
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _extension_server(folder: Path, manifest: dict[str, Any], settings: dict[str, Any], home: Path, platform: str):
    name = str(manifest.get("name") or folder.name)
    manifest_path = folder / "manifest.json"

    def unusable(problem: str) -> DiscoveredServer:
        return DiscoveredServer(name, DESKTOP, "extension", manifest_path, "unsupported", problem=problem)

    spec = manifest.get("server")
    config = spec.get("mcp_config") if isinstance(spec, dict) else None
    if not isinstance(config, dict):
        return unusable("the extension does not say how to start its server")
    override = (config.get("platform_overrides") or {}).get(platform)
    if isinstance(override, dict):
        config = {**config, **override, "env": {**_strings(config.get("env")), **_strings(override.get("env"))}}
    if not isinstance(config.get("command"), str) or not config["command"].strip():
        return unusable("the extension does not say how to start its server")

    declared = manifest.get("user_config") if isinstance(manifest.get("user_config"), dict) else {}
    saved = settings.get("userConfig") if isinstance(settings.get("userConfig"), dict) else {}

    def setting(key: str, sandbox: bool) -> Any:
        info = declared.get(key) if isinstance(declared.get(key), dict) else {}
        if sandbox and info.get("sensitive"):
            return PLACEHOLDER  # untrusted code in the sandbox never gets a saved secret
        value = saved.get(key, info.get("default"))
        return "" if value is None else value

    def lookup(variable: str, sandbox: bool) -> Any:
        if variable == "__dirname":
            return f"{SANDBOX_ROOT}/{folder.name}" if sandbox else str(folder)
        if variable in ("/", "pathSeparator"):
            return "/" if sandbox else os.sep
        if variable in ("HOME", "DESKTOP", "DOCUMENTS", "DOWNLOADS"):
            if sandbox:
                return "/tmp"  # noqa: S108 - a path inside the container
            return str(home if variable == "HOME" else home / variable.capitalize())
        if variable.startswith("user_config."):
            return setting(variable.removeprefix("user_config."), sandbox)
        return None

    def expand(text: str, sandbox: bool) -> list[str]:
        whole = _EXTENSION_VARIABLE.fullmatch(text)
        if whole:  # a setting that holds a list becomes several arguments
            value = lookup(whole.group(1), sandbox)
            if isinstance(value, list):
                return [str(item) for item in value]

        def replace_one(match: re.Match[str]) -> str:
            value = lookup(match.group(1), sandbox)
            if value is None:
                return match.group(0)
            return ",".join(map(str, value)) if isinstance(value, list) else str(value)

        return [_EXTENSION_VARIABLE.sub(replace_one, text)]

    def command(sandbox: bool) -> tuple[str, ...]:
        parts = expand(config["command"], sandbox)
        for arg in config.get("args") or []:
            if isinstance(arg, str | int | float):
                parts += expand(str(arg), sandbox)
        return tuple(parts)

    env = {key: expand(value, False)[0] for key, value in _strings(config.get("env")).items()}
    return DiscoveredServer(
        name,
        DESKTOP,
        "extension",
        manifest_path,
        "stdio",
        command=command(False),
        env=env,
        sandbox_command=command(True),
        mount=folder,
    )


def read_extensions(
    data_folder: Path, *, home: Path | None = None, platform: str | None = None
) -> tuple[list[DiscoveredServer], list[str]]:
    """Servers of the extensions installed in Claude Desktop, plus printable notes about ones left out."""
    home = home or Path.home()
    platform = platform or sys.platform
    servers: list[DiscoveredServer] = []
    notes: list[str] = []
    try:
        folders = sorted(p for p in (data_folder / "Claude Extensions").iterdir() if p.is_dir())
    except OSError:
        return [], []
    for folder in folders:
        try:
            manifest = _load_json(folder / "manifest.json")
            if not isinstance(manifest, dict):
                raise ValueError("not an object")
        except (OSError, ValueError, RecursionError):
            notes.append(f"extension {visible(folder.name)}: its manifest could not be read")
            continue
        try:
            settings = _load_json(data_folder / "Claude Extensions Settings" / f"{folder.name}.json")
        except (OSError, ValueError, RecursionError):
            settings = {}
        settings = settings if isinstance(settings, dict) else {}
        if settings.get("isEnabled") is False:
            notes.append(f"extension {visible(str(manifest.get('name') or folder.name))} is switched off; skipped")
            continue
        servers.append(_extension_server(folder, manifest, settings, home, platform))
    return servers, notes


# --- putting it together --------------------------------------------------------------------------


def _same_target(a: DiscoveredServer, b: DiscoveredServer) -> bool:
    return (a.transport, a.command, a.url) == (b.transport, b.command, b.url)


def discover(
    configs: list[Path] | None = None,
    *,
    platform: str | None = None,
    env: Mapping[str, str] | None = None,
    home: Path | None = None,
    cwd: Path | None = None,
) -> Discovery:
    """Read the given settings files, or the standard ones when none are given.

    A file the user named must be readable (``DiscoverError`` otherwise); a standard
    location that is missing or broken is only noted.
    """
    cwd = cwd or Path.cwd()
    found = Discovery()
    explicit = bool(configs)
    files = (
        [ConfigFile(GIVEN, path) for path in configs or []]
        if explicit
        else standard_locations(platform, env, home, cwd)
    )

    candidates: list[DiscoveredServer] = []
    for file in files:
        if not file.path.is_file():
            if explicit:
                raise DiscoverError(f"{file.path}: no such file")
            found.checked.append((file, "not there"))
            continue
        try:
            servers = read_config(file, cwd=cwd, env=env)
        except DiscoverError as exc:
            if explicit:
                raise DiscoverError(f"{file.path}: {exc}") from exc
            found.checked.append((file, f"could not be read ({exc})"))
            continue
        found.checked.append((file, f"found, {len(servers)} server{'s' if len(servers) != 1 else ''}"))
        candidates += servers

    if not explicit:
        for folder in desktop_data_folders(platform, env, home):
            extensions = folder / "Claude Extensions"
            if extensions.is_dir():
                servers, notes = read_extensions(folder, home=home, platform=platform)
                count = f"{len(servers)} extension{'s' if len(servers) != 1 else ''}"
                found.checked.append((ConfigFile(DESKTOP, extensions), f"found, {count}"))
                candidates += servers
                found.notes += notes

    # Claude Code uses one definition per name: local beats project beats user.
    # Its entries are settled first, so they keep their plain names.
    code = sorted((s for s in candidates if s.client == CODE), key=lambda s: _SCOPE_RANK.get(s.scope, 0))
    others = [s for s in candidates if s.client != CODE]

    def also_defined(server: DiscoveredServer, kept: DiscoveredServer) -> None:
        found.notes.append(
            f"{visible(server.name)} is also defined in {visible(server.origin)}; "
            f"using the one from {visible(kept.origin)}"
        )

    for server in code:
        kept = next((k for k in found.servers if k.name == server.name), None)
        if kept is None:
            found.servers.append(server)
        else:
            also_defined(server, kept)

    # Another app, or another given file, can use the same name for a different server: both are kept.
    for server in others:
        kept = next((k for k in found.servers if k.name == server.name), None)
        if kept is None:
            found.servers.append(server)
        elif _same_target(kept, server):
            also_defined(server, kept)
        else:
            label = server.client if server.client != GIVEN else server.config_path.name
            taken = {k.name for k in found.servers}
            renamed, n = f"{server.name} ({label})", 2
            while renamed in taken:
                renamed, n = f"{server.name} ({label} {n})", n + 1
            found.servers.append(replace(server, name=renamed))
    return found
