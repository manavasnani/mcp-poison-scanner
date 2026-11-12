"""Command-line entry point.

- ``collect`` saves what one server exposes as a snapshot file.
- ``scan`` checks one or more servers and reports findings as text, JSON or SARIF.
  It exits 1 when a finding is at or above ``--fail-on``, and 2 when the scan itself
  could not run.
- ``pin`` records servers in a lockfile as approved; ``scan --lock`` then reports
  what changed since.

- ``discover`` lists the servers found in Claude Desktop's and Claude Code's settings
  files; ``scan --discover`` and ``pin --discover`` then work on all of them.

A server can come from a snapshot file (``-s``), a remote URL (``--url``), a
command after ``--``, which runs in the Docker sandbox (``--sandbox-image``) or,
only with ``--unsafe-local``, directly on this machine, or from discovery.

A remote server that wants a browser sign-in gets one with ``--sign-in``; ``sign-out``
deletes the sign-ins that were saved.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import anyio
import typer

from scanner.collect import (
    CollectError,
    HttpTargetError,
    SandboxError,
    SignIn,
    SignInNeeded,
    SignInStore,
    SnapshotError,
    UnsafeLaunchRefused,
    collect_docker,
    collect_http,
    collect_stdio,
    default_store_path,
    load_snapshot,
    parse_header,
    save_snapshot,
    server_key,
)
from scanner.discover import DiscoveredServer, DiscoverError
from scanner.discover import discover as find_servers
from scanner.engine import scan as run_scan
from scanner.engine import sort_findings
from scanner.judge import DEFAULT_MODEL, AnthropicBackend, JudgeResult, JudgeUnavailable
from scanner.judge import judge as run_judge
from scanner.models import ServerSnapshot, Severity
from scanner.pin import DEFAULT_LOCKFILE, LockError, LockFile, check_pins, load_lock, save_lock
from scanner.pin import pin as pin_servers
from scanner.report import ScanReport, render_json, render_sarif, render_text
from scanner.rules import POISONING_RULES
from scanner.textutil import visible

app = typer.Typer(no_args_is_help=True, add_completion=False, help="Local scanner for poisoned MCP server metadata.")


class Format(StrEnum):
    TEXT = "text"
    JSON = "json"
    SARIF = "sarif"


class FailOn(StrEnum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


_RENDERERS = {Format.TEXT: render_text, Format.JSON: render_json, Format.SARIF: render_sarif}

CommandArg = Annotated[
    list[str] | None,
    typer.Argument(help="Server launch command, after '--'. Needs --sandbox-image or --unsafe-local."),
]
SnapshotsOpt = Annotated[
    list[Path] | None,
    typer.Option("--snapshot", "-s", help="Saved snapshot JSON. Repeat to treat several servers as one config."),
]
UrlOpt = Annotated[str | None, typer.Option("--url", help="Streamable HTTP endpoint of a remote server.")]
HeaderOpt = Annotated[
    list[str] | None,
    typer.Option("--header", help="Extra header for --url, as 'Name: value'. Repeatable."),
]
BearerOpt = Annotated[
    str | None,
    typer.Option("--bearer-env", help="Name of an environment variable holding a bearer token for --url."),
]
SignInOpt = Annotated[
    bool,
    typer.Option(
        "--sign-in",
        help="If a remote server asks for it, sign in through your browser (OAuth). Applies to --url and --discover.",
    ),
]
SaveSignInOpt = Annotated[
    bool,
    typer.Option(
        "--save-sign-in/--no-save-sign-in",
        help="Remember a browser sign-in for later runs (in a file in your user folder), or forget it afterwards.",
    ),
]
ImageOpt = Annotated[
    str | None,
    typer.Option("--sandbox-image", help="Run the server command inside this local Docker image, with no network."),
]
MountOpt = Annotated[
    list[Path] | None,
    typer.Option("--mount", help="Folder to show the sandbox, read-only, at /work/<folder name>. Repeatable."),
]
NameOpt = Annotated[
    str | None,
    typer.Option("--name", "-n", help="Server name to use for the live server, or for a single snapshot."),
]
UnsafeOpt = Annotated[
    bool,
    typer.Option("--unsafe-local", help="Launch the server directly on this machine. Runs untrusted code."),
]
TimeoutOpt = Annotated[float, typer.Option(help="Seconds to wait for a live server.")]
DiscoverOpt = Annotated[
    bool,
    typer.Option(
        "--discover",
        help="Use every server found in Claude Desktop's and Claude Code's settings files. Local servers "
        "also need --unsafe-local or --sandbox-image.",
    ),
]
ConfigOpt = Annotated[
    list[Path] | None,
    typer.Option("--config", help="Read servers from this settings file instead of the standard places. Repeatable."),
]
StderrOpt = Annotated[
    bool, typer.Option("--server-stderr", help="Show the server's own stderr output (untrusted text).")
]


@app.callback()
def main() -> None:
    """Local scanner for poisoned MCP server metadata."""


def _fail(message: str, cause: BaseException | None = None) -> typer.Exit:
    typer.echo(f"error: {message}", err=True)
    exit_ = typer.Exit(2)
    exit_.__cause__ = cause
    return exit_


# --- gathering servers --------------------------------------------------------------------------


@dataclass(frozen=True)
class Live:
    """How to reach a live server: a command (sandboxed or not) or a URL."""

    command: list[str]
    url: str | None
    headers: list[str]
    bearer_env: str | None
    name: str | None
    unsafe_local: bool
    image: str | None
    mounts: list[Path]
    timeout: float
    show_stderr: bool
    sign_in: bool = False
    save_sign_in: bool = True

    def browser_sign_in(self) -> SignIn | None:
        if not self.sign_in:
            return None
        store = SignInStore(default_store_path() if self.save_sign_in else None)
        return SignIn(store, announce=lambda line: typer.echo(line, err=True))

    def check(self) -> None:
        if self.sign_in and (self.command or self.bearer_env):
            raise typer.BadParameter("--sign-in applies to --url or --discover, and not together with --bearer-env")
        if self.command and self.url:
            raise typer.BadParameter("give a server command or --url, not both")
        if self.image and self.unsafe_local:
            raise typer.BadParameter("give --sandbox-image or --unsafe-local, not both")
        if self.mounts and not self.image:
            raise typer.BadParameter("--mount only applies with --sandbox-image")
        if (self.headers or self.bearer_env) and not self.url:
            raise typer.BadParameter("--header and --bearer-env only apply with --url")
        if self.url and (self.image or self.unsafe_local):
            raise typer.BadParameter("--sandbox-image and --unsafe-local apply to a server command, not to --url")


@dataclass
class Gathered:
    snapshots: list[ServerSnapshot] = field(default_factory=list)
    sources: dict[str, Path] = field(default_factory=dict)
    skipped: list[str] = field(default_factory=list)
    """Discovered servers that were not scanned, each with the reason. Safe to print."""
    notes: list[str] = field(default_factory=list)


class _Unreachable(Exception):
    """A live server could not be collected. The message is safe to print."""


def _load_file(path: Path, name: str | None) -> ServerSnapshot:
    try:
        snapshot = load_snapshot(path, name)
    except SnapshotError as exc:
        raise _fail(str(exc), exc) from exc
    # A full snapshot carries its own name; an explicit --name still wins.
    return snapshot.model_copy(update={"server_name": name}) if name else snapshot


def _http_headers(live: Live) -> dict[str, str]:
    try:
        headers = dict(parse_header(line) for line in live.headers)
    except HttpTargetError as exc:
        raise _fail(str(exc), exc) from exc
    if live.bearer_env:
        token = os.environ.get(live.bearer_env, "").strip()
        if not token:
            raise _fail(f"environment variable {live.bearer_env} is not set")
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _connect(live: Live) -> ServerSnapshot:
    """Collect from the live server described by ``live``."""
    headers = _http_headers(live) if live.url else {}

    async def collect() -> ServerSnapshot:
        if live.url:
            return await collect_http(
                live.url,
                headers=headers,
                server_name=live.name,
                timeout_s=live.timeout,
                sign_in=live.browser_sign_in(),
            )
        if live.image:
            return await collect_docker(
                live.image,
                live.command,
                mounts=live.mounts,
                server_name=live.name,
                timeout_s=live.timeout,
                show_stderr=live.show_stderr,
            )
        return await collect_stdio(
            live.command[0],
            live.command[1:],
            server_name=live.name,
            unsafe_local=live.unsafe_local,
            timeout_s=live.timeout,
            show_stderr=live.show_stderr,
        )

    if live.unsafe_local:
        typer.echo(f"warning: launching untrusted server on the host: {live.command[0]}", err=True)
    try:
        return _collect(collect, timeout=live.timeout, hint=not (live.url or live.show_stderr))
    except _Unreachable as exc:
        raise _fail(str(exc), exc.__cause__) from exc


def _collect(run, *, timeout: float, hint: bool) -> ServerSnapshot:
    """Run one collection and turn every way it can fail into ``_Unreachable``."""
    try:
        return anyio.run(run)
    except UnsafeLaunchRefused as exc:
        raise _Unreachable(
            "refusing to run a server on the host: it would run untrusted code. Use a snapshot, run it "
            "in the sandbox with --sandbox-image IMAGE, or pass --unsafe-local if you trust this server."
        ) from exc
    except (SandboxError, HttpTargetError) as exc:
        raise _Unreachable(str(exc)) from exc
    except SignInNeeded as exc:
        raise _Unreachable(
            f"{exc}. Add --sign-in to sign in through your browser, or pass a token with --bearer-env"
        ) from exc
    except CollectError as exc:
        extra = " (add --server-stderr to see the server's own error output)" if hint else ""
        raise _Unreachable(f"{exc}{extra}") from exc
    except TimeoutError as exc:
        raise _Unreachable(f"server did not respond within {timeout}s") from exc
    except OSError as exc:
        raise _Unreachable(f"could not launch server: {visible(str(exc))}") from exc


def _collect_discovered(server: DiscoveredServer, live: Live) -> ServerSnapshot:
    """Collect from one server found in a settings file."""

    async def collect() -> ServerSnapshot:
        if server.transport == "http":
            has_token = any(name.lower() == "authorization" for name in server.headers)
            return await collect_http(
                server.url or "",
                headers=dict(server.headers),
                server_name=server.name,
                timeout_s=live.timeout,
                sign_in=None if has_token else live.browser_sign_in(),
            )
        command = list(server.command)
        if live.image:
            # The sandbox gets the variable names with stand-in values: untrusted code never sees real keys.
            return await collect_docker(
                live.image,
                list(server.sandbox_command or server.command),
                mounts=[*live.mounts, *([server.mount] if server.mount else [])],
                server_name=server.name,
                timeout_s=live.timeout,
                show_stderr=live.show_stderr,
                env=server.placeholder_env(),
            )
        return await collect_stdio(
            command[0],
            command[1:],
            server_name=server.name,
            env=dict(server.env),
            unsafe_local=live.unsafe_local,
            timeout_s=live.timeout,
            show_stderr=live.show_stderr,
        )

    return _collect(collect, timeout=live.timeout, hint=server.transport == "stdio" and not live.show_stderr)


def _gather_discovered(configs: list[Path], live: Live, gathered: Gathered) -> None:
    try:
        found = find_servers(configs or None)
    except DiscoverError as exc:
        raise _fail(visible(str(exc)), exc) from exc
    if not found.servers:
        looked = "; ".join(f"{file.path} ({status})" for file, status in found.checked)
        raise _fail(f"no MCP servers found in any settings file. Looked in: {visible(looked)}")
    gathered.notes += found.notes

    local = [s for s in found.servers if s.transport == "stdio"]
    if live.unsafe_local and local:
        typer.echo(f"warning: launching {len(local)} local server(s) directly on this machine:", err=True)
        for server in local:
            typer.echo(f"  {visible(server.name)}  {server.describe()}", err=True)

    for server in found.servers:
        label = f"{visible(server.name)} ({visible(server.origin)})"
        if server.problem:
            gathered.skipped.append(f"{label}: {server.problem}")
            continue
        if server.transport == "stdio" and not (live.image or live.unsafe_local):
            gathered.skipped.append(
                f"{label}: it is a local program. Add --unsafe-local to run it the way Claude already does, "
                "or --sandbox-image IMAGE to run it in the sandbox"
            )
            continue
        missing = None if live.image else server.missing_program()
        if missing:
            own = " (Claude Desktop runs extensions with its own built-in copy)" if server.mount else ""
            gathered.skipped.append(
                f"{label}: it needs the program {visible(missing)!r}, which is not installed on this computer{own}. "
                "Install it, or use --sandbox-image with an image that contains it"
            )
            continue
        try:
            snapshot = _collect_discovered(server, live)
        except _Unreachable as exc:
            reason = str(exc)
            if server.remarks:
                reason += "; " + "; ".join(server.remarks)
            gathered.skipped.append(f"{label}: {reason}")
            continue
        typer.echo(f"collected {label}: {len(snapshot.tools)} tools", err=True)
        gathered.snapshots.append(snapshot)


def _gather(paths: list[Path], live: Live, discover: bool = False, configs: list[Path] | None = None) -> Gathered:
    live.check()
    gathered = Gathered()
    is_live = bool(live.command or live.url)
    discover = discover or bool(configs)
    if discover and is_live:
        raise typer.BadParameter("--discover and --config cannot be combined with a server command or --url")
    if live.sign_in and not (live.url or discover):
        raise typer.BadParameter("--sign-in applies to --url or --discover")
    if discover and live.name:
        raise typer.BadParameter("--name does not apply with --discover: servers keep their settings-file names")
    if live.name and not is_live and len(paths) != 1:
        raise typer.BadParameter("--name needs a live server or exactly one --snapshot to apply to")
    for path in paths:
        snapshot = _load_file(path, None if is_live else live.name)
        gathered.snapshots.append(snapshot)
        gathered.sources.setdefault(snapshot.server_name, path)
    if is_live:
        gathered.snapshots.append(_connect(live))
    if discover:
        _gather_discovered(configs or [], live, gathered)
        if not gathered.snapshots:
            for line in gathered.skipped:
                typer.echo(f"not scanned: {line}", err=True)
            raise _fail("none of the servers found could be scanned")
    if not gathered.snapshots:
        raise typer.BadParameter("give a --snapshot FILE, a --url, a server command after '--', or --discover")
    names = [s.server_name for s in gathered.snapshots]
    repeated = sorted({visible(n) for n in names if names.count(n) > 1})
    if repeated:
        raise _fail(f"two servers are both named {', '.join(repeated)}; findings could not be told apart")
    return gathered


# --- commands -----------------------------------------------------------------------------------


@app.command()
def collect(
    command: CommandArg = None,
    snapshot: Annotated[
        Path | None, typer.Option("--snapshot", "-s", help="Read a saved tools/list (or full) snapshot JSON.")
    ] = None,
    url: UrlOpt = None,
    header: HeaderOpt = None,
    bearer_env: BearerOpt = None,
    name: NameOpt = None,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Write snapshot JSON here.")] = None,
    unsafe_local: UnsafeOpt = False,
    sandbox_image: ImageOpt = None,
    mount: MountOpt = None,
    timeout: TimeoutOpt = 30.0,
    server_stderr: StderrOpt = False,
    sign_in: SignInOpt = False,
    save_sign_in: SaveSignInOpt = True,
) -> None:
    """Collect a server's tools, prompts and resources into a snapshot."""
    if sum([snapshot is not None, bool(command), url is not None]) != 1:
        raise typer.BadParameter("give exactly one of --snapshot FILE, --url URL, or a server command after '--'")

    if snapshot is not None:
        snap = _load_file(snapshot, name)
    else:
        live = Live(
            command or [], url, header or [], bearer_env, name, unsafe_local, sandbox_image, mount or [], timeout,
            server_stderr, sign_in, save_sign_in,
        )  # fmt: skip
        live.check()
        snap = _connect(live)

    _emit(snap, output)
    for err in snap.errors:
        typer.echo(f"warning: {visible(err)}", err=True)


@app.command(name="discover")
def discover_command(config: ConfigOpt = None) -> None:
    """List the MCP servers found in Claude Desktop's and Claude Code's settings files.

    Only reads files: no server is started or contacted. Secret values are never shown.
    """
    try:
        found = find_servers(config or None)
    except DiscoverError as exc:
        raise _fail(visible(str(exc)), exc) from exc
    typer.echo("Settings files checked:")
    for file, status in found.checked:
        typer.echo(f"  {file.client:15} {visible(str(file.path))}  -  {status}")
    typer.echo("")
    typer.echo(f"Servers found: {len(found.servers)}")
    for server in found.servers:
        typer.echo(f"  {visible(server.name)}  ({visible(server.origin)})")
        typer.echo(f"      {'cannot be scanned: ' + server.problem if server.problem else server.describe()}")
        for remark in server.remarks:
            typer.echo(f"      note: {visible(remark)}")
    for note in found.notes:
        typer.echo(f"note: {note}")
    typer.echo("")
    typer.echo("Not listed in any local file: connectors switched on at claude.ai, and servers bundled with plugins.")
    typer.echo("A connector can be scanned by its address: scan --url ADDRESS --sign-in")
    if found.servers:
        typer.echo("To scan what was found: scan --discover --unsafe-local   (or --sandbox-image IMAGE)")


@app.command(name="sign-out")
def sign_out(
    url: Annotated[str | None, typer.Argument(help="Server address to sign out of. Leave out for all.")] = None,
) -> None:
    """Delete browser sign-ins the scanner saved on this computer.

    This removes the saved tokens. To also withdraw the permission you gave, use the
    service's own settings page for connected apps.
    """
    path = default_store_path()
    try:
        gone = SignInStore(path).forget(server_key(url) if url else None)
    except OSError as exc:
        raise _fail(f"cannot update {path}: {exc.strerror or exc}", exc) from exc
    for address in gone:
        typer.echo(f"signed out of {visible(address)}")
    if not gone:
        typer.echo("no saved sign-in for that address" if url else "no saved sign-ins")


@app.command()
def scan(
    command: CommandArg = None,
    snapshot: SnapshotsOpt = None,
    url: UrlOpt = None,
    header: HeaderOpt = None,
    bearer_env: BearerOpt = None,
    name: NameOpt = None,
    unsafe_local: UnsafeOpt = False,
    sandbox_image: ImageOpt = None,
    mount: MountOpt = None,
    timeout: TimeoutOpt = 30.0,
    server_stderr: StderrOpt = False,
    sign_in: SignInOpt = False,
    save_sign_in: SaveSignInOpt = True,
    discover: DiscoverOpt = False,
    config: ConfigOpt = None,
    judge: Annotated[
        bool,
        typer.Option("--judge", help="Also classify each item with Claude. Sends the metadata to the Claude API."),
    ] = False,
    judge_model: Annotated[str, typer.Option("--judge-model", help="Claude model for --judge.")] = DEFAULT_MODEL,
    lock: Annotated[
        Path | None,
        typer.Option("--lock", help="Lockfile written by 'pin'. Reports what changed since each server was pinned."),
    ] = None,
    report_format: Annotated[Format, typer.Option("--format", "-f", help="Report format.")] = Format.TEXT,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Write the report here.")] = None,
    fail_on: Annotated[
        FailOn,
        typer.Option("--fail-on", help="Exit 1 when a finding has this severity or higher. 'none' always exits 0."),
    ] = FailOn.HIGH,
) -> None:
    """Scan one or more servers and report findings.

    Servers given together are treated as one client config, so cross-server checks
    (shadowing, duplicate tool names, capability combinations) apply across all of them.
    """
    live = Live(
        command or [], url, header or [], bearer_env, name, unsafe_local, sandbox_image, mount or [], timeout,
        server_stderr, sign_in, save_sign_in,
    )  # fmt: skip
    gathered = _gather(snapshot or [], live, discover, config)
    snapshots = gathered.snapshots

    findings = run_scan(snapshots)
    notes: list[str] = []
    if lock is not None:
        try:
            changed, notes = check_pins(load_lock(lock), snapshots)
        except LockError as exc:
            raise _fail(str(exc), exc) from exc
        findings += changed
    judged = _judge(snapshots, judge_model) if judge else None
    if judged is not None:
        findings += judged.findings
    findings = sort_findings(findings, [s.server_name for s in snapshots])

    notes = [*gathered.notes, *notes, *(f"not scanned: {line}" for line in gathered.skipped)]
    report = ScanReport(snapshots, findings, judged, notes, gathered.sources)
    _deliver(_RENDERERS[report_format](report), output)
    # A server that could not be scanned is unknown, not safe: the gate stays closed.
    if _should_fail(report, fail_on) or (gathered.skipped and fail_on is not FailOn.NONE):
        raise typer.Exit(1)


@app.command()
def pin(
    command: CommandArg = None,
    snapshot: SnapshotsOpt = None,
    url: UrlOpt = None,
    header: HeaderOpt = None,
    bearer_env: BearerOpt = None,
    name: NameOpt = None,
    unsafe_local: UnsafeOpt = False,
    sandbox_image: ImageOpt = None,
    mount: MountOpt = None,
    timeout: TimeoutOpt = 30.0,
    server_stderr: StderrOpt = False,
    sign_in: SignInOpt = False,
    save_sign_in: SaveSignInOpt = True,
    discover: DiscoverOpt = False,
    config: ConfigOpt = None,
    lock: Annotated[Path, typer.Option("--lock", help="Lockfile to create or update.")] = Path(DEFAULT_LOCKFILE),
) -> None:
    """Record servers in a lockfile as approved, replacing any earlier pin of the same server.

    Pinning means "this is the version I reviewed". Run 'scan' first: pinning a server
    does not make it safe, it only makes later changes visible.
    """
    live = Live(
        command or [], url, header or [], bearer_env, name, unsafe_local, sandbox_image, mount or [], timeout,
        server_stderr, sign_in, save_sign_in,
    )  # fmt: skip
    gathered = _gather(snapshot or [], live, discover, config)
    snapshots = gathered.snapshots
    for line in gathered.skipped:
        typer.echo(f"warning: not pinned: {line}", err=True)
    try:
        current = load_lock(lock) if lock.exists() else LockFile()
        save_lock(pin_servers(current, snapshots), lock)
    except LockError as exc:
        raise _fail(str(exc), exc) from exc
    except OSError as exc:
        raise _fail(f"cannot write {lock}: {exc.strerror or exc}", exc) from exc

    for snap in snapshots:
        shown = visible(snap.server_name)
        typer.echo(f"pinned {shown}: {len(snap.tools)} tools, {len(snap.prompts)} prompts", err=True)
        if snap.errors:
            typer.echo(f"warning: {shown} was only partly collected, so the pin is incomplete", err=True)
        flagged = len(run_scan([snap], rules=POISONING_RULES))
        if flagged:
            typer.echo(f"warning: {shown} has {flagged} poisoning findings; run 'scan' before trusting it", err=True)
    typer.echo(f"wrote {lock}", err=True)


# --- helpers ------------------------------------------------------------------------------------


def _judge(snapshots: list[ServerSnapshot], model: str) -> JudgeResult:
    try:
        return run_judge(snapshots, AnthropicBackend(model))
    except JudgeUnavailable as exc:
        raise _fail(f"--judge cannot run: {exc}", exc) from exc


def _should_fail(report: ScanReport, fail_on: FailOn) -> bool:
    if fail_on is FailOn.NONE:
        return False
    threshold = Severity(fail_on.value).rank
    if any(f.severity.rank >= threshold for f in report.findings):
        return True
    # An item the judge could not classify is unknown, not safe: the gate stays closed.
    return report.judge is not None and bool(report.judge.errors)


def _deliver(text: str, output: Path | None) -> None:
    if output is None:
        # Reports can contain non-ASCII text from a server; never crash on a narrow console encoding.
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(errors="backslashreplace")
        sys.stdout.write(text)
        return
    try:
        output.write_text(text, encoding="utf-8")
    except OSError as exc:
        raise _fail(f"cannot write {output}: {exc.strerror or exc}", exc) from exc
    typer.echo(f"wrote {output}", err=True)


def _emit(snap: ServerSnapshot, output: Path | None) -> None:
    if output is not None:
        save_snapshot(snap, output)
        typer.echo(
            f"wrote {output}: {len(snap.tools)} tools, {len(snap.prompts)} prompts, "
            f"{len(snap.resources)} resources, {len(snap.resource_templates)} resource templates",
            err=True,
        )
    else:
        sys.stdout.write(json.dumps(snap.model_dump(mode="json"), indent=2, ensure_ascii=True) + "\n")


if __name__ == "__main__":
    app()
