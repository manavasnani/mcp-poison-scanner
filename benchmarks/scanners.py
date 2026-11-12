"""Scanner adapters: run one scanner over benchmark cases and say which target items it flagged.

Every adapter returns an ``Outcome`` per case. An outcome never contains dataset
text, only flags, severities and rule names, so result files are safe to commit.

Paid adapters (the judge, and Cisco's LLM analyzer) keep an on-disk cache of every
answer, keyed by the exact item, so an interrupted run resumes without paying twice.
The cache does hold dataset text and is git-ignored.
"""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from benchmarks.cases import Case
from scanner.engine import scan
from scanner.judge.judge import Answer, AnthropicBackend, JudgeError, to_finding
from scanner.judge.judge import JudgeItem as _JudgeItem
from scanner.judge.prompt import SYSTEM_PROMPT, build_user_message
from scanner.models import Finding
from scanner.pin import diff_server
from scanner.rules import POISONING_RULES

CACHE_DIR = Path(__file__).resolve().parent / "results" / "cache"

# US dollars per million tokens (input, output), from Anthropic's price list on 2026-11-03.
PRICES = {
    "claude-opus-5-5": (4.00, 20.00),
    "claude-opus-5": (5.00, 25.00),
    "claude-opus-4-8": (5.00, 25.00),
    "claude-sonnet-5-5": (2.00, 10.00),
    "claude-haiku-5-5": (0.10, 0.50),
}
UNKNOWN_PRICE = (5.00, 25.00)


@dataclass
class Outcome:
    flagged: bool
    severity: str | None = None
    """Highest severity reported for the target item."""
    rules: list[str] = field(default_factory=list)
    """Rule ids, judge category, or the other scanner's threat names."""
    error: str | None = None
    """Set when the scanner could not give an answer for this item (not judged, unsupported)."""


@dataclass
class Run:
    scanner: str
    settings: dict[str, Any]
    outcomes: dict[str, Outcome]
    seconds: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    stopped_early: str | None = None

    def to_json(self) -> dict[str, Any]:
        data = asdict(self)
        data["outcomes"] = {case_id: asdict(o) for case_id, o in self.outcomes.items()}
        return data


def _on_target(case: Case, finding: Finding) -> bool:
    if finding.item_kind != case.target_kind:
        return False
    return case.target_kind == "server" or finding.item_name == case.target_name


def _from_findings(findings: Sequence[Finding]) -> Outcome:
    if not findings:
        return Outcome(False)
    top = max(findings, key=lambda f: f.severity.rank)
    return Outcome(True, top.severity.value, sorted({f.rule_id for f in findings}))


# --- our static rules ---------------------------------------------------------------------------


def run_static(cases: Sequence[Case], progress: Callable[[str], None] = print) -> Run:
    """Poisoning rules only, plus the pin diff for cases that come with a pinned version.

    Capability rules are left out on purpose: they report risk on honest servers and are
    not a claim of poisoning.
    """
    started = time.perf_counter()
    scanned: dict[int, list[Finding]] = {}
    outcomes: dict[str, Outcome] = {}
    for case in cases:
        key = id(case.snapshot)
        if key not in scanned:
            scanned[key] = scan([case.snapshot], rules=POISONING_RULES)
        findings = [f for f in scanned[key] if _on_target(case, f)]
        if case.pinned is not None:
            findings += [f for f in diff_server(case.pinned, case.snapshot) if _on_target(case, f)]
        outcomes[case.id] = _from_findings(findings)
    return Run("static", {"rules": [r.id for r in POISONING_RULES] + ["RP001 (pinned cases)"]}, outcomes,
               time.perf_counter() - started)  # fmt: skip


# --- shared cache -------------------------------------------------------------------------------


class Cache:
    """Append-only JSON-lines store of answers, keyed by a hash of the exact item."""

    def __init__(self, name: str) -> None:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        self.path = CACHE_DIR / f"{name}.jsonl"
        self._lock = threading.Lock()
        self.entries: dict[str, dict[str, Any]] = {}
        if self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    entry = json.loads(line)
                    self.entries[entry["key"]] = entry

    def put(self, key: str, entry: dict[str, Any]) -> None:
        entry = {"key": key, **entry}
        with self._lock:
            self.entries[key] = entry
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, ensure_ascii=True) + "\n")


def item_key(case: Case) -> str:
    """Identifies the judged item by content, so identical items share one answer."""
    payload = _judge_payload(case)
    blob = json.dumps([case.target_kind, case.target_name, payload], sort_keys=True, ensure_ascii=True)
    return hashlib.sha256(blob.encode()).hexdigest()


def _judge_payload(case: Case) -> Any:
    if case.target_kind == "server":
        return {"instructions": case.snapshot.instructions, "serverInfo": case.snapshot.server_info}
    return case.target_item()


# --- our LLM judge ------------------------------------------------------------------------------

# An answer of these kinds is final. Anything else (rate limit, network) is retried on the next run.
_FINAL_ERRORS = ("declined", "too large", "cut off", "not valid", "no answer")


def _cost(model: str, input_tokens: int, output_tokens: int) -> float:
    price_in, price_out = PRICES.get(model, UNKNOWN_PRICE)
    return (input_tokens * price_in + output_tokens * price_out) / 1_000_000


def run_judge(
    cases: Sequence[Case],
    *,
    model: str,
    pass_number: int = 1,
    workers: int = 6,
    max_cost: float = 5.0,
    backend: Callable[[str, str], Answer] | None = None,
    progress: Callable[[str], None] = print,
) -> Run:
    """Our judge on each case's target item. Stops submitting new items once ``max_cost`` is reached."""
    started = time.perf_counter()
    cache = Cache(f"judge-{model}-pass{pass_number}")
    by_key: dict[str, Case] = {}
    for case in cases:
        if _judge_payload(case) is not None:
            by_key.setdefault(item_key(case), case)

    def is_final(entry: dict[str, Any]) -> bool:
        error = entry.get("error")
        return error is None or any(word in error for word in _FINAL_ERRORS)

    todo = [key for key in by_key if key not in cache.entries or not is_final(cache.entries[key])]
    progress(
        f"judge pass {pass_number}: {len(by_key)} unique items, {len(by_key) - len(todo)} cached, {len(todo)} to send"
    )
    spent = 0.0
    spent_lock = threading.Lock()
    done = 0
    stopped: str | None = None

    if todo:
        call = backend or AnthropicBackend(model)

        def work(key: str) -> None:
            nonlocal spent, done, stopped
            with spent_lock:
                if spent >= max_cost:
                    stopped = f"stopped at the ${max_cost:.2f} cost cap"
                    return
            case = by_key[key]
            try:
                message = build_user_message(case.target_kind, case.target_name, _judge_payload(case))
                answer = call(SYSTEM_PROMPT, message)
                entry = {
                    **answer.verdict.model_dump(),
                    "model": answer.model,
                    "input_tokens": answer.input_tokens,
                    "output_tokens": answer.output_tokens,
                }
                price = _cost(answer.model, answer.input_tokens, answer.output_tokens)
            except JudgeError as exc:
                entry, price = {"error": str(exc)}, 0.0
            cache.put(key, entry)
            with spent_lock:
                spent += price
                done += 1
                if done % 100 == 0:
                    progress(f"  {done}/{len(todo)} judged, about ${spent:.2f} spent this run")

        with ThreadPoolExecutor(max_workers=workers) as pool:
            list(pool.map(work, todo))

    outcomes: dict[str, Outcome] = {}
    tokens_in = tokens_out = 0
    total_cost = 0.0
    for entry in cache.entries.values():
        if entry["key"] in by_key and "error" not in entry:
            tokens_in += entry["input_tokens"]
            tokens_out += entry["output_tokens"]
            total_cost += _cost(entry["model"], entry["input_tokens"], entry["output_tokens"])
    for case in cases:
        if _judge_payload(case) is None:
            outcomes[case.id] = Outcome(False, error="target item not found")
            continue
        entry = cache.entries.get(item_key(case))
        if entry is None or (entry.get("error") and not is_final(entry)):
            outcomes[case.id] = Outcome(False, error="not run")
        elif entry.get("error"):
            outcomes[case.id] = Outcome(False, error=f"not judged: {entry['error']}")
        else:
            from scanner.judge.judge import Verdict

            verdict = Verdict(**{k: entry[k] for k in ("verdict", "category", "severity", "rationale", "evidence")})
            finding = to_finding(_JudgeItem("", case.target_kind, case.target_name, "", None), verdict)
            outcomes[case.id] = (
                Outcome(True, finding.severity.value, [verdict.category]) if finding is not None else Outcome(False)
            )
    return Run(
        f"judge-pass{pass_number}",
        {"model": model, "effort": "medium", "fallbacks": "default", "unique_items": len(by_key)},
        outcomes,
        time.perf_counter() - started,
        tokens_in,
        tokens_out,
        round(total_cost, 4),
        stopped,
    )


# --- Cisco mcp-scanner --------------------------------------------------------------------------

CISCO_VERSION = "4.8.7"
CISCO_BATCH = 100
_CISCO_ENTRY = "from mcpscanner.cli import cli_entry_point as m; m()"
_CISCO_FLAG = {"tool": "--tools", "prompt": "--prompts", "resource": "--resources"}
_CISCO_KEY = {"tool": "tools", "prompt": "prompts", "resource": "resources"}
_CISCO_RANK = {"SAFE": 0, "UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 3}


def _cisco_command() -> list[str]:
    """How to start Cisco's scanner: through uv, pinned to the version under test."""
    # BENCH_UV overrides how uv is started, e.g. "C:\Python312\python.exe -m uv" when uv is not on PATH.
    override = os.environ.get("BENCH_UV")
    base = shlex.split(override, posix=False) if override else [shutil.which("uv") or "uv"]
    return [*base, "tool", "run", "--python", "3.12", "--from", f"cisco-ai-mcp-scanner=={CISCO_VERSION}",
            "python", "-c", _CISCO_ENTRY]  # fmt: skip


def _parse_cisco(stdout: str) -> list[dict[str, Any]]:
    start = stdout.find("[")
    if start == -1:
        raise ValueError("no JSON list in the scanner's output")
    return json.JSONDecoder().raw_decode(stdout[start:])[0]


def _cisco_outcome(result: dict[str, Any]) -> dict[str, Any]:
    severities, threats, incomplete = [], [], False
    for analyzer in (result.get("findings") or {}).values():
        if isinstance(analyzer, dict):
            severities.append(str(analyzer.get("severity", "SAFE")).upper())
            threats += [str(t) for t in analyzer.get("threat_names") or []]
            # The LLM analyzer says this when the model returned nothing (for example a safety refusal).
            incomplete = incomplete or "did not complete" in str(analyzer.get("threat_summary", ""))
    top = max(severities, key=lambda s: _CISCO_RANK.get(s, 0), default="SAFE")
    # Cisco skips some items (a resource whose type it does not read, say) and reports no verdict for them.
    skipped = result.get("status") == "skipped" or result.get("is_safe") is None
    return {
        "is_safe": bool(result.get("is_safe", True)),
        "severity": top,
        "threats": sorted(set(threats)),
        "incomplete": incomplete,
        "skipped": skipped,
    }


def run_cisco(
    cases: Sequence[Case],
    *,
    analyzer: str = "yara",
    llm_model: str | None = None,
    max_items: int | None = None,
    progress: Callable[[str], None] = print,
) -> Run:
    """Cisco mcp-scanner in static mode on each case's target item.

    Items are sent in batches of files; results come back in order and are matched by
    position, since different cases can share a tool name. Server-level instructions
    cannot be given to its static mode and are recorded as unsupported.
    """
    started = time.perf_counter()
    label = f"cisco-{analyzer}" + (f"-{llm_model.replace('/', '_')}" if llm_model else "")
    cache = Cache(f"{label}-{CISCO_VERSION}")
    env = dict(os.environ)
    if analyzer == "llm":
        if not llm_model:
            raise ValueError("the llm analyzer needs a model")
        env["MCP_SCANNER_LLM_MODEL"] = llm_model
        env.setdefault("MCP_SCANNER_LLM_API_KEY", env.get("ANTHROPIC_API_KEY", ""))
        env.setdefault("MCP_SCANNER_LLM_TIMEOUT", "120")

    pending: dict[str, dict[str, tuple[str, Any]]] = {"tool": {}, "prompt": {}, "resource": {}}
    for case in cases:
        if case.target_kind in pending and case.target_item() is not None:
            key = item_key(case)
            if key not in cache.entries:
                pending[case.target_kind].setdefault(key, (key, case.target_item()))
    todo = sum(len(v) for v in pending.values())
    progress(f"{label}: {todo} items to scan")
    sent = 0
    stopped: str | None = None

    for kind, items in pending.items():
        batch_items = list(items.values())
        for offset in range(0, len(batch_items), CISCO_BATCH):
            if max_items is not None and sent >= max_items:
                stopped = f"stopped after {sent} items (limit)"
                break
            batch = batch_items[offset : offset + CISCO_BATCH]
            if max_items is not None:
                batch = batch[: max_items - sent]
            with tempfile.TemporaryDirectory() as folder:
                file = Path(folder) / "items.json"
                file.write_text(json.dumps({_CISCO_KEY[kind]: [item for _key, item in batch]}), encoding="utf-8")
                completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
                    [*_cisco_command(), "--analyzers", analyzer, "--raw", "static", _CISCO_FLAG[kind], str(file)],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    env=env,
                    timeout=3600,
                    check=False,
                )
            try:
                results = _parse_cisco(completed.stdout)
            except ValueError as exc:
                tail = completed.stderr.strip().splitlines()[-1:] or ["no output"]
                raise RuntimeError(f"Cisco scanner failed (exit {completed.returncode}): {tail[0][:300]}") from exc
            if len(results) != len(batch):
                raise RuntimeError(f"Cisco returned {len(results)} results for {len(batch)} items")
            for (key, _item), result in zip(batch, results, strict=True):
                cache.put(key, _cisco_outcome(result))
            sent += len(batch)
            progress(f"  {sent}/{todo} scanned")

    outcomes: dict[str, Outcome] = {}
    for case in cases:
        if case.target_kind not in pending:
            what = "server instructions" if case.target_kind == "server" else "resource templates"
            outcomes[case.id] = Outcome(False, error=f"unsupported: static mode cannot take {what}")
            continue
        entry = cache.entries.get(item_key(case)) if case.target_item() is not None else None
        if entry is None:
            outcomes[case.id] = Outcome(False, error="not run")
        elif entry.get("skipped"):
            outcomes[case.id] = Outcome(False, error="skipped: Cisco gave no verdict for this item")
        elif entry.get("incomplete"):
            # Cisco itself marks these items unsafe. They are kept apart here, like our own unjudged items.
            outcomes[case.id] = Outcome(False, error="not judged: the LLM analysis did not complete")
        else:
            flagged = not entry["is_safe"]
            outcomes[case.id] = Outcome(flagged, entry["severity"].lower() if flagged else None, entry["threats"])
    settings = {"version": CISCO_VERSION, "analyzers": analyzer, "mode": "static", "llm_model": llm_model}
    return Run(label, settings, outcomes, time.perf_counter() - started, stopped_early=stopped)
