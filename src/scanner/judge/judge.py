"""LLM001: ask Claude to classify each item's full metadata.

One request per tool, prompt, resource and resource template, plus one for the
server's instructions. The static rules never see the judge's answers and the judge
never sees theirs, so the two can be measured separately.

Two rules shape the error handling:

- An item the judge could not classify (API error, refusal, cut-off answer, item
  too large) is reported as *not judged*. It is never counted as benign.
- The judge's rationale and evidence are derived from attacker-written text, so
  they are escaped and length-capped like any other server-controlled string.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from scanner.judge.prompt import SYSTEM_PROMPT, build_user_message
from scanner.models import Finding, ItemKind, ServerSnapshot, Severity
from scanner.normalize import to_pointer
from scanner.textutil import redact, visible

RULE_ID = "LLM001"
DEFAULT_MODEL = "claude-opus-5-5"
MAX_REQUEST_CHARS = 200_000
"""An item whose request would be longer than this is reported as not judged rather than cut short."""
MAX_OUTPUT_TOKENS = 8000
MAX_WORKERS = 4
MAX_RATIONALE = 300
MAX_EVIDENCE = 200

REMEDIATION = (
    "Read the quoted text. If the server is not one you fully trust, remove it from your config; "
    "otherwise ask its author why the text is there."
)

Category = Literal[
    "instruction_injection",
    "data_exfiltration",
    "hidden_content",
    "tool_shadowing",
    "parameter_poisoning",
    "reviewer_manipulation",
    "other",
    "none",
]


class Verdict(BaseModel):
    """The judge's structured answer for one item."""

    model_config = ConfigDict(extra="forbid")

    verdict: Literal["malicious", "suspicious", "benign"]
    category: Category
    severity: Literal["high", "medium", "low", "none"]
    rationale: str
    evidence: str


@dataclass(frozen=True)
class Answer:
    verdict: Verdict
    model: str = ""
    """The model that actually answered (a fallback model may differ from the one requested)."""
    input_tokens: int = 0
    output_tokens: int = 0


class JudgeError(RuntimeError):
    """One item could not be judged; the scan goes on."""


class JudgeUnavailable(RuntimeError):
    """The judge cannot run at all (no credentials, unknown model); the scan stops."""


Backend = Callable[[str, str], Answer]
"""Takes (system prompt, user message) and returns the judge's answer, or raises ``JudgeError``."""


@dataclass(frozen=True)
class JudgeItem:
    server: str
    kind: ItemKind
    name: str
    pointer: str
    payload: Any


@dataclass
class JudgeResult:
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    """One line per item that could not be judged. Already safe to print."""
    judged: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    models: set[str] = field(default_factory=set)


_SECTIONS: tuple[tuple[str, str, ItemKind], ...] = (
    ("tools", "tools", "tool"),
    ("prompts", "prompts", "prompt"),
    ("resources", "resources", "resource"),
    ("resource_templates", "resourceTemplates", "resource_template"),
)


def iter_items(snapshot: ServerSnapshot) -> Iterator[JudgeItem]:
    """Everything in a snapshot the model would read, one item at a time."""
    server = snapshot.server_name
    if snapshot.instructions:
        payload = {"instructions": snapshot.instructions, "serverInfo": snapshot.server_info}
        yield JudgeItem(server, "server", server, "/instructions", payload)
    for attr, segment, kind in _SECTIONS:
        for index, item in enumerate(getattr(snapshot, attr)):
            if not isinstance(item, dict):
                continue
            name = next((item[k] for k in ("name", "uri", "uriTemplate") if isinstance(item.get(k), str)), f"#{index}")
            yield JudgeItem(server, kind, name, to_pointer((segment, index)), item)


def _clip(text: str, limit: int) -> str:
    shown = visible(redact(text))
    return shown if len(shown) <= limit else shown[: limit - 3] + "..."


def to_finding(item: JudgeItem, verdict: Verdict) -> Finding | None:
    if verdict.verdict == "benign":
        return None
    # A non-benign verdict always gets a real severity, whatever the model put in that field.
    severity = Severity(verdict.severity) if verdict.severity != "none" else Severity.LOW
    category = verdict.category if verdict.category != "none" else "other"
    return Finding(
        rule_id=RULE_ID,
        severity=severity,
        title=f"LLM judge: {category.replace('_', ' ')}",
        server=item.server,
        item_kind=item.kind,
        item_name=item.name,
        pointer=item.pointer,
        message=f"Judged {verdict.verdict}. {_clip(verdict.rationale, MAX_RATIONALE)}",
        evidence=_clip(verdict.evidence, MAX_EVIDENCE) or "(the judge quoted no text)",
        remediation=REMEDIATION,
    )


def _label(item: JudgeItem) -> str:
    return f"{visible(item.server)} {item.kind} {visible(item.name)}"


def _judge_one(item: JudgeItem, backend: Backend) -> Answer:
    try:
        message = build_user_message(item.kind, item.name, item.payload)
    except (RecursionError, ValueError, TypeError) as exc:
        raise JudgeError("metadata could not be serialised") from exc
    if len(message) > MAX_REQUEST_CHARS:
        raise JudgeError(f"metadata is too large to judge ({len(message):,} characters)")
    return backend(SYSTEM_PROMPT, message)


def judge(snapshots: Sequence[ServerSnapshot], backend: Backend, max_workers: int = MAX_WORKERS) -> JudgeResult:
    """Judge every item in every snapshot. Items are sent concurrently; results keep document order."""
    items = [item for snapshot in snapshots for item in iter_items(snapshot)]
    result = JudgeResult()

    def attempt(item: JudgeItem) -> Answer | JudgeError:
        try:
            return _judge_one(item, backend)
        except JudgeError as exc:
            return exc

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        outcomes = list(pool.map(attempt, items))

    for item, outcome in zip(items, outcomes, strict=True):
        if isinstance(outcome, JudgeError):
            result.errors.append(f"{_label(item)}: not judged: {visible(str(outcome))}")
            continue
        result.judged += 1
        result.input_tokens += outcome.input_tokens
        result.output_tokens += outcome.output_tokens
        if outcome.model:
            result.models.add(outcome.model)
        finding = to_finding(item, outcome.verdict)
        if finding is not None:
            result.findings.append(finding)
    return result


class AnthropicBackend:
    """Calls the Claude API. The request carries no tools, so the judge can only answer."""

    def __init__(self, model: str = DEFAULT_MODEL, client: Any = None) -> None:
        import anthropic

        self._anthropic = anthropic
        self.model = model
        # Credentials come from the environment (ANTHROPIC_API_KEY or an `ant auth login` profile).
        try:
            self._client = client if client is not None else anthropic.Anthropic()
        except anthropic.AnthropicError as exc:
            raise JudgeUnavailable(f"no Claude API credentials: {exc}") from exc

    def __call__(self, system: str, user: str) -> Answer:
        errors = self._anthropic
        try:
            response = self._client.beta.messages.parse(
                model=self.model,
                max_tokens=MAX_OUTPUT_TOKENS,
                system=system,
                messages=[{"role": "user", "content": user}],
                output_format=Verdict,
                output_config={"effort": "medium"},
                # If the model's safety filter declines a request, let the API retry it on
                # another model instead of leaving the item unjudged.
                betas=["server-side-fallback-2026-07-01"],
                fallbacks="default",
            )
        except (errors.AuthenticationError, errors.PermissionDeniedError, errors.NotFoundError) as exc:
            raise JudgeUnavailable(f"the Claude API rejected the request: {exc.message}") from exc
        except errors.RateLimitError as exc:
            raise JudgeError("rate limited by the Claude API") from exc
        except errors.APIStatusError as exc:
            raise JudgeError(f"Claude API error {exc.status_code}") from exc
        except errors.APIConnectionError as exc:
            raise JudgeError("could not reach the Claude API") from exc
        except (ValueError, TypeError) as exc:  # the answer did not match the schema
            raise JudgeError("the judge's answer was not valid") from exc

        if response.stop_reason == "refusal":
            category = getattr(getattr(response, "stop_details", None), "category", None)
            reason = f" (safety category: {category})" if category else ""
            raise JudgeError(f"the model declined to classify this item{reason}")
        if response.stop_reason == "max_tokens":
            raise JudgeError("the judge's answer was cut off")
        verdict = response.parsed_output
        if verdict is None:
            raise JudgeError("the judge returned no answer")
        usage = response.usage
        return Answer(verdict, response.model, usage.input_tokens or 0, usage.output_tokens or 0)
