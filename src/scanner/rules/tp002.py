"""TP002: sensitive paths or secrets referenced in metadata.

A tool description has little reason to name a private key, a credentials file or
the agent's own config. Naming one usually means the text is steering the model
to read it. Literal secrets (API keys) pasted into metadata are reported too, with
the value redacted.
"""

from __future__ import annotations

from collections.abc import Iterator

from scanner.models import Finding, Severity
from scanner.rules.base import Rule, ScanContext, first_match, match_evidence, pattern

SENSITIVE_PATTERNS = (
    pattern(
        "an SSH key or SSH directory",
        r"(?<![\w-])\.ssh\b|\bid_(rsa|dsa|ecdsa|ed25519)\b|\bauthorized_keys\b|\bssh-(rsa|ed25519)\s+AAAA",
    ),
    pattern("an environment file", r"(?<![\w.-])\.env(\.[a-z]+)?\b"),
    pattern(
        "cloud credentials",
        r"(?<![\w-])\.aws\b|\baws[/\\]credentials\b|\.config[/\\]gcloud\b|\bapplication_default_credentials\b"
        r"|(?<![\w-])\.azure\b|(?<![\w-])\.kube[/\\]config\b|\bkubeconfig\b",
    ),
    pattern(
        "a credentials file",
        r"\bcredentials\.(json|db|xml|ya?ml|ini)\b|\.git-credentials\b|(?<![\w-])\.netrc\b|(?<![\w-])\.npmrc\b"
        r"|(?<![\w-])\.pypirc\b|\.docker[/\\]config\.json\b|\bsecrets?\.(json|ya?ml|toml)\b|\bwallet\.dat\b",
    ),
    pattern("a system account file", r"/etc/(passwd|shadow|sudoers)\b"),
    pattern(
        "an AI agent's own configuration",
        r"\bclaude_desktop_config\.json\b|(?<![\w-])\.cursor[/\\]mcp\.json\b|(?<![\w.-])mcp\.json\b",
    ),
    pattern("private key material", r"-----BEGIN [A-Z ]{0,30}PRIVATE KEY-----"),
    pattern(
        "a hard-coded secret",
        r"\b(sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}"
        r"|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{30,})",
        case_sensitive=True,
    ),
)


def _check(rule: Rule, ctx: ScanContext) -> Iterator[Finding]:
    for field in ctx.fields:
        text = field.canonical
        hit = first_match(SENSITIVE_PATTERNS, text)
        if hit:
            pat, match = hit
            yield rule.finding(field, f"Text references {pat.label}.", match_evidence(text, match))


RULE = Rule(
    id="TP002",
    title="Sensitive path or secret in metadata",
    severity=Severity.HIGH,
    remediation=(
        "Check why this server's metadata names a secret or credential location. If the tool has no "
        "legitimate need for it, treat the server as hostile."
    ),
    check=_check,
)
