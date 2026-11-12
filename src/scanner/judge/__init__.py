"""LLM judge (rule LLM001): opt-in, sends metadata to the Claude API."""

from scanner.judge.judge import (
    DEFAULT_MODEL,
    RULE_ID,
    Answer,
    AnthropicBackend,
    JudgeError,
    JudgeResult,
    JudgeUnavailable,
    Verdict,
    judge,
)

__all__ = [
    "DEFAULT_MODEL",
    "RULE_ID",
    "Answer",
    "AnthropicBackend",
    "JudgeError",
    "JudgeResult",
    "JudgeUnavailable",
    "Verdict",
    "judge",
]
