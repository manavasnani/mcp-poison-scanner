"""TP001: instructions aimed at the model.

Tool metadata should describe what a tool does. Text that gives the model orders
(override earlier instructions, hide something from the user, call another tool
first) is the core of a tool-poisoning attack. Matching runs on the canonical
text, so words split by invisible characters are still caught.

Honest servers give orders too: "always call this first", "before calling this tool you
must fetch the id". Those shapes are marked ``weak``. A weak match alone is reported at
low severity, as something to read. It becomes high when the same text also names a
secret location, or matches one of the other patterns, which honest servers do not write.
"""

from __future__ import annotations

from collections.abc import Iterator

from scanner.models import Finding, Severity
from scanner.rules.base import Rule, ScanContext, all_matches, first_match, match_evidence, pattern
from scanner.rules.tp002 import SENSITIVE_PATTERNS

_NOT = r"(?:do not|don't|never|must not|mustn't|should not|shouldn't)"
_PERSON = r"(?:the\s+)?(?:user|human|anyone)"

INSTRUCTION_PATTERNS = (
    pattern(
        "tells the model to override earlier instructions",
        # No word boundary after the noun: payloads run words together ("instructionsand do the following").
        r"\b(ignore|disregard|forget|override|bypass)\b.{0,30}"
        r"\b(previous|prior|above|earlier|preceding|all|any|other|existing|your)\b.{0,30}"
        r"\b(instructions?|prompts?|rules|guidelines|directives)"
        r"|\b(ignore|disregard|override)\s+(their|the\s+user'?s?|user'?s?)\s+(actual\s+|original\s+)?"
        r"(query|request|input|question|instructions?)\b"
        r"|\bpriority\s+(is\s+)?(higher|greater)\s+than\b.{0,40}\b(user|system)\b"
        r"|\btakes?\s+(precedence|priority)\s+over\s+(the\s+)?(user|system)\b",
    ),
    pattern(
        "tells the model to hide something from the user",
        # Keeping the user in the dark, not advice on what to say: "do not tell the user it has
        # finished" and "do not mention the paid plan" are wording guidance and do not match.
        rf"\b{_NOT}\s+(tell|inform|notify|alert)\s+{_PERSON}"
        r"(\s+(about|of|that|you|what\s+you|this|any\s+of)\b|\s*[.,;!)]|\s*$)"
        rf"|\b{_NOT}\s+(mention|reveal|disclose|show|display)\b.{{0,40}}\bto\s+{_PERSON}\b"
        rf"|\b{_NOT}\s+(mention|reveal|disclose)\s+(this|these|that|the)\s+"
        r"(instruction|step|action|note|message|call|operation|behaviou?r|tool|requirement|process)"
        r"|\bwithout\s+(telling|mentioning|informing|notifying|alerting)\b.{0,30}\b(user|human|anyone)\b"
        r"|\b(not|never)\s+be\s+(shown|revealed|disclosed|mentioned|visible)\s+to\s+the\s+user\b"
        r"|\bhide\s+(this|it|that)\s+from\s+the\s+user\b"
        r"|\bwithout\s+the\s+user(?:'s)?\s+(knowledge|knowing|consent|noticing|awareness)\b",
    ),
    pattern(
        "makes another action a precondition for using a tool",
        r"\bbefore\s+(using|calling|invoking|executing|running|utilizing)\s+(this|the|any|that)\b.{0,40}\btool\b"
        r".{0,5}\b(read|call|send|pass|fetch|execute|run|write|include|summari[sz]e|first|you|always)\b",
        weak=True,
    ),
    pattern(
        "uses fake system or priority markup",
        r"<\s*/?\s*(important|system|instructions?|secret|admin|critical|override|hidden)\s*>"
        r"|\[\s*(system|admin)\s*\]",
    ),
    pattern("uses a fake SYSTEM: prefix", r"(?:^|[\s.!>])SYSTEM\s*:", case_sensitive=True),
    pattern(
        "tries to reassign the model's role or mode",
        r"\byou are now\b|\bfrom now on,? you\b|\bnew instructions?\s*:"
        r"|\b(maintenance|developer|debug|admin|god)\s+mode\b.{0,40}\b(skip|ignore|disable|bypass)\b",
    ),
    pattern(
        "addresses the model directly",
        # "instructions for the LLM" also describes a feature, so it needs the colon of an address.
        r"\b(note|message|reminder|attention)\s+(to|for)\s+(the\s+)?"
        r"(ai|assistant|model|llm|agent|language model)\b"
        r"|\binstructions?\s+(to|for)\s+(the\s+)?(ai|assistant|model|llm|agent|language model)\s*[:\-]"
        r"|(?:^|[.!?:]\s|<!--\s*)(ai\s+)?assistant\s*[:,]\s"
        r"|\b(dear|hey|attention)\s+(ai|assistant|model|llm)\b",
    ),
    pattern(
        "forces a tool call",
        r"\balways\s+(call|invoke|run|execute|use)\b.{0,60}\b(first|before|prior to|after|whenever|every)\b"
        r"|\byou\s+must\s+(first|always)\b|\bmust\s+first\s+(call|invoke|run|execute|read|send)\b",
        weak=True,
    ),
    pattern(
        "demands to be used before everything else",
        # Not workflow among a server's own tools: a claim on every request the user makes.
        r"\bbefore\s+(using|calling|invoking|running)\s+any\s+(other\s+)?tools?\b"
        r"|\b(always|must)\b.{0,40}\bbefore\s+(answering|responding|replying|any\s+other|every\s+other)\b"
        r"|\b(call|use|invoke|run)\b.{0,30}\b(for|on|with)\s+every\s+(request|message|query|prompt|turn)\b",
    ),
    pattern(
        "tells the model to change what the user asked for",
        r"\b(must|always|should)\s+(be\s+)?(automatically\s+|silently\s+|secretly\s+)?"
        r"(chang|modif|rewr|redirect|replac|overrid)\w{0,6}\b.{0,60}"
        r"\b(param\w{0,8}|arguments?|query|request|recipient)\b"
        r"|\b(silently|secretly)\s+(chang|modif|rewr|redirect|replac|append|add|insert)\w{0,6}\b",
    ),
    pattern(
        "tells the model to skip user confirmation",
        r"\b(skip|bypass|disable|do not ask for|don't ask for|never ask for|no need for)\s+"
        r"(all\s+|any\s+|the\s+|user\s+)*(confirmations?|approval|permission|consent|verification)\b"
        r"|\bwithout\s+(asking|prompting|confirming with)\s+(the\s+)?user\b",
    ),
    pattern(
        "pressures the model with a false consequence",
        r"\botherwise\b.{0,40}\b(tool|it|this|server|system)\s+will\s+(not\s+work|fail|crash|break)\b"
        r"|\b(always|must)\s+approve\b",
    ),
)


def _check(rule: Rule, ctx: ScanContext) -> Iterator[Finding]:
    for field in ctx.fields:
        if field.is_key:
            continue
        text = field.canonical
        hits = all_matches(INSTRUCTION_PATTERNS, text)
        if not hits:
            continue
        # One finding per field: lead with the strongest hit, list the rest.
        hits.sort(key=lambda hit: hit[0].weak)
        labels = [pat.label for pat, _ in hits]
        message = "Text " + labels[0] + (f" (also: {'; '.join(labels[1:])})" if len(labels) > 1 else "") + "."
        evidence = match_evidence(text, hits[0][1])
        if not hits[0][0].weak:
            yield rule.finding(field, message, evidence)
            continue
        secret = first_match(SENSITIVE_PATTERNS, text)
        if secret:
            yield rule.finding(field, f"{message[:-1]}, in text that names {secret[0].label}.", evidence)
        else:
            yield rule.finding(field, message, evidence, severity=Severity.LOW, remediation=_WORKFLOW_REMEDIATION)


_WORKFLOW_REMEDIATION = (
    "Usually ordinary guidance about the server's own tools. Read it, and check that it does not make "
    "the model do something you did not ask for."
)


RULE = Rule(
    id="TP001",
    title="Instructions aimed at the model",
    severity=Severity.HIGH,
    remediation=(
        "Do not connect this server until the text is removed. Metadata should describe the tool, "
        "not give the model orders."
    ),
    check=_check,
)
