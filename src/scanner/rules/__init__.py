"""Static detection rules. Each module defines one ``RULE``.

``POISONING_RULES`` (TP) look for hostile text. ``CAPABILITY_RULES`` (CAP) flag
risky capabilities, which honest servers can have too, so a CAP finding is not a
claim that a server is malicious. The benchmark's false-positive rate is measured
on the TP rules only.
"""

from scanner.rules import cap001, cap002, tp001, tp002, tp003, tp004, tp005, tp006
from scanner.rules.base import Rule, ScanContext

POISONING_RULES: tuple[Rule, ...] = (tp001.RULE, tp002.RULE, tp003.RULE, tp004.RULE, tp005.RULE, tp006.RULE)
CAPABILITY_RULES: tuple[Rule, ...] = (cap001.RULE, cap002.RULE)
STATIC_RULES: tuple[Rule, ...] = POISONING_RULES + CAPABILITY_RULES

__all__ = ["CAPABILITY_RULES", "POISONING_RULES", "STATIC_RULES", "Rule", "ScanContext"]
