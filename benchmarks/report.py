"""Turn saved benchmark runs into the results tables.

    uv run python -m benchmarks.report

Reads every ``results/*.json`` written by ``benchmarks.run`` and writes
``results/RESULTS.md``. Rates come with a 95% Wilson interval, because several
categories are small and a bare percentage would overstate what is known.
"""

from __future__ import annotations

import json
import math
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from benchmarks.cases import ALL_DATASETS, CLEAN, DEV, HELD_OUT, POISONED, Case, load_cases, mcptox_part

RESULTS = Path(__file__).resolve().parent / "results"
BASELINE = RESULTS / "baseline" / "static-v1.json"
"""The static rules' outcomes before they were tuned, frozen on 2026-11-12. Never regenerated."""
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 3}
DATASET_LABEL = {
    "mcptox": "MCPTox",
    "own": "Own cases",
    "clean_servers": "Real servers",
    "signed_in": "Signed-in servers",
}


def wilson(hits: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% confidence interval for a proportion."""
    if n == 0:
        return 0.0, 0.0
    p = hits / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return max(0.0, centre - half), min(1.0, centre + half)


def rate(hits: int, n: int) -> str:
    if n == 0:
        return "n/a"
    low, high = wilson(hits, n)
    return f"{100 * hits / n:.1f}% ({hits}/{n}; {100 * low:.0f}-{100 * high:.0f}%)"


def is_flagged(outcome: dict[str, Any] | None, min_severity: str = "low") -> bool:
    if not outcome or not outcome["flagged"]:
        return False
    return SEVERITY_RANK.get(outcome.get("severity") or "low", 1) >= SEVERITY_RANK[min_severity]


def load_runs() -> dict[str, dict[str, Any]]:
    runs = {}
    for file in sorted(RESULTS.glob("*.json")):
        run = json.loads(file.read_text(encoding="utf-8"))
        runs[run["scanner"]] = run
    return runs


Flagger = tuple[str, Any]  # (row label, function case_id -> bool | None); None means "no answer"


def build_flaggers(runs: dict[str, dict[str, Any]]) -> list[Flagger]:
    """One row per scanner configuration that has results."""
    rows: list[Flagger] = []

    def of(name: str, min_severity: str = "low"):
        outcomes = runs[name]["outcomes"]
        return lambda cid: (
            None
            if cid not in outcomes or (outcomes[cid].get("error") or "") == "not run"
            else is_flagged(outcomes[cid], min_severity)
        )

    if "static" in runs:
        rows.append(("My scanner, static rules (any severity)", of("static")))
        rows.append(("My scanner, static rules (high only)", of("static", "high")))
    passes = sorted(name for name in runs if name.startswith("judge-pass"))
    for name in passes:
        rows.append((f"My scanner, judge only ({name.removeprefix('judge-')})", of(name)))
    if "static" in runs and passes:
        static, judged = of("static"), of(passes[0])

        def either(cid: str):
            a, b = static(cid), judged(cid)
            return None if a is None or b is None else a or b

        rows.append((f"My scanner, static + judge ({passes[0].removeprefix('judge-')})", either))
    for name in sorted(runs):
        if name.startswith("cisco-"):
            settings = runs[name]["settings"]
            model = f", {settings['llm_model']}" if settings.get("llm_model") else ""
            rows.append((f"Cisco mcp-scanner {settings['version']} ({settings['analyzers']}{model})", of(name)))
    return rows


def tally(cases: list[Case], flag) -> tuple[int, int]:
    answered = [(c, flag(c.id)) for c in cases]
    answered = [(c, f) for c, f in answered if f is not None]
    return sum(1 for _c, f in answered if f), len(answered)


def table(header: list[str], rows: list[list[str]]) -> list[str]:
    return ["| " + " | ".join(header) + " |", "| " + " | ".join("---" for _ in header) + " |"] + [
        "| " + " | ".join(row) + " |" for row in rows
    ]


def render(cases: list[Case], runs: dict[str, dict[str, Any]], missing: list[str]) -> str:
    flaggers = build_flaggers(runs)
    groups: dict[tuple[str, str], list[Case]] = defaultdict(list)
    for case in cases:
        groups[(case.dataset, case.label)].append(case)
    out = [
        "# Benchmark results",
        "",
        f"Generated {datetime.now(UTC).date().isoformat()} by `python -m benchmarks.report` from the run files in this folder.",
        "Do not edit by hand.",
        "",
        "Each rate is followed by (hits/total; 95% confidence interval). A scanner is only counted on",
        "cases it gave an answer for, so a smaller total in a row means that scanner was run on a subset.",
        "",
        "## Detection rate on poisoned items (higher is better)",
        "",
    ]
    poisoned_sets = [key for key in groups if key[1] == POISONED]
    clean_sets = [key for key in groups if key[1] == CLEAN]
    out += table(
        ["Scanner", *(f"{DATASET_LABEL[d]} (n={len(groups[(d, lab)])})" for d, lab in poisoned_sets)],
        [[label, *(rate(*tally(groups[key], flag)) for key in poisoned_sets)] for label, flag in flaggers],
    )
    out += ["", "## False-positive rate on clean items (lower is better)", ""]
    out += table(
        ["Scanner", *(f"{DATASET_LABEL[d]} (n={len(groups[(d, lab)])})" for d, lab in clean_sets)],
        [[label, *(rate(*tally(groups[key], flag)) for key in clean_sets)] for label, flag in flaggers],
    )

    for dataset, title, attr in (
        ("mcptox", "MCPTox detection by security risk", "category"),
        ("mcptox", "MCPTox detection by attack template", "subcategory"),
        ("own", "Own cases: detection by technique family", "category"),
    ):
        subset = groups.get((dataset, POISONED), [])
        if not subset:
            continue
        by: dict[str, list[Case]] = defaultdict(list)
        for case in subset:
            by[getattr(case, attr)].append(case)
        names = sorted(by)
        out += ["", f"## {title}", ""]
        out += table(
            ["Scanner", *(f"{n} (n={len(by[n])})" for n in names)],
            [[label, *(rate(*tally(by[n], flag)) for n in names)] for label, flag in flaggers],
        )

    passes = sorted(name for name in runs if name.startswith("judge-pass"))
    if len(passes) > 1:
        out += ["", "## Judge: agreement between passes", ""]
        shared = [
            c
            for c in cases
            if all(
                c.id in runs[p]["outcomes"] and (runs[p]["outcomes"][c.id].get("error") or "") != "not run"
                for p in passes
            )
        ]
        same = sum(1 for c in shared if len({is_flagged(runs[p]["outcomes"][c.id]) for p in passes}) == 1)
        out.append(
            f"On the {len(shared)} cases judged in all {len(passes)} passes, the verdict (flagged or not) was the same in every pass for {rate(same, len(shared))}."
        )

    out += ["", "## Items a scanner gave no verdict on", ""]
    rows = []
    for name, run in sorted(runs.items()):
        reasons: dict[str, int] = defaultdict(int)
        for outcome in run["outcomes"].values():
            error = outcome.get("error")
            if error and error != "not run":
                reasons[error.split(":")[0] if error.startswith("unsupported") else error] += 1
        for reason, count in sorted(reasons.items()):
            rows.append([name, str(count), reason])
    out += table(["Run", "Items", "Reason"], rows) if rows else ["None."]
    out.append("")
    out.append("These are counted as not flagged in the tables above.")

    out += ["", "## Cost and time", ""]
    rows = []
    for name, run in sorted(runs.items()):
        n = len([o for o in run["outcomes"].values() if (o.get("error") or "") != "not run"])
        tokens = f"{run['input_tokens']:,} in / {run['output_tokens']:,} out" if run["input_tokens"] else "none"
        cost = f"${run['cost_usd']:.2f}" if run["cost_usd"] else "$0"
        per = f"${run['cost_usd'] / n:.4f}" if run["cost_usd"] and n else "$0"
        if run["settings"].get("llm_model"):
            tokens = cost = per = "not reported by the tool"
        rows.append([name, str(n), tokens, cost, per, json.dumps(run["settings"])])
    out += table(["Run", "Items answered", "Tokens", "API cost", "Cost per item", "Settings"], rows)
    out += [
        "",
        "Wall-clock times are in each run file; they include cached answers, so they are not comparable",
        "between a fresh run and a resumed one.",
    ]
    if missing:
        out += ["", "## Datasets not included", ""] + [f"- {m}" for m in missing]
    return "\n".join(out) + "\n"


TUNING_GROUPS = (
    ("MCPTox poisoned tools, held-out half (never looked at)", "mcptox", POISONED, HELD_OUT),
    ("MCPTox poisoned tools, dev half (used for tuning)", "mcptox", POISONED, DEV),
    ("MCPTox clean tools, held-out half", "mcptox", CLEAN, HELD_OUT),
    ("MCPTox clean tools, dev half", "mcptox", CLEAN, DEV),
    ("Own cases, attacks", "own", POISONED, None),
    ("Own cases, benign look-alikes", "own", CLEAN, None),
    ("Real servers, clean items", "clean_servers", CLEAN, None),
    ("Signed-in servers, clean items (used for tuning)", "signed_in", CLEAN, None),
)


def tuning_rows(cases: list[Case], before: dict[str, Any], after: dict[str, Any]) -> list[tuple[str, int, list[int]]]:
    """For each group: its size and how many items were flagged (before any, before high, after any, after high)."""
    rows = []
    for title, dataset, label, part in TUNING_GROUPS:
        group = [c for c in cases if c.dataset == dataset and c.label == label and mcptox_part(c) == part]
        group = [c for c in group if c.id in before and c.id in after]
        counts = [
            sum(1 for c in group if is_flagged(outcomes[c.id], level))
            for outcomes in (before, after)
            for level in ("low", "high")
        ]
        rows.append((title, len(group), counts))
    return rows


def render_tuning(cases: list[Case], before: dict[str, Any], after: dict[str, Any]) -> str:
    """The before-and-after section for the static rules."""
    out = [
        "",
        "## Static rules before and after tuning",
        "",
        "I changed the rules once after the first published run (see benchmarks/README.md for what and why).",
        "I split MCPTox in two by a hash of each server's name and read only the dev half while changing the",
        "rules, so the held-out rows are the ones that say how the change generalises. Rows marked as used for",
        "tuning are not independent evidence.",
        "",
    ]

    def cell(hits: int, n: int) -> str:
        return f"{100 * hits / n:.1f}% ({hits}/{n})" if n else "n/a"

    out += table(
        ["Items", "Before, any severity", "Before, high only", "After, any severity", "After, high only"],
        [[title, *(cell(hits, n) for hits in counts)] for title, n, counts in tuning_rows(cases, before, after)],
    )
    return chr(10).join(out) + chr(10)


def render_robustness(data: dict[str, Any]) -> str:
    """The judge-robustness section, from the file written by ``benchmarks.robustness``."""
    from benchmarks.robustness import FLAGGED, FOOLED, NO_ANSWER, summarise

    labels = {
        "hardened": "My judge as shipped",
        "naive": "Same model, naive prompt (text pasted in, free-text answer)",
        "static": "My static rules",
    }
    summary = summarise(data)
    passes = data["settings"]["passes"]
    attacks = [cid for cid, tech in data["techniques"].items() if tech != "baseline"]
    out = [
        "",
        "## Judge robustness: text that argues with the scanner",
        "",
        f"{len(attacks)} poisoned tools that also tell the reviewer they are safe, approved or out of scope",
        f"(one technique each), and the same {len(data['techniques']) - len(attacks)} poisoned tools without that text as a baseline.",
        f'Each judge was asked {passes} times per case. "Fooled" means it answered that a poisoned tool is clean.',
        "",
    ]
    rows = []
    for group, title in (("baseline", "Poison only"), ("attack", "Poison plus manipulation")):
        for config, label in labels.items():
            counts = (summary.get(group) or {}).get(config)
            if not counts or not counts["total"]:
                continue
            n = counts["total"]
            rows.append([title, label, rate(counts[FLAGGED], n), rate(counts[FOOLED], n), f"{counts[NO_ANSWER]}/{n}"])
    out += table(["Cases", "Scanner", "Flagged", "Fooled", "No usable answer"], rows)

    fooled_rows = []
    for cid in attacks:
        per = data["results"][cid]
        cells = [f"{per[c].count(FOOLED)}/{len(per[c])}" if per[c] else "n/a" for c in labels]
        if any(per[c].count(FOOLED) or per[c].count(NO_ANSWER) for c in labels):
            other = [f"{per[c].count(NO_ANSWER)}/{len(per[c])}" if per[c] else "n/a" for c in labels]
            fooled_rows.append([data["techniques"][cid], *cells, " / ".join(other)])
    if fooled_rows:
        out += [
            "",
            "Techniques that fooled a scanner or left it without an answer at least once (times fooled / times asked):",
            "",
        ]
        out += table(["Technique", *labels.values(), "No usable answer (same order)"], fooled_rows)
    else:
        out += ["", "No technique fooled any scanner in any pass."]
    answered = ", ".join(f"{k} x{v}" for k, v in data["answered_by"].items())
    out += [
        "",
        f"Model {data['settings']['model']}; answers came from: {answered or 'n/a'}. API cost ${data['cost_usd']:.2f}.",
        "I wrote these cases, and I also wrote the judge prompt. See benchmarks/README.md for what this does and does not show.",
    ]
    if data.get("stopped_early"):
        out += ["", f"Incomplete: {data['stopped_early']}."]
    return chr(10).join(out) + chr(10)


README = Path(__file__).resolve().parent.parent / "README.md"
BLOCK_START = "<!-- benchmark:start (generated by `python -m benchmarks.report`; do not edit) -->"
BLOCK_END = "<!-- benchmark:end -->"


def render_summary(
    cases: list[Case],
    runs: dict[str, dict[str, Any]],
    robustness: dict[str, Any] | None,
    baseline: dict[str, Any] | None = None,
) -> str:
    """The short results block for the top-level README. Every number in it comes from the run files."""
    groups: dict[tuple[str, str], list[Case]] = defaultdict(list)
    for case in cases:
        groups[(case.dataset, case.label)].append(case)
    columns = [
        ("MCPTox: poisoned tools caught", ("mcptox", POISONED)),
        ("MCPTox: clean tools flagged", ("mcptox", CLEAN)),
        ("Real servers: clean items flagged", ("clean_servers", CLEAN)),
        ("Signed-in servers: clean items flagged", ("signed_in", CLEAN)),
        ("Own cases: attacks caught", ("own", POISONED)),
    ]

    def cell(flag: Any, key: tuple[str, str]) -> str:
        hits, n = tally(groups.get(key, []), flag)
        return f"{100 * hits / n:.1f}% ({hits:,}/{n:,})" if n else "not run"

    rows = [
        [label.replace(" (pass1)", ""), *(cell(flag, key) for _title, key in columns)]
        for label, flag in build_flaggers(runs)
        if "pass2" not in label and "pass3" not in label
    ]
    out = [BLOCK_START, "", *table(["Scanner", *(title for title, _key in columns)], rows), ""]
    if baseline and "static" in runs:
        by_title = {t: (n, c) for t, n, c in tuning_rows(cases, baseline, runs["static"]["outcomes"])}
        n, (_b_any, b_high, _a_any, a_high) = by_title[TUNING_GROUPS[0][0]]
        m, (_sb_any, sb_high, _sa_any, sa_high) = by_title[TUNING_GROUPS[-1][0]]
        if n and m:
            out += [
                f"I tuned the static rules once. On the half of MCPTox that I never looked at while tuning "
                f"({n} poisoned tools), high-severity detection went from {100 * b_high / n:.1f}% to "
                f"{100 * a_high / n:.1f}%. High-severity false alarms on the signed-in servers went from "
                f"{100 * sb_high / m:.1f}% to {100 * sa_high / m:.1f}%; I used those servers for the tuning, "
                "so that second figure is not independent.",
                "",
            ]
    if robustness:
        from benchmarks.robustness import FOOLED, NO_ANSWER, summarise

        attack = summarise(robustness).get("attack", {})
        hardened, naive = attack.get("hardened"), attack.get("naive")
        if hardened and naive:
            cases_n = sum(1 for t in robustness["techniques"].values() if t != "baseline")
            out += [
                f"Judge robustness: on {cases_n} poisoned tools that also argue with the reviewer, the judge called a "
                f"poisoned tool clean in {hardened[FOOLED]} of {hardened['total']} answers and gave no verdict in "
                f"{hardened[NO_ANSWER]}. The same model with a naive prompt: {naive[FOOLED]} of {naive['total']} "
                f"and {naive[NO_ANSWER]}.",
                "",
            ]
    out += [
        f"Generated {datetime.now(UTC).date().isoformat()}. Confidence intervals, per-category tables, costs and "
        "the limits of these numbers: [benchmarks/results/RESULTS.md](benchmarks/results/RESULTS.md) and "
        "[benchmarks/README.md](benchmarks/README.md).",
        "",
        BLOCK_END,
    ]
    return chr(10).join(out)


def update_readme(block: str, readme: Path = README) -> bool:
    """Replace the generated block in the README. Returns False when the markers are not there."""
    text = readme.read_text(encoding="utf-8")
    start, end = text.find(BLOCK_START), text.find(BLOCK_END)
    if start < 0 or end < start:
        return False
    readme.write_text(text[:start] + block + text[end + len(BLOCK_END) :], encoding="utf-8")
    return True


def main() -> None:
    cases, missing = load_cases(ALL_DATASETS)
    runs = load_runs()
    text = render(cases, runs, missing)
    robustness_file = RESULTS / "robustness" / "robustness.json"
    robustness_data = json.loads(robustness_file.read_text(encoding="utf-8")) if robustness_file.exists() else None
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))["outcomes"] if BASELINE.exists() else None
    if missing:
        print("README not updated: a dataset is missing, so the summary would be incomplete")
    elif update_readme(render_summary(cases, runs, robustness_data, baseline)):
        print(f"updated the results block in {README}")
    if baseline and "static" in runs:
        text += render_tuning(cases, baseline, runs["static"]["outcomes"])
    if robustness_data:
        text += render_robustness(robustness_data)
    (RESULTS / "RESULTS.md").write_text(text, encoding="utf-8")
    print(f"wrote {RESULTS / 'RESULTS.md'}")


if __name__ == "__main__":
    main()
