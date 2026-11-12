"""Run one scanner over the benchmark datasets and save its outcomes.

    uv run python -m benchmarks.run static
    uv run python -m benchmarks.run cisco-yara
    uv run python -m benchmarks.run judge --pass 1 --max-cost 25      # paid: Claude API
    uv run python -m benchmarks.run cisco-llm --llm-model anthropic/claude-opus-5-5 --max-items 20   # paid
    uv run python -m benchmarks.report                                 # rebuild results/RESULTS.md

Paid runs cache every answer, so rerunning continues where the last run stopped.
"""

from __future__ import annotations

import argparse
import json
import random
from datetime import UTC, datetime

from benchmarks import scanners
from benchmarks.cases import ALL_DATASETS, Case, load_cases
from benchmarks.report import RESULTS
from scanner.judge import DEFAULT_MODEL


def sample(cases: list[Case], per_group: int, seed: int) -> list[Case]:
    """At most ``per_group`` cases from each (dataset, label) group, chosen with a fixed seed."""
    groups: dict[tuple[str, str], list[Case]] = {}
    for case in cases:
        groups.setdefault((case.dataset, case.label), []).append(case)
    rng = random.Random(seed)  # noqa: S311 - reproducible sampling, not security
    picked: list[Case] = []
    for group in groups.values():
        picked += group if len(group) <= per_group else rng.sample(group, per_group)
    return picked


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scanner", choices=["static", "judge", "cisco-yara", "cisco-llm"])
    parser.add_argument("--datasets", nargs="+", default=ALL_DATASETS, choices=ALL_DATASETS)
    parser.add_argument("--sample", type=int, help="use at most this many cases per dataset and label")
    parser.add_argument("--seed", type=int, default=20261111)
    parser.add_argument("--pass", dest="pass_number", type=int, default=1, help="judge: which repeat this is")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="judge: Claude model")
    parser.add_argument("--max-cost", type=float, default=5.0, help="judge: stop sending at this many dollars")
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--llm-model", help="cisco-llm: LiteLLM model name")
    parser.add_argument("--max-items", type=int, help="cisco: stop after this many items")
    args = parser.parse_args()

    cases, missing = load_cases(args.datasets)
    for note in missing:
        print(f"skipping: {note}")
    if args.sample:
        cases = sample(cases, args.sample, args.seed)
    print(f"{len(cases)} cases")

    if args.scanner == "static":
        run = scanners.run_static(cases)
    elif args.scanner == "judge":
        run = scanners.run_judge(
            cases, model=args.model, pass_number=args.pass_number, workers=args.workers, max_cost=args.max_cost
        )
    elif args.scanner == "cisco-yara":
        run = scanners.run_cisco(cases, analyzer="yara", max_items=args.max_items)
    else:
        run = scanners.run_cisco(cases, analyzer="llm", llm_model=args.llm_model, max_items=args.max_items)

    data = run.to_json()
    data["generated"] = datetime.now(UTC).isoformat(timespec="seconds")
    data["sample"] = {"per_group": args.sample, "seed": args.seed} if args.sample else None
    RESULTS.mkdir(parents=True, exist_ok=True)
    out = RESULTS / f"{run.scanner}.json"
    out.write_text(json.dumps(data, indent=1, ensure_ascii=True) + "\n", encoding="utf-8")

    answered = [o for o in run.outcomes.values() if (o.error or "") != "not run"]
    flagged = sum(1 for o in answered if o.flagged)
    print(f"{run.scanner}: {flagged} of {len(answered)} items flagged, {run.seconds:.1f}s, ${run.cost_usd:.2f}")
    if run.stopped_early:
        print(f"note: {run.stopped_early}; rerun to continue")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
