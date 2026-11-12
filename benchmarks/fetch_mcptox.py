"""Download MCPTox into ``datasets/raw/mcptox`` at the exact commit the results were measured on.

    uv run python -m benchmarks.fetch_mcptox

MCPTox (https://github.com/zhiqiangwang4/MCPTox-Benchmark, paper arXiv:2508.14925)
has no license, so it is fetched here and never committed to this repository. Its
``def_tool/`` Python files are attack samples: they are downloaded as part of the
clone but never imported or run. Only ``response_all.json`` is read, as data.
"""

from __future__ import annotations

import shutil
import subprocess
import sys

from benchmarks.cases import MCPTOX_FILE

REPO = "https://github.com/zhiqiangwang4/MCPTox-Benchmark"
COMMIT = "f85189f"


def main() -> None:
    target = MCPTOX_FILE.parent
    git = shutil.which("git")
    if git is None:
        sys.exit("error: git is not installed")
    if MCPTOX_FILE.exists():
        print(f"already present: {MCPTOX_FILE}")
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run([git, "clone", REPO, str(target)], check=True)  # noqa: S603 - fixed argv
    subprocess.run([git, "-C", str(target), "checkout", "--quiet", COMMIT], check=True)  # noqa: S603
    print(f"MCPTox at commit {COMMIT} in {target}")


if __name__ == "__main__":
    main()
