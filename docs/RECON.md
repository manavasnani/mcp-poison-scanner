# Week 1 recon notes

## MCPTox dataset access and license

Checked 2026-11-03.

- Paper: [arXiv:2508.14925](https://arxiv.org/abs/2508.14925v1), [AAAI 2026](https://ojs.aaai.org/index.php/AAAI/article/view/40895)
- Dataset: the paper links only an anonymized review repo, <https://anonymous.4open.science/r/AAAI26-7C02>.
  It renders with JavaScript and couldn't be read automatically. **TODO: open in a browser, check that
  the files download, and look for a LICENSE.**
- License: the arXiv page shows only arXiv's non-exclusive distribution license, which covers the paper,
  not the data. No open-source license for the dataset has been found yet.
- If no license or no usable data: email the authors, or use the plan's fallback (rebuild a smaller
  set from the paper's attack templates and say so).

### Update 2026-11-11: public GitHub repo found

- Repo: <https://github.com/zhiqiangwang4/MCPTox-Benchmark> (last pushed 2025-12-03).
- Files: `pure_tool.json` (about 317 KB, likely the original clean tools), `response_all.json` (about 20.7 MB,
  likely the test cases with model responses), a `def_tool/` folder and `analysis.ipynb`. The README is
  effectively empty, so the file meanings are inferred from names and still need confirming.
- **License: none.** GitHub reports no license and there is no LICENSE file. With no license, the default
  is all rights reserved: I may download and run it for my own evaluation, but should not copy the data
  into this repo. Plan: a script that downloads it at benchmark time, plus citing the paper.
- TODO: ask the authors (open a GitHub issue) to add a license.

### MCPTox contents, checked 2026-11-11

Cloned commit `f85189f` (2025-12-03) into `benchmarks/datasets/raw/mcptox/` (git-ignored, not redistributed).
Inspected with read-only scripts; the contents are attack text and were treated as data only.

- **`response_all.json` is the dataset.** 45 servers, 353 declared clean tool names, 1,348 malicious
  instances. 1,312 have `wrong_data == "0"`, matching the paper's count; the other 36 are marked `"2"`
  and should be excluded.
- **Each instance** has `poisoned_tool` (text), `metadata.paradigm` (Template-1: 211, Template-2: 519,
  Template-3: 618), `metadata["security risk"]` (11 categories), and one `datas` entry with the query,
  system prompt, a model response and a label.
- **Poisoned tools are plain text, not JSON schemas.** Format: `Tool: NAME
Description: ...
Arguments: ...`.
  1,338 of the 1,348 strings are unique. No `inputSchema`. The poison is in the description.
- **Clean tools exist only as text** inside each server's `clean_system_promot` (sic), in the same
  `Tool: / Description: / Arguments:` format. 362 tool blocks parse out of those prompts versus 353
  declared names; the difference needs checking.
- **`pure_tool.json` is not clean tools**, despite the name. It holds 485 poisoned tool descriptions with
  their query, risk and paradigm, each pointing at a `def_tool/N.py` file.
- **`def_tool/`** has 485 small Python files, each an `@mcp.tool()` function whose docstring is the
  poisoned description. Only 14 have any parameters. Do not import or run these.
- 26 poisoned strings contain non-ASCII text; some annotation fields are in Chinese.

**What this means for the benchmark (Week 5):**

1. A loader must parse the `Tool: / Description: / Arguments:` text into tool dicts. There is no ready
   `tools/list` JSON.
2. MCPTox only exercises **description-level** poisoning. It cannot show the value of full-schema
   scanning (params, enums, defaults), hidden Unicode or rug-pull diffs. Those need my own cases,
   as the plan already says.
3. Negatives come from the clean tool text in the system prompts (about 353 tools).
4. MCPTox labels measure whether an *agent* was fooled. For a scanner, every one of the 1,312 poisoned
   tools counts as a positive regardless of that label.

## Comparison tools

Record exact version, install command, settings, API keys needed, and run date.

| | Snyk Agent Scan | Cisco mcp-scanner |
| --- | --- | --- |
| Version | | 4.8.7 (PyPI `cisco-ai-mcp-scanner`), run 2026-11-11 |
| Install | | `uv tool run --python 3.12 --from cisco-ai-mcp-scanner mcp-scanner` |
| Keys required | Snyk API token | None for `--analyzers yara` (confirmed). LLM and API analyzers need keys; not run |
| Command used | | `--analyzers yara --raw stdio --stdio-command PYTHON --stdio-arg SERVER.py`, and `--analyzers yara --raw static --tools/--prompts/--resources FILE` |

Targets: `fixtures/servers/clean.py`, `fixtures/servers/poisoned.py`, `fixtures/servers/rugpull_v1.py` then v2.
Saved listings are in `fixtures/snapshots/`.

### What each catches on `poisoned.py`

Expected attacks are in `POISONED_LOCATIONS` in `fixtures/servers/poisoned.py`.

| Attack (location) | Snyk | Cisco |
| --- | --- | --- |
| Server `instructions` | | Not tested: its `instructions` subcommand only takes a server URL, not stdio or a file |
| `add` description `<IMPORTANT>` + `~/.ssh/id_rsa` | | **Caught** (HIGH: coercive injection, credential harvesting, prompt injection) |
| `get_weather` Unicode tag chars in description | | Missed |
| `get_weather.city` zero-width + bidi in param description | | Missed |
| `convert_temperature` HTML comment / base64 / padding | | Missed (all three, tested separately too) |
| `lookup_contact` shadows `send_email` | | Missed |
| `translate.target` instruction in enum | | Missed |
| `translate.context` asks for conversation | | Missed alone; see note |
| `translate.mode` instruction in default | | Missed alone; see note |
| `run_command` shell capability | | Missed |
| `review_code` prompt description | | Missed (static `--prompts`) |
| `docs://readme` resource description | | Missed (static `--resources`) |
| False positives on `clean.py` | | None (3 tools, all SAFE) |
| Rug-pull v1 to v2: reports *what* changed? | | No pinning or diff. v1 all SAFE; v2 flags `get_fact` on its own text (HIGH: data exfiltration, prompt injection); new `fetch_url` tool not flagged |

### Cisco mcp-scanner 4.8.7, YARA only: notes

Raw output is in `docs/recon/cisco-4.8.7/`. Inputs for the isolated runs are in `docs/recon/isolated/`,
built by `docs/recon/make_isolated.py` (one attack per otherwise-bland tool).

- **Whole poisoned server:** 2 of 6 tools flagged (`add`, `translate`). Stdio and static modes agree.
- **`translate` is flagged only by a combination.** It scans parameters as well as descriptions, but no
  single poisoned parameter fires. The `context` description plus the `mode` default together trigger
  "credential harvesting" (`translate_ablation.static.raw.json`). So it does read defaults, but the
  instruction-in-enum, instruction-in-default and ask-for-conversation attacks each pass on their own.
- **Hidden text is not detected at all:** Unicode tag characters, zero-width splitting, bidi override,
  HTML comment, base64 blob and whitespace padding all come back SAFE.
- **Scope of this result:** YARA analyzer only, default rules. I did not run the LLM analyzer or the Cisco AI Defense
  API analyzer, which may catch more, and I did not test server instructions. This is 12 isolated
  cases on my own fixtures, not a benchmark number.
- **Windows note:** the `mcp-scanner.exe` shim failed with "Access is denied" right after install, so I
  ran it as `python -c "from mcpscanner.cli import cli_entry_point as m; m()" ...` in the same environment.

### Snyk Agent Scan: blocked by daily cap (2026-11-11)

First run of `uvx snyk-agent-scan@latest fixtures/mcp.json --json` with `SNYK_TOKEN` set failed with
"Daily usage limit reached for the public version of Agent-Scan". No findings were returned. Per [snyk/agent-scan issue #527](https://github.com/snyk/agent-scan/issues/527),
this is a per-day analysis budget on the free public API that a personal token does not lift.
**Decision (2026-11-11): I dropped Snyk Agent Scan from the measured comparison for the whole project.**
My benchmark compares against Cisco mcp-scanner only. I wrote up Snyk's documented capabilities
in [RELATED_TOOLS.md](RELATED_TOOLS.md). The Snyk columns in the tables above stay empty on purpose.
