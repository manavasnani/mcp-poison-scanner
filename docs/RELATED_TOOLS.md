# Related tools

Two established scanners cover similar ground. This project measures itself against one of them and
describes the other.

| | Cisco mcp-scanner | Snyk Agent Scan |
| --- | --- | --- |
| Role in this project | **Measured comparison** | Described only, not measured |
| Runs without a vendor account | Yes, in YARA mode | No, needs a Snyk API token |
| Where analysis happens | Locally (YARA); optional LLM and Cisco API analyzers | Tool metadata is sent to Snyk's API |

## Snyk Agent Scan

Formerly `mcp-scan` from Invariant Labs, now maintained by Snyk: <https://github.com/snyk/agent-scan>.

**Everything in this section comes from Snyk's own documentation and third-party write-ups. I could
not verify any of it, because I could not complete a scan.**

What it is documented to do:

- Discover agent configurations on a machine (Claude Desktop, VS Code, Cursor and similar) and scan the
  MCP servers they list, or scan a specific config file passed on the command line.
- Connect to each server and check its tool descriptions for prompt injection and tool poisoning, using
  local checks plus analysis through Snyk's API.
- Scan agent skills as well as MCP servers.
- Pin tools by hash, so that a later change to a tool's definition is detected (rug-pull detection).
  The pin records that a tool changed.
- Optionally run as a runtime proxy that monitors live tool calls. This project does not do runtime
  proxying at all.
- Ask for consent before launching each stdio server, with `--dangerously-run-mcp-servers` to skip the
  prompts. I did observe this part: it listed my three servers and asked before starting each one.
- Output JSON with `--json`.

### Why it is not in my benchmark

On 2026-11-11 I ran `uvx snyk-agent-scan@latest fixtures/mcp.json --json` with a valid `SNYK_TOKEN`
against three small fixture servers. The scan failed with:

> Daily usage limit reached for the public version of Agent-Scan.

No findings were returned. A Snyk maintainer states in
[issue #527](https://github.com/snyk/agent-scan/issues/527) that the free public version has a limited
analysis budget per day, and users there report that a personal token does not lift it. A benchmark of
more than a thousand cases is not possible under that limit, so I left Snyk Agent Scan out of every
measured table in this project. That is a statement about access, not about its detection quality,
which I did not get to observe.

## Cisco mcp-scanner

<https://github.com/cisco-ai-defense/mcp-scanner>, PyPI package `cisco-ai-mcp-scanner`.

- Analyzers: YARA rules (local, no key), an LLM judge (needs an LLM API key) and the Cisco AI Defense
  API (needs a Cisco key), plus several others for source code and packages.
- Inputs: live stdio or remote servers, known client configs, or static JSON files of
  `tools/list`, `prompts/list` and `resources/list` output.
- No tool pinning or change tracking.

My first observations of version 4.8.7 in YARA mode are in [RECON.md](RECON.md). The benchmark
numbers are in [benchmarks/results/RESULTS.md](../benchmarks/results/RESULTS.md).
