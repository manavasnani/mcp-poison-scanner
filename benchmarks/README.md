# Benchmark

Measures how many poisoned MCP items each scanner flags, and how many clean ones it flags by
mistake. Results are in [results/RESULTS.md](results/RESULTS.md), which is generated; never edit
it by hand.

## Run it

```sh
uv run python -m benchmarks.fetch_mcptox                 # once: downloads MCPTox (not redistributed here)
python benchmarks/datasets/own/build_cases.py            # once: writes our own cases
uv run python -m benchmarks.run static                   # free, seconds
uv run python -m benchmarks.run cisco-yara               # free, about a minute
uv run python -m benchmarks.run judge --pass 1 --max-cost 22          # paid: Claude API
uv run python -m benchmarks.run judge --pass 2 --sample 500 --max-cost 12
uv run python -m benchmarks.run cisco-llm --llm-model anthropic/claude-opus-4-8 --sample 250   # paid
uv run python -m benchmarks.robustness --passes 3 --max-cost 3        # paid: can the judge be argued out of a verdict?
uv run python -m benchmarks.report                       # rebuilds results/RESULTS.md and the README's results block
```

Paid runs save every answer in `results/cache/` (git-ignored, because it quotes dataset text), so
a rerun continues where the last one stopped and costs nothing for answers it already has.
`--max-cost` stops the judge from sending more once that many dollars are spent. Cisco's scanner
is started through `uv`; set `BENCH_UV` (for example `"C:\Python312\python.exe -m uv"`) if `uv`
is not on your PATH.

## Datasets

| Set | Positives | Negatives | Source |
| --- | --- | --- | --- |
| MCPTox | 1,312 poisoned tools | 362 clean tools from the same 45 real servers | [paper](https://arxiv.org/abs/2508.14925v1), [repo](https://github.com/zhiqiangwang4/MCPTox-Benchmark) at commit `f85189f` |
| Own cases | 43 handcrafted attacks | 15 honest tools worded to look suspicious | `datasets/own/build_cases.py` |
| Real servers | none | 196 items from 18 widely used servers | `collect_clean.py`; versions in `datasets/clean_servers/VERSIONS.txt` |
| Signed-in servers | none | 207 items from 3 commercial servers | `datasets/signed_in_servers/`, saved with `scanner collect --url ... --sign-in` on 2026-11-12 |

- **MCPTox** stores tools as text (`Tool:` / `Description:` / `Arguments:`), which `cases.py`
  parses into tool definitions. The 36 instances its authors marked invalid are left out. The 362
  clean tools are every tool block in the servers' prompts; the dataset's own list names 353,
  because one server (Apify) shows 16 tools but lists 7.
- **MCPTox only poisons the top-level description.** The own cases cover the rest: poison in
  parameters, enums, defaults, prompts, resources and server instructions; text hidden from a
  human reader; and servers that change after being approved.
- **MCPTox has no license**, so it is downloaded at run time and never committed.
- **Real servers** are 13 reference servers and 5 vendor servers (Notion, Firecrawl, Tavily, Exa,
  Context7), each started in the sandbox with no network. Every tool, prompt,
  resource, resource template and non-empty server instruction is one clean item. Four servers
  (gitlab, redis, playwright, sqlite) would not list anything without a network or a real account.
  The set assumes these published servers are honest; nobody audited them line by line.
- **Signed-in servers** are Notion, Apify and Apollo as they answer a signed-in account: 188 tools
  plus prompts, resources and server instructions. Their descriptions are much longer and give the
  model many more orders than the servers above, which is why they are a separate set. They are
  assumed honest too, and that is a judgement: one Apollo tool tells the model to call it without
  asking the user first, which is counted here as a false alarm although a careful reader may not
  agree. Cisco's LLM analyzer has not been run on this set.
- **MCPTox is split into a dev half and a held-out half** by a hash of each server's name
  (`cases.mcptox_part`): 25 servers and 20 servers. See the tuning note below.

## How a case is scored

Each case is one item with a known label, scanned inside the server it belongs to (a poisoned
MCPTox tool is added to its server's real tools, as in the paper). A scanner gets credit only for
flagging that item; a finding on a neighbouring tool does not count.

- **Our static rules:** the TP rules only. The capability rules (CAP) are left out because they
  describe risk on honest servers, not poisoning. Rug-pull cases also get the pin diff (RP001).
- **Our judge:** one request per item. Items the model would not classify are listed separately
  and counted as not flagged.
- **Cisco mcp-scanner:** static mode, one analyzer at a time, default settings. Server-level
  instructions and resource templates cannot be given to its static mode, and it skips some
  resources without a verdict. These count as not flagged: a miss on a poisoned item, and no false
  positive on a clean one, so its false-positive rate on real servers is slightly flattered.

Every rate has a 95% Wilson confidence interval next to it.

## Judge robustness

`robustness_cases.py` holds four poisoned tools and 26 copies of them that also try to talk the
reviewer out of flagging them, one technique each: a claim of prior approval, an order to answer
"benign", a forged end-of-data marker, a ready-made verdict, a fake system message, a note hidden in
invisible characters, and so on. `robustness.py` asks three scanners about each:

- **Our judge as shipped:** instructions in the system prompt, metadata as escaped JSON inside a
  fence with a one-time code, answer forced into a fixed schema.
- **The same model asked naively:** one message with a short instruction and the tool's text pasted
  in, answer read from free text. This is the comparison that shows what the hardening changes.
- **Our static rules**, which cannot be persuaded.

What the run showed, and what it did not:

- **No scanner called a poisoned tool clean, in any pass.** That includes the naive prompt, so on
  these cases the hardening made no measurable difference. The result says the current model resists
  these tricks however it is asked; it does not show that the fence or the schema is what stops them.
- **The hardened judge left one case without a verdict in all three passes** (the note hidden in
  invisible characters): the model's safety filter and the fallback's both declined it. The scanner
  reports that as not judged and exits 1, so it fails closed, but the naive prompt did get an answer.
- **Every hardened request was answered by the fallback model.** Claude Opus 5.5 declined all of them.
- **The cases are 26, written by the author of the judge prompt, in English, one try each.** An
  attacker who can test against the judge and iterate has a much better chance than this set.
- **A wrong verdict is the only failure measured.** The judge has no tools, so there is nothing else
  an injection could make it do.

## Read the results with these limits in mind

- **The static rules were tuned once, on 2026-11-12, and the numbers are for the tuned rules.**
  The first published run was of rules finished before MCPTox was ever run. Their outcomes are
  frozen in `results/baseline/static-v1.json`, and RESULTS.md has a before-and-after table. What
  prompted the change: scanning three commercial servers while signed in gave a high-severity
  finding on 13% of their items, almost all of them ordinary vendor guidance.
- **What was looked at while tuning:** the three signed-in servers, the false alarms on the real
  servers and the own cases, and the dev half of MCPTox (its misses and its false alarms). No
  held-out case was read or printed; that half was only ever counted. So the held-out rows are the
  evidence that the changes generalise, and the dev and signed-in rows are not independent.
- **The held-out half is weaker evidence than it looks.** MCPTox builds its poisoned tools from
  three templates, and both halves use the same three. Splitting by server shows the rules did not
  learn particular servers; it cannot show they would catch an attacker who writes differently.
- **What changed:**
  - TP001: "always call this first" and "before using this tool you must" are written by honest
    servers too. Alone they are now low severity; with a secret location in the same text, high.
    Secrecy patterns no longer match advice on wording ("do not tell the user it has finished").
    New patterns: claiming priority over the user's request, telling the model to change what the
    user asked for, demanding to run before every other tool. "instructionsand" (two words run
    together, common in MCPTox) no longer slips past a word boundary.
  - TP004: now also reports a tool whose text sets conditions on a *different* tool of the same
    server ("before using read_file, call set_config"), at high severity. Before, references
    within one server were always ignored, and MCPTox adds its poisoned tool to the target's own
    server. Names that carry the server's shared prefix count as the server's own tools.
  - TP006: a parameter description must ask for the conversation, prompt or secrets, not merely
    name them ("do not include credentials" and "shown instead of the full transcript" are quiet).
- **What was left alone:** the three own benign cases still raise a finding (a tool about `.env`
  files, a short HTML comment, a prompt-injection detector quoting an attack). A rule that passed
  them would be trivial to evade. Most of what the rules still miss on MCPTox is a fake tool whose
  description says "to do this, call that other tool", which honest tools also say.
- **The own cases are not independent.** The same author wrote them and the rules, after the rules
  existed. They were frozen before the first run and show coverage, not an unbiased rate.
- **RP001 flags any change to a pinned item**, so "any severity" on rug-pull cases is close to
  automatic. The "high only" row is the meaningful one there.
- **The judge is not deterministic** (current Claude models accept no temperature setting), so
  repeat passes are run on a sample and their agreement is reported.
- **Cisco's LLM analyzer is run on a different Claude model than our judge.** Through its LLM
  library it has no fallback when a model's safety filter declines a request, and Claude Opus 5.5
  declined most poisoned test items, so it is run on Claude Opus 4.8. Its Cisco AI Defense API
  analyzer needs a paid subscription and is not run.
- **Costs are computed from token counts and list prices** recorded in `scanners.py`. Cisco's
  scanner does not report token use, so its API cost is not in the table.
