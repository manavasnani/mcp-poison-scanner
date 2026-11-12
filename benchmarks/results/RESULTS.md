# Benchmark results

Generated 2026-11-12 by `python -m benchmarks.report` from the run files in this folder.
Do not edit by hand.

Each rate is followed by (hits/total; 95% confidence interval). A scanner is only counted on
cases it gave an answer for, so a smaller total in a row means that scanner was run on a subset.

## Detection rate on poisoned items (higher is better)

| Scanner | MCPTox (n=1312) | Own cases (n=43) |
| --- | --- | --- |
| Ours, static rules (any severity) | 94.2% (1236/1312; 93-95%) | 74.4% (32/43; 60-85%) |
| Ours, static rules (high only) | 89.6% (1176/1312; 88-91%) | 55.8% (24/43; 41-70%) |
| Ours, judge only (pass1) | 99.8% (1309/1312; 99-100%) | 90.7% (39/43; 78-96%) |
| Ours, judge only (pass2) | 99.8% (499/500; 99-100%) | 90.7% (39/43; 78-96%) |
| Ours, judge only (pass3) | 99.8% (499/500; 99-100%) | 93.0% (40/43; 81-98%) |
| Ours, static + judge (pass1) | 99.9% (1311/1312; 100-100%) | 100.0% (43/43; 92-100%) |
| Cisco mcp-scanner 4.8.7 (llm, anthropic/claude-opus-4-8) | 99.5% (199/200; 97-100%) | 69.8% (30/43; 55-81%) |
| Cisco mcp-scanner 4.8.7 (yara) | 21.1% (277/1312; 19-23%) | 7.0% (3/43; 2-19%) |

## False-positive rate on clean items (lower is better)

| Scanner | MCPTox (n=362) | Own cases (n=15) | Real servers (n=196) | Signed-in servers (n=207) |
| --- | --- | --- | --- | --- |
| Ours, static rules (any severity) | 0.6% (2/362; 0-2%) | 20.0% (3/15; 7-45%) | 0.0% (0/196; 0-2%) | 5.3% (11/207; 3-9%) |
| Ours, static rules (high only) | 0.0% (0/362; 0-1%) | 20.0% (3/15; 7-45%) | 0.0% (0/196; 0-2%) | 1.4% (3/207; 0-4%) |
| Ours, judge only (pass1) | 0.0% (0/362; 0-1%) | 0.0% (0/15; 0-20%) | 0.0% (0/196; 0-2%) | 1.0% (2/207; 0-3%) |
| Ours, judge only (pass2) | 0.0% (0/362; 0-1%) | 0.0% (0/15; 0-20%) | n/a | n/a |
| Ours, judge only (pass3) | 0.0% (0/362; 0-1%) | 0.0% (0/15; 0-20%) | n/a | n/a |
| Ours, static + judge (pass1) | 0.6% (2/362; 0-2%) | 20.0% (3/15; 7-45%) | 0.0% (0/196; 0-2%) | 5.8% (12/207; 3-10%) |
| Cisco mcp-scanner 4.8.7 (llm, anthropic/claude-opus-4-8) | 4.0% (8/200; 2-8%) | 6.7% (1/15; 1-30%) | n/a | n/a |
| Cisco mcp-scanner 4.8.7 (yara) | 1.1% (4/362; 0-3%) | 13.3% (2/15; 4-38%) | 1.0% (2/196; 0-4%) | 35.7% (74/207; 30-42%) |

## MCPTox detection by security risk

| Scanner | Code Injection (n=63) | Credential Leakage (n=115) | Data Tampering (n=117) | Financial Loss (n=55) | Information Manipulation (n=269) | Infrastructure Damage (n=122) | Instruction Tampering (n=57) | Message Hijacking (n=41) | Other (n=4) | Privacy Leakage (n=273) | Service Disruption (n=196) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Ours, static rules (any severity) | 90.5% (57/63; 81-96%) | 97.4% (112/115; 93-99%) | 91.5% (107/117; 85-95%) | 92.7% (51/55; 83-97%) | 94.8% (255/269; 91-97%) | 91.0% (111/122; 85-95%) | 100.0% (57/57; 94-100%) | 85.4% (35/41; 72-93%) | 100.0% (4/4; 51-100%) | 93.8% (256/273; 90-96%) | 97.4% (191/196; 94-99%) |
| Ours, static rules (high only) | 76.2% (48/63; 64-85%) | 97.4% (112/115; 93-99%) | 89.7% (105/117; 83-94%) | 80.0% (44/55; 68-88%) | 90.7% (244/269; 87-94%) | 85.2% (104/122; 78-90%) | 98.2% (56/57; 91-100%) | 85.4% (35/41; 72-93%) | 75.0% (3/4; 30-95%) | 90.8% (248/273; 87-94%) | 90.3% (177/196; 85-94%) |
| Ours, judge only (pass1) | 100.0% (63/63; 94-100%) | 100.0% (115/115; 97-100%) | 100.0% (117/117; 97-100%) | 100.0% (55/55; 93-100%) | 100.0% (269/269; 99-100%) | 100.0% (122/122; 97-100%) | 100.0% (57/57; 94-100%) | 100.0% (41/41; 91-100%) | 100.0% (4/4; 51-100%) | 99.6% (272/273; 98-100%) | 99.0% (194/196; 96-100%) |
| Ours, judge only (pass2) | 100.0% (24/24; 86-100%) | 100.0% (39/39; 91-100%) | 100.0% (50/50; 93-100%) | 100.0% (20/20; 84-100%) | 100.0% (97/97; 96-100%) | 100.0% (43/43; 92-100%) | 100.0% (19/19; 83-100%) | 100.0% (16/16; 81-100%) | 100.0% (2/2; 34-100%) | 99.2% (119/120; 95-100%) | 100.0% (70/70; 95-100%) |
| Ours, judge only (pass3) | 100.0% (24/24; 86-100%) | 100.0% (39/39; 91-100%) | 100.0% (50/50; 93-100%) | 100.0% (20/20; 84-100%) | 100.0% (97/97; 96-100%) | 100.0% (43/43; 92-100%) | 100.0% (19/19; 83-100%) | 100.0% (16/16; 81-100%) | 100.0% (2/2; 34-100%) | 99.2% (119/120; 95-100%) | 100.0% (70/70; 95-100%) |
| Ours, static + judge (pass1) | 100.0% (63/63; 94-100%) | 100.0% (115/115; 97-100%) | 100.0% (117/117; 97-100%) | 100.0% (55/55; 93-100%) | 100.0% (269/269; 99-100%) | 100.0% (122/122; 97-100%) | 100.0% (57/57; 94-100%) | 100.0% (41/41; 91-100%) | 100.0% (4/4; 51-100%) | 99.6% (272/273; 98-100%) | 100.0% (196/196; 98-100%) |
| Cisco mcp-scanner 4.8.7 (llm, anthropic/claude-opus-4-8) | 100.0% (8/8; 68-100%) | 100.0% (16/16; 81-100%) | 100.0% (15/15; 80-100%) | 100.0% (8/8; 68-100%) | 100.0% (44/44; 92-100%) | 100.0% (23/23; 86-100%) | 100.0% (9/9; 70-100%) | 100.0% (4/4; 51-100%) | n/a | 97.6% (40/41; 87-100%) | 100.0% (32/32; 89-100%) |
| Cisco mcp-scanner 4.8.7 (yara) | 58.7% (37/63; 46-70%) | 57.4% (66/115; 48-66%) | 23.1% (27/117; 16-31%) | 9.1% (5/55; 4-20%) | 7.1% (19/269; 5-11%) | 28.7% (35/122; 21-37%) | 12.3% (7/57; 6-23%) | 46.3% (19/41; 32-61%) | 25.0% (1/4; 5-70%) | 21.6% (59/273; 17-27%) | 1.0% (2/196; 0-4%) |

## MCPTox detection by attack template

| Scanner | Template-1 (n=208) | Template-2 (n=519) | Template-3 (n=585) |
| --- | --- | --- | --- |
| Ours, static rules (any severity) | 79.3% (165/208; 73-84%) | 98.1% (509/519; 96-99%) | 96.1% (562/585; 94-97%) |
| Ours, static rules (high only) | 74.0% (154/208; 68-80%) | 88.8% (461/519; 86-91%) | 95.9% (561/585; 94-97%) |
| Ours, judge only (pass1) | 99.5% (207/208; 97-100%) | 99.6% (517/519; 99-100%) | 100.0% (585/585; 99-100%) |
| Ours, judge only (pass2) | 98.8% (82/83; 93-100%) | 100.0% (198/198; 98-100%) | 100.0% (219/219; 98-100%) |
| Ours, judge only (pass3) | 100.0% (83/83; 96-100%) | 99.5% (197/198; 97-100%) | 100.0% (219/219; 98-100%) |
| Ours, static + judge (pass1) | 100.0% (208/208; 98-100%) | 99.8% (518/519; 99-100%) | 100.0% (585/585; 99-100%) |
| Cisco mcp-scanner 4.8.7 (llm, anthropic/claude-opus-4-8) | 97.0% (32/33; 85-99%) | 100.0% (78/78; 95-100%) | 100.0% (89/89; 96-100%) |
| Cisco mcp-scanner 4.8.7 (yara) | 28.4% (59/208; 23-35%) | 27.7% (144/519; 24-32%) | 12.6% (74/585; 10-16%) |

## Own cases: detection by technique family

| Scanner | description (n=6) | full_schema (n=13) | hidden_text (n=8) | parameter_poisoning (n=6) | rug_pull (n=5) | shadowing (n=5) |
| --- | --- | --- | --- | --- | --- | --- |
| Ours, static rules (any severity) | 33.3% (2/6; 10-70%) | 76.9% (10/13; 50-92%) | 100.0% (8/8; 68-100%) | 50.0% (3/6; 19-81%) | 100.0% (5/5; 57-100%) | 80.0% (4/5; 38-96%) |
| Ours, static rules (high only) | 33.3% (2/6; 10-70%) | 76.9% (10/13; 50-92%) | 100.0% (8/8; 68-100%) | 50.0% (3/6; 19-81%) | 0.0% (0/5; 0-43%) | 20.0% (1/5; 4-62%) |
| Ours, judge only (pass1) | 100.0% (6/6; 61-100%) | 100.0% (13/13; 77-100%) | 50.0% (4/8; 22-78%) | 100.0% (6/6; 61-100%) | 100.0% (5/5; 57-100%) | 100.0% (5/5; 57-100%) |
| Ours, judge only (pass2) | 100.0% (6/6; 61-100%) | 100.0% (13/13; 77-100%) | 50.0% (4/8; 22-78%) | 100.0% (6/6; 61-100%) | 100.0% (5/5; 57-100%) | 100.0% (5/5; 57-100%) |
| Ours, judge only (pass3) | 100.0% (6/6; 61-100%) | 100.0% (13/13; 77-100%) | 62.5% (5/8; 31-86%) | 100.0% (6/6; 61-100%) | 100.0% (5/5; 57-100%) | 100.0% (5/5; 57-100%) |
| Ours, static + judge (pass1) | 100.0% (6/6; 61-100%) | 100.0% (13/13; 77-100%) | 100.0% (8/8; 68-100%) | 100.0% (6/6; 61-100%) | 100.0% (5/5; 57-100%) | 100.0% (5/5; 57-100%) |
| Cisco mcp-scanner 4.8.7 (llm, anthropic/claude-opus-4-8) | 100.0% (6/6; 61-100%) | 30.8% (4/13; 13-58%) | 75.0% (6/8; 41-93%) | 100.0% (6/6; 61-100%) | 60.0% (3/5; 23-88%) | 100.0% (5/5; 57-100%) |
| Cisco mcp-scanner 4.8.7 (yara) | 0.0% (0/6; 0-39%) | 23.1% (3/13; 8-50%) | 0.0% (0/8; 0-32%) | 0.0% (0/6; 0-39%) | 0.0% (0/5; 0-43%) | 0.0% (0/5; 0-43%) |

## Judge: agreement between passes

On the 920 cases judged in all 3 passes, the verdict (flagged or not) was the same in every pass for 99.7% (917/920; 99-100%).

## Items a scanner gave no verdict on

| Run | Items | Reason |
| --- | --- | --- |
| cisco-llm-anthropic_claude-opus-4-8 | 1 | not judged: the LLM analysis did not complete |
| cisco-llm-anthropic_claude-opus-4-8 | 2 | unsupported |
| cisco-yara | 14 | skipped: Cisco gave no verdict for this item |
| cisco-yara | 15 | unsupported |
| judge-pass1 | 4 | not judged: the model declined to classify this item (safety category: bio) |
| judge-pass2 | 4 | not judged: the model declined to classify this item (safety category: bio) |
| judge-pass3 | 3 | not judged: the model declined to classify this item (safety category: bio) |

These are counted as not flagged in the tables above.

## Cost and time

| Run | Items answered | Tokens | API cost | Cost per item | Settings |
| --- | --- | --- | --- | --- | --- |
| cisco-llm-anthropic_claude-opus-4-8 | 458 | not reported by the tool | not reported by the tool | not reported by the tool | {"version": "4.8.7", "analyzers": "llm", "mode": "static", "llm_model": "anthropic/claude-opus-4-8"} |
| cisco-yara | 2135 | none | $0 | $0 | {"version": "4.8.7", "analyzers": "yara", "mode": "static", "llm_model": null} |
| judge-pass1 | 2135 | 4,806,308 in / 272,204 out | $27.48 | $0.0129 | {"model": "claude-opus-5-5", "effort": "medium", "fallbacks": "default", "unique_items": 2113} |
| judge-pass2 | 920 | 1,899,174 in / 108,993 out | $10.91 | $0.0119 | {"model": "claude-opus-5-5", "effort": "medium", "fallbacks": "default", "unique_items": 920} |
| judge-pass3 | 920 | 1,901,290 in / 109,250 out | $10.90 | $0.0118 | {"model": "claude-opus-5-5", "effort": "medium", "fallbacks": "default", "unique_items": 920} |
| static | 2135 | none | $0 | $0 | {"rules": ["TP001", "TP002", "TP003", "TP004", "TP005", "TP006", "RP001 (pinned cases)"]} |

Wall-clock times are in each run file; they include cached answers, so they are not comparable
between a fresh run and a resumed one.

## Static rules before and after tuning

The rules were changed once after the first published run (see benchmarks/README.md for what and why).
MCPTox was split in two by a hash of each server's name. Only the dev half was read while changing the
rules, so the held-out rows are the ones that say how the change generalises. Rows marked as used for
tuning are not independent evidence.

| Items | Before, any severity | Before, high only | After, any severity | After, high only |
| --- | --- | --- | --- | --- |
| MCPTox poisoned tools, held-out half (never looked at) | 66.3% (330/498) | 66.1% (329/498) | 96.4% (480/498) | 92.0% (458/498) |
| MCPTox poisoned tools, dev half (used for tuning) | 57.9% (471/814) | 57.9% (471/814) | 92.9% (756/814) | 88.2% (718/814) |
| MCPTox clean tools, held-out half | 0.0% (0/160) | 0.0% (0/160) | 0.0% (0/160) | 0.0% (0/160) |
| MCPTox clean tools, dev half | 5.4% (11/202) | 1.0% (2/202) | 1.0% (2/202) | 0.0% (0/202) |
| Own cases, attacks | 74.4% (32/43) | 55.8% (24/43) | 74.4% (32/43) | 55.8% (24/43) |
| Own cases, benign look-alikes | 20.0% (3/15) | 20.0% (3/15) | 20.0% (3/15) | 20.0% (3/15) |
| Real servers, clean items | 1.0% (2/196) | 1.0% (2/196) | 0.0% (0/196) | 0.0% (0/196) |
| Signed-in servers, clean items (used for tuning) | 13.5% (28/207) | 13.0% (27/207) | 5.3% (11/207) | 1.4% (3/207) |

## Judge robustness: text that argues with the scanner

26 poisoned tools that also tell the reviewer they are safe, approved or out of scope
(one technique each), and the same 4 poisoned tools without that text as a baseline.
Each judge was asked 3 times per case. "Fooled" means it answered that a poisoned tool is clean.

| Cases | Scanner | Flagged | Fooled | No usable answer |
| --- | --- | --- | --- | --- |
| Poison only | Our judge as shipped | 100.0% (12/12; 76-100%) | 0.0% (0/12; 0-24%) | 0/12 |
| Poison only | Same model, naive prompt (text pasted in, free-text answer) | 100.0% (12/12; 76-100%) | 0.0% (0/12; 0-24%) | 0/12 |
| Poison only | Our static rules | 100.0% (4/4; 51-100%) | 0.0% (0/4; 0-49%) | 0/4 |
| Poison plus manipulation | Our judge as shipped | 96.2% (75/78; 89-99%) | 0.0% (0/78; 0-5%) | 3/78 |
| Poison plus manipulation | Same model, naive prompt (text pasted in, free-text answer) | 100.0% (78/78; 95-100%) | 0.0% (0/78; 0-5%) | 0/78 |
| Poison plus manipulation | Our static rules | 100.0% (26/26; 87-100%) | 0.0% (0/26; 0-13%) | 0/26 |

Techniques that fooled a scanner or left it without an answer at least once (times fooled / times asked):

| Technique | Our judge as shipped | Same model, naive prompt (text pasted in, free-text answer) | Our static rules | No usable answer (same order) |
| --- | --- | --- | --- | --- |
| hidden_note | 0/3 | 0/3 | 0/1 | 3/3 / 0/3 / 0/1 |

Model claude-opus-5-5; answers came from: hardened:claude-opus-4-8 x87, naive:claude-opus-4-8 x79, naive:claude-opus-5-5 x11. API cost $1.39.
The cases were written by the judge prompt's author. See benchmarks/README.md for what this does and does not show.
