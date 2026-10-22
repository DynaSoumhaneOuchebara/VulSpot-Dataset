---
pretty_name: VulSpot
dataset_name: VulSpot
configs:
  - config_name: cpp
    data_files:
      - split: full
        path: cpp/full/data.parquet
      - split: balanced
        path: cpp/balanced/data.parquet
  - config_name: multi
    data_files:
      - split: full
        path: multi/full/data.parquet
      - split: balanced
        path: multi/balanced/data.parquet
---

# VulSpot

VulSpot is a statement-level dataset for **vulnerability detection, CWE classification, and localization**.
It follows the SecVulEval collection pipeline (NVD CVEs with a `Patch` tag, GitHub fixing commits, function extraction, filtering) through 2026, and adds AST-level statement diffs, sink-candidate anchors for additive fixes, label-confidence tiers, untouched negatives, and deterministic local context. It does **not** include the LLM-generated §3.4 context of SecVulEval.

```python
from datasets import load_dataset

cpp = load_dataset("DynaOuchebara/VulSpot", "cpp", split="full")
multi = load_dataset("DynaOuchebara/VulSpot", "multi", split="full")
```

## Configs

| config | contents |
|---|---|
| `cpp` | C/C++ only (`.c/.cc/.cpp/.h/.hpp/...`) |
| `multi` | every supported language, with a `language` column |

Each config has two splits:

- `full` — every row that survived structural filters
- `balanced` — `full` with a per-year cap on post-2024 kernel.org-CNA Linux CVEs (see `is_kernel_cna`)

Chronological and project-holdout index files live next to the parquet (`splits/chrono.json`, `splits/project_holdout.json`). They refer to the `idx` column.

## Collection

1. **NVD** (API 2.0): all non-rejected CVEs, windowed by publication date, incremental via `lastModified`.
2. **Patch commits**: references tagged `Patch` whose URL is a GitHub commit (plus `git.kernel.org` remapped to `torvalds/linux`). Other hosts are counted in the pipeline report and not fetched. Forks are kept only if the SHA exists on the parent, and are attributed to the parent.
3. **Commit artifacts**: GitHub REST + `raw.githubusercontent.com` (message, unified diff, before/after file contents). Merge commits are dropped.
4. **Functions**: tree-sitter extraction; before/after pairing by name + signature + order; statement-unit AST diff.
5. **Filters**: extension filter; multi-commit CVEs dropped; files with no in-function edits dropped; tangled-change heuristic becomes a **confidence tier** rather than a hard drop (unmentioned functions in multi-function files are still dropped).

## Label semantics

Two localization layers:

- `changed_lines` / `changed_statements` (`fix_*`): SecVulEval semantics. On a vulnerable row these are the **deleted/updated** statements; on a fixed row, the **added/updated** ones. Serialized as JSON strings `[[line, text], ...]` with file-absolute line numbers so existing SecVulEval loaders work.
- `sink_candidates` (vulnerable rows only): deleted + updated statements, plus insertion anchors in the vulnerable version (the next statement, or, for a guard `if (...) return/goto/break/continue`, the first later use of a guard identifier). Each entry has abs/rel line, byte range, text, and `kind`.

`is_vulnerable` is the function-level flag. `cwe_list` / `cwe_1003_list` are the type labels (raw NVD CWEs and the CWE-1003 simplified-mapping view).

### Confidence tiers (`label_confidence`)

- `high` — the commit changes exactly one function (test files excluded), or the function is named in a linked CVE description
- `medium` — the only changed function in its file, but the commit touches several files
- `low` — several functions changed in the file; this one is named in the commit message

### Negatives (`neg_type`)

- `fixed` — patched version of a vulnerable function
- `untouched` — unchanged function from a file that also contains a changed function
- `patched_later_vulnerable` — a `fixed` row whose function is modified again by a later CVE commit in this dataset (`later_fixed_by`)

`clean` is true when `label_confidence ∈ {high, medium}` (or the row is an untouched negative), `label_conflict` is false, and `neg_type` is not `patched_later_vulnerable`.

`is_kernel_cna` flags CVEs assigned by the kernel.org CNA with `published_date ≥ 2024-02-01`.

## Splits

- `splits/chrono.json` — 80/10/10 by CVE `published_date`, then clone-group aware (`clone_group_id`): a row whose near-duplicate group already appears in an earlier split (train < val < test) is excluded, so train never contains rows newer than test.
- `splits/project_holdout.json` — a random ~10% of rows, taken as whole projects, as test (Linux always stays in train/val); the rest split chronologically into train/val. Same clone-group exclusion.

Both files also contain evaluation subsets of `test`:

- `test_high` — `clean` test rows, without vulnerable rows whose `label_confidence` is not `high` (all negatives kept)
- `test_paired_high` — high-confidence vulnerable rows whose fixed version is also in test, plus those fixed versions (PrimeVul-style paired evaluation)
- `test_no_linux` — test without `torvalds/linux` rows

In `balanced`, the post-2024 kernel CVEs kept each year are a seeded sample spread over the year, so chronological val/test still contain some Linux.

Exact duplicates use `hash` (md5 of per-line-stripped body). `norm_hash` drops comments/whitespace. `clone_group_id` is MinHash-LSH (5-shingles, Jaccard ≥ 0.8).

## Licensing

Function bodies are reproduced **verbatim** from the original open-source repositories for research. Each row points back to its source via `project_url` and `commit_id`. The code remains under the license of its original project. **This dataset does not grant or claim a single license covering the code.**
