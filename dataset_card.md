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
      - split: paired
        path: cpp/paired/data.parquet
  - config_name: multi
    data_files:
      - split: full
        path: multi/full/data.parquet
      - split: balanced
        path: multi/balanced/data.parquet
      - split: paired
        path: multi/paired/data.parquet
---

# VulSpot

VulSpot is a statement-level dataset for **vulnerability detection, CWE classification, and localization**.
It follows the SecVulEval collection pipeline (NVD CVEs with a `Patch` tag, GitHub fixing commits, function extraction, filtering) through 2026, and adds AST-level statement diffs, sink-candidate anchors for additive fixes, label-confidence tiers, untouched negatives, and deterministic local context. It does **not** include the LLM-generated §3.4 context of SecVulEval.

```python
from datasets import load_dataset

cpp = load_dataset("ods01/VulSpot", "cpp", split="full")
multi = load_dataset("ods01/VulSpot", "multi", split="full")
```

## Releases

> **Paper reference release: [`v2026-10-12`](https://huggingface.co/datasets/ods01/VulSpot/tree/v2026-10-12)** (CVEs published through 2026-10-12). This is the version described and evaluated in the paper; use it for reproducibility studies.

```python
cpp = load_dataset("ods01/VulSpot", "cpp", split="full", revision="v2026-10-12")
```

VulSpot is updated every month. Each release is a tag of this repository named after the last NVD publication day it covers (`v<YYYY-MM-DD>`), and loading without `revision` gives the latest one. Releases appear in the branch selector of the *Files and versions* tab, and can be listed with:

```python
from huggingface_hub import list_repo_refs
print(sorted(t.name for t in list_repo_refs("ods01/VulSpot", repo_type="dataset").tags))
```

The split files of a release are fetched the same way, e.g. `hf_hub_download("ods01/VulSpot", "cpp/full/splits/chrono.json", repo_type="dataset", revision="v2026-10-12")`. Each release's `version.json` records the window it covers.

## Configs

| config | contents |
|---|---|
| `cpp` | C/C++ only (`.c/.cc/.cpp/.h/.hpp/...`) |
| `multi` | every supported language, with a `language` column |

Each config has three splits:

- `full` — every row that survived structural filters
- `balanced` — `full` with a per-year cap on post-2024 kernel.org-CNA Linux CVEs (see `is_kernel_cna`)
- `paired` — `full` restricted to vulnerable functions whose fixed version is also in `full`, plus those fixed rows. A vulnerable function with no fixed row is dropped, as are untouched functions and functions added by the patch. `idx` and `fixed_func_idx` are the same values as in `full`, so the patched function is the row with `idx == fixed_func_idx`.

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
- `sink_candidates` (vulnerable rows only): deleted + updated statements, plus one anchor per group of consecutive inserted statements, in the vulnerable version. `anchor_dataflow`: the statement tied to the inserted code by a shared variable, with the rule in `anchor_rule`: `guard_use_strict` (inserted guard `if (...) return/goto/break/continue`: the first later use of a guard identifier), `guard_use_relaxed` (any other inserted `if`, same lookup), `status_def`, `init_use`, `release_acquire`, `lock_region`, `jump_enclosing`, `shared_ident`. `anchor_next` / `anchor_prev`: the neighbouring statement, only when nothing shares an identifier. A fix that only reorders statements gets `anchor_dataflow` entries too: `move_early` on a statement moved later (it ran too early), `move_crossed` on the first statement a statement moved earlier jumped over and shares an identifier with. Each entry has abs/rel line, byte range, text, and `kind`.

`is_vulnerable` is the function-level flag. `cwe_list` is the raw NVD CWE list.

`cwe_1000_list` maps those CWEs onto the 10 pillars of the CWE-1000 view (Research Concepts). The mapping follows the primary ChildOf link in that view until it reaches a pillar. A CWE that is itself a pillar stays unchanged. A CWE with no path to a pillar is dropped. The list keeps first-seen order and drops duplicates, so it can be shorter than `cwe_list`.

`cwe_699_list` maps those CWEs onto the 40 categories of the CWE-699 view (Software Development). A CWE that is one of those categories stays unchanged. A weakness the view lists under one or more categories maps to all of those categories, in the view's category order. A CWE outside the view is walked up the CWE-1000 primary ChildOf chain to the nearest ancestor that is a category or a listed member, and then to that ancestor's categories. A CWE with no such ancestor is dropped, including classes that sit above the view's members (CWE-119 has no CWE-699 category; CWE-787, which the view lists under CWE-1218, does). The list keeps first-seen order and drops duplicates.

`cwe_1003_list` maps those CWEs onto any of the 130 members of the CWE-1003 view. A member stays as itself, including the 93 that sit under the 37 top-level entries. A CWE outside the view is walked up to the nearest view member and kept as that member. A CWE with no such ancestor is dropped. The list keeps first-seen order and drops duplicates.

`cwe_1003_high_list` uses only the 37 top-level entries. A member among the 93 is replaced by its parent in the view. A CWE outside the view is walked up to the nearest view member and then to that member's top-level parent.

`cwe_1400_list` has one entry per CWE in `cwe_list`, in the same order: the CWE-1400 category of that CWE (`"CWE-1399"`), or null when that CWE is not in the view. An empty `cwe_list` gives an empty list.

`top15_cwe_1400` has one entry per CWE in `cwe_list`, in the same order. It is fit separately on each table, using the vulnerable rows of that table's chronological training split (`splits/chrono.json`). The 15 most frequent CWEs on those rows are kept as in `cwe_list`. Every other entry is copied from `cwe_1400_list` at the same position, including null when that CWE is not in the view. Ties break toward the smaller CWE id. An empty `cwe_list` gives an empty list.

### Confidence tiers (`label_confidence`)

- `high` — the commit changes exactly one function (test files excluded), or the function is named in a linked CVE description
- `medium` — the only changed function in its file, but the commit touches several files
- `low` — several functions changed in the file; this one is named in the commit message

### Negatives (`neg_type`)

- `fixed` — patched version of a vulnerable function
- `untouched` — unchanged function from a file that also contains a changed function
- `patched_later_vulnerable` — a `fixed` row whose function is modified again by a later CVE commit in this dataset (`later_fixed_by`)

`clean` is true when `label_confidence ∈ {high, medium}` (or the row is an untouched negative), `label_conflict` is false, `neg_type` is not `patched_later_vulnerable`, and the row is not a vulnerable function in a test file or a vulnerable function whose fix changed only comments in it (the real fix is elsewhere).

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
