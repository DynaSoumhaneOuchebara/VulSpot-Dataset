# VulSpot

Statement-level dataset pipeline for vulnerability **detection**, **CWE classification**, and **localization**.
Replicates SecVulEval §3.1–3.3 (through today) and adds AST diffs, sink-candidate anchors, confidence tiers, untouched negatives, and deterministic context. No LLM §3.4 context.

Hugging Face: [DynaOuchebara/VulSpot](https://huggingface.co/datasets/DynaOuchebara/VulSpot) (configs `cpp` and `multi`).

## Setup

```bash
bash 00_setup_env.sh
source .venv/bin/activate
export NVD_API_KEY=...      # optional but strongly recommended
export GITHUB_TOKEN=...     # required for stage 3 (5000 req/h)
export HF_TOKEN=...         # required for stage 7
```

## Pipeline

| script | stage | network? | output |
|---|---|---|---|
| `01_fetch_nvd.py` | 1 NVD dump | yes | `data/raw/nvd/` |
| `02_extract_commit_refs.py` | 1b patch URLs + CWE-1003 | CWE CSVs once | `data/interim/cves.jsonl.gz`, `commit_jobs.jsonl` |
| `03_fetch_commits.py` | 2 GitHub artifacts | yes | `data/raw/commits/<owner>__<repo>/<sha>/` |
| `04_extract_functions.py` | 3 functions + diffs | no | `data/interim/functions.jsonl.gz` |
| `05_filter_build.py` | 4–5 filter, dedup, splits | no | `data/out/{cpp,multi}/{full,balanced}/` |
| `06_report.py` | report | no | `data/out/report.md` |
| `07_upload_hf.py` | 6 Hub upload | yes | `DynaOuchebara/VulSpot` |

Everything is resumable from cache. Re-run a stage after a crash; completed NVD windows and commits with a final `meta.json` status are skipped.

## Offline extractor check (before any network stage)

The three SecVulEval linux commits (`04bcef2a`, `05692d70`, `0926f910`) are already cached under `data/raw/commits/`. No token needed:

```bash
source .venv/bin/activate
python tests/test_stage3_secvuleval.py --verbose
python tests/test_sink_anchor.py
```

## Network stages (run on the login node / SLURM)

See `jobs/run_pipeline.sh` (nohup) and `jobs/run_pipeline.sbatch` (SLURM). Typical order:

```bash
source .venv/bin/activate
python 01_fetch_nvd.py                  # hours without a key; ~30 min with one
python 02_extract_commit_refs.py
python 03_fetch_commits.py              # the long one; 5–8 h with a token
# ping the agent / then:
python 04_extract_functions.py
python 05_filter_build.py
python 06_report.py
python 07_upload_hf.py
```

## Layout

```
VulSpot/
  config.yaml
  vulspot/          # library
  tests/
  data/raw/         # NVD windows + commit blobs (not uploaded)
  data/interim/     # stage jsonl
  data/out/         # parquet + jsonl + splits + report
  logs/
```
