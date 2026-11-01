#!/usr/bin/env bash
# nohup wrapper. Run from the VulSpot root, with secrets already exported.
# Usage:
#   source .venv/bin/activate
#   export NVD_API_KEY=... GITHUB_TOKEN=... HF_TOKEN=...
#   nohup bash jobs/run_pipeline.sh nvd     > logs/nohup_nvd.log 2>&1 &
#   nohup bash jobs/run_pipeline.sh commits > logs/nohup_commits.log 2>&1 &
#   nohup bash jobs/run_pipeline.sh build   > logs/nohup_build.log 2>&1 &
#   VULSPOT_EXTRACT_ARGS=--fresh nohup bash jobs/run_pipeline.sh build > logs/nohup_build.log 2>&1 &
#   nohup bash jobs/run_pipeline.sh upload  > logs/nohup_upload.log 2>&1 &
#   nohup bash jobs/run_pipeline.sh all     > logs/nohup_all.log 2>&1 &
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
mkdir -p logs
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
PY="${ROOT}/.venv/bin/python"
STAGE="${1:-all}"

run() {
  echo "[$(date -Is)] >>> $*"
  "$@"
  echo "[$(date -Is)] <<< $*"
}

case "$STAGE" in
  nvd)
    run "$PY" 01_fetch_nvd.py
    run "$PY" 02_extract_commit_refs.py
    ;;
  commits)
    run "$PY" 03_fetch_commits.py
    ;;
  build)
    # VULSPOT_EXTRACT_ARGS=--fresh re-extracts every commit (e.g. after a sinks.py change);
    # without it, commits already in commit_extract.jsonl are skipped.
    # shellcheck disable=SC2086
    run "$PY" 04_extract_functions.py ${VULSPOT_EXTRACT_ARGS:-}
    run "$PY" 05_filter_build.py
    run "$PY" 06_report.py
    ;;
  upload)
    run "$PY" 07_upload_hf.py
    ;;
  all)
    run "$PY" 01_fetch_nvd.py
    run "$PY" 02_extract_commit_refs.py
    run "$PY" 03_fetch_commits.py
    run "$PY" 04_extract_functions.py
    run "$PY" 05_filter_build.py
    run "$PY" 06_report.py
    run "$PY" 07_upload_hf.py
    ;;
  *)
    echo "usage: $0 {nvd|commits|build|upload|all}" >&2
    exit 2
    ;;
esac
echo "[$(date -Is)] stage $STAGE done"
