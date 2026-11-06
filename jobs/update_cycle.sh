#!/usr/bin/env bash
# One stage of a dataset update, then submit the next stage.
#
#   bash jobs/update_cycle.sh nvd
#   bash jobs/update_cycle.sh commits
#   bash jobs/update_cycle.sh build
#   bash jobs/update_cycle.sh upload
#   bash jobs/update_cycle.sh all          # foreground, no follow-up submission
#   bash jobs/update_cycle.sh plan         # write the window and print it
#
# The cutoff day is VULSPOT_CUTOFF_DAY (YYYY-MM-DD) when the scheduler set it,
# otherwise today UTC. A date includes that whole UTC day. Completed NVD
# windows and commits are skipped by the stage scripts.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
mkdir -p logs
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
export PYTHONUNBUFFERED=1
PY="${ROOT}/.venv/bin/python"
STAGE="${1:-${VULSPOT_UPDATE_STAGE:-nvd}}"
CHAIN=0
if [[ -n "${SLURM_JOB_ID:-}" && "${2:-}" != "--no-chain" ]]; then
  CHAIN=1
fi
MAX_RETRIES="$("$PY" -c 'from vulspot.config import load_config; print(int(load_config()["update"]["max_stage_retries"]))')"

load_secrets() {
  local file="${VULSPOT_SECRETS:-$ROOT/secrets.env}"
  if [[ -f "$file" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "$file"
    set +a
  fi
  if [[ -z "${HF_TOKEN:-}" && -f "${HOME}/.cache/huggingface/token" ]]; then
    HF_TOKEN="$(tr -d '[:space:]' < "${HOME}/.cache/huggingface/token")"
    export HF_TOKEN
  fi
}

require_secret() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "missing $name. Put it in $ROOT/secrets.env (mode 600) or export it." >&2
    exit 1
  fi
}

cutoff_day() {
  if [[ -n "${VULSPOT_CUTOFF_DAY:-}" ]]; then
    printf '%s\n' "$VULSPOT_CUTOFF_DAY"
    return
  fi
  date -u +%F
}

submit_stage() {
  local stage="$1"
  local begin="${2:-}"
  local cutoff="${3:-${VULSPOT_CUTOFF_DAY:-}}"
  if [[ -z "$cutoff" ]]; then
    cutoff="$("$PY" -m vulspot.update cutoff-day)"
  fi
  local -a args=()
  if [[ -n "$begin" ]]; then
    local pending
    pending="$(squeue -u "$USER" -h -n vulspot-update -o '%i %T' | awk -v self="${SLURM_JOB_ID:-}" '$2=="PENDING" && $1!=self {print $1; exit}')"
    if [[ -n "$pending" ]]; then
      echo "update already pending as job $pending"
      return
    fi
    args+=(--begin="$begin")
  fi
  sbatch "${args[@]}" \
    --export=ALL,VULSPOT_UPDATE_STAGE="$stage",VULSPOT_CUTOFF_DAY="$cutoff" \
    "$ROOT/jobs/update_cycle.sbatch"
}

retry_or_stop() {
  local status="$1"
  local retries=0
  local file="$ROOT/logs/update_retry_${STAGE}"
  if [[ -f "$file" ]]; then
    retries="$(cat "$file")"
  fi
  retries=$((retries + 1))
  printf '%s\n' "$retries" > "$file"
  if [[ "$CHAIN" == 1 && "$retries" -le "$MAX_RETRIES" ]]; then
    echo "stage $STAGE failed (status $status), retry $retries/$MAX_RETRIES in 30 minutes"
    submit_stage "$STAGE" "now+30minutes"
    exit 0
  fi
  echo "stage $STAGE failed (status $status); not scheduling the next update" >&2
  exit "$status"
}

run_py() {
  echo "[$(date -Is)] >>> $*"
  "$PY" "$@"
  echo "[$(date -Is)] <<< $*"
}

# Copy the version on disk to snapshots/out_<previous covered_through> before the
# build overwrites it. A finished snapshot is never touched again, so a rerun of
# the build stage keeps the pristine previous version.
snapshot_previous() {
  local out prev snap
  out="$("$PY" -c 'from vulspot.config import load_config; print(load_config().paths.out)')"
  prev="$("$PY" -c 'import json; from vulspot.config import load_config; from vulspot.update import plan_path; print(json.loads(plan_path(load_config().paths.logs).read_text())["previous_covered_through"])')"
  snap="$(dirname "$out")/snapshots/out_${prev}"
  if [[ ! -d "$out/cpp" ]]; then
    echo "no previous version in $out; no snapshot"
  elif [[ -e "$snap" ]]; then
    echo "snapshot $snap already exists"
  else
    mkdir -p "$(dirname "$snap")"
    rm -rf "${snap}.tmp"
    cp -a "$out" "${snap}.tmp"
    mv "${snap}.tmp" "$snap"
    echo "previous version copied to $snap"
  fi
}

run_stage() {
  case "$STAGE" in
    plan)
      run_py -m vulspot.update plan --cutoff-day "$(cutoff_day)"
      echo "previous=$("$PY" -c 'import json; from vulspot.config import load_config; from vulspot.update import plan_path; print(json.loads(plan_path(load_config().paths.logs).read_text())["previous_covered_through"])')"
      echo "cutoff=$("$PY" -m vulspot.update cutoff-day)"
      ;;
    nvd)
      if [[ -z "${NVD_API_KEY:-}" ]]; then
        echo "warning: NVD_API_KEY is unset; the NVD fetch will be slow"
      fi
      run_py -m vulspot.update plan --cutoff-day "$(cutoff_day)"
      run_py 01_fetch_nvd.py --cutoff "$("$PY" -m vulspot.update cutoff-day)"
      run_py 02_extract_commit_refs.py
      ;;
    commits)
      require_secret GITHUB_TOKEN
      run_py 03_fetch_commits.py
      ;;
    build)
      snapshot_previous
      run_py 04_extract_functions.py
      run_py 05_filter_build.py
      run_py 06_report.py
      ;;
    upload)
      require_secret HF_TOKEN
      local day
      day="$("$PY" -m vulspot.update cutoff-day)"
      run_py 07_upload_hf.py --message "Update VulSpot through $day" --tag "v$day"
      run_py -m vulspot.update record
      ;;
    all)
      bash "$ROOT/jobs/update_cycle.sh" plan --no-chain
      bash "$ROOT/jobs/update_cycle.sh" nvd --no-chain
      bash "$ROOT/jobs/update_cycle.sh" commits --no-chain
      bash "$ROOT/jobs/update_cycle.sh" build --no-chain
      bash "$ROOT/jobs/update_cycle.sh" upload --no-chain
      ;;
    *)
      echo "usage: $0 {plan|nvd|commits|build|upload|all}" >&2
      exit 2
      ;;
  esac
}

load_secrets

set +e
(
  set -e
  run_stage
)
status=$?
set -e
if [[ "$status" -ne 0 ]]; then
  retry_or_stop "$status"
fi
rm -f "$ROOT/logs/update_retry_${STAGE}"

if [[ "$CHAIN" == 1 ]]; then
  case "$STAGE" in
    nvd) submit_stage commits ;;
    commits) submit_stage build ;;
    build) submit_stage upload ;;
    upload)
      next="$("$PY" -m vulspot.update next-begin --cutoff-day "$("$PY" -m vulspot.update cutoff-day)")"
      next_day="${next%%T*}"
      echo "next update $next_day begins at $next"
      submit_stage nvd "$next" "$next_day"
      ;;
  esac
fi
echo "[$(date -Is)] stage $STAGE done"
