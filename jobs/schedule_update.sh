#!/usr/bin/env bash
# Arm the next dataset update, one month after the version already on disk.
#
#   bash jobs/schedule_update.sh            # submit the SLURM job
#   bash jobs/schedule_update.sh --dry-run  # print the window and the sbatch command
#
# The current covered_through date comes from data/out/version.json, or, the
# first time, from the last NVD publication window. The job runs on that date
# plus one month and collects through that day.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
PY="${ROOT}/.venv/bin/python"
DRY=0
if [[ "${1:-}" == "--dry-run" ]]; then
  DRY=1
fi

"$PY" -m vulspot.update seed >/dev/null
COVERED="$("$PY" -m vulspot.update seed)"
BEGIN="$("$PY" -m vulspot.update next-begin)"
NEXT_DAY="${BEGIN%%T*}"
echo "covered_through=$COVERED"
echo "next_cutoff_day=$NEXT_DAY"
echo "begin=$BEGIN"

if [[ "$DRY" == 1 ]]; then
  printf 'sbatch --begin=%s --export=ALL,VULSPOT_UPDATE_STAGE=nvd,VULSPOT_CUTOFF_DAY=%s %s\n' \
    "$BEGIN" "$NEXT_DAY" "$ROOT/jobs/update_cycle.sbatch"
  exit 0
fi

pending="$(squeue -u "$USER" -h -n vulspot-update -o '%i %T' | awk '$2=="PENDING" {print $1; exit}')"
if [[ -n "$pending" ]]; then
  echo "update already pending as job $pending"
  exit 0
fi

sbatch --begin="$BEGIN" \
  --export=ALL,VULSPOT_UPDATE_STAGE=nvd,VULSPOT_CUTOFF_DAY="$NEXT_DAY" \
  "$ROOT/jobs/update_cycle.sbatch"
