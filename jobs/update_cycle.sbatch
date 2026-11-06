#!/bin/bash
# One stage of the monthly VulSpot update. The stage script submits the next
# stage when this one finishes. Near the time limit it resubmits itself so a
# long commit fetch continues from the commits already stored.
#
#   sbatch --export=ALL,VULSPOT_UPDATE_STAGE=nvd,VULSPOT_CUTOFF_DAY=2026-11-12 \
#     jobs/update_cycle.sbatch
#
# Tokens are read at start from secrets.env or the environment. Do not put
# tokens in this file.
#SBATCH --job-name=vulspot-update
#SBATCH --chdir=/gpfs/projects/acad/maiaone/douch/VulSpot
#SBATCH --output=/gpfs/projects/acad/maiaone/douch/VulSpot/logs/%j_vulspot_update.out
#SBATCH --partition=batch
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=8
#SBATCH --mem=32G
#SBATCH --time=24:00:00
#SBATCH --signal=B:USR1@180
#SBATCH --account=maiaone

ROOT="/gpfs/projects/acad/maiaone/douch/VulSpot"
cd "$ROOT"
mkdir -p logs
export LANG="${LANG:-C.UTF-8}"
export LC_ALL="${LC_ALL:-C.UTF-8}"
echo "vulspot update job=${SLURM_JOB_ID:-?} host=$(hostname) stage=${VULSPOT_UPDATE_STAGE:-nvd} cutoff=${VULSPOT_CUTOFF_DAY:-today}"
date
module load devel/python/3.9.13 2>/dev/null || true

set -m
resubmit_same() {
  echo "time limit approaching; resubmitting ${VULSPOT_UPDATE_STAGE:-nvd}"
  if [[ -n "${child:-}" ]]; then
    kill -TERM -- "-${child}" 2>/dev/null || kill -TERM "${child}" 2>/dev/null || true
    wait "${child}" 2>/dev/null || true
  fi
  sbatch --export=ALL,VULSPOT_UPDATE_STAGE="${VULSPOT_UPDATE_STAGE:-nvd}",VULSPOT_CUTOFF_DAY="${VULSPOT_CUTOFF_DAY:-}" \
    "$ROOT/jobs/update_cycle.sbatch"
  exit 0
}
trap resubmit_same USR1

export PYTHONUNBUFFERED=1
STAGE="${VULSPOT_UPDATE_STAGE:-nvd}"
bash jobs/update_cycle.sh "$STAGE" &
child=$!
set +e
wait "$child"
status=$?
set -e
if [[ "$status" -ne 0 ]]; then
  echo "stage $STAGE exited $status"
  exit "$status"
fi
date
