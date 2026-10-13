#!/bin/bash
# SLURM wrapper for the VulSpot network / CPU stages (no GPU).
# Usage:
#   sbatch --export=ALL,VULSPOT_STAGE=nvd     jobs/run_pipeline.sbatch
#   sbatch --export=ALL,VULSPOT_STAGE=commits jobs/run_pipeline.sbatch
#   sbatch --export=ALL,VULSPOT_STAGE=build   jobs/run_pipeline.sbatch
#   sbatch --export=ALL,VULSPOT_STAGE=upload  jobs/run_pipeline.sbatch
#   sbatch --export=ALL,VULSPOT_STAGE=all     jobs/run_pipeline.sbatch
#
# Export NVD_API_KEY, GITHUB_TOKEN, HF_TOKEN in the environment before sbatch
# (or put them in ~/.bashrc). Do not paste tokens into this file.
#SBATCH --job-name=vulspot
#SBATCH --output=logs/%j_vulspot_%x.out
#SBATCH --partition=batch
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=8
#SBATCH --mem=32G
#SBATCH --time=24:00:00
#SBATCH --account=maiaone

# Do not `source /etc/profile` here: with `set -e`/`set -u` it aborts before any
# pipeline output (jobs 16200041, 16200696). Working cluster jobs only `module load`.
ROOT="/gpfs/home/acad/umons-artint/douch/projects/VulSpot"
cd "$ROOT"
mkdir -p logs
export LANG="${LANG:-C.UTF-8}"
export LC_ALL="${LC_ALL:-C.UTF-8}"
echo "vulspot sbatch start job=${SLURM_JOB_ID:-?} host=$(hostname) stage=${VULSPOT_STAGE:-all}"
date
module load devel/python/3.9.13 2>/dev/null || true

set -euo pipefail
export PYTHONUNBUFFERED=1
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
STAGE="${VULSPOT_STAGE:-all}"
echo "stage=$STAGE python=$(command -v python3 || true) venv=$ROOT/.venv/bin/python"
bash jobs/run_pipeline.sh "$STAGE"
date
