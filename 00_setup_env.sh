#!/usr/bin/env bash
# Create the VulSpot virtualenv and install dependencies.
# Usage: bash 00_setup_env.sh            (uses python3 on PATH, >=3.9)
#        PYTHON=python3.11 bash 00_setup_env.sh
set -euo pipefail
cd "$(dirname "$0")"

PYTHON="${PYTHON:-python3}"
VENV=".venv"

if [ ! -x "$VENV/bin/python" ]; then
  echo "[setup] creating venv with $PYTHON"
  "$PYTHON" -m venv "$VENV"
fi

"$VENV/bin/pip" install --upgrade pip >/dev/null
"$VENV/bin/pip" install -r requirements.txt

"$VENV/bin/python" - <<'EOF'
import tree_sitter, tree_sitter_c, tree_sitter_cpp, tree_sitter_language_pack, datasketch, pandas, pyarrow, huggingface_hub
from tree_sitter import Language, Parser
Parser(Language(tree_sitter_c.language())).parse(b"int f(void){return 0;}")
Parser(Language(tree_sitter_cpp.language())).parse(b"int f(void){return 0;}")
tree_sitter_language_pack.get_parser("python").parse(b"def f():\n  return 0\n")
print("[setup] environment OK")
EOF

mkdir -p data/raw/nvd data/raw/commits data/interim data/out logs
echo "[setup] done. Activate with: source $VENV/bin/activate"
echo "[setup] export NVD_API_KEY=... GITHUB_TOKEN=... HF_TOKEN=... before running network stages."
