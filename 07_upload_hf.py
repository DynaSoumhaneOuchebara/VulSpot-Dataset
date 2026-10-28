#!/usr/bin/env python
"""Stage 7: upload VulSpot to Hugging Face (public), resumable by content hash.

    HF_TOKEN=... python 07_upload_hf.py
    python 07_upload_hf.py --dry-run

Does not upload data/raw/.
"""
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from vulspot.config import env_secret, load_config
from vulspot.log import get_logger

CARD = Path(__file__).resolve().parent / "dataset_card.md"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def files_to_upload(out: Path) -> list[tuple[Path, str]]:
    """(local path, repo path) pairs."""
    pairs = []
    for cfg_name in ("cpp", "multi"):
        for variant in ("full", "balanced"):
            d = out / cfg_name / variant
            pq = d / "data.parquet"
            if pq.exists():
                pairs.append((pq, f"{cfg_name}/{variant}/data.parquet"))
            for split in ("chrono.json", "project_holdout.json"):
                p = d / "splits" / split
                if p.exists():
                    pairs.append((p, f"{cfg_name}/{variant}/splits/{split}"))
    report = out / "report.md"
    if report.exists():
        pairs.append((report, "report.md"))
    return pairs


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=None)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--message", default="Update VulSpot dataset artifacts")
    args = ap.parse_args()
    cfg = load_config(args.config)
    log = get_logger("07_upload_hf", cfg.paths.logs)
    repo_id = cfg["hf"]["repo_id"]
    private = bool(cfg["hf"].get("private", False))
    pairs = files_to_upload(cfg.paths.out)
    if not pairs:
        raise SystemExit("no parquet outputs found; run 05_filter_build.py first")
    log.info("%d files to consider for %s (private=%s)", len(pairs), repo_id, private)

    if args.dry_run:
        for local, remote in pairs:
            log.info("  %s -> %s (%d bytes)", local, remote, local.stat().st_size)
        return

    from huggingface_hub import CommitOperationAdd, HfApi, create_repo

    token = env_secret("HF_TOKEN", required=True)
    api = HfApi(token=token)
    create_repo(repo_id, repo_type="dataset", private=private, exist_ok=True, token=token)

    # skip LFS files whose sha256 matches what's already on the hub
    remote_sha = {}
    try:
        for s in api.list_repo_tree(repo_id, repo_type="dataset", recursive=True):
            path = getattr(s, "path", None)
            lfs = getattr(s, "lfs", None)
            if path and lfs and getattr(lfs, "sha256", None):
                remote_sha[path] = lfs.sha256
    except Exception:  # noqa: BLE001
        remote_sha = {}

    ops = []
    for local, remote in pairs:
        digest = _sha256(local)
        if remote_sha.get(remote) == digest:
            log.info("skip (same hash) %s", remote)
            continue
        ops.append(CommitOperationAdd(path_in_repo=remote, path_or_fileobj=str(local)))
        log.info("upload %s", remote)

    readme = CARD if CARD.exists() else cfg.paths.root / "README.md"
    if readme.exists():
        ops.append(CommitOperationAdd(path_in_repo="README.md", path_or_fileobj=str(readme)))

    if not ops:
        log.info("nothing to upload")
        return
    api.create_commit(
        repo_id=repo_id,
        repo_type="dataset",
        operations=ops,
        commit_message=args.message,
    )
    log.info("https://huggingface.co/datasets/%s", repo_id)


if __name__ == "__main__":
    main()
