#!/usr/bin/env python
"""Stage 3: fetch commit artifacts from GitHub into data/raw/commits/<owner>__<repo>/<sha>/.

Per commit: meta.json (status, canonical repo, parents, dates), commit.json (REST payload
with per-file patches), commit.diff (raw unified diff), before/<path> and after/<path>
(full file contents at parent and at the commit, code files only).

Resumable: commits whose meta.json has a final status are skipped. Safe to re-run.

    python 03_fetch_commits.py                 # everything in data/interim/commit_jobs.jsonl
    python 03_fetch_commits.py --limit 50      # smoke test
    python 03_fetch_commits.py --repo torvalds/linux
    python 03_fetch_commits.py --retry-errors  # re-fetch commits with 'errors' in meta

Requires GITHUB_TOKEN (5000 req/h). Writes data/interim/commit_resolution.jsonl at the end.
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

from tqdm import tqdm

sys.path.insert(0, str(Path(__file__).resolve().parent))

from vulspot.config import env_secret, load_config
from vulspot.github import DONE_STATUSES, GitHubClient, load_meta
from vulspot.io import iter_jsonl, write_jsonl
from vulspot.log import get_logger


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=None)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--repo", default=None, help="only this owner/repo")
    ap.add_argument("--retry-errors", action="store_true", help="re-fetch commits whose meta has errors")
    ap.add_argument("--resolution-only", action="store_true", help="only rebuild commit_resolution.jsonl")
    args = ap.parse_args()

    cfg = load_config(args.config)
    log = get_logger("03_fetch_commits", cfg.paths.logs)
    jobs = list(iter_jsonl(cfg.paths.interim / "commit_jobs.jsonl"))
    if args.repo:
        jobs = [j for j in jobs if j["repo"] == args.repo]
    log.info("%d commit jobs", len(jobs))

    code_exts = set(cfg["languages"]["extension_map"].keys())
    gh = GitHubClient(cfg, env_secret("GITHUB_TOKEN"), cfg.paths.raw_commits,
                      cfg.paths.root / "data" / "raw" / "github_repos")

    if not args.resolution_only:
        gh.ensure_mirrors()
        todo = []
        for j in jobs:
            # the commit may have been stored under the canonical repo; check both locations
            meta = load_meta(gh.commit_dir(j["repo"], j["sha"]))
            if meta is None:
                info = gh.repo_info(j["repo"]) if (gh.repos_dir / f"{j['repo'].replace('/', '__')}.json").exists() else None
                for cand in filter(None, [(info or {}).get("parent"), (info or {}).get("full_name"), (info or {}).get("source")]):
                    meta = load_meta(gh.commit_dir(cand, j["sha"]))
                    if meta:
                        break
            if meta and meta.get("status") in DONE_STATUSES:
                if args.retry_errors and meta.get("errors"):
                    todo.append(j)
                continue
            todo.append(j)
        if args.limit:
            todo = todo[: args.limit]
        log.info("%d to fetch (%d already done)", len(todo), len(jobs) - len(todo))

        stat = Counter()
        for j in tqdm(todo, desc="commits", unit="commit"):
            try:
                meta = gh.fetch_commit(j["repo"], j["sha"], j["cve_ids"], code_exts)
                stat[meta["status"]] += 1
            except Exception as e:  # noqa: BLE001
                log.exception("failed %s@%s: %s", j["repo"], j["sha"], e)
                stat["exception"] += 1
        log.info("fetch statuses: %s", dict(stat))

    # resolution table for stage 4
    rows = []
    for j in jobs:
        meta = load_meta(gh.commit_dir(j["repo"], j["sha"]))
        if meta is None:
            info = gh.repo_info(j["repo"]) if (gh.repos_dir / f"{j['repo'].replace('/', '__')}.json").exists() else None
            for cand in filter(None, [(info or {}).get("parent"), (info or {}).get("full_name"), (info or {}).get("source")]):
                meta = load_meta(gh.commit_dir(cand, j["sha"]))
                if meta:
                    break
        rows.append({
            "repo": j["repo"], "sha": j["sha"], "kind": j["kind"], "cve_ids": j["cve_ids"],
            "canonical_repo": (meta or {}).get("canonical_repo"),
            "full_sha": (meta or {}).get("full_sha"),
            "status": (meta or {}).get("status", "not_fetched"),
            "commit_dir": str(gh.commit_dir((meta or {}).get("canonical_repo") or j["repo"], j["sha"]).relative_to(cfg.paths.root)) if meta else None,
        })
    n = write_jsonl(cfg.paths.interim / "commit_resolution.jsonl", rows)
    log.info("wrote commit_resolution.jsonl (%d rows): %s", n, dict(Counter(r["status"] for r in rows)))


if __name__ == "__main__":
    main()
