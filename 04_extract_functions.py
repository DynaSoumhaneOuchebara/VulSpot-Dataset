#!/usr/bin/env python
"""Stage 4: extract functions, statement diffs, sink candidates, and context from cached commits.

Entirely offline. Reads data/raw/commits and data/interim/{cves.jsonl.gz,commit_resolution.jsonl}.
Writes data/interim/functions.jsonl.gz and data/interim/04_summary.json.

Tree-sitter trees are dropped after each file. The process also re-execs itself after
--max-commits newly processed commits, or when resident memory passes --max-rss-gb, so
pages from earlier commits are returned to the OS. Finished commits are checkpointed
before that restart and are skipped on the next start. Gzip of functions.jsonl runs
only when every commit has been processed.

    python 04_extract_functions.py
    python 04_extract_functions.py --limit 100
    python 04_extract_functions.py --scan-raw          # all ok commits under data/raw/commits
    python 04_extract_functions.py --retry-errors
    python 04_extract_functions.py --max-commits 0     # never re-exec
"""
from __future__ import annotations

import argparse
import ctypes
import gc
import logging
import os
import sys
from collections import Counter
from pathlib import Path

from tqdm import tqdm

sys.path.insert(0, str(Path(__file__).resolve().parent))

from vulspot.config import load_config
from vulspot.extract import Extractor
from vulspot.github import load_meta
from vulspot.io import JsonlAppender, iter_jsonl, write_json
from vulspot.log import get_logger


def _cve_index(cves_path: Path) -> dict[str, str]:
    out = {}
    if not cves_path.exists():
        return out
    for rec in iter_jsonl(cves_path):
        out[rec["cve_id"]] = rec.get("description") or ""
    return out


def _jobs_from_resolution(path: Path, root: Path) -> list[dict]:
    jobs = []
    for r in iter_jsonl(path):
        if r.get("status") != "ok" or not r.get("commit_dir"):
            continue
        jobs.append(r)
    return jobs


def _jobs_from_raw(commits_dir: Path) -> list[dict]:
    jobs = []
    for meta_path in commits_dir.glob("*/*/meta.json"):
        meta = load_meta(meta_path.parent)
        if not meta or meta.get("status") != "ok":
            continue
        repo = meta.get("canonical_repo") or meta["repo"]
        sha = meta.get("full_sha") or meta["sha"]
        jobs.append({
            "repo": repo, "sha": sha, "cve_ids": meta.get("cve_ids") or [],
            "canonical_repo": repo, "full_sha": sha, "status": "ok",
            "commit_dir": str(meta_path.parent),
        })
    return jobs


def _rss_bytes() -> int:
    try:
        with open("/proc/self/status", encoding="utf-8") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) * 1024
    except OSError:
        return 0
    return 0


def _release_process_memory() -> None:
    """Collect dropped parse trees and ask glibc to return free pages."""
    gc.collect()
    try:
        ctypes.CDLL("libc.so.6").malloc_trim(0)
    except (OSError, AttributeError):
        pass


def _reexec(log) -> None:
    log.info("re-exec to release memory; finished commits stay in the checkpoint")
    for handler in log.handlers:
        handler.flush()
    logging.shutdown()
    # --fresh must not repeat: it would delete the checkpoint on every restart.
    argv = [sys.executable, "-u", *[a for a in sys.argv if a != "--fresh"]]
    try:
        os.execv(sys.executable, argv)
    except OSError as e:
        sys.stderr.write(f"re-exec failed: {e}\n")
        sys.exit(1)


def _done_pair_ids(path: Path) -> set[str]:
    done = set()
    if not path.exists():
        return done
    for r in iter_jsonl(path):
        pid = r.get("pair_id")
        if pid:
            done.add(pid.split(":")[0])  # repo@sha12
    return done


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=None)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--scan-raw", action="store_true")
    ap.add_argument("--retry-errors", action="store_true")
    ap.add_argument("--fresh", action="store_true", help="overwrite functions.jsonl.gz")
    ap.add_argument("--max-commits", type=int, default=2000,
                    help="re-exec after this many newly processed commits (0 disables)")
    ap.add_argument("--max-rss-gb", type=float, default=16,
                    help="re-exec when resident memory exceeds this many GiB (0 disables)")
    args = ap.parse_args()

    cfg = load_config(args.config)
    log = get_logger("04_extract_functions", cfg.paths.logs)
    root = cfg.paths.root
    out_path = cfg.paths.interim / "functions.jsonl.gz"
    recs_path = cfg.paths.interim / "commit_extract.jsonl"

    if args.scan_raw:
        jobs = _jobs_from_raw(cfg.paths.raw_commits)
    else:
        res_path = cfg.paths.interim / "commit_resolution.jsonl"
        if not res_path.exists():
            log.error("missing %s (run 03, or pass --scan-raw)", res_path)
            sys.exit(1)
        jobs = _jobs_from_resolution(res_path, root)
    if args.limit:
        jobs = jobs[: args.limit]
    log.info("%d ok commits to extract", len(jobs))

    if args.fresh:
        for p in (out_path, recs_path, cfg.paths.interim / "functions.jsonl"):
            if p.exists():
                p.unlink()

    extracted_keys = set()
    if recs_path.exists() and not args.retry_errors:
        for rec in iter_jsonl(recs_path):
            extracted_keys.add(f"{rec.get('repo')}@{rec.get('commit_id')}")

    cve_desc = _cve_index(cfg.paths.interim / "cves.jsonl.gz")
    ex = Extractor(cfg, cve_desc=cve_desc)
    stat = Counter()
    n_rows = 0

    # functions.jsonl.gz is rewritten at the end if we need gzip; during the run we append
    # uncompressed then gzip. For resume, append to an uncompressed sidecar.
    raw_out = cfg.paths.interim / "functions.jsonl"
    rec_app = JsonlAppender(recs_path)
    fun_app = JsonlAppender(raw_out)
    rss_limit = int(args.max_rss_gb * (1024 ** 3)) if args.max_rss_gb and args.max_rss_gb > 0 else 0
    processed_new = 0
    restart = False

    try:
        for j in tqdm(jobs, desc="extract", unit="commit"):
            repo = j.get("canonical_repo") or j["repo"]
            sha = j.get("full_sha") or j["sha"]
            key = f"{repo}@{sha}"
            if key in extracted_keys and not args.retry_errors:
                stat["skipped_done"] += 1
                continue
            cdir = Path(j["commit_dir"])
            if not cdir.is_absolute():
                # Older resolution files stored project-relative paths (data/raw/commits/...).
                text = cdir.as_posix()
                data_root = cfg.paths.raw_commits.parent.parent
                if text == "data" or text.startswith("data/"):
                    cdir = data_root / text.removeprefix("data").lstrip("/")
                else:
                    cdir = root / cdir
            meta = load_meta(cdir)
            if not meta:
                stat["missing_meta"] += 1
                continue
            try:
                rec, rows = ex.process_commit(cdir, meta)
            except Exception as e:  # noqa: BLE001
                log.exception("extract failed %s: %s", key, e)
                stat["exception"] += 1
                # Checkpoint before any restart so this commit is not parsed again.
                rec_app.write({"repo": repo, "commit_id": sha, "status": "exception", "error": str(e)})
            else:
                rec_app.write(rec)
                for r in rows:
                    fun_app.write(r)
                n_rows += len(rows)
                stat["ok"] += 1
                stat["rows"] += len(rows)
                extracted_keys.add(key)
            processed_new += 1
            _release_process_memory()
            rss = _rss_bytes()
            hit_count = bool(args.max_commits) and processed_new >= args.max_commits
            hit_rss = bool(rss_limit) and rss >= rss_limit
            if hit_count or hit_rss:
                why = "commit budget" if hit_count else f"rss {rss / (1024 ** 3):.1f} GiB"
                log.info("restarting after %d new commits (%s)", processed_new, why)
                restart = True
                break
    finally:
        rec_app.close()
        fun_app.close()

    if restart:
        _reexec(log)

    # gzip the functions file for the next stage. Skipped on re-exec; the raw jsonl
    # is the file the next process appends to.
    if raw_out.exists():
        import gzip
        import shutil
        tmp = out_path.with_suffix(out_path.suffix + ".tmp")
        with open(raw_out, "rb") as src, gzip.open(tmp, "wb") as dst:
            shutil.copyfileobj(src, dst)
        tmp.replace(out_path)

    summary = {"counts": dict(stat), "n_jobs": len(jobs), "functions_path": str(out_path)}
    write_json(cfg.paths.interim / "04_summary.json", summary, indent=2)
    log.info("done: %s", dict(stat))
    log.info("rows written: %d -> %s", n_rows, out_path)


if __name__ == "__main__":
    main()
