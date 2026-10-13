#!/usr/bin/env python
"""Stage 5: filter, confidence tiers, dedup, clone groups, later-fixed, kernel-CNA, splits, write datasets.

    python 05_filter_build.py
    python 05_filter_build.py --config config.yaml
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

import pandas as pd
from tqdm import tqdm

sys.path.insert(0, str(Path(__file__).resolve().parent))

from vulspot.build import (
    OUTPUT_COLUMNS,
    assign_confidence,
    assign_idx_and_pairs,
    attach_cve_meta,
    balanced_mask,
    clean_flag,
    cpp_mask,
    drop_multi_commit,
    drop_no_func_edits,
    exact_dedup,
    finalize_columns,
    kernel_cna_flag,
    later_fixed,
    load_cves,
    load_multi_commit_cves,
)
from vulspot.config import load_config
from vulspot.dedup import CloneDetector
from vulspot.io import iter_jsonl, write_json
from vulspot.langs import LanguageResolver
from vulspot.log import get_logger
from vulspot.splits import chrono_split, project_holdout_split


def _load_functions(interim: Path, log) -> pd.DataFrame:
    gz = interim / "functions.jsonl.gz"
    raw = interim / "functions.jsonl"
    candidates = [p for p in (raw, gz) if p.exists()]
    if not candidates:
        raise SystemExit(f"missing {gz} (run 04_extract_functions.py)")
    path = max(candidates, key=lambda p: p.stat().st_mtime)
    rows = list(tqdm(iter_jsonl(path), desc="load functions"))
    log.info("loaded %d function rows from %s", len(rows), path)
    return pd.DataFrame(rows)


def _clone_groups(df: pd.DataFrame, cfg: dict, log) -> pd.Series:
    dcfg = cfg["dedup"]
    det = CloneDetector(num_perm=int(dcfg["minhash_num_perm"]),
                        threshold=float(dcfg["jaccard_threshold"]),
                        k=int(dcfg["minhash_shingle_k"]))
    # one representative per exact hash
    reps = df.drop_duplicates("hash")
    for _, r in tqdm(reps.iterrows(), total=len(reps), desc="minhash"):
        det.add(r["hash"], r["func_body"] or "", r.get("language") or "c")
    gmap = det.groups()
    log.info("clone groups: %d unique hashes -> %d groups", len(gmap), len(set(gmap.values())))
    return df["hash"].map(gmap)


def _write_frame(df: pd.DataFrame, out_dir: Path, name: str, log) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    pq = out_dir / f"{name}.parquet"
    js = out_dir / f"{name}.jsonl.gz"
    df.to_parquet(pq, index=False)
    df.to_json(js, orient="records", lines=True, force_ascii=False, compression="gzip")
    log.info("wrote %s (%d rows, %d cols)", pq, len(df), len(df.columns))


def _write_splits(df: pd.DataFrame, out_dir: Path, cfg: dict, log) -> dict:
    frac = cfg["splits"]["chrono"]
    chrono = chrono_split(df, (frac["train"], frac["val"], frac["test"]))
    hold = project_holdout_split(df, holdout_fraction=float(cfg["splits"]["project_holdout_fraction"]),
                                 seed=int(cfg["splits"]["seed"]))
    split_dir = out_dir / "splits"
    split_dir.mkdir(parents=True, exist_ok=True)
    write_json(split_dir / "chrono.json", chrono, indent=2)
    write_json(split_dir / "project_holdout.json", hold, indent=2)
    log.info("chrono sizes %s; holdout sizes %s", chrono["meta"]["sizes"], hold["meta"]["sizes"])
    return {"chrono": chrono["meta"], "project_holdout": hold["meta"]}


def _funnel_step(funnel: dict, name: str, n: int) -> None:
    funnel[name] = n


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=None)
    args = ap.parse_args()
    cfg = load_config(args.config)
    log = get_logger("05_filter_build", cfg.paths.logs)
    resolver = LanguageResolver(cfg)
    funnel = {}

    df = _load_functions(cfg.paths.interim, log)
    _funnel_step(funnel, "extracted_rows", len(df))

    cves_path = cfg.paths.interim / "cves.jsonl.gz"
    cves = load_cves(cves_path) if cves_path.exists() else {}
    df = attach_cve_meta(df, cves)

    jobs_path = cfg.paths.interim / "commit_jobs.jsonl"
    if cfg["filters"].get("drop_multi_commit_cves", True) and jobs_path.exists():
        multi = load_multi_commit_cves(jobs_path)
        df, n = drop_multi_commit(df, multi)
        funnel["dropped_multi_commit_cve_rows"] = n
        log.info("dropped %d rows from multi-commit CVEs (%d such CVEs)", n, len(multi))
    _funnel_step(funnel, "after_multi_commit", len(df))

    df, n = drop_no_func_edits(df)
    funnel["dropped_no_func_edits"] = n
    _funnel_step(funnel, "after_no_func_edits", len(df))

    df, conf_stats = assign_confidence(df, bool(cfg["filters"].get("keep_unmentioned_in_multi_function_files", False)))
    funnel["confidence"] = conf_stats
    _funnel_step(funnel, "after_confidence", len(df))

    df, dedup_stats = exact_dedup(df)
    funnel["exact_dedup"] = dedup_stats
    _funnel_step(funnel, "after_exact_dedup", len(df))

    df["clone_group_id"] = _clone_groups(df, cfg, log)
    df = later_fixed(df)
    n_later = int((df["neg_type"] == "patched_later_vulnerable").sum())
    funnel["patched_later_vulnerable"] = n_later

    kcfg = cfg["kernel_cna"]
    df = kernel_cna_flag(df, kcfg["source_identifiers"], kcfg["start_date"])
    funnel["kernel_cna_rows"] = int(df["is_kernel_cna"].sum())

    df = assign_idx_and_pairs(df)
    df["clean"] = clean_flag(df)
    df = finalize_columns(df)

    bcfg = dict(cfg["balanced"])
    bcfg["kernel_start"] = kcfg["start_date"]
    bal = balanced_mask(df, bcfg)
    funnel["balanced_kept"] = int(bal.sum())
    funnel["balanced_dropped"] = int((~bal).sum())

    cpp = df.loc[cpp_mask(df, resolver)].copy()
    # re-index cpp so idx is contiguous within the config
    cpp = assign_idx_and_pairs(cpp)
    cpp["clean"] = clean_flag(cpp)
    cpp = finalize_columns(cpp)
    cpp_bal = balanced_mask(cpp, bcfg)
    multi = df.copy()

    stats = {
        "funnel": funnel,
        "cpp_rows": len(cpp),
        "multi_rows": len(multi),
        "cpp_vulnerable": int(cpp["is_vulnerable"].sum()),
        "multi_vulnerable": int(multi["is_vulnerable"].sum()),
        "languages": multi["language"].value_counts().to_dict(),
        "confidence_cpp": cpp["label_confidence"].value_counts(dropna=False).to_dict(),
        "neg_type_cpp": cpp["neg_type"].value_counts(dropna=False).to_dict(),
    }

    cpp_dir = cfg.paths.out / "cpp"
    multi_dir = cfg.paths.out / "multi"
    _write_frame(cpp, cpp_dir / "full", "data", log)
    _write_frame(cpp.loc[cpp_bal].copy(), cpp_dir / "balanced", "data", log)
    _write_frame(multi, multi_dir / "full", "data", log)
    _write_frame(multi.loc[bal].copy(), multi_dir / "balanced", "data", log)

    stats["splits"] = {
        "cpp_full": _write_splits(cpp, cpp_dir / "full", cfg, log),
        "cpp_balanced": _write_splits(cpp.loc[cpp_bal].copy(), cpp_dir / "balanced", cfg, log),
        "multi_full": _write_splits(multi, multi_dir / "full", cfg, log),
        "multi_balanced": _write_splits(multi.loc[bal].copy(), multi_dir / "balanced", cfg, log),
    }
    write_json(cfg.paths.interim / "05_summary.json", stats, indent=2)
    write_json(cfg.paths.out / "05_summary.json", stats, indent=2)
    log.info("cpp=%d multi=%d", len(cpp), len(multi))


if __name__ == "__main__":
    main()
