#!/usr/bin/env python
"""Stage 5: filter, confidence tiers, dedup, clone groups, later-fixed, kernel-CNA, splits, write datasets.

    python 05_filter_build.py
    python 05_filter_build.py --config config.yaml
    python 05_filter_build.py --splits-only     # balanced variants + splits from existing out/*/full
"""
from __future__ import annotations

import argparse
import gzip
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
    drop_no_func_edits,
    exact_dedup,
    finalize_columns,
    kernel_cna_flag,
    later_fixed,
    load_cves,
    load_multi_commit_cves,
    redundant_backports,
)
from vulspot.config import load_config
from vulspot.dedup import CloneDetector
from vulspot.io import iter_jsonl, write_json
from vulspot.langs import LanguageResolver
from vulspot.log import get_logger
from vulspot.cwe import Cwe1003Mapper
from vulspot.cwe_labels import cwe_1400_aligned, load_cwe1400, parse_cwe_ids
from vulspot.splits import chrono_split, project_holdout_split


def _load_functions(interim: Path, log, skip_commits: set, multi: set, funnel: dict) -> pd.DataFrame:
    """Stream rows, dropping redundant-backport and multi-commit-CVE rows before they reach memory."""
    gz = interim / "functions.jsonl.gz"
    raw = interim / "functions.jsonl"
    candidates = [p for p in (raw, gz) if p.exists()]
    if not candidates:
        raise SystemExit(f"missing {gz} (run 04_extract_functions.py)")
    path = max(candidates, key=lambda p: p.stat().st_mtime)
    rows = []
    n = n_backport = n_multi = 0
    for r in tqdm(iter_jsonl(path), desc="load functions"):
        n += 1
        if ((r.get("repo") or "").lower(), (r.get("commit_id") or "").lower()) in skip_commits:
            n_backport += 1
            continue
        ids = r.get("cve_list")
        if isinstance(ids, str):
            ids = json.loads(ids or "[]")
        if multi and set(ids or []) & multi:
            n_multi += 1
            continue
        rows.append(r)
    funnel["extracted_rows"] = n
    funnel["dropped_redundant_backport_rows"] = n_backport
    funnel["dropped_multi_commit_cve_rows"] = n_multi
    funnel["after_multi_commit"] = len(rows)
    log.info("read %d rows from %s: dropped %d backport rows, %d multi-commit CVE rows; kept %d",
             n, path, n_backport, n_multi, len(rows))
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


def _write_frame(df: pd.DataFrame, out_dir: Path, name: str, log, chunk_rows: int = 20000) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    pq = out_dir / f"{name}.parquet"
    js = out_dir / f"{name}.jsonl.gz"
    df.to_parquet(pq, index=False)
    # chunked: a single to_json call materialises the whole file as one string
    with gzip.open(js, "wt", encoding="utf-8") as f:
        for start in range(0, len(df), chunk_rows):
            text = df.iloc[start:start + chunk_rows].to_json(orient="records", lines=True, force_ascii=False)
            f.write(text if text.endswith("\n") else text + "\n")
    log.info("wrote %s (%d rows, %d cols)", pq, len(df), len(df.columns))


SPLIT_COLUMNS = ["idx", "commit_id", "published_date", "project_url", "clone_group_id", "is_vulnerable",
                 "label_confidence", "clean", "fixed_func_idx"]


def _write_splits(df: pd.DataFrame, out_dir: Path, cfg: dict, log) -> dict:
    df = df[[c for c in SPLIT_COLUMNS if c in df.columns]]
    scfg = cfg["splits"]
    frac = scfg["chrono"]
    chrono = chrono_split(df, (frac["train"], frac["val"], frac["test"]))
    hold = project_holdout_split(df, holdout_fraction=float(scfg["project_holdout_fraction"]),
                                 seed=int(scfg["seed"]),
                                 never_holdout=scfg.get("never_holdout_projects", ["torvalds/linux"]))
    split_dir = out_dir / "splits"
    split_dir.mkdir(parents=True, exist_ok=True)
    write_json(split_dir / "chrono.json", chrono, indent=2)
    write_json(split_dir / "project_holdout.json", hold, indent=2)
    log.info("%s: chrono sizes %s; holdout sizes %s", out_dir, chrono["meta"]["sizes"], hold["meta"]["sizes"])
    return {"chrono": chrono["meta"], "project_holdout": hold["meta"]}


def _attach_cwe_labels(df: pd.DataFrame, categories: dict[str, str], mapper: Cwe1003Mapper) -> pd.DataFrame:
    """Map every row onto the CWE-1000, CWE-699, and CWE-1003 views."""
    parsed = [parse_cwe_ids(x) for x in df["cwe_list"]]
    lists = [list(x) if x is not None else [] for x in df["cwe_list"]]
    out = df.copy()
    out["cwe_1000_list"] = [mapper.map_1000_list(v) for v in lists]
    out["cwe_699_list"] = [mapper.map_699_list(v) for v in lists]
    out["cwe_1003_list"] = [mapper.map_member_list(v) for v in lists]
    out["cwe_1003_high_list"] = [mapper.map_list(v) for v in lists]
    out["cwe_1400_list"] = [cwe_1400_aligned(ids, categories) for ids in parsed]
    return out[OUTPUT_COLUMNS]


def _balanced_cfg(cfg: dict) -> dict:
    bcfg = dict(cfg["balanced"])
    bcfg["kernel_start"] = cfg["kernel_cna"]["start_date"]
    return bcfg


def _rebuild_splits(cfg: dict, log) -> None:
    """Rebuild balanced variants and all split files from the existing out/{cpp,multi}/full/data.parquet."""
    bcfg = _balanced_cfg(cfg)
    summary_path = cfg.paths.out / "05_summary.json"
    stats = json.loads(summary_path.read_text()) if summary_path.exists() else {}
    stats.setdefault("funnel", {})
    stats["splits"] = {}
    for name in ("cpp", "multi"):
        d = cfg.paths.out / name
        full_pq = d / "full" / "data.parquet"
        if not full_pq.exists():
            raise SystemExit(f"missing {full_pq} (run 05_filter_build.py without --splits-only first)")
        full = pd.read_parquet(full_pq)
        full["cve_list"] = full["cve_list"].map(lambda x: list(x) if x is not None else [])
        log.info("loaded %s (%d rows)", full_pq, len(full))
        bal = balanced_mask(full, bcfg)
        if name == "multi":
            stats["funnel"]["balanced_kept"] = int(bal.sum())
            stats["funnel"]["balanced_dropped"] = int((~bal).sum())
        stats["splits"][f"{name}_full"] = _write_splits(full, d / "full", cfg, log)
        balanced = full.loc[bal]
        del full
        _write_frame(balanced, d / "balanced", "data", log)
        stats["splits"][f"{name}_balanced"] = _write_splits(balanced, d / "balanced", cfg, log)
        del balanced
    write_json(cfg.paths.interim / "05_summary.json", stats, indent=2)
    write_json(summary_path, stats, indent=2)


def _funnel_step(funnel: dict, name: str, n: int) -> None:
    funnel[name] = n


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=None)
    ap.add_argument("--splits-only", action="store_true",
                    help="reuse out/*/full/data.parquet; rebuild balanced variants and split files only")
    args = ap.parse_args()
    cfg = load_config(args.config)
    log = get_logger("05_filter_build", cfg.paths.logs)
    if args.splits_only:
        _rebuild_splits(cfg, log)
        return
    resolver = LanguageResolver(cfg)
    funnel = {}

    res_path = cfg.paths.interim / "commit_resolution.jsonl"
    ext_path = cfg.paths.interim / "commit_extract.jsonl"
    skip_commits = redundant_backports(res_path, ext_path)
    multi = set()
    if cfg["filters"].get("drop_multi_commit_cves", True):
        multi = load_multi_commit_cves(res_path, skip_commits)
    funnel["redundant_backport_commits"] = len(skip_commits)
    funnel["multi_commit_cves"] = len(multi)
    log.info("%d redundant backport commits; %d multi-commit CVEs", len(skip_commits), len(multi))
    df = _load_functions(cfg.paths.interim, log, skip_commits, multi, funnel)

    cves_path = cfg.paths.interim / "cves.jsonl.gz"
    cves = load_cves(cves_path) if cves_path.exists() else {}
    df = attach_cve_meta(df, cves)
    del cves

    df, n = drop_no_func_edits(df)
    funnel["dropped_no_func_edits"] = n
    _funnel_step(funnel, "after_no_func_edits", len(df))

    df, conf_stats = assign_confidence(df, bool(cfg["filters"].get("keep_unmentioned_in_multi_function_files", False)))
    funnel["confidence"] = conf_stats
    _funnel_step(funnel, "after_confidence", len(df))

    # Before dedup: the later CVE's vulnerable copy often has the same body as this fixed copy,
    # and dedup would remove it before it could be matched.
    df = later_fixed(df)

    df, dedup_stats = exact_dedup(df)
    funnel["exact_dedup"] = dedup_stats
    _funnel_step(funnel, "after_exact_dedup", len(df))
    n_later = int((df["neg_type"] == "patched_later_vulnerable").sum())
    funnel["patched_later_vulnerable"] = n_later

    df["clone_group_id"] = _clone_groups(df, cfg, log)

    kcfg = cfg["kernel_cna"]
    df = kernel_cna_flag(df, kcfg["source_identifiers"], kcfg["start_date"])
    funnel["kernel_cna_rows"] = int(df["is_kernel_cna"].sum())

    df = assign_idx_and_pairs(df)
    df["clean"] = clean_flag(df)
    df = finalize_columns(df)

    bcfg = _balanced_cfg(cfg)
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

    cwe_dir = cfg.paths.raw_nvd.parent / "cwe"
    categories = load_cwe1400(cwe_dir)
    mapper = Cwe1003Mapper(cwe_dir)
    mapper.ensure_levels()
    if len(mapper.roots) != 37 or len(mapper.members) != 130:
        raise SystemExit(
            f"CWE-1003 has {len(mapper.roots)} top-level entries and {len(mapper.members)} members"
        )
    if len(mapper.pillars) != 10 or len(mapper.categories_699) != 40:
        raise SystemExit(
            f"CWE-1000 has {len(mapper.pillars)} pillars; CWE-699 has {len(mapper.categories_699)} categories"
        )
    cpp = _attach_cwe_labels(cpp, categories, mapper)
    multi = _attach_cwe_labels(multi, categories, mapper)

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
