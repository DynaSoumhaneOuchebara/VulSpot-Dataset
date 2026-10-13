"""Dataset splits.

chrono.json          : 80/10/10 by CVE published_date (all rows of a CVE / commit stay together), then
                       group-aware on clone_group_id: a clone group spanning several splits is moved
                       entirely to the earliest split it appears in (no later split contains a clone of
                       an earlier one).
project_holdout.json : a random ~fraction of projects (by rows) held out as test; the remaining rows are
                       split chronologically into train/val (ratio 9:1 of the remainder).
"""
from __future__ import annotations

import random
from collections import defaultdict

import pandas as pd

ORDER = {"train": 0, "val": 1, "test": 2}


def _assign_by_cve(df: pd.DataFrame, fractions: tuple[float, float, float]) -> dict[str, str]:
    """Return commit_id -> split following the chronological order of the earliest CVE of each commit."""
    g = df.groupby("commit_id").agg(date=("published_date", "min"), n=("idx", "size")).reset_index()
    g = g.sort_values(["date", "commit_id"]).reset_index(drop=True)
    total = int(g["n"].sum())
    cum = g["n"].cumsum()
    t_cut = fractions[0] * total
    v_cut = (fractions[0] + fractions[1]) * total
    out = {}
    for cid, c in zip(g["commit_id"], cum):
        if c <= t_cut:
            out[cid] = "train"
        elif c <= v_cut:
            out[cid] = "val"
        else:
            out[cid] = "test"
    return out


def _group_fix(df: pd.DataFrame, split: pd.Series, group_col: str) -> pd.Series:
    """Move every clone group to the earliest split (train < val < test) in which one of its members lives."""
    split = split.copy()
    if group_col not in df.columns:
        return split
    grp = df[group_col]
    valid = grp.notna()
    earliest = defaultdict(lambda: 2)
    for gid, s in zip(grp[valid], split[valid]):
        earliest[gid] = min(earliest[gid], ORDER[s])
    inv = {v: k for k, v in ORDER.items()}
    moved = 0
    for i in df.index[valid]:
        e = inv[earliest[grp.at[i]]]
        if split.at[i] != e:
            split.at[i] = e
            moved += 1
    split.attrs["moved_by_clone_groups"] = moved
    return split


def chrono_split(df: pd.DataFrame, fractions=(0.8, 0.1, 0.1), group_col: str = "clone_group_id") -> dict:
    by_commit = _assign_by_cve(df, fractions)
    split = df["commit_id"].map(by_commit)
    split = _group_fix(df, split, group_col)
    return _package(df, split, {"type": "chronological", "fractions": list(fractions), "group_col": group_col,
                                "moved_by_clone_groups": split.attrs.get("moved_by_clone_groups", 0)})


def project_holdout_split(df: pd.DataFrame, holdout_fraction: float = 0.1, seed: int = 13,
                          group_col: str = "clone_group_id", val_fraction: float = 0.1) -> dict:
    rng = random.Random(seed)
    counts = df.groupby("project_url")["idx"].size().to_dict()
    projects = list(counts)
    rng.shuffle(projects)
    total = len(df)
    target = holdout_fraction * total
    held, acc = set(), 0
    # never hold out a single project that alone exceeds the target (e.g. linux)
    for p in projects:
        if acc >= target:
            break
        if counts[p] > target:
            continue
        held.add(p)
        acc += counts[p]
    split = pd.Series("train", index=df.index, dtype=object)
    split[df["project_url"].isin(held)] = "test"
    rest = df[~df["project_url"].isin(held)]
    by_commit = _assign_by_cve(rest, (1 - val_fraction, val_fraction, 0.0))
    for i, cid in zip(rest.index, rest["commit_id"]):
        if by_commit.get(cid) == "val":
            split.at[i] = "val"
    split = _group_fix(df, split, group_col)
    return _package(df, split, {"type": "project_holdout", "holdout_fraction": holdout_fraction, "seed": seed,
                                "held_out_projects": sorted(held), "group_col": group_col,
                                "moved_by_clone_groups": split.attrs.get("moved_by_clone_groups", 0)})


def _package(df: pd.DataFrame, split: pd.Series, meta: dict) -> dict:
    out = {"meta": meta, "train": [], "val": [], "test": []}
    for idx, s in zip(df["idx"], split):
        out[s].append(int(idx))
    out["meta"]["sizes"] = {k: len(out[k]) for k in ("train", "val", "test")}
    for k in ("train", "val", "test"):
        sub = df[df["idx"].isin(out[k])]
        out["meta"][f"{k}_date_range"] = [str(sub["published_date"].min()), str(sub["published_date"].max())] if len(sub) else None
    return out
