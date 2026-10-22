"""Dataset splits.

chrono.json          : 80/10/10 by CVE published_date (all rows of a CVE / commit stay together), then
                       group-aware on clone_group_id: a row whose clone group already appears in an earlier
                       split (train < val < test) is excluded, so later splits never contain a clone of an
                       earlier one and train never contains rows newer than test.
project_holdout.json : a random ~fraction of projects (by rows) held out as test; the remaining rows are
                       split chronologically into train/val (ratio 9:1 of the remainder). Projects listed in
                       `never_holdout` (Linux) or larger than the target always stay in train/val.
                       Same clone-group exclusion as chrono.

Each file also carries evaluation subsets of `test` (indices into `idx`):
  test_high         : `clean` rows of test, minus vulnerable rows whose label_confidence is not high
  test_paired_high  : high-confidence clean vulnerable rows whose fixed version is also in test, plus those fixed rows
  test_no_linux     : test without torvalds/linux rows
"""
from __future__ import annotations

import random
from collections import defaultdict

import pandas as pd

ORDER = {"train": 0, "val": 1, "test": 2}
LINUX_URL = "torvalds/linux"


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
    """Exclude (set to None) rows whose clone group has a member in an earlier split (train < val < test)."""
    split = split.copy()
    if group_col not in df.columns:
        split.attrs["dropped_by_clone_groups"] = 0
        return split
    grp = df[group_col]
    valid = grp.notna()
    earliest = defaultdict(lambda: 2)
    for gid, s in zip(grp[valid], split[valid]):
        earliest[gid] = min(earliest[gid], ORDER[s])
    dropped = 0
    for i in df.index[valid]:
        if ORDER[split.at[i]] > earliest[grp.at[i]]:
            split.at[i] = None
            dropped += 1
    split.attrs["dropped_by_clone_groups"] = dropped
    return split


def chrono_split(df: pd.DataFrame, fractions=(0.8, 0.1, 0.1), group_col: str = "clone_group_id") -> dict:
    by_commit = _assign_by_cve(df, fractions)
    split = df["commit_id"].map(by_commit)
    split = _group_fix(df, split, group_col)
    return _package(df, split, {"type": "chronological", "fractions": list(fractions), "group_col": group_col,
                                "dropped_by_clone_groups": split.attrs.get("dropped_by_clone_groups", 0)})


def _never_holdout(url: str, patterns: list[str]) -> bool:
    u = str(url).lower().rstrip("/")
    return any(u.endswith(p.lower().strip("/")) for p in patterns)


def project_holdout_split(df: pd.DataFrame, holdout_fraction: float = 0.1, seed: int = 13,
                          group_col: str = "clone_group_id", val_fraction: float = 0.1,
                          never_holdout: list[str] | None = None) -> dict:
    never_holdout = [LINUX_URL] if never_holdout is None else list(never_holdout)
    rng = random.Random(seed)
    counts = df.groupby("project_url")["idx"].size().to_dict()
    projects = sorted(counts)
    rng.shuffle(projects)
    total = len(df)
    target = holdout_fraction * total
    held, acc = set(), 0
    for p in projects:
        if acc >= target:
            break
        if counts[p] > target or _never_holdout(p, never_holdout):
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
                                "never_holdout": never_holdout, "held_out_projects": sorted(held),
                                "group_col": group_col,
                                "dropped_by_clone_groups": split.attrs.get("dropped_by_clone_groups", 0)})


def _eval_subsets(test: pd.DataFrame) -> dict[str, list[int]]:
    vul = test["is_vulnerable"].astype(bool)
    high = test["label_confidence"].eq("high")
    clean = test["clean"].fillna(False).astype(bool) if "clean" in test.columns else pd.Series(True, index=test.index)
    linux = test["project_url"].astype(str).str.lower().str.rstrip("/").str.endswith(LINUX_URL)

    test_high = test.loc[clean & ~(vul & ~high), "idx"]

    test_idx = set(int(i) for i in test["idx"])
    pos = test[vul & high & clean & test["fixed_func_idx"].notna()]
    pos = pos[pos["fixed_func_idx"].astype(int).isin(test_idx)]
    paired = set(int(i) for i in pos["idx"]) | set(int(i) for i in pos["fixed_func_idx"])

    return {
        "test_high": sorted(int(i) for i in test_high),
        "test_paired_high": sorted(paired),
        "test_no_linux": sorted(int(i) for i in test.loc[~linux, "idx"]),
    }


def _date_range(sub: pd.DataFrame):
    return [str(sub["published_date"].min()), str(sub["published_date"].max())] if len(sub) else None


def _package(df: pd.DataFrame, split: pd.Series, meta: dict) -> dict:
    out = {"meta": meta, "train": [], "val": [], "test": []}
    for idx, s in zip(df["idx"], split):
        if s is not None and not (isinstance(s, float) and pd.isna(s)):
            out[s].append(int(idx))
    out["meta"]["sizes"] = {k: len(out[k]) for k in ("train", "val", "test")}
    for k in ("train", "val", "test"):
        out["meta"][f"{k}_date_range"] = _date_range(df[df["idx"].isin(out[k])])
    test = df[df["idx"].isin(out["test"])]
    by_idx = df.set_index("idx")["is_vulnerable"].astype(bool)
    for name, ids in _eval_subsets(test).items():
        out[name] = ids
        out["meta"]["sizes"][name] = len(ids)
        out["meta"][f"{name}_vulnerable"] = int(by_idx.loc[ids].sum()) if ids else 0
    return out
