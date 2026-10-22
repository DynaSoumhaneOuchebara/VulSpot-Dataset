#!/usr/bin/env python
"""Fully offline: split invariants (chronology, Linux never held out, eval subsets) and the balanced cap."""
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vulspot.build import balanced_mask
from vulspot.splits import chrono_split, project_holdout_split

LINUX = "https://github.com/torvalds/linux"


def _frame() -> pd.DataFrame:
    rows = []
    idx = 0
    for k in range(40):
        url = LINUX if k % 2 == 0 else f"https://github.com/org/p{k % 10}"
        date = f"2020-{1 + k % 12:02d}-{1 + k % 28:02d}T00:00:00" if k < 30 else f"2025-0{1 + k % 9}-01T00:00:00"
        commit = f"c{k:03d}"
        # vulnerable + its fix + one untouched negative per commit
        for vul, neg, conf in ((True, None, "high" if k % 3 else "medium"), (False, "fixed", "high"),
                               (False, "untouched", None)):
            rows.append({
                "idx": idx, "commit_id": commit, "published_date": date, "project_url": url,
                "is_vulnerable": vul, "neg_type": neg, "label_confidence": conf, "clean": True,
                "fixed_func_idx": idx + 1 if vul else (idx if neg == "fixed" else None),
                "clone_group_id": f"g{idx}", "cve_list": [f"CVE-{k}"],
            })
            idx += 1
    df = pd.DataFrame(rows)
    # a clone of an early train row inside the last commit
    df.loc[df.index[-1], "clone_group_id"] = "g0"
    return df


def test_chrono_drops_clones_and_keeps_order():
    df = _frame()
    s = chrono_split(df)
    assert s["meta"]["dropped_by_clone_groups"] == 1
    assert int(df["idx"].iloc[-1]) not in set(s["train"]) | set(s["val"]) | set(s["test"])
    by = df.set_index("idx")["published_date"]
    assert by.loc[s["train"]].max() <= by.loc[s["test"]].min()


def test_holdout_never_holds_out_linux():
    df = _frame()
    for seed in range(10):
        s = project_holdout_split(df, holdout_fraction=0.6, seed=seed)
        assert LINUX not in s["meta"]["held_out_projects"]
        test_urls = set(df.set_index("idx").loc[s["test"], "project_url"])
        assert LINUX not in test_urls


def test_eval_subsets():
    df = _frame()
    s = chrono_split(df)
    t = df.set_index("idx")
    test = set(s["test"])
    high = set(s["test_high"])
    assert high <= test
    assert not any(t.loc[i, "is_vulnerable"] and t.loc[i, "label_confidence"] != "high" for i in high)
    paired = set(s["test_paired_high"])
    assert paired <= test
    for i in paired:
        if t.loc[i, "is_vulnerable"]:
            assert int(t.loc[i, "fixed_func_idx"]) in paired
    assert all(t.loc[i, "project_url"] != LINUX for i in s["test_no_linux"])


def test_balanced_cap_spreads_over_year():
    rows = []
    for m in range(1, 13):
        for d in range(1, 11):
            rows.append({"project": "linux", "project_url": LINUX, "is_kernel_cna": True,
                         "published_date": f"2024-{m:02d}-{d:02d}T00:00:00", "cve_list": [f"CVE-2024-{m}-{d}"]})
    for y in range(2015, 2024):
        for d in range(1, 13):
            rows.append({"project": "linux", "project_url": LINUX, "is_kernel_cna": False,
                         "published_date": f"{y}-{d:02d}-01T00:00:00", "cve_list": [f"CVE-{y}-{d}"]})
    df = pd.DataFrame(rows)
    keep = balanced_mask(df, {"linux_post_2024_cap_per_year": "auto", "kernel_start": "2024-02-01", "seed": 13})
    kept = df[keep & df["is_kernel_cna"] & (df["published_date"] >= "2024-02-01")]
    assert len(kept) == 12
    assert kept["published_date"].str[5:7].astype(int).max() >= 9


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok", name)
