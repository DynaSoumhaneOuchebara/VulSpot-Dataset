"""Stage 5 helpers: join CVE metadata, confidence tiers, later-fixed, kernel-CNA, balancing."""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone

import pandas as pd

from .langs import LanguageResolver


def _parse_json(val, default=None):
    if val is None or (isinstance(val, float) and pd.isna(val)):
        return default
    if isinstance(val, (list, dict)):
        return val
    if isinstance(val, str):
        try:
            return json.loads(val)
        except json.JSONDecodeError:
            return default
    return default


def _parse_dt(s) -> datetime | None:
    if s is None or (isinstance(s, float) and pd.isna(s)):
        return None
    text = str(s).replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        try:
            dt = datetime.strptime(str(s)[:10], "%Y-%m-%d")
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def load_cves(path) -> dict[str, dict]:
    from .io import iter_jsonl
    return {r["cve_id"]: r for r in iter_jsonl(path)}


# Linux stable backports cite the mainline fix ("commit <sha> upstream." / "[ Upstream commit <sha> ]").
_UPSTREAM_REF = re.compile(
    r"(?im)^\s*(?:\[\s*)?(?:upstream commit [0-9a-f]{7,40}|commit [0-9a-f]{7,40} upstream)\b")


def _commit_key(r: dict) -> tuple[str, str]:
    return ((r.get("canonical_repo") or r["repo"]).lower(), (r.get("full_sha") or r["sha"]).lower())


def redundant_backports(resolution_path, extract_path) -> set[tuple[str, str]]:
    """(repo, sha) of backport commits whose CVEs all also reference a non-backport commit.

    NVD lists a kernel fix together with every stable backport of it. Those are one fix, not a
    multi-commit CVE. A backport is kept when it is the only commit we have for one of its CVEs.
    """
    from .io import iter_jsonl
    backport = set()
    for r in iter_jsonl(extract_path):
        if r.get("repo") and r.get("commit_id") and _UPSTREAM_REF.search(r.get("commit_message_raw") or ""):
            backport.add((r["repo"].lower(), r["commit_id"].lower()))
    cves_of = defaultdict(set)
    has_main = set()
    for r in iter_jsonl(resolution_path):
        key = _commit_key(r)
        for cid in r.get("cve_ids") or []:
            cves_of[key].add(cid)
            if key not in backport:
                has_main.add(cid)
    return {k for k in backport if cves_of.get(k) and cves_of[k] <= has_main}


def load_multi_commit_cves(resolution_path, skip_commits: set[tuple[str, str]]) -> set[str]:
    """CVEs referencing more than one distinct commit, after removing redundant backports."""
    from .io import iter_jsonl
    commits = defaultdict(set)
    for r in iter_jsonl(resolution_path):
        key = _commit_key(r)
        if key in skip_commits:
            continue
        for cid in r.get("cve_ids") or []:
            commits[cid].add(key)
    return {c for c, s in commits.items() if len(s) > 1}


def attach_cve_meta(df: pd.DataFrame, cves: dict[str, dict]) -> pd.DataFrame:
    descriptions, cwes, published, cnas, cvss = [], [], [], [], []
    scores, sevs, vectors = [], [], []
    for raw in df["cve_list"]:
        ids = _parse_json(raw, []) or []
        descs, cw, pubs, sources = [], [], [], []
        cv = None
        for cid in ids:
            rec = cves.get(cid) or {}
            if rec.get("description"):
                descs.append(rec["description"])
            for x in rec.get("cwe_list") or []:
                if x not in cw:
                    cw.append(x)
            if rec.get("published_date"):
                pubs.append(rec["published_date"])
            src = rec.get("source_identifier")
            if src and src not in sources:
                sources.append(src)
            if cv is None:
                cv = rec.get("cvss")
        descriptions.append(descs)
        cwes.append(cw)
        published.append(min(pubs) if pubs else None)
        cnas.append(sources[0] if sources else None)
        cvss.append(cv)
        scores.append((cv or {}).get("base_score"))
        sevs.append((cv or {}).get("base_severity"))
        vectors.append((cv or {}).get("vector"))
    df = df.copy()
    df["cve_list"] = [_parse_json(x, []) or [] for x in df["cve_list"]]
    df["cwe_list"] = cwes
    df["cve_descriptions"] = descriptions
    df["published_date"] = published
    df["cna"] = cnas
    df["cvss"] = [json.dumps(c, ensure_ascii=False) if c else None for c in cvss]
    df["cvss_base_score"] = scores
    df["cvss_severity"] = sevs
    df["cvss_vector"] = vectors
    return df


def assign_confidence(df: pd.DataFrame, keep_unmentioned: bool) -> tuple[pd.DataFrame, dict]:
    """high / medium / low; drop unmentioned functions in multi-function files (unless keep_unmentioned)."""
    stats = Counter()
    conf, drop = [], []
    for _, r in df.iterrows():
        if r.get("neg_type") == "untouched" or r.get("pair_status") == "untouched":
            conf.append(None)
            drop.append(False)
            stats["untouched"] += 1
            continue
        if r.get("is_test_file") and int(r.get("is_vulnerable") or 0):
            conf.append("low")
            drop.append(True)
            stats["drop_test_positive"] += 1
            continue
        n_commit = int(r.get("commit_n_funcs") or 0)
        n_file = int(r.get("file_n_changed_funcs") or 0)
        in_desc = bool(r.get("mentioned_in_cve_desc"))
        in_msg = bool(r.get("mentioned_in_commit_msg"))
        if n_commit == 1 or in_desc:
            c = "high"
        elif n_file == 1:
            c = "medium"
        elif in_msg:
            c = "low"
        else:
            c = None
        if c is None and not keep_unmentioned:
            drop.append(True)
            conf.append(None)
            stats["drop_unmentioned"] += 1
        else:
            drop.append(False)
            conf.append(c or "low")
            stats[c or "low"] += 1
    out = df.copy()
    out["label_confidence"] = conf
    kept = out.loc[[not d for d in drop]].copy()
    stats["dropped"] = int(sum(drop))
    return kept, dict(stats)


def drop_no_func_edits(df: pd.DataFrame) -> tuple[pd.DataFrame, int]:
    """Drop changed-function rows from files that ended up with zero in-function code edits."""
    changed = df["pair_status"].isin(["paired", "renamed"])
    has_edit = (df["n_code_edits"].fillna(0) > 0) | (df["n_changed_lines"].fillna(0) > 0)
    bad_files = set()
    for (cid, path), g in df[changed].groupby(["commit_id", "filepath"]):
        if not bool((g["n_code_edits"].fillna(0) > 0).any()) and not bool((g["n_changed_lines"].fillna(0) > 0).any()):
            bad_files.add((cid, path))
    if not bad_files:
        return df, 0
    mask = df.apply(lambda r: (r["commit_id"], r["filepath"]) in bad_files, axis=1)
    # keep untouched of other files; drop everything in bad files
    return df.loc[~mask].copy(), int(mask.sum())


def exact_dedup(df: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    """Keep first occurrence of each body hash (oldest published_date, then commit_id). Flag label conflicts."""
    df = df.copy()
    df["_ord"] = pd.to_datetime(df["published_date"], errors="coerce", utc=True)
    df = df.sort_values(["_ord", "commit_date", "commit_id", "filepath", "func_name"], kind="mergesort")
    conflict = {}
    for h, g in df.groupby("hash", sort=False):
        labs = set(int(x) for x in g["is_vulnerable"].tolist())
        if len(labs) > 1:
            conflict[h] = True
    keep_idx = df.drop_duplicates("hash", keep="first").index
    out = df.loc[keep_idx].copy()
    out["label_conflict"] = out["hash"].map(lambda h: bool(conflict.get(h)))
    stats = {
        "before": len(df),
        "after": len(out),
        "dropped": len(df) - len(out),
        "conflict_hashes": len(conflict),
        "conflict_rows": int(out["label_conflict"].sum()),
    }
    return out.drop(columns=["_ord"]), stats


def later_fixed(df: pd.DataFrame) -> pd.DataFrame:
    """Patched rows whose function is modified by a later CVE commit -> patched_later_vulnerable."""
    df = df.copy()
    df["later_fixed_by"] = [[] for _ in range(len(df))]
    events = defaultdict(list)
    for i, r in df.iterrows():
        if r.get("pair_status") not in ("paired", "renamed"):
            continue
        dt = _parse_dt(r.get("commit_date")) or _parse_dt(r.get("published_date"))
        if dt is None:
            continue
        key = (r["project_url"], r["func_name"], str(r["filepath"]).rsplit("/", 1)[-1])
        events[key].append((dt, r["commit_id"], i, int(r["is_vulnerable"])))
    for key, ev in events.items():
        ev.sort()
        for k, (dt, cid, idx, vul) in enumerate(ev):
            if vul != 0:
                continue
            later = [e[1] for e in ev[k + 1:] if e[3] == 1 and e[1] != cid]
            if later:
                df.at[idx, "later_fixed_by"] = sorted(set(later))
                df.at[idx, "neg_type"] = "patched_later_vulnerable"
    df["later_fixed_by"] = df["later_fixed_by"].map(lambda x: json.dumps(x, ensure_ascii=False))
    return df


def kernel_cna_flag(df: pd.DataFrame, source_ids: list[str], start_date: str) -> pd.DataFrame:
    ids = {s.lower() for s in source_ids}
    start = datetime.strptime(start_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    flags = []
    for cna, pub in zip(df["cna"], df["published_date"]):
        dt = _parse_dt(pub)
        flags.append(bool(cna) and str(cna).lower() in ids and dt is not None and dt >= start)
    out = df.copy()
    out["is_kernel_cna"] = flags
    return out


def balanced_mask(df: pd.DataFrame, cfg: dict) -> pd.Series:
    """True for rows kept in the balanced variant."""
    linux = df["project"].str.lower().eq("linux") | df["project_url"].str.contains("torvalds/linux", na=False)
    start_s = cfg.get("kernel_start", "2024-02-01")
    start = datetime.strptime(start_s, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    cap = cfg.get("linux_post_2024_cap_per_year", "auto")
    keep = pd.Series(True, index=df.index)
    if cap is None:
        return keep
    k = linux & df["is_kernel_cna"]
    if not k.any():
        return keep
    pubs = df["published_date"].map(_parse_dt)
    pre = linux & pubs.map(lambda d: d is not None and d < start)
    if cap == "auto":
        pre_cves = {c for ids in df.loc[pre, "cve_list"] if ids is not None for c in ids}
        years = set()
        for d, m in zip(pubs, pre):
            if m and d is not None:
                years.add(d.year)
        n_years = max(len(years), 1)
        cap_n = max(int(round(len(pre_cves) / n_years)), 1)
    else:
        cap_n = int(cap)
    # Per calendar year after start: keep cap_n CVEs spread over the whole year. Taking the earliest
    # ones would empty the end of every year, i.e. the chronological val/test splits.
    # Ranking by a seeded hash of the CVE id keeps the choice identical across configs (cpp / multi).
    seed = str(cfg.get("seed", 13))
    post = k & pubs.map(lambda d: d is not None and d >= start)
    by_year = defaultdict(set)
    rows = []
    for i, d, ids in zip(df.index[post], pubs[post], df.loc[post, "cve_list"]):
        ids = list(ids) if ids is not None else []
        cid = ids[0] if ids else "?"
        by_year[d.year].add(cid)
        rows.append((i, d.year, cid))
    kept = {}
    for year, cids in by_year.items():
        ranked = sorted(cids, key=lambda c: hashlib.sha1(f"{seed}:{c}".encode()).hexdigest())
        kept[year] = set(ranked[:cap_n])
    drop_idx = [i for i, year, cid in rows if cid not in kept[year]]
    keep.loc[drop_idx] = False
    other_cap = cfg.get("other_projects_cap_per_year")
    if other_cap:
        # optional global per-project yearly cap
        pass
    return keep


def assign_idx_and_pairs(df: pd.DataFrame) -> pd.DataFrame:
    df = df.sort_values(["published_date", "commit_id", "filepath", "func_name", "is_vulnerable"],
                        kind="mergesort").reset_index(drop=True)
    df["idx"] = range(len(df))
    pair_to_fixed = {}
    for i, r in df.iterrows():
        if int(r["is_vulnerable"]) == 0 and r.get("pair_status") in ("paired", "renamed"):
            pair_to_fixed[r["pair_id"]] = int(r["idx"])
    fixed_idx = []
    for _, r in df.iterrows():
        if r.get("pair_status") in ("paired", "renamed"):
            fi = pair_to_fixed.get(r["pair_id"])
            if int(r["is_vulnerable"]) == 0:
                fixed_idx.append(int(r["idx"]))
            else:
                fixed_idx.append(fi if fi is not None else None)
        else:
            fixed_idx.append(int(r["idx"]) if int(r["is_vulnerable"]) == 0 else None)
    df["fixed_func_idx"] = fixed_idx
    return df


def paired_frame(df: pd.DataFrame) -> pd.DataFrame:
    """Vulnerable rows whose fixed partner is in `df`, plus those partners.

    `idx` and `fixed_func_idx` stay as they are in `df`. A vulnerable row is
    dropped when the partner is missing. Untouched functions and functions
    added by the patch are dropped.
    """
    if df["idx"].duplicated().any():
        raise ValueError("idx values are not unique")
    lookup = df.set_index("idx")
    vul = df.loc[df["is_vulnerable"].astype(bool) & df["fixed_func_idx"].notna(), ["idx", "pair_id", "fixed_func_idx"]]
    partner = vul["fixed_func_idx"].astype("int64")
    present = partner.isin(lookup.index)
    vul, partner = vul.loc[present], partner.loc[present]
    if vul.empty:
        return df.iloc[0:0].copy()
    fixed = lookup.loc[partner.to_numpy()]
    ok = (~fixed["is_vulnerable"].astype(bool).to_numpy()) & (fixed["pair_id"].to_numpy() == vul["pair_id"].to_numpy())
    vul = vul.loc[ok]
    partner = partner.loc[ok]
    keep = set(vul["idx"].astype("int64")) | set(partner.astype("int64"))
    return df.loc[df["idx"].isin(keep)].copy()


def _comment_only_fix(row) -> bool:
    """Paired row whose fix changed only comments in this function (the real fix is elsewhere)."""
    if row.get("pair_status") not in ("paired", "renamed"):
        return False
    acts = row.get("edit_actions")
    acts = json.loads(acts) if isinstance(acts, str) else (acts or [])
    return bool(acts) and not any(a.get("is_code") for a in acts)


def clean_flag(df: pd.DataFrame) -> pd.Series:
    conf_ok = df["label_confidence"].isin(["high", "medium"]) | df["label_confidence"].isna()
    # untouched negatives have null confidence; they are clean if not later-vulnerable
    not_conflict = ~df["label_conflict"].fillna(False)
    not_later = df["neg_type"].fillna("") != "patched_later_vulnerable"
    not_test_pos = ~(df["is_test_file"].fillna(False) & df["is_vulnerable"].astype(bool))
    not_comment_pos = ~(df["is_vulnerable"].astype(bool) & df.apply(_comment_only_fix, axis=1))
    return conf_ok & not_conflict & not_later & not_test_pos & not_comment_pos


def cpp_mask(df: pd.DataFrame, resolver: LanguageResolver) -> pd.Series:
    return df["filepath"].map(resolver.is_cpp_dataset_file) & df["language"].isin(["c", "cpp"])


OUTPUT_COLUMNS = [
    "idx", "project", "project_url", "filepath", "commit_id", "commit_message", "is_vulnerable",
    "hash", "func_name", "func_body", "changed_lines", "changed_statements", "cve_list", "cwe_list",
    "fixed_func_idx", "language", "sink_candidates", "edit_actions", "label_confidence", "neg_type",
    "later_fixed_by", "norm_hash", "clone_group_id", "label_conflict", "is_test_file", "is_kernel_cna",
    "cna", "cwe_1000_list", "cwe_699_list", "cwe_1003_list", "cwe_1003_high_list", "cwe_1400_list", "top15_cwe_1400", "callees", "types_used", "macros_used", "globals_used", "same_file_callee_defs",
    "func_start_line", "func_end_line", "func_byte_range", "cve_descriptions", "cvss", "cvss_base_score",
    "cvss_severity", "published_date", "commit_date", "parent_commit_id", "commit_message_raw",
    "commit_n_files", "commit_n_funcs", "file_n_changed_funcs", "clean", "pair_id", "pair_status",
    "n_code_edits", "n_sink_candidates", "mentioned_in_commit_msg", "mentioned_in_cve_desc",
    "func_signature", "qualified_name", "n_lines", "n_statements",
]


def finalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    out["is_vulnerable"] = out["is_vulnerable"].astype(bool)
    if "func_byte_range" not in out.columns:
        out["func_byte_range"] = [[int(a), int(b)] for a, b in zip(out.get("func_byte_start", [0]*len(out)),
                                                                  out.get("func_byte_end", [0]*len(out)))]
    for col in OUTPUT_COLUMNS:
        if col not in out.columns:
            out[col] = None
    return out[OUTPUT_COLUMNS]
