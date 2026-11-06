#!/usr/bin/env python
"""Offline check of the Stage-4 extractor against published SecVulEval rows.

Builds commit caches for three torvalds/linux commits (04bcef2a, 05692d70, 0926f910) in the exact
layout Stage 3 produces (data/raw/commits/torvalds__linux/<sha>/), runs `Extractor.process_commit`,
and compares `changed_statements` / `changed_lines` with the rows of arag0rn/SecVulEval. Also checks
that the vulnerable `mlx4_register_mac` gets a guard-anchor sink candidate.

Requires the three linux commits already cached under data/raw/commits/ (no network).

    .venv/bin/python tests/test_stage3_secvuleval.py [--verbose]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vulspot.config import load_config  # noqa: E402
from vulspot.extract import Extractor  # noqa: E402
from vulspot.io import write_json  # noqa: E402

FIX = ROOT / "tests" / "fixtures"
REPO = "torvalds/linux"


def build_fixture_caches(commits_dir: Path) -> list[Path]:
    dirs = []
    missing = []
    for c in json.loads((FIX / "secvuleval_commits.json").read_text()):
        d = commits_dir / REPO.replace("/", "__") / c["sha"]
        d.mkdir(parents=True, exist_ok=True)
        commit_json = {"sha": c["sha"], "commit": c["commit"], "parents": [{"sha": c["parent"]}], "files": c["files"]}
        write_json(d / "commit.json", commit_json)
        meta = {"repo": REPO, "canonical_repo": REPO, "sha": c["sha"], "full_sha": c["sha"], "cve_ids": c["cve_ids"],
                "status": "ok", "parents": [c["parent"]], "commit_date": c["commit"]["committer"]["date"],
                "author_date": c["commit"]["author"]["date"], "errors": [], "fixture": True}
        write_json(d / "meta.json", meta, indent=2)
        for f in c["files"]:
            for side, _ref in (("before", c["parent"]), ("after", c["sha"])):
                p = d / side / f["filename"]
                if not p.exists():
                    missing.append(str(p))
        dirs.append(d)
    if missing:
        raise SystemExit(
            "offline SecVulEval fixtures are missing (no network in this test):\n  "
            + "\n  ".join(missing)
        )
    return dirs


def norm_stmt(s: str) -> str:
    s = s.strip()
    if s.endswith("{"):
        s = s[:-1].rstrip()
    return " ".join(s.split())


def compare(expected: list[dict], rows: list[dict], verbose: bool) -> int:
    failures = 0
    by_key = {}
    for r in rows:
        by_key[(r["commit_id"], r["filepath"], r["func_name"], bool(r["is_vulnerable"]))] = r
    for e in expected:
        key = (e["commit_id"], e["filepath"], e["func_name"], bool(e["is_vulnerable"]))
        r = by_key.get(key)
        tag = f"{e['commit_id'][:8]} {e['func_name']} {'vuln' if e['is_vulnerable'] else 'fixed'}"
        if r is None:
            print(f"FAIL {tag}: row not produced")
            failures += 1
            continue
        exp_lines = json.loads(e["changed_lines"])
        got_lines = json.loads(r["changed_lines"])
        exp_st = json.loads(e["changed_statements"])
        got_st = json.loads(r["changed_statements"])
        ok_lines = exp_lines == got_lines
        ok_st = [(ln, norm_stmt(t)) for ln, t in exp_st] == [(ln, norm_stmt(t)) for ln, t in got_st]
        ok_body = (e.get("func_body") is None) or (e["func_body"].strip() == r["func_body"].strip())
        status = "OK  " if (ok_lines and ok_st and ok_body) else "FAIL"
        if status == "FAIL":
            failures += 1
        print(f"{status} {tag}: lines={'ok' if ok_lines else 'DIFF'} statements={'ok' if ok_st else 'DIFF'} body={'ok' if ok_body else 'DIFF'}"
              f" sinks={r['n_sink_candidates']} edits={r['n_code_edits']}")
        if verbose or status == "FAIL":
            if not ok_lines:
                print("   expected lines:", exp_lines)
                print("   got lines     :", got_lines)
            if not ok_st:
                print("   expected stmts:", exp_st)
                print("   got stmts     :", got_st)
            if r["is_vulnerable"]:
                for s in json.loads(r["sink_candidates"]):
                    print(f"   sink {s['kind']:20s} L{s['abs_line']} (rel {s['rel_line']}) {s['text'][:70]!r}"
                          + (f"  <- inserted {s['inserted_text'][:50]!r}" if s.get("inserted_text") else ""))
    return failures


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    cfg = load_config()
    dirs = build_fixture_caches(cfg.paths.raw_commits)
    ex = Extractor(cfg, cve_desc={})
    rows = []
    for d in dirs:
        meta = json.loads((d / "meta.json").read_text())
        rec, rs = ex.process_commit(d, meta)
        print(f"commit {rec['sha_short']}: files={rec['n_files']} code={rec['n_code_files']} changed_funcs={rec['n_changed_funcs']} "
              f"untouched={rec['n_untouched_funcs']} rows={len(rs)}")
        rows.extend(rs)
    expected = json.loads((FIX / "secvuleval_expected.json").read_text())
    failures = compare(expected, rows, args.verbose)

    # guard-anchor check
    mac = [r for r in rows if r["func_name"] == "mlx4_register_mac" and r["is_vulnerable"]]
    assert mac, "mlx4_register_mac vulnerable row missing"
    sinks = json.loads(mac[0]["sink_candidates"])
    guard = [s for s in sinks if s["kind"] == "anchor_dataflow" and s.get("anchor_rule") == "guard_use_strict"]
    if guard and "free" in guard[0]["text"]:
        print(f"OK   mlx4_register_mac guard anchor -> L{guard[0]['abs_line']} {guard[0]['text']!r} (guard ident {guard[0]['guard_ident']})")
    else:
        print("FAIL mlx4_register_mac: no guard-anchor sink candidate; sinks =", sinks)
        failures += 1
    print(f"\n{len(expected)} expected rows checked, {failures} failure(s)")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
