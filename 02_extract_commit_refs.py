#!/usr/bin/env python
"""Stage 2: offline pass over the NVD cache -> CVE metadata + patch-commit references.

Outputs (data/interim/):
  cves.jsonl.gz        one record per non-rejected CVE with description, dates, CNA,
                       CVSS, the raw CWE list, the four view columns
                       (cwe_1000_list, cwe_699_list, cwe_1003_list, cwe_1003_high_list),
                       and parsed patch refs
  commit_jobs.jsonl    unique (repo, sha) pairs to fetch in stage 3, with their CVE ids
  02_summary.json      funnel counts and per-host statistics for the report

Network is only used to download MITRE's CWE data once (cached under data/raw/cwe/).
Pass --no-cwe-download to stay fully offline (the view columns will be null).
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from vulspot.config import load_config
from vulspot.cwe import Cwe1003Mapper, extract_cwes
from vulspot.io import write_json, write_jsonl
from vulspot.log import get_logger
from vulspot.nvd import NvdClient
from vulspot.refs import parse_reference


def pick_cvss(cve: dict) -> dict:
    metrics = cve.get("metrics", {}) or {}
    for key, ver in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        entries = metrics.get(key) or []
        if not entries:
            continue
        entries = sorted(entries, key=lambda e: 0 if e.get("type") == "Primary" else 1)
        d = entries[0].get("cvssData", {})
        return {
            "version": ver,
            "base_score": d.get("baseScore"),
            "base_severity": d.get("baseSeverity") or entries[0].get("baseSeverity"),
            "vector": d.get("vectorString"),
        }
    return {"version": None, "base_score": None, "base_severity": None, "vector": None}


def english_description(cve: dict) -> str:
    for d in cve.get("descriptions", []) or []:
        if d.get("lang") == "en":
            return d.get("value", "")
    ds = cve.get("descriptions") or []
    return ds[0].get("value", "") if ds else ""


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=None)
    ap.add_argument("--no-cwe-download", action="store_true")
    args = ap.parse_args()

    cfg = load_config(args.config)
    log = get_logger("02_extract_commit_refs", cfg.paths.logs)
    rcfg = cfg["refs"]
    gh_hosts = set(rcfg["github_hosts"])
    kernel_repo = rcfg["kernel_org_repo"]
    require_tag = rcfg["require_tag"]
    accept_untagged = bool(rcfg.get("accept_untagged_commit_urls", False))

    mapper = Cwe1003Mapper(cfg.paths.raw_nvd.parent / "cwe")
    if not mapper.available and not args.no_cwe_download:
        mapper.download()
    if mapper.available:
        mapper.ensure_levels()
        mapper.check_views()

    nvd = NvdClient(cfg, api_key=None, raw_dir=cfg.paths.raw_nvd)

    summary = Counter()
    hosts_other = Counter()
    hosts_patch_other = Counter()
    cves_out = []
    jobs: dict[tuple[str, str], dict] = {}

    for cve in nvd.iter_all():
        summary["cves_total"] += 1
        status = cve.get("vulnStatus", "")
        if status.lower() == "rejected" or english_description(cve).startswith("** REJECT **"):
            summary["cves_rejected"] += 1
            continue
        summary["cves_kept_non_rejected"] += 1

        refs = cve.get("references", []) or []
        patch_refs = [r for r in refs if require_tag in (r.get("tags") or [])]
        if patch_refs:
            summary["cves_with_patch_tag"] += 1

        commits: dict[tuple[str, str], dict] = {}
        other_patch_refs = []
        for r in refs:
            tags = r.get("tags") or []
            is_patch = require_tag in tags
            parsed = parse_reference(r.get("url", ""), gh_hosts, kernel_repo)
            if parsed.kind in ("github", "kernel.org") and parsed.sha:
                if is_patch or accept_untagged:
                    k = (parsed.repo, parsed.sha)
                    if k not in commits:
                        d = parsed.to_dict()
                        d["tags"] = tags
                        commits[k] = d
                elif parsed.kind == "github":
                    summary["github_commit_urls_without_patch_tag"] += 1
            elif is_patch:
                other_patch_refs.append({"url": r.get("url"), "host": parsed.host, "note": parsed.note})
                hosts_patch_other[parsed.host or "?"] += 1
            if parsed.kind == "other":
                hosts_other[parsed.host or "?"] += 1

        cwe_ids, cwe_raw = extract_cwes(cve)
        rec = {
            "cve_id": cve["id"],
            "published_date": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "vuln_status": status,
            "source_identifier": cve.get("sourceIdentifier"),
            "description": english_description(cve),
            "cvss": pick_cvss(cve),
            "cwe_list": cwe_ids,
            "cwe_raw": cwe_raw,
            **mapper.view_lists(cwe_ids),
            "patch_commits": list(commits.values()),
            "other_patch_refs": other_patch_refs,
            "n_refs": len(refs),
        }
        cves_out.append(rec)

        if commits:
            summary["cves_with_commit_ref"] += 1
            if any(c["kind"] == "github" for c in commits.values()):
                summary["cves_with_github_commit"] += 1
            if any(c["kind"] == "kernel.org" for c in commits.values()):
                summary["cves_with_kernel_org_commit"] += 1
            if len(commits) > 1:
                summary["cves_with_multiple_commit_refs"] += 1
            for (repo, sha), c in commits.items():
                j = jobs.setdefault((repo, sha), {"repo": repo, "sha": sha, "kind": c["kind"],
                                                   "urls": [], "cve_ids": [], "notes": set()})
                j["cve_ids"].append(cve["id"])
                j["urls"].append(c["url"])
                if c.get("note"):
                    j["notes"].add(c["note"])
        elif other_patch_refs:
            summary["cves_with_patch_tag_but_no_supported_commit"] += 1

    n = write_jsonl(cfg.paths.interim / "cves.jsonl.gz", cves_out)
    job_rows = []
    for j in jobs.values():
        j["notes"] = sorted(j["notes"])
        j["cve_ids"] = sorted(set(j["cve_ids"]))
        j["urls"] = sorted(set(j["urls"]))
        job_rows.append(j)
    job_rows.sort(key=lambda j: (j["repo"], j["sha"]))
    m = write_jsonl(cfg.paths.interim / "commit_jobs.jsonl", job_rows)

    summary["unique_commit_jobs"] = m
    summary["unique_repos"] = len({j["repo"] for j in job_rows})
    out = {
        "counts": dict(summary),
        "top_other_hosts_with_patch_tag": hosts_patch_other.most_common(40),
        "top_other_hosts_all_refs": hosts_other.most_common(40),
        "cwe_1003_mapping_available": mapper.available,
    }
    write_json(cfg.paths.interim / "02_summary.json", out, indent=2)
    log.info("wrote %d CVE records and %d commit jobs (%d repos)", n, m, summary["unique_repos"])
    for k, v in sorted(summary.items()):
        log.info("  %-50s %d", k, v)


if __name__ == "__main__":
    main()
