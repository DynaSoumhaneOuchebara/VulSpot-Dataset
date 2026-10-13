"""CWE helpers: parse NVD weakness entries and map to the CWE-1003 view.

The CWE-1003 view ("Weaknesses for Simplified Mapping of Published Vulnerabilities")
is the set NVD analysts are supposed to use. We download MITRE's CSV exports for view
1003 (membership) and view 1000 (ChildOf hierarchy) and map any CWE to its nearest
ancestor that is a member of 1003.
"""
from __future__ import annotations

import csv
import io
import logging
import re
import zipfile
from pathlib import Path

from .http import HttpClient
from .io import read_json, write_json

log = logging.getLogger("cwe")

CWE_1003_URL = "https://cwe.mitre.org/data/csv/1003.csv.zip"
CWE_1000_URL = "https://cwe.mitre.org/data/csv/1000.csv.zip"

_CWE_ID = re.compile(r"CWE-(\d+)")
_CHILDOF = re.compile(r"NATURE:ChildOf:CWE ID:(\d+)")


def normalize_cwe(value: str) -> str | None:
    """'CWE-119' -> 'CWE-119'; 'NVD-CWE-Other'/'NVD-CWE-noinfo' -> None."""
    if not value:
        return None
    m = _CWE_ID.search(value)
    return f"CWE-{int(m.group(1))}" if m else None


def extract_cwes(cve: dict) -> tuple[list[str], list[dict]]:
    """Return (unique CWE ids in order, raw weakness entries with source/type)."""
    raw = []
    ids: list[str] = []
    for w in cve.get("weaknesses", []) or []:
        for d in w.get("description", []) or []:
            if d.get("lang", "en") != "en":
                continue
            v = d.get("value", "")
            raw.append({"value": v, "source": w.get("source"), "type": w.get("type")})
            n = normalize_cwe(v)
            if n and n not in ids:
                ids.append(n)
    return ids, raw


class Cwe1003Mapper:
    def __init__(self, cache_dir: Path):
        self.cache_dir = cache_dir
        self.cache = cache_dir / "cwe_hierarchy.json"
        self.members: set[str] = set()
        self.parents: dict[str, list[str]] = {}
        self.available = False
        data = read_json(self.cache)
        if data:
            self.members = set(data["members_1003"])
            self.parents = data["parents"]
            self.available = True

    def download(self) -> bool:
        http = HttpClient(min_interval_s=0.5, max_retries=3)
        try:
            members = self._parse_csv_zip(http, CWE_1003_URL, want_parents=False)[0]
            _, parents = self._parse_csv_zip(http, CWE_1000_URL, want_parents=True)
        except Exception as e:  # noqa: BLE001
            log.warning("could not download CWE data (%s); cwe_1003_list will be null", e)
            return False
        self.members, self.parents, self.available = members, parents, True
        write_json(self.cache, {"members_1003": sorted(members), "parents": parents})
        log.info("CWE data cached: %d members in view 1003, %d nodes with parents", len(members), len(parents))
        return True

    @staticmethod
    def _parse_csv_zip(http: HttpClient, url: str, want_parents: bool) -> tuple[set[str], dict[str, list[str]]]:
        r = http.get(url)
        if r is None:
            raise RuntimeError(f"download failed: {url}")
        zf = zipfile.ZipFile(io.BytesIO(r.content))
        name = [n for n in zf.namelist() if n.endswith(".csv")][0]
        text = zf.read(name).decode("utf-8", errors="replace")
        members: set[str] = set()
        parents: dict[str, list[str]] = {}
        for row in csv.DictReader(io.StringIO(text)):
            cid = row.get("CWE-ID")
            if not cid:
                continue
            key = f"CWE-{int(cid)}"
            members.add(key)
            if want_parents:
                rel = row.get("Related Weaknesses", "") or ""
                ps = [f"CWE-{int(p)}" for p in _CHILDOF.findall(rel)]
                if ps:
                    parents[key] = ps
        return members, parents

    def map(self, cwe: str) -> str | None:
        """Nearest 1003 ancestor (BFS over ChildOf), or None."""
        if not self.available:
            return None
        if cwe in self.members:
            return cwe
        seen = {cwe}
        frontier = [cwe]
        while frontier:
            nxt = []
            for c in frontier:
                for p in self.parents.get(c, []):
                    if p in self.members:
                        return p
                    if p not in seen:
                        seen.add(p)
                        nxt.append(p)
            frontier = nxt
        return None

    def map_list(self, cwes: list[str]) -> list[str] | None:
        if not self.available:
            return None
        out: list[str] = []
        for c in cwes:
            m = self.map(c)
            if m and m not in out:
                out.append(m)
        return out
