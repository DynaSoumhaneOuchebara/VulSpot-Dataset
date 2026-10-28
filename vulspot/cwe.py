"""CWE helpers: parse NVD weakness entries and map them onto CWE views.

CWE-1000 (Research Concepts) is labeled by its 10 pillars. The mapping follows
the primary ChildOf link in that view up to a pillar.

CWE-699 (Software Development) is labeled by its 40 categories. A weakness the
view lists under those categories maps to them. Anything else is walked up the
CWE-1000 primary ChildOf chain to the nearest listed member or category.

CWE-1003 has 130 members: 37 sit directly under the view and 93 sit under those
37. `map_member_list` keeps whichever of the 130 is nearest. `map_list` is the
older rollup onto the 37 only.
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
CWE_XML_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
TOP_LEVEL_1000 = 10
TOP_LEVEL_699 = 40
TOP_LEVEL_1003 = 37
VIEW_1003_MEMBERS = 130
VIEW_COLUMNS = ("cwe_1000_list", "cwe_699_list", "cwe_1003_list", "cwe_1003_high_list")
PILLARS_1000 = {
    "CWE-284", "CWE-435", "CWE-664", "CWE-682", "CWE-691",
    "CWE-693", "CWE-697", "CWE-703", "CWE-707", "CWE-710",
}

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


def parse_1003_tree(xml: str) -> tuple[list[str], dict[str, str]]:
    """Direct CWE-1003 members, and each deeper member's parent in that view."""
    view = re.search(r'<View ID="1003" .*?</View>', xml, re.S)
    if view is None:
        raise RuntimeError("CWE-1003 view not found")
    mem = re.search(r"<Members>.*?</Members>", view.group(0), re.S)
    if mem is None:
        raise RuntimeError("CWE-1003 members not found")
    roots = [f"CWE-{int(c)}" for c in re.findall(r'CWE_ID="(\d+)"', mem.group(0))]
    if len(roots) != len(set(roots)):
        raise RuntimeError("duplicate CWE-1003 top-level ids")
    parent_of: dict[str, str] = {}
    starts = list(re.finditer(r"<(Weakness|Category) ID=\"(\d+)\"", xml))
    for i, match in enumerate(starts):
        end = starts[i + 1].start() if i + 1 < len(starts) else len(xml)
        chunk = xml[match.start():end]
        kind = match.group(1)
        close = chunk.find(f"</{kind}>")
        if close != -1:
            chunk = chunk[: close + len(kind) + 3]
        parents = re.findall(
            r'<Related_Weakness Nature="ChildOf" CWE_ID="(\d+)" View_ID="1003"',
            chunk,
        )
        if not parents:
            continue
        if len(set(parents)) > 1:
            raise RuntimeError(f"CWE-{match.group(2)} has multiple CWE-1003 parents")
        parent_of[f"CWE-{int(match.group(2))}"] = f"CWE-{int(parents[0])}"
    rootset = set(roots)
    outside = set(parent_of.values()) - rootset
    if outside:
        raise RuntimeError(f"CWE-1003 parents outside the top level: {sorted(outside)}")
    if set(parent_of) & rootset:
        raise RuntimeError("a CWE-1003 top-level id is also listed as a child")
    if len(roots) != TOP_LEVEL_1003:
        log.warning("CWE-1003 top level has %d entries, expected %d", len(roots), TOP_LEVEL_1003)
    return roots, parent_of


def rollup_to_root(
    cwe: str,
    *,
    roots: set[str],
    view_parent: dict[str, str],
    members: set[str],
    childof: dict[str, list[str]],
) -> str | None:
    """Map one CWE to a top-level CWE-1003 id, or None."""
    if cwe in roots:
        return cwe
    if cwe in view_parent:
        return view_parent[cwe]
    seen = {cwe}
    frontier = [cwe]
    while frontier:
        nxt: list[str] = []
        for node in frontier:
            for parent in childof.get(node, []):
                if parent in members:
                    if parent in roots:
                        return parent
                    rolled = view_parent.get(parent)
                    if rolled:
                        return rolled
                if parent not in seen:
                    seen.add(parent)
                    nxt.append(parent)
        frontier = nxt
    return None


def map_cwe_list(
    cwes: list[str],
    *,
    roots: set[str],
    view_parent: dict[str, str],
    members: set[str],
    childof: dict[str, list[str]],
) -> list[str]:
    """Top-level CWE-1003 ids, first-seen order, duplicates dropped."""
    out: list[str] = []
    for cwe in cwes:
        mapped = rollup_to_root(
            cwe, roots=roots, view_parent=view_parent, members=members, childof=childof,
        )
        if mapped and mapped not in out:
            out.append(mapped)
    return out


def nearest_view_member(
    cwe: str,
    *,
    members: set[str],
    childof: dict[str, list[str]],
) -> str | None:
    """Nearest CWE-1003 view member, without rolling a child up to its parent."""
    if cwe in members:
        return cwe
    seen = {cwe}
    frontier = [cwe]
    while frontier:
        nxt: list[str] = []
        for node in frontier:
            for parent in childof.get(node, []):
                if parent in members:
                    return parent
                if parent not in seen:
                    seen.add(parent)
                    nxt.append(parent)
        frontier = nxt
    return None


def map_cwe_members(
    cwes: list[str],
    *,
    members: set[str],
    childof: dict[str, list[str]],
) -> list[str]:
    """CWE-1003 members (any of the 130), first-seen order, duplicates dropped."""
    out: list[str] = []
    for cwe in cwes:
        mapped = nearest_view_member(cwe, members=members, childof=childof)
        if mapped and mapped not in out:
            out.append(mapped)
    return out


def map_to_pillar(cwe: str, *, pillars: set[str], primary: dict[str, str]) -> str | None:
    """Follow the primary CWE-1000 ChildOf chain to one of the 10 pillars."""
    seen: set[str] = set()
    cur = cwe
    while cur and cur not in seen:
        if cur in pillars:
            return cur
        seen.add(cur)
        cur = primary.get(cur)
    return None


def map_pillar_list(cwes: list[str], *, pillars: set[str], primary: dict[str, str]) -> list[str]:
    """CWE-1000 pillars, first-seen order, duplicates dropped."""
    out: list[str] = []
    for cwe in cwes:
        mapped = map_to_pillar(cwe, pillars=pillars, primary=primary)
        if mapped and mapped not in out:
            out.append(mapped)
    return out


def map_to_699(
    cwe: str,
    *,
    categories: set[str],
    member_of: dict[str, list[str]],
    primary: dict[str, str],
) -> list[str]:
    """Categories of the nearest CWE-699 member on the primary CWE-1000 chain."""
    seen: set[str] = set()
    cur = cwe
    while cur and cur not in seen:
        seen.add(cur)
        if cur in categories:
            return [cur]
        cats = member_of.get(cur)
        if cats:
            return list(cats)
        cur = primary.get(cur)
    return []


def map_category_699_list(
    cwes: list[str],
    *,
    categories: set[str],
    member_of: dict[str, list[str]],
    primary: dict[str, str],
) -> list[str]:
    """CWE-699 categories, first-seen order, duplicates dropped."""
    out: list[str] = []
    for cwe in cwes:
        for mapped in map_to_699(cwe, categories=categories, member_of=member_of, primary=primary):
            if mapped not in out:
                out.append(mapped)
    return out


def _tag_attrs(chunk: str, name: str):
    for tag in re.findall(rf"<{name}\b[^>]*?/?>", chunk):
        yield dict(re.findall(r'([A-Za-z_]+)="([^"]*)"', tag))


def _entry_chunks(xml: str) -> dict[str, str]:
    starts = list(re.finditer(r'<(Weakness|Category|CompoundElement) ID="(\d+)"', xml))
    chunks: dict[str, str] = {}
    for i, match in enumerate(starts):
        end = starts[i + 1].start() if i + 1 < len(starts) else len(xml)
        chunk = xml[match.start():end]
        kind = match.group(1)
        close = chunk.find(f"</{kind}>")
        if close != -1:
            chunk = chunk[: close + len(kind) + 3]
        chunks[f"CWE-{int(match.group(2))}"] = chunk
    return chunks


def _view_member_ids(xml: str, view_id: str) -> list[str]:
    view = re.search(rf'<View ID="{view_id}" .*?</View>', xml, re.S)
    if view is None:
        raise RuntimeError(f"CWE-{view_id} view not found")
    mem = re.search(r"<Members>.*?</Members>", view.group(0), re.S)
    if mem is None:
        raise RuntimeError(f"CWE-{view_id} members not found")
    ids = [f"CWE-{int(c)}" for c in re.findall(r'CWE_ID="(\d+)"', mem.group(0))]
    if len(ids) != len(set(ids)):
        raise RuntimeError(f"duplicate CWE-{view_id} member ids")
    return ids


def view_levels_from_xml(xml: str) -> dict:
    """Pillars of view 1000, its primary parents, and the CWE-699 category map."""
    chunks = _entry_chunks(xml)
    pillars = _view_member_ids(xml, "1000")
    categories = _view_member_ids(xml, "699")
    primary: dict[str, str] = {}
    for cid, chunk in chunks.items():
        parents = []
        for attrs in _tag_attrs(chunk, "Related_Weakness"):
            if (
                attrs.get("Nature") == "ChildOf"
                and attrs.get("View_ID") == "1000"
                and attrs.get("Ordinal") == "Primary"
                and attrs.get("CWE_ID")
            ):
                parents.append(f"CWE-{int(attrs['CWE_ID'])}")
        if not parents:
            continue
        if len(set(parents)) > 1:
            raise RuntimeError(f"{cid} has multiple primary parents in CWE-1000")
        primary[cid] = parents[0]
    order = {cat: i for i, cat in enumerate(categories)}
    member_of: dict[str, list[str]] = {}
    for cat in categories:
        chunk = chunks.get(cat)
        if chunk is None:
            raise RuntimeError(f"{cat} is a CWE-699 category but has no entry")
        for attrs in _tag_attrs(chunk, "Has_Member"):
            if attrs.get("View_ID") != "699" or not attrs.get("CWE_ID"):
                continue
            key = f"CWE-{int(attrs['CWE_ID'])}"
            cats = member_of.setdefault(key, [])
            if cat not in cats:
                cats.append(cat)
    for cats in member_of.values():
        cats.sort(key=lambda cat: order[cat])
    return {
        "pillars_1000": pillars,
        "primary_1000": primary,
        "categories_699": categories,
        "member_699": member_of,
    }


class Cwe1003Mapper:
    def __init__(self, cache_dir: Path):
        self.cache_dir = cache_dir
        self.cache = cache_dir / "cwe_hierarchy.json"
        self.members: set[str] = set()
        self.parents: dict[str, list[str]] = {}
        self.roots: set[str] = set()
        self.view_parent: dict[str, str] = {}
        self.pillars: list[str] = []
        self.primary_1000: dict[str, str] = {}
        self.categories_699: list[str] = []
        self.member_699: dict[str, list[str]] = {}
        self.available = False
        data = read_json(self.cache)
        if data:
            self.members = set(data["members_1003"])
            self.parents = data["parents"]
            self.roots = set(data.get("roots_1003") or [])
            self.view_parent = {str(k): str(v) for k, v in (data.get("parent_1003") or {}).items()}
            self._load_levels(data)
            self.available = True

    def _load_levels(self, data: dict) -> None:
        self.pillars = [str(x) for x in (data.get("pillars_1000") or [])]
        self.primary_1000 = {str(k): str(v) for k, v in (data.get("primary_1000") or {}).items()}
        self.categories_699 = [str(x) for x in (data.get("categories_699") or [])]
        self.member_699 = {
            str(k): [str(x) for x in v] for k, v in (data.get("member_699") or {}).items()
        }

    def levels_ready(self) -> bool:
        return (
            len(self.pillars) == TOP_LEVEL_1000
            and len(self.categories_699) == TOP_LEVEL_699
            and bool(self.primary_1000)
            and bool(self.member_699)
        )

    def ensure_levels(self) -> None:
        """Cache the CWE-1000 pillars and CWE-699 categories without touching the 1003 graph."""
        if self.levels_ready():
            return
        http = HttpClient(min_interval_s=0.5, max_retries=3, timeout=120)
        xml = self._download_xml(http)
        levels = view_levels_from_xml(xml)
        self._load_levels(levels)
        data = read_json(self.cache) or {}
        data.update(levels)
        write_json(self.cache, data)
        log.info(
            "CWE view levels cached: %d pillars, %d primary parents, %d categories, %d memberships",
            len(self.pillars), len(self.primary_1000), len(self.categories_699), len(self.member_699),
        )
        if not self.levels_ready():
            raise RuntimeError(
                f"CWE view levels are {len(self.pillars)} pillars and "
                f"{len(self.categories_699)} categories"
            )

    def download(self) -> bool:
        http = HttpClient(min_interval_s=0.5, max_retries=3, timeout=120)
        try:
            members = self._parse_csv_zip(http, CWE_1003_URL, want_parents=False)[0]
            _, parents = self._parse_csv_zip(http, CWE_1000_URL, want_parents=True)
            xml = self._download_xml(http)
            roots, view_parent = parse_1003_tree(xml)
            levels = view_levels_from_xml(xml)
        except Exception as e:  # noqa: BLE001
            log.warning("could not download CWE data (%s); CWE view columns will be null", e)
            return False
        self.members, self.parents, self.available = members, parents, True
        self.roots, self.view_parent = set(roots), view_parent
        self._load_levels(levels)
        write_json(self.cache, {
            "members_1003": sorted(members),
            "parents": parents,
            "roots_1003": roots,
            "parent_1003": view_parent,
            **levels,
        })
        log.info(
            "CWE data cached: %d top-level and %d deeper members in view 1003, %d nodes with parents",
            len(roots), len(view_parent), len(parents),
        )
        return True

    @staticmethod
    def _download_xml(http: HttpClient) -> str:
        xml_resp = http.get(CWE_XML_URL)
        if xml_resp is None:
            raise RuntimeError(f"download failed: {CWE_XML_URL}")
        zf = zipfile.ZipFile(io.BytesIO(xml_resp.content))
        xml_name = next(n for n in zf.namelist() if n.endswith(".xml"))
        return zf.read(xml_name).decode("utf-8", "replace")

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
        """Top-level CWE-1003 id (one of the 37), or None."""
        if not self.available:
            return None
        if not self.roots:
            raise RuntimeError("CWE-1003 top-level roots are missing from the cache")
        return rollup_to_root(
            cwe,
            roots=self.roots,
            view_parent=self.view_parent,
            members=self.members,
            childof=self.parents,
        )

    def map_list(self, cwes: list[str] | None) -> list[str] | None:
        """Top-level CWE-1003 ids (the 37). This is `cwe_1003_high_list`."""
        if not self.available:
            return None
        if not self.roots:
            raise RuntimeError("CWE-1003 top-level roots are missing from the cache")
        return map_cwe_list(
            list(cwes or []),
            roots=self.roots,
            view_parent=self.view_parent,
            members=self.members,
            childof=self.parents,
        )

    def map_member_list(self, cwes: list[str] | None) -> list[str] | None:
        """Nearest CWE-1003 member (any of the 130). This is `cwe_1003_list`."""
        if not self.available:
            return None
        if len(self.members) != VIEW_1003_MEMBERS:
            raise RuntimeError(f"CWE-1003 has {len(self.members)} members, expected {VIEW_1003_MEMBERS}")
        return map_cwe_members(list(cwes or []), members=self.members, childof=self.parents)

    def map_1000_list(self, cwes: list[str] | None) -> list[str] | None:
        if not self.available:
            return None
        if len(self.pillars) != TOP_LEVEL_1000:
            raise RuntimeError(f"CWE-1000 has {len(self.pillars)} pillars, expected {TOP_LEVEL_1000}")
        return map_pillar_list(list(cwes or []), pillars=set(self.pillars), primary=self.primary_1000)

    def map_699_list(self, cwes: list[str] | None) -> list[str] | None:
        if not self.available:
            return None
        if len(self.categories_699) != TOP_LEVEL_699:
            raise RuntimeError(f"CWE-699 has {len(self.categories_699)} categories, expected {TOP_LEVEL_699}")
        return map_category_699_list(
            list(cwes or []),
            categories=set(self.categories_699),
            member_of=self.member_699,
            primary=self.primary_1000,
        )

    def rollup_member(self, member: str) -> str | None:
        """Top-level CWE-1003 parent of a view member."""
        if member in self.view_parent:
            return self.view_parent[member]
        if member in self.roots:
            return member
        return None

    def view_lists(self, cwes: list[str] | None) -> dict[str, list[str] | None]:
        """The four dataset view columns for one raw CWE list.

        `cwe_1000_list` is the CWE-1000 pillars, `cwe_699_list` the CWE-699
        categories, `cwe_1003_list` any of the 130 CWE-1003 members, and
        `cwe_1003_high_list` the 37 top-level entries of that view.
        """
        if not self.available:
            return {name: None for name in VIEW_COLUMNS}
        ids = list(cwes or [])
        return {
            "cwe_1000_list": self.map_1000_list(ids),
            "cwe_699_list": self.map_699_list(ids),
            "cwe_1003_list": self.map_member_list(ids),
            "cwe_1003_high_list": self.map_list(ids),
        }

    def check_views(self) -> None:
        """Fail if the cached graphs are not the views the dataset columns use."""
        if len(self.roots) != TOP_LEVEL_1003 or len(self.members) != VIEW_1003_MEMBERS:
            raise RuntimeError(
                f"CWE-1003 has {len(self.roots)} top-level entries and {len(self.members)} members"
            )
        if set(self.pillars) != PILLARS_1000 or len(self.categories_699) != TOP_LEVEL_699:
            raise RuntimeError(
                f"CWE-1000 pillars {self.pillars}; CWE-699 has {len(self.categories_699)} categories"
            )
        if len(self.primary_1000) < 900 or len(self.member_699) < 350:
            raise RuntimeError(
                f"CWE graph looks short: {len(self.primary_1000)} primary parents, "
                f"{len(self.member_699)} CWE-699 memberships"
            )
        expect = {
            ("CWE-787",): (["CWE-664"], ["CWE-1218"], ["CWE-787"], ["CWE-119"]),
            ("CWE-122",): (["CWE-664"], ["CWE-1218"], ["CWE-787"], ["CWE-119"]),
            ("CWE-119",): (["CWE-664"], [], ["CWE-119"], ["CWE-119"]),
            ("CWE-476",): (["CWE-710"], ["CWE-465"], ["CWE-476"], ["CWE-754"]),
            ("CWE-416",): (["CWE-664"], ["CWE-465"], ["CWE-416"], ["CWE-672"]),
            ("CWE-798",): (["CWE-284"], ["CWE-255", "CWE-320"], ["CWE-798"], ["CWE-287"]),
            ("CWE-20",): (["CWE-707"], [], ["CWE-20"], ["CWE-20"]),
            ("CWE-125", "CWE-787"): (["CWE-664"], ["CWE-1218"], ["CWE-125", "CWE-787"], ["CWE-119"]),
        }
        for ids, (pillars, cats, members, high) in expect.items():
            got = self.view_lists(list(ids))
            mapped = (
                got["cwe_1000_list"], got["cwe_699_list"],
                got["cwe_1003_list"], got["cwe_1003_high_list"],
            )
            if mapped != (pillars, cats, members, high):
                raise RuntimeError(f"{ids}: mapped to {mapped}, expected {(pillars, cats, members, high)}")
            rolled = []
            for member in got["cwe_1003_list"] or []:
                parent = self.rollup_member(member)
                if parent and parent not in rolled:
                    rolled.append(parent)
            if rolled != high:
                raise RuntimeError(f"{ids}: cwe_1003_high_list {high} is not the rollup of {got['cwe_1003_list']}")
