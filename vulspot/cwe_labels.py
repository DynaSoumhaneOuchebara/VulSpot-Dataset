"""Per-CWE CWE-1400 category.

`cwe_1400_list` stays aligned with `cwe_list`: one entry per CWE, in the same
order. The hybrid top-15 helpers below are not written into the dataset.

The hybrid scheme is fit on vulnerable rows of one config's chronological
training split. The 15 most frequent CWEs stay as themselves. Every other CWE
is replaced by its CWE-1400 category, and a category that labels fewer than
100 of those training rows is merged into OTHER. A CWE with no category is
OTHER. A category is counted once per training row that contains it on a CWE
outside the top 15.
"""
from __future__ import annotations

import io
import logging
import re
import urllib.request
import zipfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from .io import read_json, write_json

log = logging.getLogger("cwe_labels")

CWE_XML_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
TOP_K = 15
MIN_CATEGORY_ROWS = 100

_CWE_NUM = re.compile(r"(\d+)")


def parse_cwe_ids(value) -> list[str]:
    """Numeric CWE ids, in list order, without duplicates."""
    if value is None:
        return []
    ids: list[str] = []
    for item in value:
        m = _CWE_NUM.search(str(item))
        if not m:
            continue
        cid = str(int(m.group(1)))
        if cid not in ids:
            ids.append(cid)
    return ids


def load_cwe1400(cache_dir: Path) -> dict[str, str]:
    """Map each CWE-1400 member id to its category id. Cached as JSON."""
    cache = cache_dir / "cwe_1400.json"
    data = read_json(cache)
    if data:
        return {str(k): str(v) for k, v in data.items()}
    log.info("downloading CWE XML for the CWE-1400 view")
    raw = urllib.request.urlopen(CWE_XML_URL, timeout=120).read()
    zf = zipfile.ZipFile(io.BytesIO(raw))
    xml = zf.read(next(n for n in zf.namelist() if n.endswith(".xml"))).decode("utf-8", "replace")
    members = re.search(r'<View ID="1400" .*?</Members>', xml, re.S)
    if members is None:
        raise RuntimeError("CWE-1400 view not found in the downloaded XML")
    mapping: dict[str, str] = {}
    for cid in re.findall(r'CWE_ID="(\d+)"', members.group(0)):
        block = re.search(r'<Category ID="%s".*?</Category>' % cid, xml, re.S)
        if block is None:
            continue
        for wid in re.findall(r'<Has_Member CWE_ID="(\d+)" View_ID="1400"/>', block.group(0)):
            mapping[wid] = cid
    write_json(cache, mapping)
    log.info("cached %d CWE-1400 memberships at %s", len(mapping), cache)
    return mapping


@dataclass(frozen=True)
class HybridScheme:
    freq: dict[str, int]
    top: tuple[str, ...]
    small: frozenset[str]
    categories: dict[str, str]

    @property
    def topset(self) -> set[str]:
        return set(self.top)


def fit_scheme(
    train_lists: list[list[str]],
    categories: dict[str, str],
    *,
    k: int = TOP_K,
    min_rows: int = MIN_CATEGORY_ROWS,
) -> HybridScheme:
    """Fit the hybrid label set on training rows that already have CWEs."""
    freq: Counter[str] = Counter()
    for ids in train_lists:
        freq.update(ids)
    top = tuple(cid for cid, _ in sorted(freq.items(), key=lambda kv: (-kv[1], int(kv[0])))[:k])
    topset = set(top)
    assigned: Counter[str] = Counter()
    for ids in train_lists:
        seen: set[str] = set()
        for cid in ids:
            if cid in topset:
                continue
            cat = categories.get(cid)
            if cat and cat not in seen:
                seen.add(cat)
                assigned[cat] += 1
    small = frozenset(cat for cat, n in assigned.items() if n < min_rows)
    return HybridScheme(freq=dict(freq), top=top, small=small, categories=categories)


def cwe_1400_aligned(ids: list[str], categories: dict[str, str]) -> list[str | None]:
    """CWE-1400 category of each CWE. Null when that CWE is not in the view."""
    out: list[str | None] = []
    for cid in ids:
        cat = categories.get(cid)
        out.append(f"CWE-{cat}" if cat else None)
    return out


def label_rows(
    cwe_values, scheme: HybridScheme,
) -> tuple[list[list[str | None]], list[list[str]]]:
    """Parallel columns for a sequence of raw `cwe_list` values."""
    parsed = [parse_cwe_ids(value) for value in cwe_values]
    return (
        [cwe_1400_aligned(ids, scheme.categories) for ids in parsed],
        [top15_labels(ids, scheme) for ids in parsed],
    )


def top15_labels(ids: list[str], scheme: HybridScheme) -> list[str]:
    """Hybrid label of each CWE. Empty when the row has no CWE."""
    return [_top15_one(cid, scheme) for cid in ids]


def _top15_one(cid: str, scheme: HybridScheme) -> str:
    if cid in scheme.topset:
        return f"CWE-{cid}"
    cat = scheme.categories.get(cid)
    if cat and cat not in scheme.small:
        return f"CWE-{cat}"
    return "OTHER"
