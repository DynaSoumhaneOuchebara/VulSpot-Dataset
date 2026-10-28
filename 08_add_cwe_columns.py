#!/usr/bin/env python
"""Add the CWE view columns on the existing cpp and multi datasets.

cwe_1000_list is the 10 CWE-1000 pillars. cwe_699_list is the 40 CWE-699
categories. cwe_1003_list is any of the 130 CWE-1003 members. The previous
cwe_1003_list (37 top-level entries) is renamed to cwe_1003_high_list.
top15_cwe_1400 is removed.

full, balanced, and paired are rewritten, in parquet and jsonl. Split files
are index lists into those tables, so every split sees the new columns.

    python 08_add_cwe_columns.py
"""
from __future__ import annotations

import gzip
import json
import os
import sys
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parent))

from vulspot.config import load_config
from vulspot.cwe import Cwe1003Mapper
from vulspot.log import get_logger

NEW_COLS = ("cwe_1000_list", "cwe_699_list", "cwe_1003_list", "cwe_1003_high_list")
PILLARS = {
    "CWE-284", "CWE-435", "CWE-664", "CWE-682", "CWE-691",
    "CWE-693", "CWE-697", "CWE-703", "CWE-707", "CWE-710",
}


def _as_list(value) -> list:
    if value is None:
        return []
    return list(value)


def _check_mapper(mapper: Cwe1003Mapper) -> None:
    if len(mapper.roots) != 37 or len(mapper.members) != 130:
        raise SystemExit(
            f"CWE-1003 has {len(mapper.roots)} top-level entries and {len(mapper.members)} members"
        )
    if set(mapper.pillars) != PILLARS or len(mapper.categories_699) != 40:
        raise SystemExit(
            f"CWE-1000 pillars {mapper.pillars}; CWE-699 has {len(mapper.categories_699)} categories"
        )
    if len(mapper.primary_1000) < 900 or len(mapper.member_699) < 350:
        raise SystemExit(
            f"CWE graph looks short: {len(mapper.primary_1000)} primary parents, "
            f"{len(mapper.member_699)} CWE-699 memberships"
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
        got = (
            mapper.map_1000_list(list(ids)),
            mapper.map_699_list(list(ids)),
            mapper.map_member_list(list(ids)),
            mapper.map_list(list(ids)),
        )
        if got != (pillars, cats, members, high):
            raise SystemExit(f"{ids}: mapped to {got}, expected {(pillars, cats, members, high)}")


def _label_rows(cwe_values, mapper: Cwe1003Mapper) -> dict[str, list]:
    pillars = set(mapper.pillars)
    categories = set(mapper.categories_699)
    columns = {name: [] for name in NEW_COLS}
    allowed = {
        "cwe_1000_list": pillars,
        "cwe_699_list": categories,
        "cwe_1003_list": mapper.members,
        "cwe_1003_high_list": mapper.roots,
    }
    for raw in cwe_values:
        ids = _as_list(raw)
        mapped = {
            "cwe_1000_list": mapper.map_1000_list(ids),
            "cwe_699_list": mapper.map_699_list(ids),
            "cwe_1003_list": mapper.map_member_list(ids),
            "cwe_1003_high_list": mapper.map_list(ids),
        }
        for name, values in mapped.items():
            bad = [x for x in values if x not in allowed[name]]
            if bad:
                raise SystemExit(f"{name} has ids outside its view: {bad[:5]} from {ids}")
        rolled = []
        for member in mapped["cwe_1003_list"]:
            parent = mapper.rollup_member(member)
            if not parent:
                raise SystemExit(f"{member} is a CWE-1003 member with no top-level parent")
            if parent not in rolled:
                rolled.append(parent)
        if rolled != mapped["cwe_1003_high_list"]:
            raise SystemExit(
                f"cwe_1003_high_list {mapped['cwe_1003_high_list']} is not the rollup of "
                f"{mapped['cwe_1003_list']} for {ids}"
            )
        for name in NEW_COLS:
            columns[name].append(mapped[name])
    return columns


def _samples(idxs, cwe_values, columns) -> dict:
    found = {}

    def take(key, i, raw):
        if key in found:
            return
        found[key] = {
            "idx": idxs[i],
            "cwe_list": _as_list(raw),
            **{name: columns[name][i] for name in NEW_COLS},
        }

    for i, raw in enumerate(cwe_values):
        ids = _as_list(raw)
        if not ids:
            take("empty", i, raw)
        elif ids == ["CWE-787"]:
            take("only-787", i, raw)
        elif ids == ["CWE-122"]:
            take("only-122", i, raw)
        elif ids == ["CWE-119"]:
            take("only-119", i, raw)
        elif ids == ["CWE-476"]:
            take("only-476", i, raw)
        elif "CWE-798" in ids:
            take("has-798", i, raw)
        elif "CWE-416" in ids and "CWE-787" in ids:
            take("416-and-787", i, raw)
        elif ids == ["CWE-125", "CWE-787"] or ids == ["CWE-787", "CWE-125"]:
            take("125-and-787", i, raw)
    return found


def _rewrite_parquet(path: Path, columns: dict[str, list], log) -> None:
    table = pq.read_table(path)
    n = table.num_rows
    for name, values in columns.items():
        if len(values) != n:
            raise SystemExit(f"{path}: {name} has {len(values)} values for {n} rows")
    drop = set(NEW_COLS) | {"top15_cwe_1400"}
    keep = [name for name in table.column_names if name not in drop]
    if "cwe_1400_list" not in keep:
        raise SystemExit(f"{path}: missing cwe_1400_list")
    table = table.select(keep)
    at = keep.index("cwe_1400_list")
    list_type = pa.list_(pa.string())
    for offset, name in enumerate(NEW_COLS):
        table = table.add_column(at + offset, name, pa.array(columns[name], type=list_type))
    if "top15_cwe_1400" in table.column_names or table.column_names.count("cwe_1003_list") != 1:
        raise SystemExit(f"{path}: column rewrite produced {table.column_names}")
    meta = dict(table.schema.metadata or {})
    meta.pop(b"pandas", None)
    table = table.replace_schema_metadata(meta)
    comp = pq.ParquetFile(path).metadata.row_group(0).column(0).compression
    tmp = path.with_name(path.name + ".tmp")
    pq.write_table(table, tmp, compression=comp)
    os.replace(tmp, path)
    log.info("wrote %s (%d rows, %d cols)", path, table.num_rows, table.num_columns)
    del table


def _rewrite_jsonl(path: Path, columns: dict[str, list], log) -> None:
    if not path.exists():
        log.info("no jsonl at %s", path)
        return
    tmp = path.with_name(path.name + ".tmp")
    n = 0
    managed = set(NEW_COLS) | {"top15_cwe_1400"}
    with gzip.open(path, "rt", encoding="utf-8") as src, gzip.open(tmp, "wt", encoding="utf-8") as dst:
        for line in src:
            rec = json.loads(line)
            fresh = {}
            placed = False
            for key, value in rec.items():
                if key in managed:
                    continue
                if key == "cwe_1400_list" and not placed:
                    for name in NEW_COLS:
                        fresh[name] = columns[name][n]
                    placed = True
                fresh[key] = value
            if not placed:
                for name in NEW_COLS:
                    fresh[name] = columns[name][n]
            dst.write(json.dumps(fresh, ensure_ascii=False) + "\n")
            n += 1
    if n != len(columns["cwe_1003_list"]):
        tmp.unlink(missing_ok=True)
        raise SystemExit(f"{path}: {n} jsonl rows, {len(columns['cwe_1003_list'])} labels")
    os.replace(tmp, path)
    log.info("wrote %s (%d rows)", path, n)


def _load(path: Path) -> tuple[list, list, list]:
    names = pq.read_schema(path).names
    old_name = "cwe_1003_high_list" if "cwe_1003_high_list" in names else "cwe_1003_list"
    if old_name not in names:
        raise SystemExit(f"{path}: no existing CWE-1003 column to preserve")
    table = pq.read_table(path, columns=["idx", "cwe_list", old_name])
    return (
        table.column("idx").to_pylist(),
        table.column("cwe_list").to_pylist(),
        table.column(old_name).to_pylist(),
    )


def _same(a, b) -> bool:
    return _as_list(a) == _as_list(b)


def main() -> None:
    cfg = load_config()
    log = get_logger("08_add_cwe_columns", cfg.paths.logs)
    cwe_dir = cfg.paths.raw_nvd.parent / "cwe"
    mapper = Cwe1003Mapper(cwe_dir)
    if not mapper.available:
        raise SystemExit(f"missing {mapper.cache}; the CWE-1003 cache is required")
    mapper.ensure_levels()
    _check_mapper(mapper)
    log.info(
        "views ready: 1000 pillars %d, 699 categories %d (%d memberships), "
        "1003 members %d (%d top-level), primary parents %d",
        len(mapper.pillars), len(mapper.categories_699), len(mapper.member_699),
        len(mapper.members), len(mapper.roots), len(mapper.primary_1000),
    )

    planned = []
    stored = {}
    for name in ("cpp", "multi"):
        for variant in ("full", "balanced", "paired"):
            path = cfg.paths.out / name / variant / "data.parquet"
            if variant == "paired" and not path.exists():
                log.info("skip %s", path)
                continue
            log.info("labeling %s", path)
            idxs, cwe_values, old_high = _load(path)
            columns = _label_rows(cwe_values, mapper)
            bad = []
            for i, (new, old) in enumerate(zip(columns["cwe_1003_high_list"], old_high)):
                if _same(new, old):
                    continue
                bad.append((idxs[i], cwe_values[i], new, old))
                if len(bad) >= 3:
                    break
            if bad:
                raise SystemExit(f"{path}: cwe_1003_high_list disagrees with the old column, e.g. {bad}")
            for col in NEW_COLS:
                filled = sum(bool(v) for v in columns[col])
                log.info("  %s filled on %d/%d rows", col, filled, len(idxs))
            stored[(name, variant)] = (idxs, columns)
            planned.append((path, columns, _samples(idxs, cwe_values, columns)))
            log.info("%s/%s: %d rows match the previous cwe_1003_list", name, variant, len(idxs))
            for key, sample in planned[-1][2].items():
                log.info("  sample %s %s", key, json.dumps(sample, ensure_ascii=False))

    for name in ("cpp", "multi"):
        full_idx, full_cols = stored[(name, "full")]
        bal_idx, bal_cols = stored[(name, "balanced")]
        full_at = {idx: n for n, idx in enumerate(full_idx)}
        for n, idx in enumerate(bal_idx):
            src = full_at.get(idx)
            if src is None:
                raise SystemExit(f"{name}: balanced idx {idx} is not in full")
            for col in NEW_COLS:
                if bal_cols[col][n] != full_cols[col][src]:
                    raise SystemExit(f"{name}: idx {idx} {col} differs between full and balanced")
        log.info("%s: balanced labels match full on %d shared idx values", name, len(bal_idx))

    for path, columns, _samples_found in planned:
        _rewrite_parquet(path, columns, log)
        _rewrite_jsonl(path.with_name("data.jsonl.gz"), columns, log)

    _verify_written(planned, log)


def _verify_written(planned, log) -> None:
    """Re-read the written files and check the samples that were just computed."""
    for path, _columns, samples in planned:
        schema = pq.read_schema(path)
        names = schema.names
        if "top15_cwe_1400" in names:
            raise SystemExit(f"{path}: top15_cwe_1400 is still present")
        missing = [name for name in NEW_COLS if name not in names]
        if missing:
            raise SystemExit(f"{path}: missing {missing}")
        if names.count("cwe_1003_list") != 1 or names.count("cwe_1003_high_list") != 1:
            raise SystemExit(f"{path}: duplicated CWE columns in {names}")
        at = names.index("cwe_1400_list")
        if tuple(names[at - 4:at]) != NEW_COLS:
            raise SystemExit(f"{path}: CWE columns are {names[at - 4:at + 1]}")
        check_idx = {sample["idx"] for sample in samples.values()}
        table = pq.read_table(path, columns=["idx", "cwe_list", *NEW_COLS])
        idxs = table.column("idx").to_pylist()
        by_idx = {}
        for i, idx in enumerate(idxs):
            if idx in check_idx:
                by_idx[idx] = {
                    "cwe_list": _as_list(table.column("cwe_list")[i].as_py()),
                    **{name: _as_list(table.column(name)[i].as_py()) for name in NEW_COLS},
                }
        for key, sample in samples.items():
            got = by_idx.get(sample["idx"])
            if got is None:
                raise SystemExit(f"{path}: sample {key} idx {sample['idx']} missing after rewrite")
            for name in ("cwe_list", *NEW_COLS):
                if got[name] != sample[name]:
                    raise SystemExit(f"{path}: sample {key} {name} is {got[name]}, expected {sample[name]}")
        del table
        _verify_jsonl(path.with_name("data.jsonl.gz"), samples, len(idxs))
        log.info("verified %s (%d rows, samples %s)", path, len(idxs), ",".join(samples))
    log.info("all four tables verified")


def _line_idx(line: str):
    """idx is the first field: {"idx": 123, ..."""
    if not line.startswith('{"idx": '):
        return None
    end = line.find(",", 8)
    if end < 0:
        return None
    try:
        return int(line[8:end])
    except ValueError:
        return None


def _verify_jsonl(path: Path, samples: dict, n_rows: int) -> None:
    if not path.exists():
        return
    want = {sample["idx"]: sample for sample in samples.values()}
    n = 0
    with gzip.open(path, "rt", encoding="utf-8") as src:
        for line in src:
            n += 1
            idx = _line_idx(line)
            if idx is None or idx not in want:
                continue
            rec = json.loads(line)
            sample = want.pop(rec["idx"])
            if "top15_cwe_1400" in rec:
                raise SystemExit(f"{path}: idx {rec['idx']} still has top15_cwe_1400")
            for name in ("cwe_list", *NEW_COLS):
                if _as_list(rec.get(name)) != sample[name]:
                    raise SystemExit(
                        f"{path}: idx {rec['idx']} {name} is {rec.get(name)}, expected {sample[name]}"
                    )
    if n != n_rows:
        raise SystemExit(f"{path}: {n} jsonl rows, parquet has {n_rows}")
    if want:
        raise SystemExit(f"{path}: jsonl missing samples {sorted(want)}")


if __name__ == "__main__":
    main()
