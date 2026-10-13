"""JSON / JSONL helpers with atomic writes."""
from __future__ import annotations

import gzip
import json
import os
from pathlib import Path
from typing import Any, Iterable, Iterator


def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)


def atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def write_json(path: Path, obj: Any, indent: int | None = None) -> None:
    atomic_write_text(path, json.dumps(obj, indent=indent, ensure_ascii=False))


def read_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8") as f:
        return json.load(f)


def iter_jsonl(path: Path) -> Iterator[dict]:
    if not path.exists():
        return
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def write_jsonl(path: Path, rows: Iterable[dict]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    n = 0
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(tmp, "wt", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False))
            f.write("\n")
            n += 1
    os.replace(tmp, path)
    return n


class JsonlAppender:
    """Append-only JSONL writer that flushes per record (crash-safe resumption)."""

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.f = open(path, "a", encoding="utf-8")

    def write(self, obj: dict) -> None:
        self.f.write(json.dumps(obj, ensure_ascii=False))
        self.f.write("\n")
        self.f.flush()

    def close(self) -> None:
        self.f.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()
