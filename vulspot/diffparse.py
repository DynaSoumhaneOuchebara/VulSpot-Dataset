"""Unified-diff parsing: hunks -> deleted (old-file) and added (new-file) line numbers.

Sources, in order of preference (see 04_extract_functions.py):
  1. per-file `patch` field in the GitHub commit JSON (hunks only, starts with '@@')
  2. the full `commit.diff` (application/vnd.github.diff) split per file
  3. difflib over the cached before/after contents
"""
from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field

_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_DIFF_HDR = re.compile(r"^diff --git a/(.*?) b/(.*)$")


@dataclass
class LineDiff:
    deleted: list[int] = field(default_factory=list)   # old-file line numbers (1-based)
    added: list[int] = field(default_factory=list)     # new-file line numbers (1-based)
    # (old_line, new_line) of lines that difflib/hunks consider replaced positionally; informational
    hunks: list[tuple[int, int, int, int]] = field(default_factory=list)  # (old_start, old_len, new_start, new_len)
    source: str = ""

    @property
    def empty(self) -> bool:
        return not self.deleted and not self.added


def parse_hunks(patch: str) -> LineDiff:
    """Parse a hunk-only patch (GitHub `files[].patch`) or a single-file section of a unified diff."""
    ld = LineDiff(source="patch")
    old = new = 0
    in_hunk = False
    for line in patch.splitlines():
        m = _HUNK.match(line)
        if m:
            old = int(m.group(1))
            new = int(m.group(3))
            ld.hunks.append((old, int(m.group(2) or 1), new, int(m.group(4) or 1)))
            in_hunk = True
            continue
        if not in_hunk:
            continue
        if line.startswith("\\"):      # "\ No newline at end of file"
            continue
        if line.startswith("+"):
            ld.added.append(new)
            new += 1
        elif line.startswith("-"):
            ld.deleted.append(old)
            old += 1
        elif line.startswith(" ") or line == "":
            old += 1
            new += 1
        else:
            # header of the next file section or garbage -> stop
            if line.startswith(("diff ", "index ", "--- ", "+++ ")):
                in_hunk = False
            else:
                old += 1
                new += 1
    return ld


def split_unified_diff(diff_text: str) -> dict[str, str]:
    """Split a multi-file unified diff into {new_path: section_text}. Binary sections are included as-is."""
    out: dict[str, str] = {}
    cur_path = None
    buf: list[str] = []
    for line in diff_text.splitlines():
        m = _DIFF_HDR.match(line)
        if m:
            if cur_path is not None:
                out[cur_path] = "\n".join(buf)
            cur_path = _unquote(m.group(2))
            buf = [line]
            continue
        if cur_path is not None:
            buf.append(line)
    if cur_path is not None:
        out[cur_path] = "\n".join(buf)
    return out


def _unquote(p: str) -> str:
    p = p.strip()
    if p.startswith('"') and p.endswith('"'):
        try:
            return p[1:-1].encode("latin-1").decode("unicode_escape")
        except Exception:
            return p[1:-1]
    return p


def difflib_linediff(before: str, after: str) -> LineDiff:
    """Fallback line diff computed locally. Lines are compared exactly (git default)."""
    a = before.splitlines()
    b = after.splitlines()
    sm = difflib.SequenceMatcher(a=a, b=b, autojunk=False)
    ld = LineDiff(source="difflib")
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        if tag in ("delete", "replace"):
            ld.deleted.extend(range(i1 + 1, i2 + 1))
        if tag in ("insert", "replace"):
            ld.added.extend(range(j1 + 1, j2 + 1))
        ld.hunks.append((i1 + 1, i2 - i1, j1 + 1, j2 - j1))
    return ld


def linediff_consistent(ld: LineDiff, before: str, after: str) -> bool:
    """Sanity check that hunk line numbers fall inside the cached files."""
    nb = before.count("\n") + 1
    na = after.count("\n") + 1
    return all(1 <= x <= nb for x in ld.deleted) and all(1 <= x <= na for x in ld.added)
