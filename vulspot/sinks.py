"""Sink candidates: statements of the *vulnerable* function that a localizer should point at.

  deleted / updated       -> the before-statement itself
  insert                  -> an anchor in the before version:
       anchor_guarded_use : the inserted statement is a guard (`if (cond) return/goto/break/continue;`)
                            and some identifier of `cond` is used later in the before function ->
                            first such later statement
       anchor_next        : otherwise, the next before-statement after the insertion point
       anchor_prev        : insertion at the end of the function -> the previous statement
"""
from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from typing import Optional

from .astdiff import EditAction, insertion_anchor_index, insertion_prev_index
from .langs import LangSpec
from .tsparse import Function, Unit, identifiers

_GUARD_HDR = re.compile(r"^(?:else\s+)?if\b")
_SINK_KINDS_ORDER = {"deleted": 0, "updated": 1, "anchor_guarded_use": 2, "anchor_next": 3, "anchor_prev": 4}


@dataclass
class SinkCandidate:
    kind: str
    abs_line: int
    rel_line: int
    byte_start: int           # relative to the function text (func_body)
    byte_end: int
    text: str
    node_type: str
    inserted_text: Optional[str] = None   # for anchors: the statement inserted by the fix
    guard_ident: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


def _is_jump(u: Unit, spec: LangSpec) -> bool:
    t = u.text.lstrip()
    return any(re.match(rf"^{re.escape(k)}\b", t) for k in spec.jump_keywords) or u.node_type in (
        "return_statement", "goto_statement", "break_statement", "continue_statement", "throw_statement",
        "return_expression", "break_expression", "continue_expression")


def _guard_condition(hdr: str) -> Optional[str]:
    if not _GUARD_HDR.match(hdr.lstrip()):
        return None
    m = re.search(r"\((.*)\)\s*\{?\s*$", hdr, re.S)
    if m:
        return m.group(1)
    # languages without parentheses (python/ruby/go/rust)
    s = re.sub(r"^(?:else\s+)?if\b", "", hdr.strip()).strip().rstrip(":{").strip()
    return s or None


def _inserted_guard(after: Function, actions: list[EditAction], ins: EditAction, spec: LangSpec) -> Optional[tuple[str, list[int]]]:
    """If `ins` is a header `if (...)` whose body (inserted too) ends in a jump statement, return
    (condition, after-unit indices of the body)."""
    u = after.units[ins.after_idx]
    if u.kind != "header":
        return None
    cond = _guard_condition(u.text)
    if cond is None:
        return None
    inserted_after_idx = {a.after_idx for a in actions if a.action == "insert"}
    # jumps that SequenceMatcher tags as `move` because the same `goto out` / `return`
    # already exists elsewhere still belong to this new `if` body
    moved_after_idx = {a.after_idx for a in actions if a.action == "move"}
    body: list[Unit] = []
    body_idx: list[int] = []
    for k in range(ins.after_idx + 1, len(after.units)):
        v = after.units[k]
        if v.depth <= u.depth:
            break
        if not v.is_code:
            continue
        body.append(v)
        body_idx.append(k)
    if not body or len(body) > 4:
        return None
    newish = inserted_after_idx | moved_after_idx
    if not any(i in newish for i in body_idx):
        return None
    if not any(_is_jump(v, spec) for v in body):
        return None
    return cond, body_idx


def _guard_idents(cond: str, spec: LangSpec) -> list[str]:
    ids = identifiers(cond, spec.keywords)
    # skip macro-ish constants and very short names
    return [i for i in ids if not (i.isupper() and len(i) > 1)]


def sink_candidates(before: Function, after: Function, actions: list[EditAction], spec: LangSpec) -> list[SinkCandidate]:
    out: dict[int, SinkCandidate] = {}
    base = before.start_byte

    def add(u: Unit, kind: str, inserted: Optional[str] = None, guard: Optional[str] = None):
        if not u.is_code and kind in ("deleted", "updated"):
            return
        cur = out.get(u.start_line)
        cand = SinkCandidate(kind, u.start_line, u.start_line - before.start_line + 1,
                             u.start_byte - base, u.end_byte - base, u.text, u.node_type, inserted, guard)
        if cur is None or _SINK_KINDS_ORDER[kind] < _SINK_KINDS_ORDER[cur.kind]:
            out[u.start_line] = cand

    for a in actions:
        if a.action == "delete":
            add(before.units[a.before_idx], "deleted")
        elif a.action == "update":
            add(before.units[a.before_idx], "updated")

    guard_bodies: set[int] = set()
    for a in actions:
        if a.action != "insert" or not a.is_code or a.after_idx in guard_bodies:
            continue
        au = after.units[a.after_idx]
        nxt = insertion_anchor_index(actions, a)
        g = _inserted_guard(after, actions, a, spec)
        if g is not None:
            cond, body_idx = g
            guard_bodies.update(body_idx)   # the guard's own body statements do not get separate anchors
            idents = _guard_idents(cond, spec)
            start = nxt if nxt is not None else len(before.units)
            hit = None
            for k in range(start, len(before.units)):
                v = before.units[k]
                if not v.is_code or v.kind == "signature":
                    continue
                vids = set(identifiers(v.text, spec.keywords))
                common = [i for i in idents if i in vids]
                if common:
                    hit = (v, common[0])
                    break
            if hit is not None:
                add(hit[0], "anchor_guarded_use", au.text, hit[1])
                continue
        if nxt is not None:
            # skip over bare block/tail units to the next real statement when possible
            k = nxt
            while k < len(before.units) and not before.units[k].is_code:
                k += 1
            if k < len(before.units):
                add(before.units[k], "anchor_next", au.text)
                continue
        prv = insertion_prev_index(actions, a)
        if prv is not None:
            add(before.units[prv], "anchor_prev", au.text)

    return sorted(out.values(), key=lambda c: c.abs_line)
