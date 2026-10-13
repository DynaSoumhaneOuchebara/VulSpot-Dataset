"""Statement-level diff between the vulnerable (before) and fixed (after) version of a function.

Units are aligned with difflib on whitespace-normalized keys, so whitespace-only or re-indentation
changes are `unchanged`. `replace` blocks are paired positionally into `update` actions, with the
remainder emitted as `delete`/`insert`. Identical statements that were deleted at one place and
inserted at another are tagged `move` (and ignored downstream). Comment-only edits are kept in the
action list (flag `is_code=False`) but do not count towards `n_code_edits`.
"""
from __future__ import annotations

import difflib
from dataclasses import dataclass, asdict
from typing import Optional

from .tsparse import Function, Unit

MOVE_MIN_LEN = 12


@dataclass
class EditAction:
    action: str                     # delete | update | insert | move | unchanged
    before_idx: Optional[int]       # index into before.units
    after_idx: Optional[int]        # index into after.units
    before_line: Optional[int]      # absolute line in before file
    after_line: Optional[int]       # absolute line in after file
    before_text: Optional[str]
    after_text: Optional[str]
    kind: str                       # unit kind (simple/header/tail/signature/comment)
    node_type: str
    is_code: bool

    def to_dict(self) -> dict:
        return asdict(self)


def _keys(units: list[Unit]) -> list[str]:
    return [u.key for u in units]


def diff_units(before: Function, after: Function, deleted_lines: set[int] | None = None,
               added_lines: set[int] | None = None) -> list[EditAction]:
    """Align statement units of the two versions.

    When the file-level line diff is given (`deleted_lines` in the before file, `added_lines` in the
    after file) it drives the alignment: units touching no changed line are matched first (they are the
    stable skeleton), and the changed units between two consecutive matched units form a replace block
    that is paired by textual similarity. Without line info, a plain SequenceMatcher on the unit keys
    is used.
    """
    bu, au = before.units, after.units
    actions: list[EditAction] = []

    def replace_block(bi: list[int], aj: list[int]) -> None:
        paired = _pair_replace(bu, bi, au, aj)
        for i, j in paired:
            actions.append(_act("unchanged" if bu[i].key == au[j].key else "update", bu, i, au, j))
        used_i = {i for i, _ in paired}
        used_j = {j for _, j in paired}
        for i in bi:
            if i not in used_i:
                actions.append(_act("delete", bu, i, au, None))
        for j in aj:
            if j not in used_j:
                actions.append(_act("insert", bu, None, au, j))

    if deleted_lines is not None and added_lines is not None:
        def touched(u: Unit, lines: set[int]) -> bool:
            return any(ln in lines for ln in range(u.start_line, u.end_line + 1))
        b_stable = [i for i, u in enumerate(bu) if not touched(u, deleted_lines)]
        a_stable = [j for j, u in enumerate(au) if not touched(u, added_lines)]
        sm = difflib.SequenceMatcher(a=[bu[i].key for i in b_stable], b=[au[j].key for j in a_stable], autojunk=False)
        matched: list[tuple[int, int]] = []
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag == "equal":
                for k in range(i2 - i1):
                    matched.append((b_stable[i1 + k], a_stable[j1 + k]))
        prev_i, prev_j = -1, -1
        for mi, mj in matched + [(len(bu), len(au))]:
            bi = list(range(prev_i + 1, mi))
            aj = list(range(prev_j + 1, mj))
            if bi or aj:
                replace_block(bi, aj)
            if mi < len(bu):
                actions.append(_act("unchanged", bu, mi, au, mj))
            prev_i, prev_j = mi, mj
    else:
        sm = difflib.SequenceMatcher(a=_keys(bu), b=_keys(au), autojunk=False)
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag == "equal":
                for k in range(i2 - i1):
                    actions.append(_act("unchanged", bu, i1 + k, au, j1 + k))
            elif tag == "delete":
                for i in range(i1, i2):
                    actions.append(_act("delete", bu, i, au, None))
            elif tag == "insert":
                for j in range(j1, j2):
                    actions.append(_act("insert", bu, None, au, j))
            else:
                replace_block(list(range(i1, i2)), list(range(j1, j2)))
    _mark_moves(actions)
    # document order: by before position; inserts are placed just before their next before-unit
    pos = {}
    for a in actions:
        if a.before_idx is None:
            nxt = insertion_anchor_index(actions, a)
            pos[id(a)] = (nxt if nxt is not None else len(bu), 0, a.after_idx)
        else:
            pos[id(a)] = (a.before_idx, 1, a.after_idx if a.after_idx is not None else -1)
    actions.sort(key=lambda a: pos[id(a)])
    return actions


def _pair_replace(bu, bi, au, aj) -> list[tuple[int, int]]:
    """Pair statements inside a replace block: first exact-kind positional pairing with similarity,
    fall back to pure positional pairing."""
    pairs: list[tuple[int, int]] = []
    if not bi or not aj:
        return pairs
    # similarity-guided greedy matching (small blocks only; otherwise positional)
    if len(bi) * len(aj) <= 400:
        scored = []
        for a_i, i in enumerate(bi):
            for b_j, j in enumerate(aj):
                r = difflib.SequenceMatcher(a=bu[i].key, b=au[j].key, autojunk=False).ratio()
                if bu[i].kind == au[j].kind:
                    r += 0.05
                scored.append((r, abs(a_i - b_j), i, j))
        scored.sort(key=lambda t: (-t[0], t[1]))
        used_i, used_j = set(), set()
        for r, _, i, j in scored:
            if r < 0.3:
                break
            if i in used_i or j in used_j:
                continue
            # keep order monotonic to avoid crossing pairs
            if any((i < pi and j > pj) or (i > pi and j < pj) for pi, pj in pairs):
                continue
            pairs.append((i, j))
            used_i.add(i)
            used_j.add(j)
        rem_i = [i for i in bi if i not in used_i]
        rem_j = [j for j in aj if j not in used_j]
        # positional pairing for leftovers only when it is a one-to-one rewrite of the same kinds
        if rem_i and len(rem_i) == len(rem_j):
            for i, j in zip(rem_i, rem_j):
                if bu[i].kind == au[j].kind and not any((i < pi and j > pj) or (i > pi and j < pj) for pi, pj in pairs):
                    pairs.append((i, j))
        return pairs
    for i, j in zip(bi, aj):
        pairs.append((i, j))
    return pairs


def _act(action, bu, i, au, j) -> EditAction:
    b = bu[i] if i is not None else None
    a = au[j] if j is not None else None
    ref = b or a
    return EditAction(
        action=action,
        before_idx=i, after_idx=j,
        before_line=b.start_line if b else None,
        after_line=a.start_line if a else None,
        before_text=b.text if b else None,
        after_text=a.text if a else None,
        kind=ref.kind, node_type=ref.node_type, is_code=ref.is_code,
    )


def _mark_moves(actions: list[EditAction]) -> None:
    dels = {}
    for idx, a in enumerate(actions):
        if a.action == "delete" and a.before_text and len(a.before_text.strip()) >= MOVE_MIN_LEN:
            dels.setdefault(" ".join(a.before_text.split()), []).append(idx)
    for idx, a in enumerate(actions):
        if a.action == "insert" and a.after_text:
            k = " ".join(a.after_text.split())
            if k in dels and dels[k]:
                d_idx = dels[k].pop(0)
                actions[d_idx].action = "move"
                actions[d_idx].after_idx = a.after_idx
                actions[d_idx].after_line = a.after_line
                actions[d_idx].after_text = a.after_text
                a.action = "__drop__"
    actions[:] = [a for a in actions if a.action != "__drop__"]


def code_edit_counts(actions: list[EditAction]) -> dict[str, int]:
    c = {"delete": 0, "update": 0, "insert": 0, "move": 0, "unchanged": 0, "comment_only": 0}
    for a in actions:
        if a.action == "unchanged":
            c["unchanged"] += 1
            continue
        if not a.is_code:
            c["comment_only"] += 1
            continue
        c[a.action] += 1
    c["n_code_edits"] = c["delete"] + c["update"] + c["insert"]
    return c


def insertion_anchor_index(actions: list[EditAction], ins: EditAction) -> Optional[int]:
    """Index into before.units of the first before-unit that comes *after* the inserted statement
    (i.e. the next statement in the before version), or None when inserted at the end."""
    j = ins.after_idx
    # the first action with after_idx > j that has a before_idx gives the next anchor
    best = None
    for a in actions:
        if a.after_idx is not None and a.after_idx > j and a.before_idx is not None and a.action in ("unchanged", "update", "move"):
            if best is None or a.after_idx < best[0]:
                best = (a.after_idx, a.before_idx)
    return best[1] if best else None


def insertion_prev_index(actions: list[EditAction], ins: EditAction) -> Optional[int]:
    j = ins.after_idx
    best = None
    for a in actions:
        if a.after_idx is not None and a.after_idx < j and a.before_idx is not None and a.action in ("unchanged", "update", "move"):
            if best is None or a.after_idx > best[0]:
                best = (a.after_idx, a.before_idx)
    return best[1] if best else None
