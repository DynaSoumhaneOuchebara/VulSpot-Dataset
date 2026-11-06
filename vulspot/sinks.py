"""Sink candidates: statements of the *vulnerable* function that a localizer should point at.

  deleted / updated       -> the before-statement itself
  insert                  -> an anchor in the before version. Consecutive inserted statements form one
                             insertion group, anchored once (declarations never anchor on their own):
       anchor_dataflow    : the before-statement(s) the inserted code is tied to by a shared variable,
                            found by the rule in `anchor_rule`:
            guard_use_strict   inserted guard whose body ends in a jump (`if (cond) return/goto/break/
                               continue;`): first later use of a `cond` variable
            guard_use_relaxed  any other inserted `if (cond)`: first later use of a `cond` variable
            status_def         guard on a status variable only (`if (err) goto out;`): the earlier statement
                               that assigns it, i.e. the call whose failure went unchecked
            init_use           inserted reset / zeroing of X (`p->f = NULL;`, `memset(&s, 0, ...)`): the earlier
                               free of X that left it dangling, else the next use of X
            release_acquire    inserted free/put of X: the earlier statement that assigns X; unlock of L:
                               the earlier lock of L
            lock_region        inserted lock ... unlock pair: the statements it now protects
            jump_enclosing     inserted bare return/goto/break: the condition it now exits on
            shared_ident       otherwise: nearest statement sharing the rarest identifiers with the group
       anchor_next        : nothing shares an identifier -> the next before-statement after the insertion
       anchor_prev        : insertion at the end of the function -> the previous statement
  move                    -> only when the fix has no delete / update / insert (a pure reordering), as
                             `anchor_dataflow` (moved bare jumps are skipped):
            move_early       statement moved later: the statement itself, at its old place (it ran too early)
            move_crossed     statement moved earlier: the first statement it jumped over that uses what it
                             assigns, else any of its identifiers (it ran before the fix's statement);
                             none -> move_early
"""
from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from typing import Optional

from .astdiff import EditAction, insertion_anchor_index, insertion_prev_index
from .langs import LangSpec
from .tsparse import Function, Unit, identifiers

_GUARD_HDR = re.compile(r"^(?:else\s+)?if\b")
_SINK_KINDS_ORDER = {"deleted": 0, "updated": 1, "anchor_dataflow": 2, "anchor_next": 3, "anchor_prev": 4}

# Variables that only carry a status code. A guard on them protects nothing later in the
# function; what it fixes is the unchecked call that set them.
_STATUS_NAMES = {"err", "ret", "rc", "error", "status", "result", "res", "r", "rv", "retval", "rval",
                 "ret_val", "result_code", "error_code", "errcode", "ok", "success", "failed"}
_CALLEE = re.compile(r"^\s*(?:[\w.\->\[\]*&]+\s*=\s*)?\(?\s*([A-Za-z_]\w*)\s*\(")
_ASSIGN_LHS = re.compile(r"^\s*([^=;(]+?)\s*(?:[-+*/%|&^]|<<|>>)?=(?!=)")
_RESET = re.compile(r"^\s*([^=;]+?)\s*=\s*(?:NULL|nullptr|0|false|-1|\{\s*0?\s*\})\s*;")
_ZERO_CALLS = {"memset", "bzero", "memzero_explicit", "explicit_bzero", "SecureZeroMemory", "ZeroMemory"}
_RELEASE_TOKENS = {"free", "put", "release", "unref", "destroy", "unlock", "close", "unregister", "unmap",
                   "deinit", "uninit", "fini", "cleanup", "dealloc", "unpin", "unget", "dec", "delete", "drop"}
_RELEASE_NAMES = {"kfree", "vfree", "kvfree", "kzfree", "kfree_sensitive", "fput", "dput", "iput", "mntput",
                  "sock_put", "fdput", "free", "up", "up_read", "up_write", "rcu_read_unlock", "local_irq_restore"}
_LOCK_NAMES = {"down", "down_read", "down_write", "rcu_read_lock", "local_irq_save", "local_irq_disable"}
_SHARED_WINDOW = 8          # before-statements searched on each side of an insertion


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
    anchor_rule: Optional[str] = None     # anchor_dataflow only: which rule found it (module docstring)

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


_NOT_CALLS = {"if", "while", "for", "switch", "return", "sizeof", "do", "else", "case"}


def _callee(text: str) -> Optional[str]:
    m = _CALLEE.match(text)
    return m.group(1) if m and m.group(1) not in _NOT_CALLS else None


def _tokens(name: str) -> list[str]:
    return [t for t in re.split(r"_+|(?<=[a-z])(?=[A-Z])", name.lower()) if t]


def _is_release(name: str) -> bool:
    toks = _tokens(name)
    return name in _RELEASE_NAMES or any(t in _RELEASE_TOKENS for t in toks) or (toks and toks[-1].endswith("free"))


def _is_lock(name: str) -> bool:
    toks = _tokens(name)
    return name in _LOCK_NAMES or ("lock" in toks and "unlock" not in toks and not _is_release(name))


def _call_args(text: str) -> str:
    i = text.find("(")
    return text[i + 1:] if i >= 0 else ""


class _Before:
    """Cached identifier view of the before function, for data-flow anchoring."""

    def __init__(self, before: Function, spec: LangSpec):
        self.units = before.units
        self.spec = spec
        self.ids: list[set[str]] = []
        freq: dict[str, int] = {}
        for u in self.units:
            ids = set(identifiers(u.text, spec.keywords)) if self.is_anchorable(u) else set()
            self.ids.append(ids)
            for i in ids:
                freq[i] = freq.get(i, 0) + 1
        self.freq = freq

    def is_anchorable(self, u: Unit) -> bool:
        return u.is_code and u.kind not in ("signature", "tail")

    def idents(self, text: str) -> list[str]:
        # drop macro-ish constants and one-letter names
        return [i for i in identifiers(text, self.spec.keywords) if len(i) > 1 and not (i.isupper() and len(i) > 1)]

    def forward(self, start: Optional[int], names, limit: Optional[int] = None,
                ordered: bool = False) -> Optional[tuple[int, str]]:
        """First later statement using any of ``names`` (``ordered``: try each name in turn)."""
        if start is None or not names:
            return None
        if ordered:
            for n in names:
                hit = self.forward(start, [n], limit)
                if hit:
                    return hit
            return None
        stop = len(self.units) if limit is None else min(len(self.units), start + limit)
        for k in range(start, stop):
            common = [n for n in names if n in self.ids[k]]
            if common:
                return k, common[0]
        return None

    def backward(self, start: Optional[int], names, pred=None, limit: Optional[int] = None,
                 ordered: bool = False) -> Optional[tuple[int, str]]:
        """Nearest earlier statement using any of ``names`` and passing ``pred``."""
        if start is None or not names:
            return None
        if ordered:
            for n in names:
                hit = self.backward(start, [n], pred, limit)
                if hit:
                    return hit
            return None
        stop = -1 if limit is None else max(-1, start - limit)
        for k in range(start, stop, -1):
            common = [n for n in names if n in self.ids[k]]
            if common and (pred is None or pred(self.units[k], common)):
                return k, common[0]
        return None

    def shared(self, prv: Optional[int], nxt: Optional[int], names) -> Optional[tuple[int, str]]:
        """Before-statement near the insertion sharing the rarest identifiers with ``names``."""
        weights = {n: 1.0 / self.freq[n] for n in names if self.freq.get(n)}
        if not weights:
            return None
        centre = nxt if nxt is not None else (prv + 1 if prv is not None else 0)
        best = None
        for k in range(max(0, centre - _SHARED_WINDOW), min(len(self.units), centre + _SHARED_WINDOW)):
            common = [n for n in weights if n in self.ids[k]]
            if not common:
                continue
            dist = (k - centre) if k >= centre else (centre - k) + 0.5   # ties go forward
            score = sum(weights[n] for n in common) / (1.0 + 0.1 * dist)
            if best is None or score > best[0]:
                best = (score, k, max(common, key=lambda n: weights[n]))
        return (best[1], best[2]) if best else None


def _is_decl(u: Unit) -> bool:
    # an inserted declaration introduces a new variable: nothing in the before function uses it
    return u.node_type == "declaration"


def _assigns(u: Unit, names, from_call: bool = False) -> bool:
    """``u`` assigns one of ``names`` (``from_call``: the right-hand side calls something)."""
    rhs = r"[^;=]*\w\s*\(" if from_call else ""
    return any(re.search(rf"\b{re.escape(n)}\s*(?:\[[^\]]*\])?\s*=(?!=){rhs}", u.text) for n in names)


def _specific_first(names: list[str]) -> list[str]:
    """``p->field`` / ``s.member``: the member names the object more precisely than ``p`` does."""
    return names[::-1]


def _insertion_groups(after: Function, actions: list[EditAction]) -> list[list[EditAction]]:
    """Consecutive inserted code statements (blank / comment / closing-brace units in between allowed)."""
    ins = sorted((a for a in actions if a.action == "insert" and a.is_code), key=lambda a: a.after_idx)
    groups: list[list[EditAction]] = []
    for a in ins:
        if groups:
            last = groups[-1][-1].after_idx
            gap = after.units[last + 1:a.after_idx]
            if all((not v.is_code) or v.kind == "tail" for v in gap):
                groups[-1].append(a)
                continue
        groups.append([a])
    return groups


def sink_candidates(before: Function, after: Function, actions: list[EditAction], spec: LangSpec) -> list[SinkCandidate]:
    out: dict[int, SinkCandidate] = {}
    base = before.start_byte

    def add(u: Unit, kind: str, inserted: Optional[str] = None, guard: Optional[str] = None,
            rule: Optional[str] = None):
        if not u.is_code and kind in ("deleted", "updated"):
            return
        cur = out.get(u.start_line)
        cand = SinkCandidate(kind, u.start_line, u.start_line - before.start_line + 1,
                             u.start_byte - base, u.end_byte - base, u.text, u.node_type, inserted, guard, rule)
        if cur is None or _SINK_KINDS_ORDER[kind] < _SINK_KINDS_ORDER[cur.kind]:
            out[u.start_line] = cand

    for a in actions:
        if a.action == "delete":
            add(before.units[a.before_idx], "deleted")
        elif a.action == "update":
            add(before.units[a.before_idx], "updated")

    bv = _Before(before, spec)
    groups = _insertion_groups(after, actions)
    # unlock inserted later in the function, by argument text -> its insertion point, for lock_region
    unlock_points: list[tuple[str, Optional[int]]] = []
    for g in groups:
        for a in g:
            name = _callee(after.units[a.after_idx].text)
            if name and _is_release(name) and ("unlock" in _tokens(name) or name in ("up", "up_read", "up_write", "rcu_read_unlock")):
                unlock_points.append((_call_args(after.units[a.after_idx].text), insertion_anchor_index(actions, a)))

    for g in groups:
        first = g[0]
        nxt = insertion_anchor_index(actions, first)
        prv = insertion_prev_index(actions, first)
        start = nxt if nxt is not None else len(before.units)
        units = [after.units[a.after_idx] for a in g]
        code = [u for u in units if not _is_decl(u)]
        text = units[0].text if len(units) == 1 else " ".join(u.text for u in code or units)
        if not code:
            continue   # declarations alone fix nothing; their uses are in other groups
        done = False

        def flow(k_hit, rule, guard=None, kind="anchor_dataflow"):
            add(before.units[k_hit], kind, text, guard, rule)

        # 1. guards (strict: body ends in a jump; relaxed: any inserted `if`)
        for a in g:
            u = after.units[a.after_idx]
            if u.kind != "header":
                continue
            cond = _guard_condition(u.text)
            if cond is None:
                continue
            names = _guard_idents(cond, spec)
            if not names:
                continue
            if all(n in _STATUS_NAMES for n in names):
                hit = bv.backward(prv, names, pred=lambda v, c: _assigns(v, c, from_call=True),
                                  limit=_SHARED_WINDOW)
                if hit:
                    flow(hit[0], "status_def", hit[1])
                    done = True
                    continue
            strict = _inserted_guard(after, actions, a, spec) is not None
            hit = bv.forward(start, [n for n in names if n not in _STATUS_NAMES] or names)
            if hit:
                flow(hit[0], "guard_use_strict" if strict else "guard_use_relaxed", hit[1])
                done = True
        if done:
            continue

        head = code[0]
        name = _callee(head.text)

        # 2. reset / zeroing -> next use
        m = _RESET.match(head.text)
        target = None
        if m:
            target = m.group(1)
        elif name in _ZERO_CALLS:
            target = _call_args(head.text).split(",")[0]
        if target:
            # only the most specific name: `port->usb3_dev` is about usb3_dev, not every use of port
            names = _specific_first(bv.idents(target))[:1]
            freed = lambda v, c: (_callee(v.text) or "") and _is_release(_callee(v.text))
            hit = (bv.backward(prv, names, pred=freed, limit=_SHARED_WINDOW)
                   or bv.forward(start, names))
            if hit:
                flow(hit[0], "init_use", hit[1])
                continue

        # 3. lock ... unlock pair -> protected region; release -> earlier acquire
        if name and _is_lock(name):
            args = _call_args(head.text)
            end = next((p for a_txt, p in unlock_points if a_txt == args and p is not None and p > start), None)
            if end is not None:
                region = [k for k in range(start, end) if bv.is_anchorable(bv.units[k])][:6]
                for k in region:
                    flow(k, "lock_region")
                if region:
                    continue
        if name and _is_release(name):
            names = _specific_first(bv.idents(_call_args(head.text)))
            locked = lambda v, c: bool(_callee(v.text)) and _is_lock(_callee(v.text))
            hit = ((bv.backward(prv, names, pred=locked, ordered=True) if not _is_lock(name) and
                    ("unlock" in _tokens(name) or name in _RELEASE_NAMES and name.startswith(("up", "rcu")))
                    else None)
                   or bv.backward(prv, names, pred=lambda v, c: _assigns(v, c), ordered=True)
                   or bv.backward(prv, names, pred=lambda v, c: _callee(v.text) is not None, ordered=True))
            if hit:
                flow(hit[0], "release_acquire", hit[1])
                continue

        # 4. bare jump -> the enclosing condition (or the statement just before)
        if all(_is_jump(u, spec) for u in code) and prv is not None:
            k = prv
            while k >= max(0, prv - _SHARED_WINDOW) and not (
                    bv.units[k].kind == "header" and bv.units[k].depth < head.depth):
                k -= 1
            if k < max(0, prv - _SHARED_WINDOW):
                k = prv if bv.is_anchorable(bv.units[prv]) else None
            if k is not None:
                flow(k, "jump_enclosing")
                continue

        # 5. nearest statement sharing the rarest identifiers
        names = []
        for u in code:
            names.extend(n for n in bv.idents(u.text) if n not in names)
        hit = bv.shared(prv, nxt, names)
        if hit:
            flow(hit[0], "shared_ident", hit[1])
            continue

        # 6. positional fallback
        if nxt is not None:
            k = nxt
            while k < len(before.units) and not before.units[k].is_code:
                k += 1
            if k < len(before.units):
                add(before.units[k], "anchor_next", text)
                continue
        if prv is not None:
            add(before.units[prv], "anchor_prev", text)

    # 7. reordering-only fixes: nothing deleted, updated or inserted, statements only moved
    if not any(a.is_code and a.action in ("delete", "update", "insert") for a in actions):
        for a in actions:
            if a.action != "move" or not a.is_code or a.before_idx is None:
                continue
            u = before.units[a.before_idx]
            if not bv.is_anchorable(u) or _is_jump(u, spec):
                continue
            old = a.before_idx
            land = insertion_anchor_index(actions, a)
            land = len(before.units) if land is None else land
            if land > old:
                crossed = [k for k in range(old + 1, land) if bv.is_anchorable(bv.units[k])]
            else:
                crossed = [k for k in range(land, old) if bv.is_anchorable(bv.units[k])]
            if not crossed:
                continue   # only crossed blank lines / comments: not a reordering
            if land > old:
                # moved later: it ran too early (release before a use, assignment before a free)
                add(u, "anchor_dataflow", u.text, None, "move_early")
                continue
            # moved earlier: the crossed statements ran before it (copy before a clamp, use before a reset).
            # What it assigns (`len` in `len = min_t(.., sizeof(sas))`) names the victim better than its inputs.
            m = _ASSIGN_LHS.match(u.text)
            lhs = _specific_first(bv.idents(m.group(1))) if m else []
            hit = (bv.forward(crossed[0], lhs, limit=old - crossed[0], ordered=True)
                   or bv.forward(crossed[0], bv.idents(u.text), limit=old - crossed[0]))
            if hit:
                add(bv.units[hit[0]], "anchor_dataflow", u.text, hit[1], "move_crossed")
            else:
                add(u, "anchor_dataflow", u.text, None, "move_early")

    return sorted(out.values(), key=lambda c: c.abs_line)
