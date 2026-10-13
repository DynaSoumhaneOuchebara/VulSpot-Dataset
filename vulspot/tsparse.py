"""Tree-sitter based function and statement-unit extraction.

A *statement unit* is the smallest labelable piece of code we use for localization:
  - simple statements (expression, declaration, return, ...)        -> full node text
  - compound statements (if/for/while/switch/try/case/label/...)   -> header only (text before the body)
  - trailing parts of compound statements (`while (c);` of do-while, `#endif`) -> tail unit
  - the function signature (text before the function body)         -> kind "signature"
  - comments                                                        -> kind "comment"
Lines not covered by any unit (blank lines, bare braces, error recovery) map to "raw" line units.
This mirrors SecVulEval's `changed_statements` (header-only control statements, multi-line
statements joined, braces/blank lines kept as raw lines).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterator

from tree_sitter import Node

from .langs import LangSpec, get_parser, get_spec, is_block_type, is_function_type, is_statement_type

_WS = re.compile(r"\s+")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def norm_text(s: str) -> str:
    return _WS.sub(" ", s).strip()


@dataclass
class Unit:
    kind: str            # simple | header | tail | signature | comment | raw
    node_type: str
    start_line: int      # 1-based, file-absolute, inclusive
    end_line: int        # inclusive (lines covered by the unit text)
    start_byte: int
    end_byte: int
    text: str            # stripped text (inner whitespace preserved)
    key: str = ""        # normalized key used for alignment
    depth: int = 0       # nesting depth within the function body
    is_code: bool = True # False for comment/raw units

    def __post_init__(self):
        if not self.key:
            self.key = norm_text(self.text)


@dataclass
class Function:
    name: str
    signature: str        # normalized parameter list (or "" if unknown)
    start_line: int
    end_line: int
    start_byte: int
    end_byte: int
    text: str
    node: Node = field(repr=False)
    body_node: Node | None = field(default=None, repr=False)
    units: list[Unit] = field(default_factory=list, repr=False)
    qualified_name: str = ""

    @property
    def n_lines(self) -> int:
        return self.end_line - self.start_line + 1


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _text(src: bytes, node: Node) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _line(node_point) -> int:
    return node_point[0] + 1


def line_offsets(src: bytes) -> list[int]:
    """Byte offset of the start of each line (index 0 = line 1)."""
    offs = [0]
    for m in re.finditer(rb"\n", src):
        offs.append(m.end())
    return offs


def raw_line(src: bytes, offsets: list[int], line: int) -> str:
    """Original text of a 1-based line including its trailing newline (SecVulEval `changed_lines` style)."""
    if line < 1 or line > len(offsets):
        return ""
    start = offsets[line - 1]
    end = offsets[line] if line < len(offsets) else len(src)
    return src[start:end].decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# function discovery
# ---------------------------------------------------------------------------

_NAME_FIELDS = ("name", "declarator")
_DECL_WRAPPERS = {"pointer_declarator", "reference_declarator", "parenthesized_declarator", "array_declarator",
                  "attributed_declarator", "function_declarator", "init_declarator", "abstract_pointer_declarator"}
_NAME_TYPES = {"identifier", "field_identifier", "qualified_identifier", "destructor_name", "operator_name",
               "template_function", "scoped_identifier", "property_identifier", "simple_identifier", "constant",
               "type_identifier", "name", "variable_name"}


def _find_declarator_name(src: bytes, node: Node) -> tuple[str | None, str]:
    """C/C++: walk declarator chain; return (name, parameter_list_text)."""
    params = ""
    cur = node
    guard = 0
    while cur is not None and guard < 20:
        guard += 1
        if cur.type == "function_declarator":
            pl = cur.child_by_field_name("parameters")
            if pl is not None:
                params = norm_text(_text(src, pl))
            cur = cur.child_by_field_name("declarator") or (cur.children[0] if cur.children else None)
            continue
        if cur.type in _DECL_WRAPPERS:
            nxt = cur.child_by_field_name("declarator")
            if nxt is None:
                nxt = next((c for c in cur.children if c.type in _DECL_WRAPPERS or c.type in _NAME_TYPES), None)
            cur = nxt
            continue
        if cur.type in _NAME_TYPES:
            return _text(src, cur), params
        # fall back: first name-like descendant
        for c in cur.children:
            if c.type in _NAME_TYPES:
                return _text(src, c), params
        break
    return None, params


def function_name_and_sig(src: bytes, spec: LangSpec, node: Node) -> tuple[str | None, str]:
    if spec.is_c_family:
        decl = node.child_by_field_name("declarator")
        if decl is not None:
            name, params = _find_declarator_name(src, decl)
            if name:
                return name, params
    name_node = node.child_by_field_name("name")
    params = ""
    for f in ("parameters", "formal_parameters", "parameter_list", "method_parameters", "function_value_parameters"):
        p = node.child_by_field_name(f)
        if p is not None:
            params = norm_text(_text(src, p))
            break
    if not params:
        p = next((c for c in node.children if "param" in c.type), None)
        if p is not None:
            params = norm_text(_text(src, p))
    if name_node is not None:
        return _text(src, name_node), params
    # anonymous function assigned to a name: const f = () => {}, foo: function() {}, x = lambda
    par = node.parent
    if par is not None:
        if par.type in ("variable_declarator", "assignment_expression", "assignment", "pair", "property", "let_declaration",
                        "short_var_declaration", "init_declarator", "field_definition", "public_field_definition", "keyword_argument"):
            left = par.child_by_field_name("name") or par.child_by_field_name("left") or par.child_by_field_name("key") or par.child_by_field_name("pattern")
            if left is not None and left.type in _NAME_TYPES | {"member_expression", "subscript_expression", "pattern"}:
                return _text(src, left), params
    # generic: first identifier child
    for c in node.children:
        if c.type in _NAME_TYPES:
            return _text(src, c), params
    return None, params


def _body_node(spec: LangSpec, node: Node) -> Node | None:
    b = node.child_by_field_name("body")
    if b is not None:
        return b
    for c in reversed(node.children):
        if is_block_type(spec, c.type):
            return c
    return None


def _qualified_prefix(src: bytes, spec: LangSpec, node: Node) -> str:
    """Class/namespace/impl prefix for the function (used for disambiguation only)."""
    parts = []
    cur = node.parent
    while cur is not None:
        if cur.type in ("class_specifier", "struct_specifier", "class_declaration", "class_definition", "namespace_definition",
                        "impl_item", "object_definition", "module", "class", "interface_declaration", "trait_item", "implementation_definition"):
            n = cur.child_by_field_name("name") or cur.child_by_field_name("type")
            if n is not None:
                parts.append(_text(src, n))
        cur = cur.parent
    return "::".join(reversed(parts))


def parse_file(src: bytes, lang: str, max_lines: int = 3000) -> tuple[Node, list[Function]]:
    """Parse once; return (root_node, functions)."""
    tree = get_parser(lang).parse(src)
    return tree.root_node, list(_iter_functions_in(tree.root_node, src, lang, max_lines))


def iter_functions(src: bytes, lang: str, max_lines: int = 3000) -> Iterator[Function]:
    """Yield all function definitions in a source file, outermost first (nested functions included)."""
    tree = get_parser(lang).parse(src)
    yield from _iter_functions_in(tree.root_node, src, lang, max_lines)


def _iter_functions_in(root: Node, src: bytes, lang: str, max_lines: int) -> Iterator[Function]:
    spec = get_spec(lang)
    offsets = line_offsets(src)
    stack = [root]
    while stack:
        node = stack.pop()
        if is_function_type(spec, node.type):
            body = _body_node(spec, node)
            # declarations without body (prototypes, abstract methods) are not functions
            if body is not None or (not spec.is_c_family and node.type not in ("function_signature",)):
                name, sig = function_name_and_sig(src, spec, node)
                if name is None and node.type in spec.anonymous_function_types:
                    pass  # anonymous closure: do not emit, but still descend for nested named functions
                elif body is not None and _line(node.end_point) - _line(node.start_point) + 1 <= max_lines:
                    fn = Function(
                        name=name or "<anonymous>", signature=sig,
                        start_line=_line(node.start_point), end_line=_line(node.end_point),
                        start_byte=node.start_byte, end_byte=node.end_byte,
                        text=_text(src, node), node=node, body_node=body,
                        qualified_name=_qualified_prefix(src, spec, node),
                    )
                    fn.units = build_units(src, spec, fn, offsets)
                    yield fn
        stack.extend(reversed(node.children))


def all_function_defs(src: bytes, lang: str) -> dict[str, list[Function]]:
    out: dict[str, list[Function]] = {}
    for fn in iter_functions(src, lang):
        out.setdefault(fn.name, []).append(fn)
    return out


# ---------------------------------------------------------------------------
# statement units
# ---------------------------------------------------------------------------

def _is_substatement(spec: LangSpec, n: Node) -> bool:
    if n.type in spec.comment_types:
        return True
    return is_block_type(spec, n.type) or is_statement_type(spec, n.type)


_BODY_FIELDS = ("body", "consequence", "block", "then", "statements", "alternative")


def _first_sub(spec: LangSpec, node: Node) -> Node | None:
    """The child where the header of a compound statement ends: the earliest body-like field
    (so `for (int i = 0; ...)` init declarations stay in the header), else the first sub-statement."""
    best = None
    for f in _BODY_FIELDS:
        c = node.child_by_field_name(f)
        if c is not None and (best is None or c.start_byte < best.start_byte):
            best = c
    if best is not None:
        return best
    return next((c for c in node.children if _is_substatement(spec, c)), None)


def _last_sub(spec: LangSpec, node: Node) -> Node | None:
    return next((c for c in reversed(node.children) if _is_substatement(spec, c)), None)


class _Ctx:
    """Per-file context: source bytes, line offsets, language spec."""

    __slots__ = ("src", "offsets", "spec")

    def __init__(self, src: bytes, spec: LangSpec, offsets: list[int] | None = None):
        self.src = src
        self.spec = spec
        self.offsets = offsets if offsets is not None else line_offsets(src)

    def line_of(self, byte: int) -> int:
        from bisect import bisect_right
        return bisect_right(self.offsets, byte)  # offsets[0]=0 -> line 1


def _mk(ctx: _Ctx, kind: str, node_type: str, sb: int, eb: int, depth: int, is_code: bool = True, text: str | None = None) -> Unit | None:
    if eb <= sb:
        return None
    src = ctx.src
    raw = src[sb:eb]
    stripped = raw.strip()
    if not stripped:
        return None
    lead = len(raw) - len(raw.lstrip())
    s_abs = sb + lead
    if kind == "header" and stripped.endswith(b"{") and len(stripped) > 1:
        # languages without a block node (Go switch, Rust-like braces inside the header): drop the brace
        stripped2 = stripped[:-1].rstrip()
        if stripped2:
            stripped = stripped2
    e_abs = s_abs + len(stripped)
    t = stripped.decode("utf-8", errors="replace") if text is None else text
    start_line = ctx.line_of(s_abs)
    end_line = ctx.line_of(max(e_abs - 1, s_abs))
    return Unit(kind, node_type, start_line, end_line, s_abs, e_abs, t, depth=depth, is_code=is_code)


def build_units(src: bytes, spec: LangSpec, fn: Function, offsets: list[int] | None = None) -> list[Unit]:
    """Flattened, document-ordered statement units for a function."""
    ctx = _Ctx(src, spec, offsets)
    units: list[Unit] = []
    node = fn.node
    body = fn.body_node
    if body is not None and body.start_byte > node.start_byte:
        u = _mk(ctx, "signature", node.type, node.start_byte, body.start_byte, 0)
        if u:
            units.append(u)
    if body is not None:
        _walk_block(ctx, body, units, depth=0)
    else:
        u = _mk(ctx, "simple", node.type, node.start_byte, node.end_byte, 0)
        if u:
            units.append(u)
    units.sort(key=lambda u: (u.start_byte, u.end_byte))
    return units


def _walk_block(ctx: _Ctx, block: Node, units: list[Unit], depth: int) -> None:
    for c in block.children:
        _emit(ctx, c, units, depth)


def _emit(ctx: _Ctx, node: Node, units: list[Unit], depth: int) -> None:
    spec = ctx.spec
    t = node.type
    if t in spec.comment_types:
        u = _mk(ctx, "comment", t, node.start_byte, node.end_byte, depth, is_code=False)
        if u:
            units.append(u)
        return
    if not node.is_named:
        return  # punctuation / keywords ('{', '}', ';')
    if is_block_type(spec, t):
        _walk_block(ctx, node, units, depth + 1)
        return
    if t == "ERROR":
        for c in node.children:
            _emit(ctx, c, units, depth)
        return
    subs = [c for c in node.children if _is_substatement(spec, c)]
    has_subs = bool(subs)
    if len(subs) == 1 and subs[0].start_byte == node.start_byte and subs[0].end_byte >= node.end_byte - 1:
        # transparent wrapper (e.g. rust `expression_statement` around an `if_expression`)
        _emit(ctx, subs[0], units, depth)
        return
    if node.has_error and not has_subs:
        # error recovery on a leaf-ish statement: emit as one unit
        u = _mk(ctx, "simple", t, node.start_byte, node.end_byte, depth)
        if u:
            units.append(u)
        return
    if not has_subs:
        u = _mk(ctx, "simple", t, node.start_byte, node.end_byte, depth)
        if u:
            units.append(u)
        return

    # else-if merging: else_clause whose sole substatement is an if -> one "else if (...)" header
    if t == "else_clause" and spec.name in ("c", "cpp", "javascript", "typescript", "tsx", "java", "php", "csharp"):
        subs = [c for c in node.children if _is_substatement(spec, c)]
        if len(subs) == 1 and subs[0].type in spec.if_types:
            inner = subs[0]
            inner_first = _first_sub(spec, inner)
            hdr_end = inner_first.start_byte if inner_first is not None else inner.end_byte
            raw = ctx.src[node.start_byte:hdr_end].decode("utf-8", errors="replace")
            u = _mk(ctx, "header", "else_if", node.start_byte, hdr_end, depth, text=norm_join(raw))
            if u:
                units.append(u)
            if inner_first is not None:
                _emit_children_from(ctx, inner, inner_first, units, depth)
            return

    first = _first_sub(spec, node)
    u = _mk(ctx, "header", t, node.start_byte, first.start_byte, depth)
    if u:
        units.append(u)
    _emit_children_from(ctx, node, first, units, depth)


def _same_node(a: Node, b: Node) -> bool:
    # tree-sitter's child_by_field_name() returns a distinct Python wrapper; compare ids
    return a.id == b.id


def _emit_children_from(ctx: _Ctx, node: Node, first: Node, units: list[Unit], depth: int) -> None:
    spec = ctx.spec
    last = _last_sub(spec, node)
    started = False
    for c in node.children:
        if _same_node(c, first):
            started = True
        if started and _is_substatement(spec, c):
            _emit(ctx, c, units, depth if is_block_type(spec, c.type) else depth + 1)
    if last is not None and last.end_byte < node.end_byte:
        u = _mk(ctx, "tail", node.type, last.end_byte, node.end_byte, depth)
        if u and u.text not in ("", ";", "}"):
            units.append(u)


def norm_join(raw: str) -> str:
    """Header text for merged `else if`: strip and collapse the whitespace between `else` and `if`."""
    s = raw.strip()
    return re.sub(r"^else\s+if\b", "else if", s)


# ---------------------------------------------------------------------------
# line -> unit mapping
# ---------------------------------------------------------------------------

def unit_for_line(fn: Function, line: int) -> Unit | None:
    """Innermost unit covering `line`; prefers units that start on the line."""
    cands = [u for u in fn.units if u.start_line <= line <= u.end_line]
    if not cands:
        return None
    starting = [u for u in cands if u.start_line == line]
    if starting:
        return min(starting, key=lambda u: u.start_byte)
    return min(cands, key=lambda u: (u.end_line - u.start_line, u.end_byte - u.start_byte))


def changed_statements_for_lines(src: bytes, offsets: list[int], fn: Function, lines: list[int]) -> list[tuple[int, str]]:
    """SecVulEval-style [[line, statement_text]] for a set of changed lines of this function."""
    out: dict[int, str] = {}
    for ln in sorted(set(lines)):
        if ln < fn.start_line or ln > fn.end_line:
            continue
        u = unit_for_line(fn, ln)
        if u is None or u.kind == "raw":
            if ln not in out:
                out[ln] = raw_line(src, offsets, ln)
            continue
        if u.start_line not in out:
            out[u.start_line] = u.text
    return sorted(out.items())


def changed_lines_for_fn(src: bytes, offsets: list[int], fn: Function, lines: list[int]) -> list[tuple[int, str]]:
    return [(ln, raw_line(src, offsets, ln)) for ln in sorted(set(lines)) if fn.start_line <= ln <= fn.end_line]


def identifiers(text: str, keywords: set[str]) -> list[str]:
    out = []
    for m in _IDENT.finditer(text):
        w = m.group(0)
        if w in keywords or w in out:
            continue
        out.append(w)
    return out
