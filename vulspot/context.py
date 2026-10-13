"""Deterministic context columns computed from the function AST and its file.

  callees              : names of functions/macros called inside the function (document order, unique)
  types_used           : type names referenced (struct/union/enum/typedef/class names, generics)
  macros_used          : UPPER_CASE identifiers (C/C++ convention) that are not locals/params
  globals_used         : identifiers used in the function that are declared at file scope
                         (variables/constants/enumerators of the same file) and are not local
  same_file_callee_defs: source of callees defined in the same file (size capped)
"""
from __future__ import annotations

import re
from typing import Iterable

from tree_sitter import Node

from .langs import LangSpec
from .tsparse import Function, _text

_UPPER = re.compile(r"^[A-Z][A-Z0-9_]{1,}$")
_LOCAL_DECL_TYPES = {
    "declaration", "parameter_declaration", "init_declarator", "variable_declarator", "let_declaration",
    "short_var_declaration", "var_spec", "assignment", "local_variable_declaration", "property_declaration",
    "optional_parameter_declaration", "variadic_parameter_declaration", "parameter", "typed_parameter",
    "default_parameter", "typed_default_parameter", "simple_parameter", "formal_parameter", "catch_formal_parameter",
    "for_range_loop", "condition_clause", "range_clause", "lambda_parameters", "identifier_pattern", "closure_parameters",
}
_IDENT_TYPES = {"identifier", "field_identifier", "property_identifier", "simple_identifier", "constant", "variable_name", "name"}


def _walk(node: Node) -> Iterable[Node]:
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


def _callee_name(src: bytes, call: Node, spec: LangSpec) -> str | None:
    f = call.child_by_field_name("function") or call.child_by_field_name("name") or call.child_by_field_name("method") \
        or call.child_by_field_name("macro") or call.child_by_field_name("type")
    if f is None:
        # method_invocation / member_call: last identifier child before argument list
        for c in call.children:
            if c.type in ("argument_list", "arguments"):
                break
            if c.type in _IDENT_TYPES:
                f = c
    if f is None:
        return None
    t = _text(src, f)
    # strip receiver: a->b.c(…) -> c ; ns::f -> ns::f kept
    if f.type in ("field_expression", "member_expression", "member_access_expression", "attribute", "selector_expression",
                  "navigation_expression", "scoped_call_expression", "member_call_expression"):
        fld = f.child_by_field_name("field") or f.child_by_field_name("property") or f.child_by_field_name("attribute") or f.child_by_field_name("name")
        if fld is not None:
            t = _text(src, fld)
        else:
            t = re.split(r"->|\.", t)[-1]
    t = t.strip()
    if not re.match(r"^[A-Za-z_][\w:<>\.\$]*$", t):
        return None
    return t


def _local_names(src: bytes, fn: Function) -> set[str]:
    names: set[str] = set()
    # parameters + any declarator identifiers inside the function
    for n in _walk(fn.node):
        if n.type in _LOCAL_DECL_TYPES:
            for d in _walk(n):
                if d.type in ("identifier", "simple_identifier", "variable_name"):
                    par = d.parent
                    # skip identifiers that are the *type* of a declaration or an initializer value
                    if par is not None and par.type in ("call_expression", "argument_list", "binary_expression", "initializer_list", "subscript_expression"):
                        continue
                    names.add(_text(src, d))
    return names


def file_scope_names(src: bytes, root: Node, spec: LangSpec) -> set[str]:
    """Names declared at file scope (variables, constants, enumerators, typedefs) — not functions."""
    out: set[str] = set()
    for c in root.children:
        if c.type in ("declaration", "lexical_declaration", "variable_declaration", "const_declaration", "var_declaration",
                      "static_item", "const_item", "assignment", "expression_statement", "global_declaration", "property_declaration"):
            for d in _walk(c):
                if d.type in ("identifier", "simple_identifier", "variable_name") and d.parent is not None and d.parent.type in (
                        "init_declarator", "declaration", "variable_declarator", "const_spec", "var_spec", "pointer_declarator",
                        "array_declarator", "assignment", "static_item", "const_item", "let_declaration", "expression_statement"):
                    out.add(_text(src, d))
        elif c.type in ("enum_specifier", "type_definition", "struct_specifier", "union_specifier"):
            for d in _walk(c):
                if d.type == "enumerator":
                    nm = d.child_by_field_name("name")
                    if nm is not None:
                        out.add(_text(src, nm))
        elif c.type in ("preproc_def", "preproc_function_def"):
            nm = c.child_by_field_name("name")
            if nm is not None:
                out.add(_text(src, nm))
    return out


def context_columns(src: bytes, fn: Function, spec: LangSpec, file_defs: dict[str, list[Function]],
                    file_globals: set[str], max_chars: int, max_count: int) -> dict:
    callees: list[str] = []
    types: list[str] = []
    macros: list[str] = []
    used_idents: list[str] = []
    seen_c, seen_t, seen_m, seen_u = set(), set(), set(), set()
    sig_end = fn.body_node.start_byte if fn.body_node is not None else fn.start_byte
    for n in _walk(fn.node):
        if n.type in spec.call_types:
            nm = _callee_name(src, n, spec)
            if nm and nm not in seen_c and nm not in spec.keywords:
                seen_c.add(nm)
                callees.append(nm)
        if n.type in spec.type_types and n.type != "identifier":
            t = _text(src, n)
            if n.type in ("struct_specifier", "union_specifier", "enum_specifier", "class_specifier"):
                nm = n.child_by_field_name("name")
                if nm is None:
                    continue
                t = n.type.split("_")[0] + " " + _text(src, nm)
            t = re.sub(r"\s+", " ", t).strip()
            if t and t not in seen_t and len(t) < 120:
                seen_t.add(t)
                types.append(t)
        if n.type in _IDENT_TYPES and n.start_byte >= sig_end:
            t = _text(src, n)
            if t not in seen_u:
                seen_u.add(t)
                used_idents.append(t)
    locals_ = _local_names(src, fn)
    locals_.add(fn.name)
    if spec.is_c_family:
        for t in used_idents:
            if _UPPER.match(t) and t not in locals_ and t not in seen_m:
                seen_m.add(t)
                macros.append(t)
    globals_ = [t for t in used_idents if t in file_globals and t not in locals_ and t not in seen_c]
    # same-file callee definitions
    defs: list[dict] = []
    total = 0
    for nm in callees:
        if nm == fn.name or nm not in file_defs:
            continue
        for d in file_defs[nm]:
            if d.start_byte == fn.start_byte:
                continue
            body = d.text
            if total + len(body) > max_chars and defs:
                break
            if len(body) > max_chars:
                body = body[:max_chars] + "\n/* ... truncated ... */"
            defs.append({"name": nm, "start_line": d.start_line, "end_line": d.end_line, "code": body})
            total += len(body)
            break
        if len(defs) >= max_count or total >= max_chars:
            break
    return {
        "callees": callees,
        "types_used": types,
        "macros_used": macros,
        "globals_used": globals_,
        "same_file_callee_defs": defs,
    }
