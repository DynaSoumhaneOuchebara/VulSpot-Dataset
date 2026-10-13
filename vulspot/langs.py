"""Language registry: extension -> grammar, node-type tables, parsers, test-path detection."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache

from tree_sitter import Language, Parser

# ---------------------------------------------------------------------------
# Per-language node type tables. Missing languages fall back to DEFAULT_SPEC,
# whose heuristics are name-pattern based (types containing "function"/"method", etc.).
# ---------------------------------------------------------------------------


@dataclass
class LangSpec:
    name: str
    function_types: set[str]
    block_types: set[str]
    statement_types: set[str] = field(default_factory=set)
    comment_types: set[str] = field(default_factory=lambda: {"comment", "line_comment", "block_comment"})
    call_types: set[str] = field(default_factory=lambda: {"call_expression"})
    type_types: set[str] = field(default_factory=lambda: {"type_identifier"})
    # node types that are never functions on their own (anonymous) unless named by a parent
    anonymous_function_types: set[str] = field(default_factory=set)
    # keyword set used to drop keywords from identifier extraction
    keywords: set[str] = field(default_factory=set)
    jump_keywords: set[str] = field(default_factory=lambda: {"return", "goto", "break", "continue", "exit", "abort", "panic", "BUG", "longjmp"})
    if_types: set[str] = field(default_factory=lambda: {"if_statement"})
    is_c_family: bool = False


C_KEYWORDS = set("""auto break case char const continue default do double else enum extern float for goto if inline int long
register restrict return short signed sizeof static struct switch typedef union unsigned void volatile while _Bool _Complex
_Imaginary bool true false NULL class namespace template typename this new delete public private protected virtual override
operator throw try catch using nullptr constexpr static_cast dynamic_cast reinterpret_cast const_cast noexcept explicit friend
mutable""".split())

C_SPEC = LangSpec(
    name="c",
    function_types={"function_definition"},
    block_types={"compound_statement", "declaration_list", "field_declaration_list"},
    statement_types={
        "expression_statement", "declaration", "return_statement", "break_statement", "continue_statement",
        "goto_statement", "labeled_statement", "case_statement", "if_statement", "else_clause", "for_statement",
        "while_statement", "do_statement", "switch_statement", "attributed_statement", "seh_try_statement",
        "seh_except_clause", "seh_finally_clause", "seh_leave_statement", "preproc_if", "preproc_ifdef",
        "preproc_else", "preproc_elif", "preproc_elifdef", "preproc_def", "preproc_function_def", "preproc_call",
        "preproc_include", "type_definition", "struct_specifier", "union_specifier", "enum_specifier",
    },
    call_types={"call_expression"},
    type_types={"type_identifier", "struct_specifier", "union_specifier", "enum_specifier"},
    keywords=C_KEYWORDS,
    is_c_family=True,
)

CPP_SPEC = LangSpec(
    name="cpp",
    function_types={"function_definition"},
    block_types={"compound_statement", "declaration_list", "field_declaration_list"},
    statement_types=C_SPEC.statement_types | {
        "for_range_loop", "try_statement", "catch_clause", "throw_statement", "co_return_statement",
        "co_yield_statement", "alias_declaration", "using_declaration", "static_assert_declaration",
        "template_declaration", "namespace_definition", "class_specifier",
    },
    call_types={"call_expression"},
    type_types={"type_identifier", "struct_specifier", "union_specifier", "enum_specifier", "class_specifier", "qualified_identifier"},
    keywords=C_KEYWORDS,
    jump_keywords={"return", "goto", "break", "continue", "throw", "exit", "abort", "panic", "BUG", "longjmp"},
    is_c_family=True,
)

PY_KEYWORDS = set("""False None True and as assert async await break class continue def del elif else except finally for from
global if import in is lambda nonlocal not or pass raise return try while with yield self cls print len range""".split())

PYTHON_SPEC = LangSpec(
    name="python",
    function_types={"function_definition"},
    block_types={"block"},
    statement_types={
        "expression_statement", "return_statement", "if_statement", "elif_clause", "else_clause", "for_statement",
        "while_statement", "try_statement", "except_clause", "finally_clause", "with_statement", "assert_statement",
        "pass_statement", "raise_statement", "delete_statement", "import_statement", "import_from_statement",
        "global_statement", "nonlocal_statement", "break_statement", "continue_statement", "match_statement",
        "case_clause", "decorated_definition", "class_definition",
    },
    call_types={"call"},
    type_types={"type"},
    keywords=PY_KEYWORDS,
    jump_keywords={"return", "raise", "break", "continue", "exit", "abort"},
)

JAVA_KEYWORDS = set("""abstract assert boolean break byte case catch char class const continue default do double else enum
extends final finally float for goto if implements import instanceof int interface long native new package private
protected public return short static strictfp super switch synchronized this throw throws transient try void volatile
while var record yield sealed permits true false null""".split())

JAVA_SPEC = LangSpec(
    name="java",
    function_types={"method_declaration", "constructor_declaration", "compact_constructor_declaration"},
    block_types={"block", "constructor_body", "switch_block", "switch_block_statement_group"},
    statement_types={
        "local_variable_declaration", "expression_statement", "return_statement", "if_statement", "for_statement",
        "enhanced_for_statement", "while_statement", "do_statement", "try_statement", "try_with_resources_statement",
        "catch_clause", "finally_clause", "switch_expression", "switch_statement", "throw_statement",
        "break_statement", "continue_statement", "yield_statement", "labeled_statement", "synchronized_statement",
        "assert_statement", "explicit_constructor_invocation", "switch_label", "switch_rule",
    },
    call_types={"method_invocation", "object_creation_expression"},
    type_types={"type_identifier", "generic_type", "scoped_type_identifier"},
    keywords=JAVA_KEYWORDS,
    jump_keywords={"return", "throw", "break", "continue", "exit"},
)

JS_KEYWORDS = set("""break case catch class const continue debugger default delete do else export extends finally for function
if import in instanceof new return super switch this throw try typeof var void while with yield let static async await
of undefined null true false console require module exports""".split())

JS_SPEC = LangSpec(
    name="javascript",
    function_types={"function_declaration", "method_definition", "generator_function_declaration", "function_expression",
                    "arrow_function", "generator_function", "function"},
    anonymous_function_types={"function_expression", "arrow_function", "generator_function", "function"},
    block_types={"statement_block", "class_body", "switch_body"},
    statement_types={
        "expression_statement", "lexical_declaration", "variable_declaration", "return_statement", "if_statement",
        "else_clause", "for_statement", "for_in_statement", "while_statement", "do_statement", "try_statement",
        "catch_clause", "finally_clause", "switch_statement", "switch_case", "switch_default", "throw_statement",
        "break_statement", "continue_statement", "labeled_statement", "export_statement", "import_statement",
        "debugger_statement", "with_statement", "empty_statement",
    },
    call_types={"call_expression", "new_expression"},
    type_types={"type_identifier", "predefined_type"},
    keywords=JS_KEYWORDS,
    jump_keywords={"return", "throw", "break", "continue", "exit"},
)

TS_SPEC = LangSpec(**{**JS_SPEC.__dict__, "name": "typescript"})
TS_SPEC.statement_types = JS_SPEC.statement_types | {"type_alias_declaration", "interface_declaration", "enum_declaration"}
TSX_SPEC = LangSpec(**{**TS_SPEC.__dict__, "name": "tsx"})

GO_KEYWORDS = set("""break case chan const continue default defer else fallthrough for func go goto if import interface map
package range return select struct switch type var nil true false err""".split())

GO_SPEC = LangSpec(
    name="go",
    function_types={"function_declaration", "method_declaration", "func_literal"},
    anonymous_function_types={"func_literal"},
    block_types={"block"},
    statement_types={
        "short_var_declaration", "assignment_statement", "expression_statement", "return_statement", "if_statement",
        "for_statement", "go_statement", "defer_statement", "var_declaration", "const_declaration", "inc_statement",
        "dec_statement", "send_statement", "select_statement", "expression_switch_statement", "type_switch_statement",
        "labeled_statement", "break_statement", "continue_statement", "goto_statement", "fallthrough_statement",
        "expression_case", "default_case", "type_case", "communication_case", "empty_statement",
    },
    call_types={"call_expression"},
    type_types={"type_identifier", "qualified_type"},
    keywords=GO_KEYWORDS,
    jump_keywords={"return", "panic", "break", "continue", "goto", "os.Exit", "log.Fatal"},
)

RUST_KEYWORDS = set("""as break const continue crate else enum extern false fn for if impl in let loop match mod move mut pub
ref return self Self static struct super trait true type unsafe use where while async await dyn Some None Ok Err""".split())

RUST_SPEC = LangSpec(
    name="rust",
    function_types={"function_item", "closure_expression"},
    anonymous_function_types={"closure_expression"},
    block_types={"block", "match_block", "declaration_list"},
    statement_types={
        "let_declaration", "expression_statement", "empty_statement", "if_expression", "else_clause", "match_expression",
        "match_arm", "for_expression", "while_expression", "loop_expression", "return_expression", "break_expression",
        "continue_expression", "macro_invocation", "use_declaration", "const_item", "static_item",
    },
    call_types={"call_expression", "macro_invocation"},
    type_types={"type_identifier", "generic_type", "scoped_type_identifier"},
    keywords=RUST_KEYWORDS,
    if_types={"if_expression"},
    jump_keywords={"return", "panic!", "break", "continue", "bail!", "unreachable!", "?"},
)

PHP_KEYWORDS = set("""abstract and array as break callable case catch class clone const continue declare default do echo else
elseif empty enddeclare endfor endforeach endif endswitch endwhile eval exit extends final finally fn for foreach function
global goto if implements include include_once instanceof insteadof interface isset list match namespace new or print
private protected public readonly require require_once return static switch throw trait try unset use var while xor
yield true false null self parent this""".split())

PHP_SPEC = LangSpec(
    name="php",
    function_types={"function_definition", "method_declaration", "anonymous_function", "arrow_function"},
    anonymous_function_types={"anonymous_function", "arrow_function"},
    block_types={"compound_statement", "declaration_list", "switch_block", "colon_block"},
    statement_types={
        "expression_statement", "echo_statement", "return_statement", "if_statement", "else_if_clause", "else_clause",
        "foreach_statement", "for_statement", "while_statement", "do_statement", "switch_statement", "case_statement",
        "default_statement", "try_statement", "catch_clause", "finally_clause", "global_declaration",
        "static_variable_declaration", "unset_statement", "break_statement", "continue_statement", "goto_statement",
        "named_label_statement", "function_static_declaration", "const_declaration",
    },
    call_types={"function_call_expression", "member_call_expression", "scoped_call_expression", "nullsafe_member_call_expression", "object_creation_expression"},
    type_types={"named_type", "primitive_type"},
    keywords=PHP_KEYWORDS,
    jump_keywords={"return", "throw", "break", "continue", "exit", "die"},
)

RUBY_KEYWORDS = set("""alias and begin break case class def defined? do else elsif end ensure false for if in module next nil
not or redo rescue retry return self super then true undef unless until when while yield puts raise require attr_accessor
private public protected""".split())

RUBY_SPEC = LangSpec(
    name="ruby",
    function_types={"method", "singleton_method", "lambda"},
    anonymous_function_types={"lambda"},
    block_types={"body_statement", "do_block", "block", "then", "else", "ensure"},
    statement_types={
        "call", "assignment", "operator_assignment", "if", "unless", "while", "until", "for", "case", "when", "elsif",
        "begin", "rescue", "return", "yield", "next", "break", "redo", "retry", "method_call", "if_modifier",
        "unless_modifier", "while_modifier", "until_modifier", "rescue_modifier",
    },
    call_types={"call", "method_call"},
    type_types={"constant"},
    keywords=RUBY_KEYWORDS,
    if_types={"if", "unless", "if_modifier", "unless_modifier"},
    jump_keywords={"return", "raise", "break", "next", "exit", "abort"},
)

CSHARP_SPEC = LangSpec(
    name="csharp",
    function_types={"method_declaration", "constructor_declaration", "local_function_statement", "destructor_declaration", "operator_declaration"},
    block_types={"block", "switch_body", "switch_section", "declaration_list"},
    statement_types={
        "local_declaration_statement", "expression_statement", "return_statement", "if_statement", "for_statement",
        "foreach_statement", "while_statement", "do_statement", "try_statement", "catch_clause", "finally_clause",
        "switch_statement", "switch_section", "throw_statement", "break_statement", "continue_statement",
        "using_statement", "lock_statement", "yield_statement", "labeled_statement", "goto_statement",
        "checked_statement", "unsafe_statement", "fixed_statement", "empty_statement",
    },
    call_types={"invocation_expression", "object_creation_expression"},
    type_types={"identifier", "generic_name", "predefined_type", "qualified_name"},
    keywords=JAVA_KEYWORDS | {"using", "namespace", "string", "bool", "object", "foreach", "readonly", "override", "virtual", "sealed", "internal", "out", "ref", "params", "is", "as", "lock", "checked", "unchecked", "fixed", "unsafe", "delegate", "event", "struct", "get", "set", "value"},
    jump_keywords={"return", "throw", "break", "continue", "goto", "Exit"},
)

KOTLIN_SPEC = LangSpec(
    name="kotlin",
    function_types={"function_declaration", "anonymous_function", "lambda_literal"},
    anonymous_function_types={"anonymous_function", "lambda_literal"},
    block_types={"function_body", "control_structure_body", "statements", "class_body", "when_entry"},
    statement_types={
        "property_declaration", "assignment", "call_expression", "jump_expression", "if_expression", "when_expression",
        "for_statement", "while_statement", "do_while_statement", "try_expression", "catch_block", "finally_block",
        "when_entry",
    },
    call_types={"call_expression"},
    type_types={"type_identifier", "user_type"},
    keywords=JAVA_KEYWORDS | {"fun", "val", "when", "is", "in", "object", "companion", "override", "data", "sealed", "open", "internal", "lateinit", "it"},
    if_types={"if_expression"},
    jump_keywords={"return", "throw", "break", "continue", "exitProcess", "error"},
)

SWIFT_SPEC = LangSpec(
    name="swift",
    function_types={"function_declaration", "init_declaration", "deinit_declaration", "lambda_literal"},
    anonymous_function_types={"lambda_literal"},
    block_types={"function_body", "statements", "class_body", "switch_entry"},
    statement_types={
        "property_declaration", "assignment", "call_expression", "control_transfer_statement", "if_statement",
        "guard_statement", "switch_statement", "for_statement", "while_statement", "repeat_while_statement",
        "do_statement", "catch_block", "switch_entry", "defer_statement", "throw_keyword",
    },
    call_types={"call_expression"},
    type_types={"type_identifier", "user_type"},
    keywords=set("""func let var if else guard switch case default for while repeat do try catch throw throws return break
continue fallthrough in is as class struct enum protocol extension init deinit self Self super nil true false where defer
import public private internal fileprivate open static final override mutating inout some any""".split()),
    if_types={"if_statement", "guard_statement"},
    jump_keywords={"return", "throw", "break", "continue", "fatalError", "exit"},
)

SPECS: dict[str, LangSpec] = {
    "c": C_SPEC, "cpp": CPP_SPEC, "python": PYTHON_SPEC, "java": JAVA_SPEC, "javascript": JS_SPEC,
    "typescript": TS_SPEC, "tsx": TSX_SPEC, "go": GO_SPEC, "rust": RUST_SPEC, "php": PHP_SPEC, "ruby": RUBY_SPEC,
    "csharp": CSHARP_SPEC, "kotlin": KOTLIN_SPEC, "swift": SWIFT_SPEC,
}

_FUNC_TYPE_RE = re.compile(r"(function|method|constructor|subroutine|^sub$|^def$|^fun$|lambda|closure|func_literal|procedure)")
_BLOCK_TYPE_RE = re.compile(r"(^block$|_block$|^body$|_body$|^statements$|statement_list|compound_statement|^then$|^else$)")


def default_spec(name: str) -> LangSpec:
    """Heuristic spec for languages without a hand-written table."""
    return LangSpec(
        name=name,
        function_types=set(),  # resolved dynamically via _FUNC_TYPE_RE
        block_types=set(),     # resolved dynamically via _BLOCK_TYPE_RE
        statement_types=set(),
        call_types={"call_expression", "call", "method_invocation", "invocation_expression", "function_call_expression"},
        type_types={"type_identifier"},
        keywords=C_KEYWORDS | PY_KEYWORDS | JAVA_KEYWORDS | JS_KEYWORDS,
    )


def get_spec(lang: str) -> LangSpec:
    return SPECS.get(lang) or default_spec(lang)


def is_function_type(spec: LangSpec, t: str) -> bool:
    if spec.function_types:
        return t in spec.function_types
    return bool(_FUNC_TYPE_RE.search(t)) and not t.endswith(("_call", "call_expression", "_type", "_signature", "_declarator", "_parameters", "_parameter"))


def is_block_type(spec: LangSpec, t: str) -> bool:
    if spec.block_types:
        return t in spec.block_types
    return bool(_BLOCK_TYPE_RE.search(t))


def is_statement_type(spec: LangSpec, t: str) -> bool:
    if t in spec.statement_types:
        return True
    return t.endswith(("_statement", "_clause", "_declaration")) or t in ("else_clause",)


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

@lru_cache(maxsize=None)
def get_parser(lang: str) -> Parser:
    if lang == "c":
        import tree_sitter_c
        return Parser(Language(tree_sitter_c.language()))
    if lang == "cpp":
        import tree_sitter_cpp
        return Parser(Language(tree_sitter_cpp.language()))
    import tree_sitter_language_pack as tslp
    return tslp.get_parser(lang)


def grammar_available(lang: str) -> bool:
    try:
        get_parser(lang)
        return True
    except Exception:  # noqa: BLE001
        return False


# ---------------------------------------------------------------------------
# Extension / path helpers
# ---------------------------------------------------------------------------

_CPP_HINTS = re.compile(rb"(^|\n)\s*(class\s+\w+|namespace\s+\w+|template\s*<|using\s+namespace|#include\s*<(iostream|string|vector|map|memory|algorithm)>|public:|private:|protected:)|::|\bnullptr\b|\bstatic_cast\b")


def file_extension(path: str) -> str:
    name = path.rsplit("/", 1)[-1]
    if "." not in name:
        return ""
    return "." + name.rsplit(".", 1)[-1]


class LanguageResolver:
    def __init__(self, cfg):
        lc = cfg["languages"]
        self.ext_map: dict[str, str] = dict(lc["extension_map"])
        self.cpp_exts: set[str] = set(lc["cpp_extensions"])
        self.test_res = [re.compile(p) for p in lc["test_path_patterns"]]

    def language_for(self, path: str, content: bytes | None = None, sibling_exts: set[str] | None = None) -> str | None:
        ext = file_extension(path)
        lang = self.ext_map.get(ext)
        if lang is None and ext.lower() in {e.lower() for e in self.ext_map}:
            # case-insensitive fallback (.H, .CPP)
            for k, v in self.ext_map.items():
                if k.lower() == ext.lower():
                    lang = v
                    break
        if lang is None:
            return None
        if ext in (".h",) and lang == "c":
            # .h: C++ if the content looks like C++ or the commit touches C++ sources
            if content is not None and _CPP_HINTS.search(content[:200000]):
                return "cpp"
            if sibling_exts and sibling_exts & {".cc", ".cpp", ".cxx", ".hpp", ".hh", ".C"} and not sibling_exts & {".c"}:
                return "cpp"
        return lang

    def is_cpp_dataset_file(self, path: str) -> bool:
        return file_extension(path) in self.cpp_exts

    def is_test_path(self, path: str) -> bool:
        return any(r.search(path) for r in self.test_res)
