"""Per-commit function extraction (Stage 4 core). Entirely offline: reads data/raw/commits/<repo>/<sha>/."""
from __future__ import annotations

import difflib
import json
import logging
from pathlib import Path

from .astdiff import code_edit_counts, diff_units
from .context import context_columns, file_scope_names
from .dedup import body_hash, norm_hash
from .diffparse import LineDiff, difflib_linediff, linediff_consistent, parse_hunks, split_unified_diff
from .langs import LanguageResolver, get_spec, grammar_available
from .sanitize import MessageSanitizer, mentions
from .sinks import sink_candidates
from .tsparse import (
    Function, changed_lines_for_fn, changed_statements_for_lines, line_offsets, parse_file,
    release_functions,
)

log = logging.getLogger("extract")


def _j(x) -> str:
    return json.dumps(x, ensure_ascii=False)


class Extractor:
    def __init__(self, cfg, cve_desc: dict[str, str] | None = None):
        self.cfg = cfg
        self.resolver = LanguageResolver(cfg)
        self.sanitize = MessageSanitizer(cfg["commit_message"]["trailer_patterns"])
        ex = cfg["extraction"]
        self.max_func_lines = int(ex.get("max_func_lines", 3000))
        self.ctx_max_chars = int(ex.get("same_file_callee_defs_max_chars", 4000))
        self.ctx_max_count = int(ex.get("same_file_callee_defs_max_count", 8))
        self.untouched_per_file = int(ex.get("untouched_per_file_max", 20))
        self.max_file_bytes = int(cfg["github"].get("max_file_bytes", 2_000_000))
        self.max_line_chars = int(ex.get("max_line_chars", 2000))
        self.cve_desc = cve_desc or {}
        self._grammar_ok: dict[str, bool] = {}

    # ------------------------------------------------------------------
    def _grammar(self, lang: str) -> bool:
        if lang not in self._grammar_ok:
            self._grammar_ok[lang] = grammar_available(lang)
            if not self._grammar_ok[lang]:
                log.warning("no grammar for language %s; files skipped", lang)
        return self._grammar_ok[lang]

    def process_commit(self, commit_dir: Path, meta: dict) -> tuple[dict, list[dict]]:
        repo = meta.get("canonical_repo") or meta["repo"]
        sha = meta.get("full_sha") or meta["sha"]
        cve_ids = sorted(set(meta.get("cve_ids") or []))
        data = json.loads((commit_dir / "commit.json").read_text(encoding="utf-8"))
        msg_raw = ((data.get("commit") or {}).get("message")) or ""
        msg = self.sanitize(msg_raw)
        desc = " ".join(self.cve_desc.get(c, "") for c in cve_ids)
        diff_path = commit_dir / "commit.diff"
        diff_sections: dict[str, str] | None = None

        files = data.get("files") or []
        parents = [p.get("sha") for p in (data.get("parents") or []) if p.get("sha")]
        if not parents:
            parents = list(meta.get("parents") or [])
        parent_sha = parents[0] if parents else None
        sibling_exts = {_ext(f.get("filename", "")) for f in files}
        rec = {
            "repo": repo, "commit_id": sha, "sha_short": sha[:12], "cve_ids": cve_ids,
            "project": repo.split("/")[-1], "project_url": f"https://github.com/{repo}",
            "commit_date": meta.get("commit_date"), "author_date": meta.get("author_date"),
            "parent_commit_id": parent_sha,
            "commit_message_raw": msg_raw, "commit_message": msg,
            "n_files": len(files), "n_code_files": 0, "n_test_files": 0, "n_noncode_files": 0,
            "n_files_processed": 0, "n_files_with_func_edits": 0, "n_files_no_func_edits": 0,
            "n_files_missing_content": 0, "n_files_parse_error": 0, "n_files_added": 0, "n_files_removed": 0,
            "n_changed_funcs": 0, "n_changed_funcs_test": 0, "n_untouched_funcs": 0,
            "files": [],
        }
        rows: list[dict] = []
        for f in files:
            path = f.get("filename") or ""
            status = f.get("status") or "modified"
            lang_guess = self.resolver.language_for(path, None, sibling_exts)
            frec = {"path": path, "status": status, "language": lang_guess, "is_test": self.resolver.is_test_path(path),
                    "n_changed_funcs": 0, "n_untouched": 0, "line_diff_source": None, "skipped": None}
            rec["files"].append(frec)
            if lang_guess is None:
                rec["n_noncode_files"] += 1
                frec["skipped"] = "non_code"
                continue
            rec["n_code_files"] += 1
            if frec["is_test"]:
                rec["n_test_files"] += 1
            if status == "added":
                rec["n_files_added"] += 1
                frec["skipped"] = "added_file"
                continue
            if status == "removed":
                rec["n_files_removed"] += 1
                frec["skipped"] = "removed_file"
                continue
            before_path = f.get("previous_filename") or path
            bp = commit_dir / "before" / before_path
            apath = commit_dir / "after" / path
            if not bp.exists() or not apath.exists():
                rec["n_files_missing_content"] += 1
                frec["skipped"] = "missing_content"
                continue
            bsrc = bp.read_bytes()
            asrc = apath.read_bytes()
            if len(bsrc) > self.max_file_bytes or len(asrc) > self.max_file_bytes:
                frec["skipped"] = "too_large"
                continue
            if bsrc == asrc:
                frec["skipped"] = "identical_content"
                continue
            # Minified bundles are one huge line holding thousands of nested functions;
            # every function row would copy that line and exhaust memory.
            if self.max_line_chars and max(_max_line_len(bsrc), _max_line_len(asrc)) > self.max_line_chars:
                frec["skipped"] = "minified"
                continue
            lang = self.resolver.language_for(path, asrc, sibling_exts) or lang_guess
            frec["language"] = lang
            if not self._grammar(lang):
                frec["skipped"] = "no_grammar"
                continue
            # ---- line diff
            btxt = bsrc.decode("utf-8", errors="replace")
            atxt = asrc.decode("utf-8", errors="replace")
            ld = None
            if f.get("patch"):
                ld = parse_hunks(f["patch"])
                ld.source = "patch"
            if (ld is None or ld.empty) and diff_path.exists():
                if diff_sections is None:
                    diff_sections = split_unified_diff(diff_path.read_text(encoding="utf-8", errors="replace"))
                sec = diff_sections.get(path)
                if sec:
                    ld = parse_hunks(sec)
                    ld.source = "diff"
            if ld is None or ld.empty or not linediff_consistent(ld, btxt, atxt):
                ld = difflib_linediff(btxt, atxt)
            frec["line_diff_source"] = ld.source
            # ---- parse
            # Roots and function nodes keep the tree-sitter trees alive. Always drop them
            # before the next file; `continue` from the parse-error path runs this too.
            broot = aroot = None
            bfuncs = []
            afuncs = []
            try:
                try:
                    broot, bfuncs = parse_file(bsrc, lang, self.max_func_lines)
                    aroot, afuncs = parse_file(asrc, lang, self.max_func_lines)
                except Exception as e:  # noqa: BLE001
                    rec["n_files_parse_error"] += 1
                    frec["skipped"] = f"parse_error:{type(e).__name__}"
                    continue
                rec["n_files_processed"] += 1
                frows = self._process_file(
                    repo, sha, path, lang, frec["is_test"], bsrc, asrc, broot, aroot, bfuncs, afuncs, ld,
                    msg, msg_raw, desc, cve_ids, rec.get("commit_date"), parent_sha,
                )
                n_changed = sum(1 for r in frows if r["pair_status"] in ("paired", "renamed") and r["is_vulnerable"] == 1)
                frec["n_changed_funcs"] = n_changed
                frec["n_untouched"] = sum(1 for r in frows if r["neg_type"] == "untouched")
                if n_changed:
                    rec["n_files_with_func_edits"] += 1
                    if frec["is_test"]:
                        rec["n_changed_funcs_test"] += n_changed
                    else:
                        rec["n_changed_funcs"] += n_changed
                else:
                    rec["n_files_no_func_edits"] += 1
                rec["n_untouched_funcs"] += frec["n_untouched"]
                rows.extend(frows)
            finally:
                release_functions(bfuncs)
                release_functions(afuncs)
                broot = aroot = None
                bfuncs = []
                afuncs = []
                del bsrc, asrc, btxt, atxt, ld
        # commit-level counts for tiering (non-test code files with in-function edits)
        for r in rows:
            r["commit_n_files"] = rec["n_files"]
            r["commit_n_code_files"] = rec["n_code_files"]
            r["commit_n_funcs"] = rec["n_changed_funcs"]
            r["commit_n_funcs_incl_test"] = rec["n_changed_funcs"] + rec["n_changed_funcs_test"]
        return rec, rows

    # ------------------------------------------------------------------
    def _process_file(self, repo, sha, path, lang, is_test, bsrc, asrc, broot, aroot, bfuncs, afuncs, ld: LineDiff,
                      msg, msg_raw, desc, cve_ids, commit_date, parent_sha) -> list[dict]:
        spec = get_spec(lang)
        boffs = line_offsets(bsrc)
        aoffs = line_offsets(asrc)
        deleted = sorted(set(ld.deleted))
        added = sorted(set(ld.added))
        pairs, removed, added_fns = pair_functions(bfuncs, afuncs)

        bdefs: dict[str, list[Function]] = {}
        for fn in bfuncs:
            bdefs.setdefault(fn.name, []).append(fn)
        adefs: dict[str, list[Function]] = {}
        for fn in afuncs:
            adefs.setdefault(fn.name, []).append(fn)
        bglob = file_scope_names(bsrc, broot, spec)
        aglob = file_scope_names(asrc, aroot, spec)

        rows: list[dict] = []
        changed_after_ranges: list[tuple[int, int]] = []
        untouched_after: list[Function] = []
        base = dict(
            repo=repo, project=repo.split("/")[-1], project_url=f"https://github.com/{repo}", commit_id=sha,
            filepath=path, language=lang, is_test_file=bool(is_test), cve_list=_j(cve_ids),
            commit_message=msg, commit_message_raw=msg_raw, commit_date=commit_date,
            parent_commit_id=parent_sha,
        )

        for k, (bf, af, pstatus) in enumerate(pairs):
            b_lines = [ln for ln in deleted if bf.start_line <= ln <= bf.end_line]
            a_lines = [ln for ln in added if af.start_line <= ln <= af.end_line]
            if not b_lines and not a_lines:
                untouched_after.append(af)
                continue
            changed_after_ranges.append((af.start_line, af.end_line))
            actions = diff_units(bf, af, set(b_lines), set(a_lines))
            counts = code_edit_counts(actions)
            sinks = sink_candidates(bf, af, actions, spec)
            pair_id = f"{repo}@{sha[:12]}:{path}:{bf.name}#{k}"
            mentioned_msg = mentions(bf.name, msg) or mentions(af.name, msg)
            mentioned_desc = mentions(bf.name, desc) or mentions(af.name, desc)
            actions_json = _j([a.to_dict() for a in actions if a.action != "unchanged"])
            common = dict(base, pair_id=pair_id, pair_status=pstatus, edit_actions=actions_json,
                          n_code_edits=counts["n_code_edits"], n_edits_delete=counts["delete"], n_edits_update=counts["update"],
                          n_edits_insert=counts["insert"], n_edits_move=counts["move"], n_comment_only_edits=counts["comment_only"],
                          mentioned_in_commit_msg=bool(mentioned_msg), mentioned_in_cve_desc=bool(mentioned_desc),
                          line_diff_source=ld.source)
            vrow = self._fn_row(bf, bsrc, boffs, spec, bdefs, bglob, b_lines, lang)
            vrow.update(common, is_vulnerable=1, neg_type=None, sink_candidates=_j([s.to_dict() for s in sinks]),
                        n_sink_candidates=len(sinks), counterpart_func_name=af.name)
            frow = self._fn_row(af, asrc, aoffs, spec, adefs, aglob, a_lines, lang)
            frow.update(common, is_vulnerable=0, neg_type="fixed", sink_candidates=None, n_sink_candidates=0,
                        counterpart_func_name=bf.name)
            rows.extend([vrow, frow])

        # functions removed / added by the fix (kept for completeness; filtered by default in stage 5)
        for k, bf in enumerate(removed):
            b_lines = [ln for ln in deleted if bf.start_line <= ln <= bf.end_line]
            if not b_lines:
                continue
            r = self._fn_row(bf, bsrc, boffs, spec, bdefs, bglob, b_lines, lang)
            r.update(base, pair_id=f"{repo}@{sha[:12]}:{path}:{bf.name}#rm{k}", pair_status="removed", is_vulnerable=1,
                     neg_type=None, edit_actions="[]", n_code_edits=0, n_edits_delete=0, n_edits_update=0, n_edits_insert=0,
                     n_edits_move=0, n_comment_only_edits=0, sink_candidates=None, n_sink_candidates=0,
                     mentioned_in_commit_msg=mentions(bf.name, msg), mentioned_in_cve_desc=mentions(bf.name, desc),
                     line_diff_source=ld.source, counterpart_func_name=None)
            rows.append(r)
        for k, af in enumerate(added_fns):
            a_lines = [ln for ln in added if af.start_line <= ln <= af.end_line]
            if not a_lines:
                continue
            changed_after_ranges.append((af.start_line, af.end_line))
            r = self._fn_row(af, asrc, aoffs, spec, adefs, aglob, a_lines, lang)
            r.update(base, pair_id=f"{repo}@{sha[:12]}:{path}:{af.name}#add{k}", pair_status="added", is_vulnerable=0,
                     neg_type="added_by_fix", edit_actions="[]", n_code_edits=0, n_edits_delete=0, n_edits_update=0,
                     n_edits_insert=0, n_edits_move=0, n_comment_only_edits=0, sink_candidates=None, n_sink_candidates=0,
                     mentioned_in_commit_msg=mentions(af.name, msg), mentioned_in_cve_desc=mentions(af.name, desc),
                     line_diff_source=ld.source, counterpart_func_name=None)
            rows.append(r)

        # untouched negatives (only when the file has at least one changed function)
        if changed_after_ranges and untouched_after and self.untouched_per_file > 0:
            def dist(fn: Function) -> int:
                return min(abs(fn.start_line - s) for s, _ in changed_after_ranges)
            untouched_after.sort(key=lambda fn: (dist(fn), fn.start_line))
            for k, af in enumerate(untouched_after[: self.untouched_per_file]):
                r = self._fn_row(af, asrc, aoffs, spec, adefs, aglob, [], lang)
                r.update(base, pair_id=f"{repo}@{sha[:12]}:{path}:{af.name}#u{k}", pair_status="untouched", is_vulnerable=0,
                         neg_type="untouched", edit_actions="[]", n_code_edits=0, n_edits_delete=0, n_edits_update=0,
                         n_edits_insert=0, n_edits_move=0, n_comment_only_edits=0, sink_candidates=None, n_sink_candidates=0,
                         mentioned_in_commit_msg=mentions(af.name, msg), mentioned_in_cve_desc=mentions(af.name, desc),
                         line_diff_source=ld.source, counterpart_func_name=None)
                rows.append(r)
        n_changed_in_file = sum(1 for r in rows if r["is_vulnerable"] == 1 and r["pair_status"] in ("paired", "renamed"))
        for r in rows:
            r["file_n_changed_funcs"] = n_changed_in_file
        return rows

    def _fn_row(self, fn: Function, src: bytes, offs: list[int], spec, defs, globs, lines: list[int], lang: str) -> dict:
        ctx = context_columns(src, fn, spec, defs, globs, self.ctx_max_chars, self.ctx_max_count)
        cl = changed_lines_for_fn(src, offs, fn, lines)
        cs = changed_statements_for_lines(src, offs, fn, lines)
        return {
            "func_name": fn.name, "func_signature": fn.signature, "qualified_name": fn.qualified_name,
            "func_body": fn.text, "func_start_line": fn.start_line, "func_end_line": fn.end_line,
            "func_byte_start": fn.start_byte, "func_byte_end": fn.end_byte, "n_lines": fn.n_lines,
            "n_statements": sum(1 for u in fn.units if u.is_code and u.kind != "signature"),
            "changed_lines": _j([[ln, t] for ln, t in cl]),
            "changed_statements": _j([[ln, t] for ln, t in cs]),
            "n_changed_lines": len(cl), "n_changed_statements": len(cs),
            "hash": body_hash(fn.text), "norm_hash": norm_hash(fn.text, lang),
            "callees": _j(ctx["callees"]), "types_used": _j(ctx["types_used"]), "macros_used": _j(ctx["macros_used"]),
            "globals_used": _j(ctx["globals_used"]), "same_file_callee_defs": _j(ctx["same_file_callee_defs"]),
        }


# ----------------------------------------------------------------------
def pair_functions(bfuncs: list[Function], afuncs: list[Function]):
    """Pair before/after functions: (qualified name, name, signature) -> unique name -> order within name
    -> body-similarity rename detection. Returns (pairs[(b, a, status)], removed[b], added[a])."""
    pairs: list[tuple[Function, Function, str]] = []
    ub = list(bfuncs)
    ua = list(afuncs)

    def key_full(fn):
        return (fn.qualified_name, fn.name, fn.signature)

    def match(keyf):
        nonlocal ub, ua
        bk: dict = {}
        for fn in ub:
            bk.setdefault(keyf(fn), []).append(fn)
        ak: dict = {}
        for fn in ua:
            ak.setdefault(keyf(fn), []).append(fn)
        matched_b, matched_a = set(), set()
        for k, bl in bk.items():
            al = ak.get(k)
            if not al:
                continue
            for b, a in zip(bl, al):      # same key: pair in document order
                pairs.append((b, a, "paired"))
                matched_b.add(id(b))
                matched_a.add(id(a))
        ub = [f for f in ub if id(f) not in matched_b]
        ua = [f for f in ua if id(f) not in matched_a]

    match(key_full)
    match(lambda fn: (fn.qualified_name, fn.name))
    match(lambda fn: fn.name)
    # rename detection by body similarity
    if ub and ua and len(ub) * len(ua) <= 2500:
        cands = []
        for b in ub:
            bk = [u.key for u in b.units]
            for a in ua:
                ak = [u.key for u in a.units]
                if min(len(bk), len(ak)) < 3:
                    continue
                r = difflib.SequenceMatcher(a=bk, b=ak, autojunk=False).ratio()
                if r >= 0.7:
                    cands.append((r, b, a))
        cands.sort(key=lambda t: -t[0])
        used_b, used_a = set(), set()
        for r, b, a in cands:
            if id(b) in used_b or id(a) in used_a:
                continue
            pairs.append((b, a, "renamed"))
            used_b.add(id(b))
            used_a.add(id(a))
        ub = [f for f in ub if id(f) not in used_b]
        ua = [f for f in ua if id(f) not in used_a]
    pairs.sort(key=lambda t: t[0].start_byte)
    return pairs, ub, ua


def _max_line_len(src: bytes) -> int:
    return max((len(ln) for ln in src.split(b"\n")), default=0)


def _ext(path: str) -> str:
    name = path.rsplit("/", 1)[-1]
    return "." + name.rsplit(".", 1)[-1] if "." in name else ""
