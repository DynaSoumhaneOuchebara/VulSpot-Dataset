#!/usr/bin/env python
"""Fully offline: additive bounds-check fix must produce a guard-anchor sink candidate."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vulspot.astdiff import diff_units
from vulspot.langs import get_spec
from vulspot.sinks import sink_candidates
from vulspot.tsparse import parse_file

BEFORE = b"""
int register_mac(struct table *table, u64 mac)
{
	int i;
	int free = -1;
	int err = 0;

	for (i = 0; i < MAX; i++) {
		if (table->refs[i] && table->entries[i] == mac) {
			table->refs[i]++;
			*index = i;
			err = 0;
			goto out;
		}
		if (free < 0 && table->refs[i] == 0)
			free = i;
	}

	table->entries[free] = mac;
	table->refs[free] = 1;
	*index = free;
out:
	return err;
}
"""

AFTER = b"""
int register_mac(struct table *table, u64 mac)
{
	int i;
	int free = -1;
	int err = 0;

	for (i = 0; i < MAX; i++) {
		if (table->refs[i] && table->entries[i] == mac) {
			table->refs[i]++;
			*index = i;
			err = 0;
			goto out;
		}
		if (free < 0 && table->refs[i] == 0)
			free = i;
	}

	if (free < 0) {
		err = -ENOMEM;
		goto out;
	}

	table->entries[free] = mac;
	table->refs[free] = 1;
	*index = free;
out:
	return err;
}
"""


def main() -> None:
    spec = get_spec("c")
    _, bfs = parse_file(BEFORE, "c")
    _, afs = parse_file(AFTER, "c")
    bf = next(f for f in bfs if f.name == "register_mac")
    af = next(f for f in afs if f.name == "register_mac")
    deleted = set()  # additive fix
    added = set(range(af.start_line, af.end_line + 1)) - set(range(bf.start_line, bf.end_line + 1))
    # line numbers differ because of inserted block; use AST-only alignment
    actions = diff_units(bf, af)
    sinks = sink_candidates(bf, af, actions, spec)
    print("units before:", [(u.kind, u.start_line, u.text[:60]) for u in bf.units if u.is_code])
    print("actions:", [(a.action, a.before_text, a.after_text) for a in actions if a.action != "unchanged"])
    print("sinks:", [(s.kind, s.abs_line, s.text, s.guard_ident) for s in sinks])
    guard = [s for s in sinks if s.kind == "anchor_guarded_use"]
    assert any(a.action == "insert" for a in actions), "expected an insert for the new if (free < 0)"
    assert guard, f"expected guard-anchor sink, got {sinks}"
    assert "free" in guard[0].text, guard[0]
    assert guard[0].guard_ident == "free", guard[0]
    print("OK  synthetic mlx4-style guard anchor")


if __name__ == "__main__":
    main()
