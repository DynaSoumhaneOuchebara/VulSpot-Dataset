#!/usr/bin/env python
"""Fully offline: additive fixes anchored by data flow instead of position."""
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
int probe(struct dev *d)
{
	int err;
	char *buf;

	buf = kzalloc(64, GFP_KERNEL);
	err = setup_irq(d);
	d->state = 1;
	mutex_lock(&d->lock);
	if (d->count > 4)
		return -EINVAL;
	kfree(d->cache);
	log_info(d);
	return 0;
}
"""

AFTER = b"""
int probe(struct dev *d)
{
	int err;
	char *buf;

	buf = kzalloc(64, GFP_KERNEL);
	err = setup_irq(d);
	if (err)
		return err;
	d->state = 1;
	mutex_lock(&d->lock);
	if (d->count > 4) {
		mutex_unlock(&d->lock);
		kfree(buf);
		return -EINVAL;
	}
	kfree(d->cache);
	d->cache = NULL;
	log_info(d);
	return 0;
}
"""

EXPECTED = {
    "status_def": "err = setup_irq(d);",       # unchecked call
    "release_acquire": "mutex_lock(&d->lock);", # missing unlock -> the lock (kfree(buf) is grouped with it)
    "init_use": "kfree(d->cache);",             # dangling pointer -> the free that left it dangling
}


def main() -> None:
    spec = get_spec("c")
    _, bfs = parse_file(BEFORE, "c")
    _, afs = parse_file(AFTER, "c")
    sinks = sink_candidates(bfs[0], afs[0], diff_units(bfs[0], afs[0]), spec)
    got = {s.anchor_rule: s.text for s in sinks if s.kind == "anchor_dataflow"}
    print("sinks:", [(s.kind, s.anchor_rule, s.text) for s in sinks])
    for rule, text in EXPECTED.items():
        assert got.get(rule) == text, f"{rule}: expected {text!r}, got {got.get(rule)!r}"
        print(f"OK  {rule:16s} -> {text}")
    assert not [s for s in sinks if s.kind in ("anchor_next", "anchor_prev")], "positional anchor left"


if __name__ == "__main__":
    main()
