#!/usr/bin/env python
"""Fully offline: fixes that only reorder statements, anchored on the move."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vulspot.astdiff import diff_units
from vulspot.langs import get_spec
from vulspot.sinks import sink_candidates
from vulspot.tsparse import parse_file

# release moved after the last use (use-after-free)
UAF_BEFORE = b"""
void gc_key(struct key *key)
{
	key_user_put(key->user);
	security_key_free(key);
	key_log(key->user, key->serial);
	kfree(key->description);
}
"""
UAF_AFTER = b"""
void gc_key(struct key *key)
{
	security_key_free(key);
	key_log(key->user, key->serial);
	key_user_put(key->user);
	kfree(key->description);
}
"""

# clamp moved before the copy that used the length
CLAMP_BEFORE = b"""
int get_stats(char *optval, int len)
{
	struct stats sas;
	fill_stats(&sas);
	if (copy_to_user(optval, &sas, len))
		return -EFAULT;
	len = min_t(size_t, len, sizeof(sas));
	return 0;
}
"""
CLAMP_AFTER = b"""
int get_stats(char *optval, int len)
{
	struct stats sas;
	len = min_t(size_t, len, sizeof(sas));
	fill_stats(&sas);
	if (copy_to_user(optval, &sas, len))
		return -EFAULT;
	return 0;
}
"""

# a move next to a real edit: the edit is marked, the move is not
MIXED_BEFORE = b"""
int probe(struct dev *d)
{
	int err = setup_irq(d);
	d->state = 1;
	log_info(d->name, d->state);
	return 0;
}
"""
MIXED_AFTER = b"""
int probe(struct dev *d)
{
	int err = setup_irq(d);
	log_info(d->name, d->state);
	d->state = 2;
	d->state = 1;
	return 0;
}
"""


def sinks_of(before: bytes, after: bytes):
    spec = get_spec("c")
    _, bfs = parse_file(before, "c")
    _, afs = parse_file(after, "c")
    sinks = sink_candidates(bfs[0], afs[0], diff_units(bfs[0], afs[0]), spec)
    print("sinks:", [(s.kind, s.anchor_rule, s.text) for s in sinks])
    return sinks


def main() -> None:
    got = {s.anchor_rule: s.text for s in sinks_of(UAF_BEFORE, UAF_AFTER)}
    assert got.get("move_early") == "key_user_put(key->user);", got
    print("OK  move_early   -> key_user_put(key->user);")

    got = {s.anchor_rule: s.text for s in sinks_of(CLAMP_BEFORE, CLAMP_AFTER)}
    assert got.get("move_crossed", "").startswith("if (copy_to_user(optval, &sas, len))"), got
    print("OK  move_crossed -> if (copy_to_user(optval, &sas, len))")

    rules = {s.anchor_rule for s in sinks_of(MIXED_BEFORE, MIXED_AFTER)}
    assert not rules & {"move_early", "move_crossed"}, rules
    print("OK  mixed fix    -> no move anchor")


if __name__ == "__main__":
    main()
