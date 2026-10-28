#!/usr/bin/env python
"""The six-month update window starts the day after the previous cutoff and includes the scheduled day."""
from __future__ import annotations

import json
import sys
from datetime import date, datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vulspot.nvd import inclusive_day, parse_cutoff, windows
from vulspot.update import (
    add_months,
    begin_stamp,
    covered_through,
    load_plan,
    record_version,
    seed_version,
    windows_to_fetch,
    write_plan,
)


def test_six_months_from_the_current_cutoff():
    assert add_months(date(2026, 10, 12), 6) == date(2027, 4, 12)
    assert add_months(date(2027, 4, 12), 6) == date(2027, 10, 12)
    assert add_months(date(2026, 8, 31), 6) == date(2027, 2, 28)
    assert begin_stamp(date(2027, 4, 12), 6) == "2027-04-12T06:00:00"


def test_a_cutoff_day_includes_that_whole_day():
    cutoff = parse_cutoff("2026-10-12")
    assert cutoff == datetime(2026, 10, 13, tzinfo=timezone.utc)
    assert inclusive_day(cutoff).date() == date(2026, 10, 12)


def test_forward_cutoff_refetches_only_the_truncated_window():
    """The cached window ends 2026-10-12. Extending the cutoff must start there, not earlier."""
    completed = [
        "pub_2026-06-10_2026-10-08.json.gz",
        "pub_2026-10-08_2026-10-12.json.gz",
    ]
    start = datetime(2026, 6, 10, tzinfo=timezone.utc)
    cutoff = parse_cutoff("2027-04-12")
    needed = windows_to_fetch(completed, start, cutoff, 120)
    assert needed == [
        "pub_2026-10-08_2027-02-05.json.gz",
        "pub_2027-02-05_2027-04-13.json.gz",
    ]
    fresh = [w for w in windows(start, cutoff, 120, "pub") if w.filename not in completed]
    assert fresh[0].start == datetime(2026, 10, 8, tzinfo=timezone.utc)
    assert fresh[0].end > datetime(2026, 10, 12, tzinfo=timezone.utc)
    assert fresh[-1].end == datetime(2027, 4, 13, tzinfo=timezone.utc)
    assert covered_through(completed) == date(2026, 10, 12)


def test_seed_and_record_round_trip(tmp_path=None):
    import tempfile
    base = Path(tmp_path) if tmp_path else Path(tempfile.mkdtemp())
    out = base / "out"
    logs = base / "logs"
    out.mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)
    state = {
        "completed_windows": ["pub_2026-10-08_2026-10-12.json.gz"],
        "last_sync": "2026-10-12T10:53:54+00:00",
    }
    seeded = seed_version(out, state, 6)
    assert seeded["covered_through"] == "2026-10-12"
    assert seeded["next_update"] == "2027-04-12"
    again = seed_version(out, state, 6)
    assert again["covered_through"] == "2026-10-12"
    plan = write_plan(logs, date(2026, 10, 12), date(2027, 4, 12), 6)
    assert plan["previous_covered_through"] == "2026-10-12"
    assert load_plan(logs)["cutoff_day"] == "2027-04-12"
    recorded = record_version(out, logs, {"last_sync": "2027-04-12T06:05:00+00:00"})
    assert recorded["covered_through"] == "2027-04-12"
    assert recorded["previous_covered_through"] == "2026-10-12"
    assert recorded["next_update"] == "2027-10-12"
    text = json.loads((out / "version.json").read_text())
    assert text["covered_through"] == "2027-04-12"


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok", name)
