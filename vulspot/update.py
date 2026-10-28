"""Six-month dataset update: from the last covered day through the scheduled day.

The NVD cache is resumable. Publication windows that already exist are skipped,
and the one window that was truncated at the previous cutoff is fetched again
so the days after that cutoff are not left out. Commit fetches skip any
meta.json that already has a final status. This module only decides the
window and records the version; the shell jobs run the stages.
"""
from __future__ import annotations

import argparse
import calendar
import re
from datetime import date, datetime, time, timezone
from pathlib import Path

from .config import load_config
from .io import read_json, write_json
from .nvd import parse_cutoff, windows

_PUB_WINDOW = re.compile(r"pub_(\d{4}-\d{2}-\d{2})_(\d{4}-\d{2}-\d{2})\.json\.gz$")
PLAN_NAME = "update_plan.json"
VERSION_NAME = "version.json"


def add_months(day: date, months: int) -> date:
    """Same calendar day, `months` later. A day past the target month's end is clamped."""
    month_index = day.month - 1 + months
    year = day.year + month_index // 12
    month = month_index % 12 + 1
    last = calendar.monthrange(year, month)[1]
    return date(year, month, min(day.day, last))


def parse_day(value: str) -> date:
    return datetime.strptime(value, "%Y-%m-%d").date()


def covered_through(completed_windows: list[str]) -> date | None:
    """Latest publication-window end date stored in the NVD state file."""
    ends = []
    for name in completed_windows:
        match = _PUB_WINDOW.search(name)
        if match:
            ends.append(parse_day(match.group(2)))
    return max(ends) if ends else None


def windows_to_fetch(completed: list[str], start: datetime, cutoff: datetime, window_days: int) -> list[str]:
    """Publication windows a forward cutoff still has to download."""
    done = set(completed)
    return [w.filename for w in windows(start, cutoff, window_days, "pub") if w.filename not in done]


def begin_stamp(day: date, hour_utc: int) -> str:
    stamp = datetime.combine(day, time(hour=hour_utc), tzinfo=timezone.utc)
    return stamp.strftime("%Y-%m-%dT%H:%M:%S")


def version_path(out_dir: Path) -> Path:
    return out_dir / VERSION_NAME


def plan_path(logs_dir: Path) -> Path:
    return logs_dir / PLAN_NAME


def load_version(out_dir: Path) -> dict | None:
    data = read_json(version_path(out_dir))
    return data or None


def seed_version(out_dir: Path, nvd_state: dict, every_months: int) -> dict:
    """Record the dataset that is already on disk, without fetching anything."""
    path = version_path(out_dir)
    current = read_json(path)
    if current and current.get("covered_through"):
        return current
    covered = covered_through(nvd_state.get("completed_windows") or [])
    if covered is None:
        raise SystemExit(f"NVD state has no publication windows; cannot seed {path}")
    record = {
        "covered_through": covered.isoformat(),
        "previous_covered_through": None,
        "last_sync": nvd_state.get("last_sync"),
        "every_months": every_months,
        "next_update": add_months(covered, every_months).isoformat(),
        "seeded_from": "nvd publication windows",
    }
    write_json(path, record, indent=2)
    return record


def resolve_previous(out_dir: Path, nvd_state: dict) -> date:
    current = load_version(out_dir)
    if current and current.get("covered_through"):
        return parse_day(current["covered_through"])
    covered = covered_through(nvd_state.get("completed_windows") or [])
    if covered is None:
        raise SystemExit("no version.json and no NVD publication windows")
    return covered


def write_plan(logs_dir: Path, previous: date, cutoff_day: date, every_months: int) -> dict:
    plan = {
        "previous_covered_through": previous.isoformat(),
        "cutoff_day": cutoff_day.isoformat(),
        "every_months": every_months,
        "next_update": add_months(cutoff_day, every_months).isoformat(),
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    write_json(plan_path(logs_dir), plan, indent=2)
    return plan


def load_plan(logs_dir: Path) -> dict:
    plan = read_json(plan_path(logs_dir))
    if not plan or not plan.get("cutoff_day"):
        raise SystemExit(f"missing {plan_path(logs_dir)}; the nvd stage writes it")
    return plan


def record_version(out_dir: Path, logs_dir: Path, nvd_state: dict) -> dict:
    plan = load_plan(logs_dir)
    record = {
        "covered_through": plan["cutoff_day"],
        "previous_covered_through": plan["previous_covered_through"],
        "built_at": datetime.now(timezone.utc).isoformat(),
        "last_sync": nvd_state.get("last_sync"),
        "every_months": plan["every_months"],
        "next_update": plan["next_update"],
    }
    write_json(version_path(out_dir), record, indent=2)
    return record


def _state(cfg) -> dict:
    return read_json(cfg.paths.raw_nvd / "state.json", default={}) or {}


def _months(cfg) -> int:
    return int(cfg["update"]["every_months"])


def _hour(cfg) -> int:
    return int(cfg["update"]["start_hour_utc"])


def main() -> None:
    ap = argparse.ArgumentParser(description="Plan or record a VulSpot dataset update")
    ap.add_argument("command", choices=("seed", "plan", "cutoff-day", "next-begin", "record"))
    ap.add_argument("--config", default=None)
    ap.add_argument("--cutoff-day", default=None, help="YYYY-MM-DD the update runs through")
    args = ap.parse_args()
    cfg = load_config(args.config)
    state = _state(cfg)
    months = _months(cfg)

    if args.command == "seed":
        record = seed_version(cfg.paths.out, state, months)
        print(record["covered_through"])
        return

    if args.command == "plan":
        previous = resolve_previous(cfg.paths.out, state)
        cutoff_day = parse_day(args.cutoff_day) if args.cutoff_day else datetime.now(timezone.utc).date()
        if cutoff_day < previous:
            raise SystemExit(f"cutoff {cutoff_day} is before covered_through {previous}")
        plan = write_plan(cfg.paths.logs, previous, cutoff_day, months)
        print(plan["cutoff_day"])
        return

    if args.command == "cutoff-day":
        print(load_plan(cfg.paths.logs)["cutoff_day"])
        return

    if args.command == "next-begin":
        if args.cutoff_day:
            day = add_months(parse_day(args.cutoff_day), months)
        else:
            version = load_version(cfg.paths.out)
            if not version or not version.get("next_update"):
                raise SystemExit("no next_update in version.json; run seed first")
            day = parse_day(version["next_update"])
        print(begin_stamp(day, _hour(cfg)))
        return

    record_version(cfg.paths.out, cfg.paths.logs, state)
    print(load_version(cfg.paths.out)["covered_through"])


if __name__ == "__main__":
    main()
