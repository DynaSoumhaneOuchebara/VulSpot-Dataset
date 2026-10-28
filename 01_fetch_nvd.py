#!/usr/bin/env python
"""Stage 1: fetch all NVD CVEs (API 2.0) into data/raw/nvd, resumable and incremental.

First run: windowed full fetch by publication date from nvd.start_date to the cutoff.
Later runs: lastModified sync since the previous run (new + updated CVEs).

    python 01_fetch_nvd.py                # full fetch (resume) then incremental if already complete
    python 01_fetch_nvd.py --incremental  # only lastModified sync
    python 01_fetch_nvd.py --cutoff 2026-10-09   # that whole UTC day is included

Requires NVD_API_KEY (optional but strongly recommended; 10x rate limit).
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from vulspot.config import env_secret, load_config
from vulspot.log import get_logger
from vulspot.nvd import NvdClient, inclusive_day, parse_cutoff


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=None)
    ap.add_argument("--incremental", action="store_true", help="only run lastModified sync")
    ap.add_argument("--cutoff", default=None, help="YYYY-MM-DD, inclusive (default: config or now)")
    args = ap.parse_args()

    cfg = load_config(args.config)
    log = get_logger("01_fetch_nvd", cfg.paths.logs)
    client = NvdClient(cfg, env_secret("NVD_API_KEY"), cfg.paths.raw_nvd)

    start = datetime.strptime(cfg["nvd"]["start_date"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
    cutoff_s = args.cutoff or cfg["nvd"].get("cutoff_date")
    if cutoff_s:
        cutoff = parse_cutoff(str(cutoff_s))
    else:
        cutoff = datetime.now(timezone.utc)
    log.info("NVD fetch: start=%s through=%s", start.date(), inclusive_day(cutoff).date())

    state = client.load_state()
    if args.incremental or state.get("last_sync"):
        if not args.incremental:
            # make sure all pub windows up to cutoff exist (e.g. cutoff moved forward), then sync
            client.full_fetch(start, cutoff)
        client.incremental_sync()
    else:
        client.full_fetch(start, cutoff)

    n = sum(1 for _ in client.iter_all())
    log.info("done. %d unique CVE records cached in %s", n, cfg.paths.raw_nvd)


if __name__ == "__main__":
    main()
