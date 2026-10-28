"""NVD CVE API 2.0 client: windowed full fetch + lastModified incremental sync."""
from __future__ import annotations

import gzip
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

from .http import HttpClient
from .io import read_json, write_json

log = logging.getLogger("nvd")

ISO = "%Y-%m-%dT%H:%M:%S.000"


def _fmt(dt: datetime) -> str:
    return dt.strftime(ISO)


@dataclass
class Window:
    start: datetime
    end: datetime
    kind: str  # "pub" or "mod"

    @property
    def filename(self) -> str:
        return f"{self.kind}_{self.start:%Y-%m-%d}_{self.end:%Y-%m-%d}.json.gz"


def parse_cutoff(value: str) -> datetime:
    """Cutoff for an NVD window.

    A calendar day (`YYYY-MM-DD`) includes that whole UTC day: the returned
    instant is the next midnight, and window ends are exclusive. A full
    timestamp is used as given.
    """
    text = value.strip()
    if len(text) == 10:
        day = datetime.strptime(text, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        return day + timedelta(days=1)
    dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def inclusive_day(cutoff: datetime) -> datetime:
    """Last instant the cutoff covers, for logs. Midnight means the previous day."""
    if (cutoff.hour, cutoff.minute, cutoff.second, cutoff.microsecond) == (0, 0, 0, 0):
        return cutoff - timedelta(days=1)
    return cutoff


def windows(start: datetime, end: datetime, days: int, kind: str) -> Iterator[Window]:
    cur = start
    while cur < end:
        nxt = min(cur + timedelta(days=days), end)
        yield Window(cur, nxt, kind)
        cur = nxt


class NvdClient:
    def __init__(self, cfg, api_key: str | None, raw_dir: Path):
        n = cfg["nvd"]
        self.base_url = n["base_url"]
        self.per_page = int(n["results_per_page"])
        self.window_days = int(n["window_days"])
        self.raw_dir = raw_dir
        self.state_path = raw_dir / "state.json"
        headers = {"apiKey": api_key} if api_key else {}
        interval = float(n["sleep_with_key"] if api_key else n["sleep_without_key"])
        self.http = HttpClient(min_interval_s=interval, max_retries=int(n["max_retries"]),
                               headers=headers, timeout=120)
        if not api_key:
            log.warning("no NVD_API_KEY: throttled to 5 requests / 30 s. Expect ~6 h for a full fetch.")

    # ---- state -----------------------------------------------------------
    def load_state(self) -> dict:
        return read_json(self.state_path, default={"completed_windows": [], "last_sync": None})

    def save_state(self, st: dict) -> None:
        write_json(self.state_path, st, indent=2)

    # ---- fetching --------------------------------------------------------
    def _fetch_window(self, w: Window) -> list[dict]:
        if w.kind == "pub":
            params = {"pubStartDate": _fmt(w.start), "pubEndDate": _fmt(w.end)}
        else:
            params = {"lastModStartDate": _fmt(w.start), "lastModEndDate": _fmt(w.end)}
        params["resultsPerPage"] = self.per_page
        out: list[dict] = []
        start_index = 0
        total = None
        while True:
            params["startIndex"] = start_index
            r = self.http.get(self.base_url, params=params)
            if r is None:
                raise RuntimeError(f"NVD request failed for window {w.filename} @ {start_index}")
            try:
                data = r.json()
            except json.JSONDecodeError as e:
                raise RuntimeError(f"NVD returned non-JSON for {w.filename}: {r.text[:200]}") from e
            vulns = data.get("vulnerabilities", [])
            out.extend(v["cve"] for v in vulns if "cve" in v)
            total = data.get("totalResults", 0)
            start_index += data.get("resultsPerPage", self.per_page)
            if start_index >= total or not vulns:
                break
        log.info("window %s: %d CVEs", w.filename, len(out))
        return out

    def _save_window(self, w: Window, cves: list[dict]) -> None:
        path = self.raw_dir / w.filename
        tmp = path.with_suffix(".tmp")
        with gzip.open(tmp, "wt", encoding="utf-8") as f:
            json.dump({"window": {"kind": w.kind, "start": _fmt(w.start), "end": _fmt(w.end)},
                       "fetched_at": datetime.now(timezone.utc).isoformat(),
                       "cves": cves}, f)
        tmp.replace(path)

    def full_fetch(self, start: datetime, cutoff: datetime) -> None:
        st = self.load_state()
        done = set(st["completed_windows"])
        run_started = datetime.now(timezone.utc)
        for w in windows(start, cutoff, self.window_days, "pub"):
            if w.filename in done and (self.raw_dir / w.filename).exists():
                continue
            cves = self._fetch_window(w)
            self._save_window(w, cves)
            done.add(w.filename)
            st["completed_windows"] = sorted(done)
            self.save_state(st)
        if st.get("last_sync") is None:
            st["last_sync"] = run_started.isoformat()
            self.save_state(st)

    def incremental_sync(self, now: datetime | None = None) -> None:
        st = self.load_state()
        if not st.get("last_sync"):
            log.info("no previous sync; nothing incremental to do")
            return
        now = now or datetime.now(timezone.utc)
        last = datetime.fromisoformat(st["last_sync"])
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        # small overlap to be safe
        start = last - timedelta(hours=2)
        run_started = datetime.now(timezone.utc)
        for w in windows(start, now, self.window_days, "mod"):
            cves = self._fetch_window(w)
            # tag so that stage 2 knows these are updates
            self._save_window(Window(w.start, w.end, "mod"), cves)
        st["last_sync"] = run_started.isoformat()
        self.save_state(st)

    # ---- reading ---------------------------------------------------------
    def iter_all(self) -> Iterator[dict]:
        """Yield every CVE record, latest lastModified wins across windows."""
        latest: dict[str, dict] = {}
        files = sorted(self.raw_dir.glob("pub_*.json.gz")) + sorted(self.raw_dir.glob("mod_*.json.gz"))
        for p in files:
            with gzip.open(p, "rt", encoding="utf-8") as f:
                blob = json.load(f)
            for cve in blob["cves"]:
                cid = cve["id"]
                prev = latest.get(cid)
                if prev is None or cve.get("lastModified", "") >= prev.get("lastModified", ""):
                    latest[cid] = cve
        yield from latest.values()
