"""HTTP session with retries, pacing and rate-limit awareness."""
from __future__ import annotations

import logging
import random
import time
from typing import Any

import requests

log = logging.getLogger("http")


class RateLimited(Exception):
    pass


class HttpClient:
    def __init__(self, min_interval_s: float = 0.0, max_retries: int = 8,
                 headers: dict[str, str] | None = None, timeout: int = 60):
        self.sess = requests.Session()
        self.sess.headers.update({"User-Agent": "VulSpot-dataset-builder/0.1"})
        if headers:
            self.sess.headers.update(headers)
        self.min_interval_s = min_interval_s
        self.max_retries = max_retries
        self.timeout = timeout
        self._last = 0.0

    def _pace(self) -> None:
        wait = self.min_interval_s - (time.monotonic() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()

    def get(self, url: str, params: dict[str, Any] | None = None,
            ok_statuses: tuple[int, ...] = (200,), allow_404: bool = False) -> requests.Response | None:
        """GET with exponential backoff. Returns None on 404 when allow_404."""
        backoff = 2.0
        for attempt in range(self.max_retries):
            self._pace()
            try:
                r = self.sess.get(url, params=params, timeout=self.timeout)
            except requests.RequestException as e:
                log.warning("request error %s (%s), retry %d", url, e, attempt + 1)
                time.sleep(backoff + random.random())
                backoff = min(backoff * 2, 120)
                continue
            if r.status_code in ok_statuses:
                return r
            if r.status_code == 404 and allow_404:
                return None
            if r.status_code in (403, 429):
                # GitHub primary/secondary rate limits or NVD throttling
                reset = r.headers.get("X-RateLimit-Reset")
                remaining = r.headers.get("X-RateLimit-Remaining")
                retry_after = r.headers.get("Retry-After")
                if retry_after:
                    sleep = float(retry_after) + 1
                elif reset and remaining == "0":
                    sleep = max(float(reset) - time.time(), 0) + 2
                else:
                    sleep = backoff + random.random() * 3
                sleep = min(sleep, 3700)
                log.warning("rate limited %s (%d). sleeping %.0fs", url, r.status_code, sleep)
                time.sleep(sleep)
                backoff = min(backoff * 2, 300)
                continue
            if 500 <= r.status_code < 600:
                log.warning("server error %d for %s, retry %d", r.status_code, url, attempt + 1)
                time.sleep(backoff + random.random())
                backoff = min(backoff * 2, 120)
                continue
            # other client errors: give up
            log.error("HTTP %d for %s: %s", r.status_code, url, r.text[:200])
            return None
        log.error("giving up on %s after %d attempts", url, self.max_retries)
        return None
