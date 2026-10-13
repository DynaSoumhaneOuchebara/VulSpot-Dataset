"""GitHub REST + raw.githubusercontent.com client with on-disk caching."""
from __future__ import annotations

import json
import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from .http import HttpClient
from .io import atomic_write_bytes, read_json, write_json
from .refs import repo_key

log = logging.getLogger("github")

DONE_STATUSES = {"ok", "merge_commit", "too_many_files", "commit_not_found", "repo_missing",
                 "fork_only", "root_commit", "no_files"}


class GitHubClient:
    def __init__(self, cfg, token: str | None, raw_commits_dir: Path, repos_cache_dir: Path):
        g = cfg["github"]
        self.api = g["api_url"].rstrip("/")
        self.raw = g["raw_url"].rstrip("/")
        self.max_files = int(g["max_files_per_commit"])
        self.max_file_bytes = int(g["max_file_bytes"])
        self.fetch_contents = bool(g.get("fetch_file_contents", True))
        self.drop_merges = bool(g.get("drop_merge_commits", True))
        self.commits_dir = raw_commits_dir
        self.repos_dir = repos_cache_dir
        self.repos_dir.mkdir(parents=True, exist_ok=True)
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        else:
            log.warning("no GITHUB_TOKEN: 60 requests/hour. Set a token.")
        self.http = HttpClient(min_interval_s=float(g["min_interval_s"]), max_retries=int(g["max_retries"]), headers=headers)
        # raw.githubusercontent.com is not subject to the REST quota; light pacing only
        self.raw_http = HttpClient(min_interval_s=0.05, max_retries=5)
        self.pool = ThreadPoolExecutor(max_workers=4)

    # ---- repos -----------------------------------------------------------
    def repo_info(self, repo: str) -> dict | None:
        """Cached GET /repos/{repo}. Returns None if the repo does not exist."""
        path = self.repos_dir / f"{repo_key(repo)}.json"
        cached = read_json(path)
        if cached is not None:
            return None if cached.get("_missing") else cached
        r = self.http.get(f"{self.api}/repos/{repo}", allow_404=True)
        if r is None:
            write_json(path, {"_missing": True, "repo": repo})
            return None
        d = r.json()
        info = {
            "repo": repo,
            "full_name": d.get("full_name"),
            "fork": bool(d.get("fork")),
            "parent": (d.get("parent") or {}).get("full_name"),
            "source": (d.get("source") or {}).get("full_name"),
            "default_branch": d.get("default_branch"),
            "language": d.get("language"),
            "html_url": d.get("html_url"),
            "archived": d.get("archived"),
            "fetched_at": datetime.now(timezone.utc).isoformat(),
        }
        write_json(path, info)
        return info

    def commit_exists(self, repo: str, sha: str) -> bool:
        r = self.http.get(f"{self.api}/repos/{repo}/commits/{sha}", allow_404=True)
        if r is None:
            return False
        # GitHub returns 422 for malformed sha; treat any non-200 as missing
        return r.status_code == 200

    def resolve_repo(self, repo: str, sha: str) -> tuple[str | None, str]:
        """Return (canonical_repo, status). Forks are mapped to the parent when the sha exists there."""
        info = self.repo_info(repo)
        if info is None:
            return None, "repo_missing"
        canonical = info.get("full_name") or repo
        if info.get("fork") and info.get("parent"):
            parent = info["parent"]
            if self.commit_exists(parent, sha):
                return parent, "ok"
            # try the ultimate source as well (fork of a fork)
            src = info.get("source")
            if src and src != parent and self.commit_exists(src, sha):
                return src, "ok"
            return canonical, "fork_only"
        return canonical, "ok"

    # ---- commits ---------------------------------------------------------
    def commit_dir(self, repo: str, sha: str) -> Path:
        return self.commits_dir / repo_key(repo) / sha

    def fetch_commit_json(self, repo: str, sha: str) -> dict | None:
        """GET /repos/{repo}/commits/{sha}, paginating `files` (300/page, max 3000)."""
        r = self.http.get(f"{self.api}/repos/{repo}/commits/{sha}", params={"per_page": 300}, allow_404=True)
        if r is None:
            return None
        data = r.json()
        files = list(data.get("files") or [])
        page = 2
        while len(files) >= 300 * (page - 1) and page <= 10:
            r2 = self.http.get(f"{self.api}/repos/{repo}/commits/{sha}", params={"per_page": 300, "page": page}, allow_404=True)
            if r2 is None:
                break
            more = r2.json().get("files") or []
            if not more:
                break
            files.extend(more)
            page += 1
        data["files"] = files
        return data

    def fetch_commit_diff(self, repo: str, sha: str) -> str | None:
        prev = self.http.sess.headers.get("Accept")
        try:
            self.http.sess.headers["Accept"] = "application/vnd.github.diff"
            r = self.http.get(f"{self.api}/repos/{repo}/commits/{sha}", allow_404=True)
        finally:
            if prev is None:
                self.http.sess.headers.pop("Accept", None)
            else:
                self.http.sess.headers["Accept"] = prev
        return r.text if r is not None else None

    def fetch_raw_file(self, repo: str, ref: str, path: str) -> bytes | None:
        url = f"{self.raw}/{repo}/{ref}/{path}"
        r = self.raw_http.get(url, allow_404=True)
        if r is None:
            return None
        if len(r.content) > self.max_file_bytes:
            return None
        return r.content

    # ---- orchestration ---------------------------------------------------
    def fetch_commit(self, repo: str, sha: str, cve_ids: list[str], code_extensions: set[str]) -> dict:
        """Fetch everything for one commit; returns the meta record written to meta.json."""
        canonical, status = self.resolve_repo(repo, sha)
        meta = {"repo": repo, "canonical_repo": canonical, "sha": sha, "cve_ids": cve_ids,
                "status": status, "fetched_at": datetime.now(timezone.utc).isoformat(), "errors": []}
        out_dir = self.commit_dir(canonical or repo, sha)
        if status != "ok":
            write_json(out_dir / "meta.json", meta, indent=2)
            return meta

        data = self.fetch_commit_json(canonical, sha)
        if data is None:
            meta["status"] = "commit_not_found"
            write_json(out_dir / "meta.json", meta, indent=2)
            return meta
        full_sha = data.get("sha", sha)
        meta["full_sha"] = full_sha
        parents = [p["sha"] for p in data.get("parents") or []]
        meta["parents"] = parents
        meta["commit_date"] = ((data.get("commit") or {}).get("committer") or {}).get("date")
        meta["author_date"] = ((data.get("commit") or {}).get("author") or {}).get("date")
        meta["n_files_api"] = len(data.get("files") or [])
        write_json(out_dir / "commit.json", data)

        if len(parents) == 0:
            meta["status"] = "root_commit"
        elif len(parents) > 1 and self.drop_merges:
            meta["status"] = "merge_commit"
        elif not data.get("files"):
            meta["status"] = "no_files"
        elif len(data["files"]) > self.max_files * 10:
            meta["status"] = "too_many_files"
        if meta["status"] != "ok":
            write_json(out_dir / "meta.json", meta, indent=2)
            return meta

        diff = self.fetch_commit_diff(canonical, sha)
        if diff is not None:
            atomic_write_bytes(out_dir / "commit.diff", diff.encode("utf-8", errors="replace"))
        else:
            meta["errors"].append("diff_unavailable")

        parent = parents[0]
        fetched = []
        if self.fetch_contents:
            tasks = []
            for f in data["files"]:
                path = f.get("filename") or ""
                if not path or ".." in path.split("/"):
                    continue
                ext = _ext(path)
                if ext not in code_extensions:
                    continue
                st = f.get("status")
                before_path = f.get("previous_filename") or path
                if st != "added":
                    tasks.append(("before", before_path, parent))
                if st != "removed":
                    tasks.append(("after", path, full_sha))
            # fetch in parallel per commit (raw host, no REST quota)
            results = list(self.pool.map(lambda t: (t, self.fetch_raw_file(canonical, t[2], t[1])), tasks))
            for (side, path, ref), content in results:
                if content is None:
                    meta["errors"].append(f"{side}:{path}:missing_or_too_large")
                    continue
                atomic_write_bytes(out_dir / side / path, content)
                fetched.append(f"{side}/{path}")
        meta["files_fetched"] = fetched
        write_json(out_dir / "meta.json", meta, indent=2)
        return meta


def _ext(path: str) -> str:
    name = path.rsplit("/", 1)[-1]
    if "." not in name:
        return ""
    return "." + name.rsplit(".", 1)[-1]


def load_meta(commit_dir: Path) -> dict | None:
    p = commit_dir / "meta.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
