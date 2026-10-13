"""Parse NVD reference URLs into (repo, sha) commit pointers."""
from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from urllib.parse import urlparse, parse_qs

SHA_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")

# github.com/<owner>/<repo>/commit/<sha>
# github.com/<owner>/<repo>/commits/<sha>
# github.com/<owner>/<repo>/pull/<n>/commits/<sha>
_GH_COMMIT = re.compile(
    r"^/(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+?)(?:\.git)?"
    r"/(?:commit|commits|pull/\d+/commits)/(?P<sha>[0-9a-fA-F]{7,40})(?:\.(?:patch|diff))?/?$"
)

# kernel.org cgit: /pub/scm/linux/kernel/git/<tree>/<repo>.git/commit/?id=<sha>  (also /commit/<path>?id=)
# also https://git.kernel.org/linus/<sha>  and  https://git.kernel.org/stable/c/<sha>
_KORG_SHORT = re.compile(r"^/(?:linus|stable/c|torvalds/c|stable/linux/c)/(?P<sha>[0-9a-fA-F]{7,40})/?$")
_KORG_STABLE_TREE = re.compile(r"/stable/linux(?:-stable)?\.git/")


@dataclass
class CommitRef:
    host: str
    repo: str | None       # "owner/name" on GitHub, or "torvalds/linux" for kernel.org
    sha: str | None
    url: str
    kind: str              # "github" | "kernel.org" | "other"
    note: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def parse_reference(url: str, github_hosts: set[str], kernel_repo: str) -> CommitRef:
    try:
        u = urlparse(url.strip())
    except ValueError:
        return CommitRef("", None, None, url, "other", "unparseable")
    host = (u.hostname or "").lower()
    path = u.path or ""

    if host in github_hosts:
        m = _GH_COMMIT.match(path)
        if m:
            return CommitRef(host, f"{m['owner']}/{m['repo']}", m["sha"].lower(), url, "github")
        return CommitRef(host, None, None, url, "other", "github-non-commit")

    if host == "git.kernel.org":
        q = parse_qs(u.query)
        sha = None
        if "id" in q and q["id"] and SHA_RE.match(q["id"][0]):
            sha = q["id"][0].lower()
        else:
            m = _KORG_SHORT.match(path)
            if m:
                sha = m["sha"].lower()
            else:
                m2 = re.search(r"/commit/(?:[^?]*?/)?([0-9a-fA-F]{7,40})/?$", path)
                if m2:
                    sha = m2.group(1).lower()
        if sha:
            note = "stable-tree" if _KORG_STABLE_TREE.search(path) else ""
            return CommitRef(host, kernel_repo, sha, url, "kernel.org", note)
        return CommitRef(host, None, None, url, "other", "kernel.org-non-commit")

    return CommitRef(host, None, None, url, "other")


def repo_key(repo: str) -> str:
    """Filesystem-safe key for owner/repo."""
    return repo.replace("/", "__")
