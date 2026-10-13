"""Hashing and near-duplicate (clone) detection.

  hash       : md5 over the function body with every line stripped and blank lines removed
               (SecVulEval-style exact dedup key)
  norm_hash  : md5 over the token stream with comments removed and all whitespace dropped
  clone_group_id : connected components of MinHash-LSH candidate pairs (Jaccard >= threshold on k-shingles)
"""
from __future__ import annotations

import hashlib
import re
from collections import defaultdict

_C_COMMENT = re.compile(r"/\*.*?\*/|//[^\n]*", re.S)
_HASH_COMMENT = re.compile(r"(?m)(?<![\w\"'])#(?!(?:include|define|if|ifdef|ifndef|else|elif|endif|pragma|undef|error|warning|line)\b)[^\n]*")
_TRIPLE = re.compile(r'"""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\'')
_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|\d+(?:\.\d+)?|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|\S")

HASH_COMMENT_LANGS = {"python", "ruby", "bash", "perl", "r", "elixir", "yaml", "toml", "makefile", "shell", "powershell", "nim", "julia"}
C_COMMENT_LANGS_ONLY = {"c", "cpp", "java", "javascript", "typescript", "tsx", "go", "rust", "csharp", "kotlin", "swift", "scala", "dart", "objc", "zig"}


def body_hash(body: str) -> str:
    lines = [ln.strip() for ln in body.splitlines()]
    norm = "\n".join(ln for ln in lines if ln)
    return hashlib.md5(norm.encode("utf-8", errors="replace")).hexdigest()


def strip_comments(body: str, lang: str) -> str:
    if lang in HASH_COMMENT_LANGS:
        body = _TRIPLE.sub('""', body) if lang == "python" else body
        body = _HASH_COMMENT.sub("", body)
        if lang in ("php",):
            body = _C_COMMENT.sub("", body)
        return body
    if lang == "php":
        return _HASH_COMMENT.sub("", _C_COMMENT.sub("", body))
    return _C_COMMENT.sub("", body)


def tokens(body: str, lang: str) -> list[str]:
    return _TOKEN.findall(strip_comments(body, lang))


def norm_hash(body: str, lang: str) -> str:
    return hashlib.md5("".join(tokens(body, lang)).encode("utf-8", errors="replace")).hexdigest()


def shingles(toks: list[str], k: int) -> set[str]:
    if len(toks) <= k:
        return {" ".join(toks)} if toks else set()
    return {" ".join(toks[i:i + k]) for i in range(len(toks) - k + 1)}


class CloneDetector:
    """MinHash-LSH over token shingles; returns group ids for near-duplicates."""

    def __init__(self, num_perm: int = 128, threshold: float = 0.8, k: int = 5):
        from datasketch import MinHash, MinHashLSH  # noqa: F401
        self.num_perm = num_perm
        self.threshold = threshold
        self.k = k
        self._mh = {}
        self._MinHash = MinHash
        self._lsh = MinHashLSH(threshold=threshold, num_perm=num_perm)

    def add(self, key: str, body: str, lang: str) -> None:
        sh = shingles(tokens(body, lang), self.k)
        m = self._MinHash(num_perm=self.num_perm)
        for s in sh:
            m.update(s.encode("utf-8", errors="replace"))
        self._mh[key] = m
        try:
            self._lsh.insert(key, m)
        except ValueError:
            pass  # duplicate key

    def groups(self) -> dict[str, int]:
        """Union-find over verified candidate pairs. Keys without a clone get their own singleton id."""
        parent = {k: k for k in self._mh}

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a, b):
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[max(ra, rb)] = min(ra, rb)

        for k, m in self._mh.items():
            for other in self._lsh.query(m):
                if other == k:
                    continue
                if m.jaccard(self._mh[other]) >= self.threshold:
                    union(k, other)
        roots = defaultdict(list)
        for k in self._mh:
            roots[find(k)].append(k)
        out: dict[str, int] = {}
        for gid, (root, members) in enumerate(sorted(roots.items(), key=lambda kv: kv[0])):
            for mkey in members:
                out[mkey] = gid
        return out
