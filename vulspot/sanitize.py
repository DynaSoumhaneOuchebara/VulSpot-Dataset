"""Commit message sanitization (drop trailers / sign-offs / cherry-pick lines)."""
from __future__ import annotations

import re


class MessageSanitizer:
    def __init__(self, patterns: list[str]):
        self.res = [re.compile(p, re.I) for p in patterns]

    def __call__(self, msg: str | None) -> str:
        if not msg:
            return ""
        lines = msg.replace("\r\n", "\n").split("\n")
        kept: list[str] = []
        for ln in lines:
            if any(r.match(ln.strip()) for r in self.res):
                continue
            kept.append(ln.rstrip())
        text = "\n".join(kept)
        text = re.sub(r"\n{3,}", "\n\n", text).strip()
        return text


_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")


def mentions(name: str, text: str | None) -> bool:
    """Whole-word mention of a function name in free text (commit message / CVE description)."""
    if not name or not text or len(name) < 3:
        return False
    return re.search(rf"(?<![\w]){re.escape(name)}(?![\w])", text) is not None
