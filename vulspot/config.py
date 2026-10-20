"""Configuration loading and path helpers."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent


def under_root(value: str) -> Path:
    """Absolute config paths are used as-is. Relative ones stay under the repo."""
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


@dataclass
class Paths:
    root: Path
    raw_nvd: Path
    raw_commits: Path
    interim: Path
    out: Path
    logs: Path

    def ensure(self) -> None:
        for p in (self.raw_nvd, self.raw_commits, self.interim, self.out, self.logs):
            p.mkdir(parents=True, exist_ok=True)


class Config(dict):
    """dict with attribute access and a `paths` helper."""

    def __getattr__(self, item: str) -> Any:
        try:
            v = self[item]
        except KeyError as e:
            raise AttributeError(item) from e
        return Config(v) if isinstance(v, dict) else v

    @property
    def paths(self) -> Paths:
        p = self["paths"]
        return Paths(
            root=ROOT,
            raw_nvd=under_root(p["raw_nvd"]),
            raw_commits=under_root(p["raw_commits"]),
            interim=under_root(p["interim"]),
            out=under_root(p["out"]),
            logs=under_root(p["logs"]),
        )


def load_config(path: str | os.PathLike | None = None) -> Config:
    path = Path(path) if path else ROOT / "config.yaml"
    with open(path) as f:
        cfg = Config(yaml.safe_load(f))
    cfg.paths.ensure()
    return cfg


def env_secret(name: str, required: bool = False) -> str | None:
    v = os.environ.get(name)
    if required and not v:
        raise SystemExit(f"environment variable {name} is required for this stage")
    return v
