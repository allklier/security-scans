"""Paths, the pinned-version manifest and the repo registry."""
from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"
CONFIG = TOOLS / "config"
RULES = TOOLS / "rules" / "semgrep-rules"
WORK = ROOT / "work"
REPORTS = ROOT / "reports"

MODES = ("local", "ci")


def versions() -> dict[str, str]:
    """Parse tools/versions.env (KEY=VALUE lines)."""
    out = {}
    for line in (TOOLS / "versions.env").read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            out[k] = v
    return out


@dataclass
class Repo:
    name: str
    url: str
    mode: str = "local"
    languages: list[str] = field(default_factory=list)
    # Accepted-risks file to use instead of the repo's own .security-scans.toml
    # (for repos that don't carry one yet). Relative to this project's root.
    suppressions: str | None = None
    # Paths kept out of SAST (vendored third-party source); semgrep --exclude patterns.
    exclude: list[str] = field(default_factory=list)
    is_github: bool = False


def load_registry(path: Path) -> list[Repo]:
    data = tomllib.loads(path.read_text())
    repos = []
    for i, r in enumerate(data.get("repo", [])):
        name = r.get("name")
        if not name or "/" in name or name.startswith("."):
            raise ValueError(f"{path}: repo #{i}: invalid or missing name")
        if ("github" in r) == ("url" in r):
            raise ValueError(f"{path}: {name}: give exactly one of github / url")
        mode = r.get("mode", "local")
        if mode not in MODES:
            raise ValueError(f"{path}: {name}: mode must be one of {MODES}")
        unknown = set(r) - {"name", "github", "url", "mode", "languages", "suppressions", "exclude"}
        if unknown:
            raise ValueError(f"{path}: {name}: unknown keys {sorted(unknown)}")
        if "github" in r:
            url, is_gh = f"https://github.com/{r['github']}.git", True
        else:
            url, is_gh = r["url"], False
            if url.startswith("./") or url.startswith("../"):
                url = str((ROOT / url).resolve())
        repos.append(Repo(name=name, url=url, mode=mode,
                          languages=list(r.get("languages", [])),
                          suppressions=r.get("suppressions"), exclude=list(r.get("exclude", [])),
                          is_github=is_gh))
    return repos
