"""Accepted risks: one file per scanned repo, `.security-scans.toml` at its root.

    [[accept]]
    fingerprint = "3f9c0a1b2c3d4e5f"     # from summary.md; or match by rule (+ path):
    tool = "semgrep"                     # optional
    rule = "python.lang.security.audit.dangerous-subprocess-use-audit"
    path = "acceptance/*.py"             # optional glob (fnmatch), default "*"
    reason = "Test harness only; never sees untrusted input"
    expires = 2027-03-31                 # TOML date; required
    owner = "allklier"                   # optional

Applied by the runner after every tool has run, on the normalised findings,
so one mechanism with one expiry rule covers all tools. An expired entry stops
suppressing: the finding is active again and marked `suppression_expired`.
An entry without a reason or a valid expiry is reported and ignored.
"""
from __future__ import annotations

import datetime as dt
import fnmatch
import tomllib
from pathlib import Path

FILENAME = ".security-scans.toml"
KEYS = {"fingerprint", "tool", "rule", "path", "reason", "expires", "owner"}


def load(path: Path | None) -> tuple[list[dict], list[str]]:
    if not path or not path.is_file():
        return [], []
    errors, entries = [], []
    try:
        data = tomllib.loads(path.read_text())
    except tomllib.TOMLDecodeError as e:
        return [], [f"{path.name}: not valid TOML: {e}"]
    for i, e in enumerate(data.get("accept", [])):
        where = f"{path.name} accept #{i + 1}"
        if set(e) - KEYS:
            errors.append(f"{where}: unknown keys {sorted(set(e) - KEYS)}")
            continue
        if not e.get("reason"):
            errors.append(f"{where}: missing reason")
            continue
        if not isinstance(e.get("expires"), dt.date) or isinstance(e.get("expires"), dt.datetime):
            errors.append(f"{where}: expires must be a TOML date like 2027-01-31")
            continue
        if not e.get("fingerprint") and not e.get("rule"):
            errors.append(f"{where}: needs fingerprint or rule")
            continue
        entries.append({**e, "id": i + 1})
    return entries, errors


def _matches(e: dict, f: dict) -> bool:
    if e.get("fingerprint"):
        return f["fingerprint"] == e["fingerprint"]
    if e.get("tool") and e["tool"] != f["tool"]:
        return False
    return e["rule"] == f["rule"] and fnmatch.fnmatch(f["path"], e.get("path", "*"))


def apply(findings: list[dict], entries: list[dict], today: dt.date) -> None:
    """Annotate findings in place: status = active | suppressed."""
    for f in findings:
        f["status"] = "active"
        for e in entries:
            if not _matches(e, f):
                continue
            if e["expires"] >= today:
                f["status"] = "suppressed"
                f["suppression"] = {"reason": e["reason"], "expires": e["expires"].isoformat()}
                f.pop("suppression_expired", None)
                break
            f["suppression_expired"] = {"reason": e["reason"], "expires": e["expires"].isoformat()}
