"""Turn each tool's SARIF into one normalised, fingerprinted finding list.

A fingerprint must survive unrelated edits (lines shifting), so it is built
from what the finding is about, never from a line number alone:

  dependency (osv-scanner)  tool | rule (vuln id) | file | package@version
  secret (gitleaks)         tool | rule | file | commit | line   (a commit never changes)
  missing lockfile          tool | rule | file
  code/config (others)      tool | rule | file | whitespace-normalised flagged
                            source text | n-th identical occurrence in that file
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}

# tool -> brief layer(s)
LAYER = {
    "osv-scanner": "1-deps",
    "lockfile": "1-deps",
    "semgrep": "3-sast",
    "gitleaks": "4-secrets",
    "zizmor": "5-config",
    "actionlint": "5-config",
    "trivy": "5-config",
}


def _fp(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()[:16]


def _rel_uri(uri: str, repo: Path) -> str:
    if uri.startswith("file://"):
        uri = uri[len("file://"):]
    p = str(repo.resolve())
    if uri.startswith(p + "/"):
        uri = uri[len(p) + 1:]
    uri = uri[2:] if uri.startswith("./") else uri
    if uri and not uri.startswith("/") and not (repo / uri).exists():
        # Some tools (zizmor) report paths relative to an enclosing git repo when the
        # scanned tree is a worktree; strip whatever leading part names the repo dir.
        parts = repo.resolve().parts
        for k in range(len(parts) - 1, 0, -1):
            prefix = "/".join(parts[-k:]) + "/"
            if uri.startswith(prefix) and (repo / uri[len(prefix):]).exists():
                return uri[len(prefix):]
    return uri


def _severity(tool: str, rule_id: str, level: str | None, rule_props: dict, res_props: dict) -> str:
    if tool == "gitleaks":
        return "high"          # any live-looking secret is high until rotated
    if tool == "osv-scanner" and rule_id.startswith("MAL-"):
        return "critical"      # OpenSSF malicious-package entry
    if tool == "actionlint":
        return "medium"        # lint/correctness; security issues come via zizmor
    score = res_props.get("security-severity") or rule_props.get("security-severity")
    if score is not None:
        try:
            s = float(score)
            return "critical" if s >= 9.0 else "high" if s >= 7.0 else "medium" if s >= 4.0 else "low"
        except ValueError:
            pass
    if tool == "osv-scanner":
        return "high"          # no CVSS published: don't under-rate a known vuln
    return {"error": "high", "warning": "medium"}.get(level or "warning", "low")


def _snippet(repo: Path, uri: str, start: int | None, end: int | None) -> str:
    if not start:
        return ""
    try:
        lines = (repo / uri).read_text(errors="replace").splitlines()
    except OSError:
        return ""
    end = min(end or start, start + 4)
    text = " ".join(lines[start - 1:end])
    return re.sub(r"\s+", " ", text).strip()


def _norm_rule(tool: str, rule_id: str) -> str:
    if tool == "semgrep":
        # Semgrep prefixes rule ids with the rules directory path; keep only the
        # part inside semgrep-rules so ids are the same on every machine.
        rule_id = re.sub(r"^.*?semgrep-rules\.", "", rule_id)
    return rule_id


def from_sarif(tool: str, sarif_path: Path, repo: Path) -> list[dict]:
    data = json.loads(sarif_path.read_text())
    out: list[dict] = []
    seen: dict[str, int] = {}
    for run in data.get("runs", []):
        rules = {r.get("id"): r for r in run.get("tool", {}).get("driver", {}).get("rules", []) or []}
        for res in run.get("results", []) or []:
            raw_rule = res.get("ruleId") or ""
            rule = _norm_rule(tool, raw_rule)
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            uri = _rel_uri(loc.get("artifactLocation", {}).get("uri", ""), repo)
            region = loc.get("region", {}) or {}
            start, end = region.get("startLine"), region.get("endLine")
            msg = (res.get("message") or {}).get("text", "")
            rdef = rules.get(raw_rule) or {}
            rprops = rdef.get("properties", {}) or {}
            # SARIF: a result without "level" inherits the rule's defaultConfiguration.level
            level = res.get("level") or (rdef.get("defaultConfiguration") or {}).get("level")
            sev = _severity(tool, rule, level, rprops, res.get("properties") or {})
            m = re.search(r"^Message: (.+)$", msg, re.M)  # trivy puts the useful line here
            if m:
                msg = m.group(1)
            extra = {}
            if tool == "osv-scanner":
                m = re.search(r"Package '([^']+)'", msg)
                extra["package"] = m.group(1) if m else ""
                key = (tool, rule, uri, extra["package"])
            elif tool == "gitleaks":
                commit = (res.get("partialFingerprints") or {}).get("commitSha", "")
                extra["commit"] = commit
                key = (tool, rule, uri, commit, str(start))
            else:
                snip = _snippet(repo, uri, start, end)
                base = (tool, rule, uri, snip)
                n = seen.get("|".join(base), 0)
                seen["|".join(base)] = n + 1
                key = base + (str(n),)
            fp = _fp(*key)
            if any(f["fingerprint"] == fp for f in out):
                continue  # exact duplicate result (osv-scanner emits some twice)
            out.append({
                "fingerprint": fp, "tool": tool, "layer": "2-malicious" if rule.startswith("MAL-") else LAYER[tool],
                "rule": rule, "severity": sev, "path": uri, "line": start,
                "message": msg.splitlines()[0][:300] if msg else "", **extra,
            })
    return out


# ---------------------------------------------------------------- lockfiles
# manifest file -> lockfiles that satisfy it (same directory)
LOCKS = {
    "pyproject.toml": ["poetry.lock", "uv.lock", "pdm.lock", "Pipfile.lock", "pylock.toml"],
    "setup.py": ["poetry.lock", "uv.lock", "pdm.lock", "Pipfile.lock", "pylock.toml"],
    "setup.cfg": ["poetry.lock", "uv.lock", "pdm.lock", "Pipfile.lock", "pylock.toml"],
    "Pipfile": ["Pipfile.lock"],
    "package.json": ["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb"],
    "Cargo.toml": ["Cargo.lock"],
    "go.mod": ["go.sum"],
    "Gemfile": ["Gemfile.lock"],
    "composer.json": ["composer.lock"],
    "conanfile.txt": ["conan.lock"],
    "conanfile.py": ["conan.lock"],
}
SKIP_DIRS = {".git", "node_modules", "vendor", "third_party", "fixtures", "testdata"}


def _requirements_pinned(p: Path) -> bool:
    """True if every requirement line is pinned with == / === (pip-compile style)."""
    any_req = False
    for line in p.read_text(errors="replace").splitlines():
        line = line.split("#", 1)[0].strip().rstrip("\\").strip()
        if not line or line.startswith(("-r", "-c", "--hash", "--index", "--extra-index", "--find-links")):
            continue
        any_req = True
        if line.startswith("-e") or not re.search(r"===?", line):
            return False
    return any_req


def lockfile_findings(repo: Path) -> tuple[list[dict], list[str]]:
    """Return (missing-lockfile findings, lockfiles found)."""
    findings, found = [], []
    for d in sorted([repo] + [p for p in repo.rglob("*") if p.is_dir()]):
        rel = d.relative_to(repo)
        if any(part in SKIP_DIRS or part.startswith(".") for part in rel.parts):
            continue
        names = {p.name for p in d.iterdir() if p.is_file()}
        reqs = sorted(n for n in names if re.fullmatch(r"requirements.*\.txt", n))
        pinned = [n for n in reqs if _requirements_pinned(d / n)]
        locks = sorted({l for ls in LOCKS.values() for l in ls} & names) + pinned
        found += [str(rel / n) for n in locks]
        manifests = sorted(n for n in names if n in LOCKS) + [n for n in reqs if n not in pinned]
        for m in manifests:
            ok = pinned if m.startswith("requirements") else [l for l in LOCKS[m] if l in names] + (pinned if m in ("pyproject.toml", "setup.py", "setup.cfg") else [])
            if not ok:
                path = str(rel / m) if str(rel) != "." else m
                findings.append({
                    "fingerprint": _fp("lockfile", "missing-lockfile", path), "tool": "lockfile",
                    "layer": "1-deps", "rule": "missing-lockfile", "severity": "medium",
                    "path": path, "line": None,
                    "message": f"{m} has no committed lockfile (or fully ==-pinned requirements); "
                               "dependency versions are not reproducible and CVE scanning only sees declared floors",
                })
    return findings, found
