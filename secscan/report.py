"""Run-to-run diff (new / fixed / still open) and the per-run summary.md."""
from __future__ import annotations

import json
from pathlib import Path

from . import config, findings

SEV = findings.SEV_ORDER


def load_run(run_dir: Path) -> tuple[dict, list[dict]]:
    return (json.loads((run_dir / "meta.json").read_text()),
            json.loads((run_dir / "findings.json").read_text()))


def runs_for(name: str) -> list[Path]:
    """All completed runs of a repo, oldest first (ordered by recorded UTC start)."""
    runs = []
    for m in config.REPORTS.glob(f"*/{name}/run-*/meta.json"):
        if (m.parent / "findings.json").exists():
            runs.append((json.loads(m.read_text())["started_at"], m.parent))
    return [p for _, p in sorted(runs)]


def previous_run(run_dir: Path, name: str) -> Path | None:
    runs = runs_for(name)
    idx = runs.index(run_dir) if run_dir in runs else len(runs)
    return runs[idx - 1] if idx > 0 else None


def diff(prev_dir: Path | None, cur_dir: Path) -> dict:
    cur_meta, cur = load_run(cur_dir)
    if prev_dir is None:
        prev_meta, prev = {"tools": {}}, []
    else:
        prev_meta, prev = load_run(prev_dir)
    # A tool that errored in either run can't say what was fixed or new.
    broken = sorted(t for t in set(cur_meta["tools"]) | set(prev_meta["tools"])
                    if cur_meta["tools"].get(t, {}).get("status") == "error"
                    or (prev_dir and prev_meta["tools"].get(t, {}).get("status") == "error"))
    a = {f["fingerprint"]: f for f in prev if f["status"] == "active" and f["tool"] not in broken}
    b = {f["fingerprint"]: f for f in cur if f["status"] == "active" and f["tool"] not in broken}
    key = lambda f: (-SEV[f["severity"]], f["tool"], f["path"], f["rule"])  # noqa: E731
    return {
        "previous": str(prev_dir) if prev_dir else None, "current": str(cur_dir),
        "not_compared_tools": broken,
        "new": sorted((b[k] for k in b.keys() - a.keys()), key=key),
        "fixed": sorted((a[k] for k in a.keys() - b.keys()), key=key),
        "open": sorted((b[k] for k in b.keys() & a.keys()), key=key),
    }


def _row(f: dict) -> str:
    loc = f["path"] + (f":{f['line']}" if f.get("line") else "")
    note = ""
    if f.get("suppression_expired"):
        note = f" **(suppression expired {f['suppression_expired']['expires']})**"
    msg = f["message"].replace("|", "\\|")[:160]
    return f"| {f['severity']} | {f['tool']} | `{f['rule']}` | `{loc}` | `{f['fingerprint']}` | {msg}{note} |"


HDR = "| severity | tool | rule | location | fingerprint | message |\n|---|---|---|---|---|---|"


def diff_markdown(d: dict) -> str:
    out = [f"# Diff: {Path(d['current']).parent.name}", "",
           f"- previous: `{d['previous'] or '(none - first run)'}`", f"- current: `{d['current']}`",
           f"- new: **{len(d['new'])}**, fixed: **{len(d['fixed'])}**, still open: **{len(d['open'])}**"]
    if d["not_compared_tools"]:
        out.append(f"- NOT compared (tool errored in one of the runs): {', '.join(d['not_compared_tools'])}")
    for title in ("new", "fixed", "open"):
        out += ["", f"## {title} ({len(d[title])})", ""]
        out += [HDR] + [_row(f) for f in d[title]] if d[title] else ["(none)"]
    return "\n".join(out) + "\n"


def write_diff(prev_dir: Path | None, cur_dir: Path) -> dict:
    d = diff(prev_dir, cur_dir)
    slim = {**d, **{k: [f["fingerprint"] for f in d[k]] for k in ("new", "fixed", "open")}}
    (cur_dir / "diff.json").write_text(json.dumps(slim, indent=1, sort_keys=True) + "\n")
    (cur_dir / "diff.md").write_text(diff_markdown(d))
    return d


def write_summary(run_dir: Path, d: dict | None) -> None:
    meta, fs = load_run(run_dir)
    active = [f for f in fs if f["status"] == "active"]
    sup = [f for f in fs if f["status"] == "suppressed"]
    out = [f"# Security scan: {meta['repo']}", "",
           f"- commit: `{meta['commit']}`", f"- started: {meta['started_at']}",
           f"- active findings: **{len(active)}** "
           f"({', '.join(f'{s}: {sum(f['severity'] == s for f in active)}' for s in SEV)}); suppressed: {len(sup)}"]
    if d:
        out.append(f"- vs previous run: new **{len(d['new'])}**, fixed **{len(d['fixed'])}**, "
                   f"still open **{len(d['open'])}** (see diff.md)")
    out += ["", "## Layers", "", "| layer | tool | status | active | output |", "|---|---|---|---|---|"]
    order = lambda t: ({"syft": "9"}.get(t, findings.LAYER.get(t, "1")), t)  # noqa: E731
    for tool in sorted(meta["tools"], key=order):
        s = meta["tools"][tool]
        layer = {"syft": "SBOM"}.get(tool, findings.LAYER.get(tool, ""))
        if tool == "osv-scanner":
            layer = "1-deps + 2-malicious"
        n = sum(f["tool"] == tool for f in active)
        outp = s.get("sarif") or s.get("sbom") or ""
        status = s["status"] + (f" ({s['note']})" if s.get("note") else "")
        out.append(f"| {layer} | {tool} | {status} | {n} | {('raw/' + outp) if outp else ''} |")
    locks = meta["tools"].get("lockfile", {}).get("lockfiles", [])
    out += ["", f"Lockfiles found: {', '.join(f'`{x}`' for x in locks) if locks else '**none**'}"]
    if meta.get("native_ignore_files"):
        out += ["", "## Tool-native ignore files present in the repo", ""]
        out += [f"- `{p}`: {why}" for p, why in meta["native_ignore_files"].items()]
    out += ["", "## Accepted risks", "", f"File: `{meta.get('suppressions_file') or '(none)'}`"]
    for e in meta.get("suppression_errors", []):
        out.append(f"- **INVALID entry ignored**: {e}")
    expired = [f for f in fs if f.get("suppression_expired")]
    if expired:
        out.append(f"- **{len(expired)} suppression(s) expired; those findings are active again**")
    if sup:
        out += ["", "| tool | rule | location | fingerprint | reason | expires |", "|---|---|---|---|---|---|"]
        out += [f"| {f['tool']} | `{f['rule']}` | `{f['path']}` | `{f['fingerprint']}` | "
                f"{f['suppression']['reason']} | {f['suppression']['expires']} |" for f in sup]
    out += ["", "## Active findings", ""]
    out += [HDR] + [_row(f) for f in active] if active else ["(none)"]
    (run_dir / "summary.md").write_text("\n".join(out) + "\n")


def compare_for_ci(base_dir: Path, head_dir: Path, fail_on: str) -> tuple[dict, list[dict]]:
    """PR mode: findings active on head but not on base; those at/above fail_on fail the job."""
    d = write_diff(base_dir, head_dir)
    failing = [f for f in d["new"] if SEV[f["severity"]] >= SEV[fail_on]]
    return d, failing
