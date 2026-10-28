"""Clone/update a registered repo and run every layer's tool over it.

Each tool's own SARIF (or SBOM) goes to <run>/raw/ untouched; the normalised,
fingerprinted, suppression-annotated list goes to <run>/findings.json.

Tool options used below were checked against the pinned versions with
`<tool> --help` on 2026-10-28; see docs/tools.md for the citation per flag.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from . import config, findings, suppress

# Files through which a scanned repo could silently switch off checks.
# All but .semgrepignore are neutralised by the flags below; presence is
# reported in summary.md either way so nothing is ignored without a trace.
NATIVE_IGNORES = {
    ".semgrepignore": "HONOURED by semgrep (no public flag disables it)",
    ".gitleaksignore": "neutralised (gitleaks -i points at an empty dir)",
    ".gitleaks.toml": "neutralised (gitleaks -c tools/config/gitleaks.toml)",
    ".trivyignore": "neutralised (trivy --ignorefile '')",
    ".trivyignore.yaml": "neutralised (trivy --ignorefile '')",
    "trivy.yaml": "neutralised (trivy runs outside the repo)",
    "osv-scanner.toml": "neutralised (osv-scanner --config tools/config/osv-scanner.toml)",
    "zizmor.yml": "neutralised (zizmor --no-config --no-ignores)",
    ".github/zizmor.yml": "neutralised (zizmor --no-config --no-ignores)",
    ".github/actionlint.yaml": "neutralised (actionlint -config-file tools/config/actionlint.yaml)",
    ".github/actionlint.yml": "neutralised (actionlint -config-file tools/config/actionlint.yaml)",
}


def log(msg: str) -> None:
    print(f"[secscan] {msg}", file=sys.stderr, flush=True)


def _git(*args: str, cwd: Path | None = None, extra: list[str] | None = None) -> str:
    cmd = ["git", *(extra or []), *args]
    return subprocess.run(cmd, cwd=cwd, check=True, text=True, capture_output=True).stdout.strip()


def sync(repo: config.Repo, work: Path = config.WORK) -> Path:
    """Fresh clone, or fetch + hard reset to the remote default branch."""
    dest = work / repo.name
    cred = []
    if repo.is_github and shutil.which("gh"):
        # https + gh's credential helper (SSH to github.com is blocked here);
        # only needed for private repos, harmless for public ones.
        cred = ["-c", "credential.helper=", "-c", "credential.helper=!gh auth git-credential"]
    if (dest / ".git").is_dir():
        if _git("remote", "get-url", "origin", cwd=dest) != repo.url:
            raise RuntimeError(f"{dest} is a clone of something else; remove it")
        _git("fetch", "--prune", "--tags", "--force", "origin", cwd=dest, extra=cred)
        _git("remote", "set-head", "origin", "--auto", cwd=dest, extra=cred)
    else:
        dest.parent.mkdir(parents=True, exist_ok=True)
        _git("clone", "--no-recurse-submodules", repo.url, str(dest), extra=cred)
    branch = _git("symbolic-ref", "--short", "refs/remotes/origin/HEAD", cwd=dest)
    _git("-c", "advice.detachedHead=false", "checkout", "-q", "--force", "--detach", branch, cwd=dest)
    _git("reset", "-q", "--hard", branch, cwd=dest)
    _git("clean", "-qffdx", cwd=dest)
    return dest


def _run(name: str, cmd: list[str], raw: Path, cwd: Path, ok_codes: tuple[int, ...],
         stdout_to: Path | None = None, env: dict | None = None) -> int:
    logf = raw / f"{name}.log"
    with open(logf, "w") as lf:
        lf.write("$ " + " ".join(cmd) + "\n")
        lf.flush()
        out = open(stdout_to, "w") if stdout_to else lf
        try:
            rc = subprocess.run(cmd, cwd=cwd, stdout=out, stderr=lf,
                                env={**os.environ, **(env or {})}).returncode
        finally:
            if stdout_to:
                out.close()
    if rc not in ok_codes:
        log(f"{name} FAILED (exit {rc}); see {logf}")
    return rc


def _has_actions(repo: Path) -> bool:
    wf = repo / ".github" / "workflows"
    if wf.is_dir() and any(p.suffix in (".yml", ".yaml") for p in wf.iterdir()):
        return True
    return any(p.name in ("action.yml", "action.yaml") for p in repo.rglob("action.y*ml") if ".git" not in p.parts)


def run_tools(repo: Path, raw: Path, languages: list[str], gitleaks_log_opts: str,
              name: str, version: str, skip: frozenset[str] = frozenset(),
              exclude: list[str] | None = None) -> dict:
    raw.mkdir(parents=True, exist_ok=True)
    st: dict[str, dict] = {}
    cfg = config.CONFIG

    # Layers 1+2: OSV-Scanner. --no-resolve: only versions actually written in the
    # manifest/lockfile are checked (deterministic; an unpinned ">=" floor is checked
    # as that floor). --no-ignore: the work dir lives inside this project's
    # .gitignore, which osv-scanner would otherwise apply to the clone.
    out = raw / "osv-scanner.sarif"
    rc = _run("osv-scanner", ["osv-scanner", "scan", "source", "-r", "--no-ignore", "--no-resolve",
                              "--config", str(cfg / "osv-scanner.toml"), "--format", "sarif",
                              "--output-file", str(out), str(repo)], raw, raw, (0, 1, 128))
    st["osv-scanner"] = ({"status": "n/a", "note": "no package manifests or lockfiles found"} if rc == 128
                         else {"status": "ok" if rc in (0, 1) and out.exists() else "error", "sarif": out.name})
    st["osv-scanner"]["exit"] = rc

    # Layer 3: Semgrep CE with the pinned semgrep-rules, security rules only.
    rule_dirs = sorted(str(d) for lang in languages for d in (config.RULES / lang).glob("**/security") if d.is_dir())
    out = raw / "semgrep.sarif"
    if not rule_dirs:
        st["semgrep"] = {"status": "n/a", "note": f"no semgrep-rules security dirs for languages {languages}"}
    else:
        cmd = ["semgrep", "scan", "--metrics=off", "--disable-version-check", "--disable-nosem", "--quiet",
               f"--sarif-output={out}"]
        for d in rule_dirs:
            cmd += ["--config", d]
        for pat in exclude or []:
            cmd.append(f"--exclude={pat}")  # semgrep scan --help: --exclude=PATTERN
        rc = _run("semgrep", cmd + ["."], raw, repo, (0, 1))
        st["semgrep"] = {"status": "ok" if rc in (0, 1) and out.exists() else "error", "exit": rc,
                         "sarif": out.name, "rulesets": [str(Path(d).relative_to(config.RULES)) for d in rule_dirs]}

    # Layer 4: Gitleaks over git history (log opts "--all" = every fetched ref).
    out = raw / "gitleaks.sarif"
    empty = raw / "_empty"
    empty.mkdir(exist_ok=True)
    if "gitleaks" in skip:
        # CI PR mode, base side: secrets are judged on the PR's own commits only
        st["gitleaks"] = {"status": "skipped"}
    else:
        rc = _run("gitleaks", ["gitleaks", "git", "--no-banner", "--redact", "--exit-code", "0",
                               "--ignore-gitleaks-allow", "-c", str(cfg / "gitleaks.toml"), "-i", str(empty),
                               f"--log-opts={gitleaks_log_opts}", "--report-format", "sarif",
                               "--report-path", str(out), str(repo)], raw, raw, (0,))
        st["gitleaks"] = {"status": "ok" if rc == 0 and out.exists() else "error", "exit": rc,
                          "sarif": out.name, "log_opts": gitleaks_log_opts}

    # Layer 5: GitHub Actions (zizmor offline = no token, deterministic; actionlint).
    if _has_actions(repo):
        out = raw / "zizmor.sarif"
        rc = _run("zizmor", ["zizmor", "--offline", "--no-config", "--no-ignores", "--no-progress",
                             "--no-exit-codes", "--format", "sarif", str(repo)], raw, raw, (0,), stdout_to=out)
        st["zizmor"] = {"status": "ok" if rc == 0 else "error", "exit": rc, "sarif": out.name}
        out = raw / "actionlint.sarif"
        tmpl = (cfg / "actionlint-sarif.tmpl").read_text()
        # shellcheck/pyflakes integrations off: they are not pinned here, so their
        # findings would vary with whatever happens to be on PATH.
        rc = _run("actionlint", ["actionlint", "-format", tmpl, "-shellcheck=", "-pyflakes=",
                                 "-config-file", str(cfg / "actionlint.yaml")], raw, repo, (0, 1), stdout_to=out)
        st["actionlint"] = {"status": "ok" if rc in (0, 1) else "error", "exit": rc, "sarif": out.name}
    else:
        for t in ("zizmor", "actionlint"):
            st[t] = {"status": "n/a", "note": "no GitHub workflows or actions in repo"}

    # Layer 5: Trivy misconfiguration (Dockerfile, Terraform, k8s, Helm, ...),
    # using only the checks embedded in the pinned binary (--skip-check-update).
    out = raw / "trivy.sarif"
    rc = _run("trivy", ["trivy", "fs", "--scanners", "misconfig", "--skip-check-update", "--ignorefile", "",
                        "--disable-telemetry", "--skip-version-check", "--quiet", "--format", "sarif",
                        "--output", str(out), str(repo)], raw, raw, (0,))
    st["trivy"] = {"status": "ok" if rc == 0 and out.exists() else "error", "exit": rc, "sarif": out.name}

    # SBOM (supports layer 1: re-check old commits against new CVEs later).
    out = raw / "sbom.cdx.json"
    rc = _run("syft", ["syft", "scan", f"dir:{repo}", "-q", "-o", f"cyclonedx-json={out}",
                       "--source-name", name, "--source-version", version], raw, raw, (0,),
              env={"SYFT_CHECK_FOR_APP_UPDATE": "false"})
    st["syft"] = {"status": "ok" if rc == 0 and out.exists() else "error", "exit": rc, "sbom": out.name}
    shutil.rmtree(empty, ignore_errors=True)
    return st


def scan_path(repo: Path, name: str, run_dir: Path, languages: list[str],
              gitleaks_log_opts: str = "--all", suppressions_file: Path | None = None,
              extra_meta: dict | None = None, today: dt.date | None = None,
              skip: frozenset[str] = frozenset(), exclude: list[str] | None = None) -> dict:
    """Scan an existing checkout; write raw/, findings.json, meta.json. Returns meta."""
    started = dt.datetime.now(dt.timezone.utc)
    commit = _git("rev-parse", "HEAD", cwd=repo)
    raw = run_dir / "raw"
    st = run_tools(repo, raw, languages, gitleaks_log_opts, name, commit, skip, exclude)

    all_f: list[dict] = []
    for tool, s in st.items():
        if s["status"] == "ok" and s.get("sarif"):
            all_f += findings.from_sarif(tool, raw / s["sarif"], repo)
    lock_f, locks_found = findings.lockfile_findings(repo)
    all_f += lock_f
    st["lockfile"] = {"status": "ok", "lockfiles": locks_found}

    sup_path = suppressions_file or (repo / suppress.FILENAME)
    entries, sup_errors = suppress.load(sup_path)
    suppress.apply(all_f, entries, today or dt.date.today())
    all_f.sort(key=lambda f: (-findings.SEV_ORDER[f["severity"]], f["tool"], f["path"], f["line"] or 0,
                              f["rule"], f["fingerprint"]))

    v = config.versions()
    meta = {
        "repo": name, "commit": commit, "run_dir": str(run_dir),
        "started_at": started.isoformat(timespec="seconds"),
        "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "languages": languages, "sast_exclude": exclude or [], "tools": st,
        "tool_versions": {k: v[k] for k in sorted(v) if k.endswith("_VERSION") or k == "SEMGREP_RULES_COMMIT"},
        "suppressions_file": str(sup_path) if sup_path.is_file() else None,
        "suppression_errors": sup_errors,
        "native_ignore_files": {p: why for p, why in NATIVE_IGNORES.items() if (repo / p).exists()}
        | {str(p.relative_to(repo)): NATIVE_IGNORES["osv-scanner.toml"]
           for p in repo.rglob("osv-scanner.toml") if ".git" not in p.parts},
        **(extra_meta or {}),
    }
    (run_dir / "findings.json").write_text(json.dumps(all_f, indent=1, sort_keys=True) + "\n")
    (run_dir / "meta.json").write_text(json.dumps(meta, indent=1, sort_keys=True) + "\n")
    return meta


def new_run_dir(name: str, now: dt.datetime | None = None) -> Path:
    """reports/<YYYY-MM-DD>/<repo>/run-<HHMMSS> (local time); never reuses a folder."""
    now = now or dt.datetime.now()
    base = config.REPORTS / now.strftime("%Y-%m-%d") / name
    d = base / f"run-{now.strftime('%H%M%S')}"
    n = 1
    while d.exists():
        n += 1
        d = base / f"run-{now.strftime('%H%M%S')}-{n}"
    d.mkdir(parents=True)
    return d
