# CLAUDE.md — security-scans

Repeatable security scanning for my GitHub repos: a central scanner project
that other repos are wired into, one small step per repo. The full brief
(goals, five layers, best practices, acceptance criteria) is in
`docs/brief.md` — read it first.

## Decisions (2026-10-28, answers to the brief's section 6)

| Question | Decision |
|---|---|
| Where this project lives | Git repo, branch `main`; to be published as **public** `allklier/security-scans`, because a public repo can only call reusable workflows from a public repo. **Ask the user before creating the GitHub repo or pushing.** Reports never go into git. Private details (machines, private repos, org plans) live in the git-ignored `CLAUDE.local.md`. |
| Scope | The scanner is a pattern for any repo; the repos it scans are listed in `repos.toml`, added one at a time. |
| Where scans run | Decided **per repo**. Default is **local** (`make scan` on demand). CI is opt-in per repo; the setup must support it via a reusable GitHub Actions workflow (PR: changed code, fail only on new high severity; weekly schedule; `workflow_dispatch`). No repo is switched to CI in this round. |
| Tool install | **Native**, no Docker. Linux: Python tools in a new conda env `secscan`; single-binary tools downloaded at pinned versions with checksum verification into the project's `tools/bin/` (gitignored). macOS: Homebrew. Nothing system-wide. Versions pinned in one manifest in the repo. |
| Platforms | Linux (Ubuntu 24.04 workstation; CI runners) **and macOS** (Homebrew available). Same `make scan` on both. |
| AI triage | **On demand only**, local, Claude Code headless, read-only, no credentials, no network write. Never in CI this round. Scanned code is untrusted data (prompt-injection risk). |
| GitHub plan | Free plan assumed: code-scanning upload (SARIF) is free on public repos only. |

## Build decisions (round 1, 2026-10-28)

| Concern | Decision | Why |
|---|---|---|
| Tool set and pins | OSV-Scanner 2.7.0 (deps + OpenSSF malicious packages), Semgrep CE 1.180.0 with semgrep-rules pinned by commit (security folders only), Gitleaks 8.30.1 (full history), zizmor 1.30.1 + actionlint 1.7.12 (Actions), Trivy 0.75.0 (misconfig only), Syft 1.54.1 (SBOM), plus a built-in missing-lockfile check. All pins in `tools/versions.env`; a release must be ≥14 days old when pinned. Binaries checksum-verified; Python tools hash-locked in `tools/requirements.lock` | Brief §3/§5. Opengrep rejected: releases have cosign signatures but no checksum file. zizmor from PyPI because its GitHub binaries have no checksums. Trivy 0.75.0 is after the March 2026 compromise (GHSA-69fq-xp46-6x23). GuardDog, Bandit, pip-audit, hadolint, TruffleHog left out as overlapping (`docs/tools.md`). |
| Tool behaviour | OSV `--no-resolve` (only versions written in the file are checked, e.g. `lxml>=5.0` checks 5.0); actionlint's shellcheck/pyflakes off (not pinned); Trivy `--skip-check-update` (checks built into the pinned binary); zizmor `--offline` (no token) | Reproducible results; no unpinned extras. |
| Reports | `reports/<date>/<repo>/run-<HHMMSS>/` with `raw/` (each tool's untouched SARIF; Syft CycloneDX JSON), `findings.json`, `summary.md`, `diff.*`, `triage.md`. Gitignored | Same-day re-runs never overwrite each other. |
| Finding fingerprints | Dependency: vuln id + file + package@version. Secret: rule + file + commit + line. Code/config: rule + file + normalised flagged text + occurrence index | Survive line shifts (verified: findings moved from line 12 to 15 kept their fingerprints). |
| Severity | Malicious package = critical, secret = high, actionlint = medium, otherwise CVSS / SARIF level | |
| Accepted risks | One `.security-scans.toml` in the scanned repo (reason + expiry, matched by fingerprint or rule + path), applied by the runner to all tools; tools' own ignore files switched off where possible | One format with expiry for every tool. Gap: `.semgrepignore` and Trivy inline ignore comments can't be switched off (summary lists a `.semgrepignore` if present). |
| Diff | A tool that errored is left out of the comparison rather than reported as "all fixed" | |
| CI | Reusable `.github/workflows/scan.yml` (`workflow_call`, `contents: read` only): PR mode fails on new findings at high or above; full mode fails only on tool errors. SARIF upload is a separate opt-in workflow (`upload-sarif.yml`) so the scan never needs `security-events: write`. Actions pinned by SHA. Example caller in `examples/` | Brief §5. Not yet run on GitHub (repo unpublished). |
| AI triage | `make triage REPO=…`, on demand: `claude -p` with only Read/Grep/Glob (`--tools`), other tools also disallowed, `--restricted --safe-mode --strict-mcp-config --permission-mode dontAsk`, no session persistence, environment reduced to HOME/PATH/LANG/USER. Defaults: sonnet, $1.50 cap | Read-only and credential-free per the decision above; the real enforcement is the tool restriction, the prompt only marks repo text as untrusted. |
| Dependency policy | No lockfiles in the scanned repos (user decision 2026-10-28): plugins share their host's Python environment. Keep minimum versions above known CVEs instead; the `missing-lockfile` finding is accepted in each repo's `.security-scans.toml` | Exact pins would conflict with the host app (e.g. ComfyUI) and other plugins. |
| CodeQL (planned 2026-10-28, see `docs/plan.md` §5) | Second SAST tool for all four repos: `cpp` on both OFX repos, `python` on all four. Build mode `none`, `security-extended` suite, full bundle 2.27.2 checksum-verified. **Rules with precision medium/low are lowered one severity level.** Licence gate: only public repos under an OSI licence | Semgrep has no C++ rules. Trial: deterministic, fingerprints work unchanged; most own-code findings were medium-precision `$HOME` path injection, which would otherwise fail every PR as high. Python included by user decision despite low yield in the trial. |
| Release verification (2026-10-28, `docs/plan.md` §4) | Policy C: patch → normal release after CI; minor/major → pre-release until the off-CI acceptance tier passes; one-way override to pre-release; manual promote updates a Verification block in the release notes | Avoids being stuck in pre-release when test hardware or testers aren't available, while big changes still get the full check. First used by ComfyUI_OpenClip. |

**UNVERIFIED:** the whole macOS path; all CI behaviour on GitHub (incl. cross-owner calls, multi-tool SARIF upload, OSV absolute paths in code scanning); the installer branch that creates the conda env from scratch; whether org-level required-workflow rulesets exist on the free plan.

**Known gaps:** C/C++ gets little Semgrep coverage (no `cpp` rule folder) — CodeQL is the better tool for the C++ repos (planned, `docs/plan.md` §5); transitive Python dependencies are hash-pinned but not held to the 14-day rule. Found scanning the first four repos (2026-10-28): OSV-Scanner reads `requirements.txt` but not `pyproject.toml`, so a repo whose dependencies are only in `pyproject.toml` (CheckMyRender) gets no dependency CVE check at all (reported as "n/a"); unversioned dependencies couldn't be checked anyway. Vendored C++ libraries under `third_party/` (both OFX repos) have no manifest, so nothing checks them for CVEs; they're also excluded from SAST.

## Working rules

- Never invent a tool flag or config key: verify with `--help` / docs for the installed version and cite it (see global CLAUDE.md §6).
- Ask before installing anything outside the `secscan` env / `tools/bin`, before creating GitHub repos, pushing, or changing any repo's settings.
- Accepted risks live in the scanned repo with a reason and an expiry date; no silent ignores.
