# Plan: next steps for security-scans

Status 2026-10-28. Covers the four repos in `repos.toml`: ComfyUI_OpenClip, Flame_MatteRefine_OFX,
Flame_PartnerNodes_OFX, CheckMyRender. Each part is started only when the owner says go.

| # | Part | State |
|---|---|---|
| 1 | Scanner round 1 (seven tools, reports, diff, accepted risks, AI triage) | Done; scans the four repos locally |
| 2 | Publish this repo (public, so public repos can call its reusable workflow) | Done |
| 3 | CI on ComfyUI_OpenClip: tests, security scan, release workflow | Done: PR #6 merged; PR, manual full-scan and release runs green. First weekly scheduled run pending (Mondays 05:17 UTC) |
| 4 | Release verification policy (below) | In use: OpenClip v1.1.1 released by the workflow as a patch (normal release, LIGHTLY TESTED). Promote not yet used |
| 5 | CodeQL in the scanner, all four repos (below) | Planned |
| 6 | Show it to others: sample report from the seeded repo, one real CI run, short overview | Draft written (private); CodeQL section waits for 5 |

## 3. CI on ComfyUI_OpenClip (the reference repo)

OpenClip is the first repo with CI and serves as the worked example for the others.

- **Tests** on every push and pull request (pytest on a GitHub Linux runner).
- **Security scan** by calling this repo's reusable workflow, pinned by commit: pull requests
  fail only on *new* findings rated high or above; a full scan runs weekly and on demand.
- **Release workflow** on version tags, applying the policy below.
- A live ComfyUI acceptance run is deferred: it needs ComfyUI on the runner and a test clip that
  can be published. Until then it stays a manual, off-CI test tier.

Details: OpenClip's `docs/ci.md`. Result on the first full scan after the fixes: 0 high (was 1), 3 accepted risks with reasons and expiry, 2 low notes.

## 4. Release verification policy ("policy C")

Separates *is it released* from *how well is it verified*.

- **Test tiers.** Tier 1 = CI (unit tests + security scan), required for every release. Tier 2 =
  full acceptance run off CI (live host application, real media). Tier 3 = tested by a person in
  a named host version (e.g. Flame 2027).
- **The version number decides the starting state.** Patch bump (x.y.Z: fixes only, no new
  behaviour) → normal release once tier 1 passes. Minor or major bump → pre-release until tier 2
  results are attached.
- **One-way override.** A risky patch can be forced to start as a pre-release. A minor or major
  release can never skip straight to a normal release.
- **Promotion, not rebuilding.** The tag and package never change. A manual promote step attaches
  the evidence, clears the pre-release flag and updates the release notes' Verification block:

  ```
  Verification
    CI (unit tests, security scan)   ✔ <run link>
    Acceptance (live host)           ✔ <date>, results attached
    Host version X                    – not tested
  Status: FULLY TESTED   (was: LIGHTLY TESTED, <date>)
  ```
- **Version discipline matters:** a change of default or a new input is a minor bump, not a patch.
- Package registries without a pre-release channel (UNVERIFIED for the ComfyUI registry) get every
  release; there the status label is advisory only.

## 5. CodeQL for all four repos

Adds CodeQL as a second SAST tool next to Semgrep. Main reason: Semgrep has no C++ rules, so the
two OFX repos get almost no code analysis today. Based on a local trial on 2026-10-28 (CodeQL
2.27.2, both OFX repos).

### Decisions

| Concern | Decision |
|---|---|
| Repos and languages | Flame_MatteRefine_OFX: `cpp`, `python`. Flame_PartnerNodes_OFX: `cpp`, `python`. ComfyUI_OpenClip: `python`. CheckMyRender: `python`. Set per repo with a new `codeql = [...]` key in `repos.toml`. |
| Python | Included for all four repos for consistency, although the trial found little: on PartnerNodes CodeQL Python reported 2 findings vs Semgrep's 11, with no overlap. Semgrep stays. Review after the first month of results. |
| Licence gate | CodeQL's licence allows use only on code under an OSI-approved licence (or with paid GitHub Advanced Security). The scanner refuses CodeQL for a repo that is private or whose licence (`gh api repos/<repo> --jq .license.spdx_id`) is not on an OSI allowlist. All four repos qualify today (MIT, MPL-2.0 ×3). Private repos get no CodeQL. |
| Build mode | `none` (no build). Generally available for C/C++ since 2025-10. Needs no build dependencies (the ML part of MatteRefine needs ONNX Runtime) and covered more code than a real build in the trial. A real build found 11 extra findings, all in tests/tools (argv → `dlopen`/file path); not worth the build setup. |
| Query suite | `security-extended`. The default suite missed every path/permission finding; `security-and-quality` is mostly float-comparison noise. |
| Exclusions | `exclude` paths from `repos.toml` (e.g. `third_party`) are passed as `paths-ignore` in a generated CodeQL config, and filtered again in the runner. Test and tool folders stay in scope. |
| **Severity** | **Results from rules with `precision` medium or low are lowered one level** (critical → high → medium → low). High and very-high precision rules keep the normal `security-severity` mapping. In the trial this moved 16 of 20 MatteRefine findings (path injection from `$HOME`, world-writable file creation) from high to medium, so they no longer fail pull requests. The 4 integer-cast findings (high precision) stay high: each gets fixed or an accepted-risk entry with a reason. |
| Pinning | Full CodeQL bundle `codeql-bundle-v2.27.2` from `github/codeql-action` releases, verified against its published `.checksum.txt`. Unpacked into `tools/codeql/` (1.4 GB, gitignored), `tools/bin/codeql` symlinked. The per-language bundles are not used: no checksum file, Linux only. |
| Determinism | Verified in the trial: analysing the same database twice gave byte-identical SARIF; rebuilding the database gave the same result set. The existing fingerprint scheme works unchanged. |
| CI | `scan.yml` gets an optional CodeQL step, run when the caller lists languages; the bundle is cached. Results stay in the workflow artifacts like the other tools. Turning on GitHub's own CodeQL code-scanning setup is a separate repo-settings decision, not part of this plan. |

### Work items (about one day)

1. `tools/versions.env`: `CODEQL_VERSION=2.27.2`. `scripts/install-tools.sh`: `install_codeql()`
   (Linux x64, Linux arm64, macOS bundles; checksum check with the existing `fetch_verified`).
2. `secscan/config.py`: `codeql` key per repo plus the licence gate.
3. `secscan/runner.py`: per language, `codeql database create --build-mode=none` (with the
   generated `paths-ignore` config), `codeql database analyze` with the security-extended suite,
   `--ram=4096`, SARIF to `raw/codeql-<lang>.sarif`; delete the database afterwards (up to 0.6 GB).
4. `secscan/findings.py`: `codeql` → layer 3, precision-based severity lowering, exclude filter.
5. Tests: unit tests for the severity rule and licence gate; a planted C++ problem (argv →
   `system()`) in the seeded test repo; a reproducibility check.
6. `scan.yml`: optional CodeQL step with bundle caching. `docs/tools.md` and `CLAUDE.md` updated.
7. First run on the four repos; accepted-risk entries or fixes for what remains high.

Cost per scan: about 20–45 s and up to about 4 GB RAM per C++ repo, a few seconds per Python repo.

### UNVERIFIED

- All of macOS (native arm64 run is beta upstream; untested here).
- The release attestation signature (only the checksum was verified; the local `gh` has no
  `gh attestation` command).
- CodeQL in GitHub Actions through `scan.yml`.
- CodeQL Python on OpenClip, CheckMyRender and MatteRefine (only PartnerNodes was tried).

## 6. Showing it to others

In this order, once parts 3 and 5 are done:

1. A sample report from `make seeded` (planted secret, malicious package, insecure workflow,
   and the planted C++ problem). It shows every layer working and exposes nothing real.
2. One real CI run on OpenClip: a pull request, a manual run and a weekly run.
3. A short overview: coverage, what the scans found (counts and examples, no open weaknesses
   of real repos), cost, and how another organisation would adopt the pattern.

Reports on real repos with open findings are not published.
