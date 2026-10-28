# security-scans

Repeatable security scanning for my GitHub repos: one pinned toolchain, one
command, SARIF per tool, run-to-run diff, accepted risks with expiry dates,
optional AI triage, and a reusable GitHub Actions workflow for repos that
opt into CI. Brief: `docs/brief.md`; decisions: `CLAUDE.md`.

## Quick start

```sh
make tools                 # pinned, checksum-verified tools (tools/versions.env)
make scan                  # clone/update + scan every repo in repos.toml
make diff                  # new / fixed / still open vs the previous run
make triage REPO=ComfyUI_OpenClip   # AI second opinion (Claude Code, read-only)
make test                  # unit tests of the runner
make seeded                # build the planted-problems test repo and scan it
make lint-ci               # actionlint + zizmor over this repo's workflows
```

Requirements: Linux with conda (or `python3.12` for a venv), git, curl,
make; macOS path is written but UNTESTED (docs/tools.md). No Docker.

## Layers and tools

| Layer | Tool | Output in `raw/` |
|---|---|---|
| 1 dependencies (CVEs) + missing lockfile | OSV-Scanner + built-in lockfile check | `osv-scanner.sarif` (lockfile findings only in `findings.json`) |
| 2 malicious packages | OSV-Scanner (OpenSSF `MAL-*` entries) | same SARIF, layer `2-malicious` |
| 3 own code (SAST) | Semgrep CE + pinned semgrep-rules (security rules only) | `semgrep.sarif` |
| 4 secrets, full git history | Gitleaks (redacted) | `gitleaks.sarif` |
| 5 Actions / IaC / containers | zizmor, actionlint, Trivy misconfig | `zizmor.sarif`, `actionlint.sarif` (SARIF via actionlint's own template), `trivy.sarif` |
| SBOM | Syft | `sbom.cdx.json` (CycloneDX, not findings) |

Tool versions, why each was chosen, every flag and where it was verified:
`docs/tools.md`.

## Reports

```
reports/<YYYY-MM-DD>/<repo>/run-<HHMMSS>/   (local time; a same-second rerun gets -2, -3)
  raw/            each tool's own SARIF / SBOM + its log (command line first)
  findings.json   normalised findings: fingerprint, tool, layer, rule, severity, path, line, status
  meta.json       commit, UTC start, tool versions, per-tool status, lockfiles, native ignore files
  summary.md      the human view
  diff.md/.json   vs the previous run of that repo (ordered by recorded UTC start time)
  triage.md       only after `make triage`
```

Every run gets its own folder, so same-day re-runs never overwrite each
other. `reports/`, `work/` (clones) and `test-work/` are gitignored.

**Fingerprints** identify a finding by what it is about, not where it is:
dependency = tool + vuln id + file + package@version; secret = rule + file +
commit + line (a commit never changes); code/config = tool + rule + file +
whitespace-normalised flagged source text + n-th identical occurrence. Lines
moving does not create "new" findings. A tool that errored in either run is
left out of the diff rather than reporting everything as fixed.

**Severity** (critical/high/medium/low): CVSS-like `security-severity` when the
tool gives one; OpenSSF malicious package = critical; any secret = high;
actionlint = medium; otherwise SARIF level error/warning/note = high/medium/low.

## Accepted risks

One file in the scanned repo, `.security-scans.toml`, entries with `reason`
and `expires` (TOML date), matched by fingerprint or rule (+ tool, path glob).
Applied by the runner to all tools alike; expired entries stop suppressing
and the finding comes back as **new** in the diff. Repo-side native ignores
(`.trivyignore`, `nosemgrep`, ...) are switched off where the tool allows and
always listed in the summary. Details: `docs/adding-a-repo.md`, `docs/tools.md`.

## AI triage (`make triage REPO=x`)

Claude Code headless over the latest run's active findings plus the cloned
code. Read-only by construction: only Read/Grep/Glob exist in the session,
`--restricted --safe-mode --strict-mcp-config`, permission prompts auto-denied,
file access confined to the run's triage folder and the clone, environment
rebuilt with no tokens. The scanned code is treated as untrusted (the prompt
says so; the enforcement is the tool restriction, not the prompt). Default
model `sonnet`, cap `--max-budget-usd 1.50`. See `secscan/triage.py`.
Output varies between runs; it is a second opinion, never the baseline.

## CI (opt-in per repo)

`.github/workflows/scan.yml` (reusable, `contents: read` only): `pr` mode
fails only on findings new on the PR head at or above `fail-on` (default
high); `full` mode for the weekly schedule and manual runs. SARIF upload to
code scanning is a separate reusable workflow (`upload-sarif.yml`) a caller
adds only if it wants it. Example caller: `examples/security-scan-caller.yml`.
Not yet run on GitHub (this repo isn't published yet).

## Adding a repo

`docs/adding-a-repo.md`; draft Claude Code skill in
`skills/add-repo-to-security-scans/SKILL.md`.

## Plan

Next steps (CI on OpenClip, release verification policy, CodeQL for all scanned repos):
`docs/plan.md`.

## Tests

- `make test`: unit tests (fingerprints, suppressions, lockfiles, diff, registry).
- `make seeded` builds `test-work/seeded-repo` with a fake secret in history,
  a pinned vulnerable dependency, a known-malicious package pin, injectable
  Flask code, an insecure workflow and a root Dockerfile, then scans it.
  `tests/seed-new-finding.sh` and `tests/seed-expire-suppression.sh` change it
  for the diff and expiry demonstrations.
