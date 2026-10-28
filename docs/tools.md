# Tools: choice, pins, flags

Reference for the toolchain. Pins live in `tools/versions.env` (the one
manifest); Python tool hashes in `tools/requirements.lock`.

## Chosen set (minimal for the five layers)

| Layer | Tool | Version | Installed from | Why this one |
|---|---|---|---|---|
| 1 deps (CVEs) | OSV-Scanner | 2.7.0 | GitHub release binary, sha256 from `osv-scanner_SHA256SUMS` | One tool for every ecosystem's lockfiles; OSV covers PyPI/npm/Go/crates/etc. |
| 2 malicious pkgs | OSV-Scanner (same run) | | | OSV includes the OpenSSF malicious-packages feed (`MAL-*` ids); shown as layer `2-malicious`, severity critical |
| 1 deps (lockfile) | built-in check (`secscan/findings.py`) | | | Brief: "flag any repo without a lockfile" |
| 3 own code | Semgrep CE | 1.180.0 | PyPI, hash-locked | Semgrep CE + pinned `semgrep/semgrep-rules` commit: runs offline, no login, reproducible. Opengrep was the alternative, but its releases publish only cosign signatures, no checksum file, and verifying them would need cosign as one more tool. |
| 3 rules | semgrep-rules | commit `9bbf021d` (2026-10-08) | git fetch by SHA | Only `<language>/**/security` rule dirs are used (no best-practice/style noise). Licence: Semgrep Rules License v1.0 (internal use; we download, never redistribute). |
| 4 secrets | Gitleaks | 8.30.1 | release, `gitleaks_8.30.1_checksums.txt` | Full git history (`--log-opts=--all`); redacts secrets in its report |
| 5 Actions | zizmor | 1.30.1 | PyPI, hash-locked | Actions security audits (injection, dangerous triggers, unpinned uses, permissions). Releases ship binaries without checksums; PyPI hashes are verifiable. |
| 5 Actions | actionlint | 1.7.12 | release, `actionlint_1.7.12_checksums.txt` | Workflow correctness + untrusted-expression checks |
| 5 IaC/containers | Trivy (misconfig only) | 0.75.0 | release, `trivy_0.75.0_checksums.txt` | Dockerfile/Terraform/k8s/Helm checks. Runs on every repo (cheap; empty when nothing applies). Vuln and secret scanners off: OSV and Gitleaks own those. |
| SBOM | Syft | 1.54.1 | release, `syft_1.54.1_checksums.txt` | CycloneDX SBOM per run, to re-check old commits against new CVEs |

Not added (cost > value for now): GuardDog (needs its own semgrep + yara; OSV
already covers known-malicious packages), Bandit (overlaps Semgrep's Python
security rules), pip-audit (overlaps OSV for PyPI), hadolint (Trivy covers
Dockerfile security), TruffleHog (live-key verification means network calls
with found secrets; can be added later), CodeQL (planned for all
scanned repos: see `docs/plan.md` §5; its licence allows it only on code under an
OSI-approved licence).

**Pinning policy**: a release must be at least 14 days old when pinned. Trivy
had a supply-chain compromise in March 2026 (GHSA-69fq-xp46-6x23; malicious
release and rewritten action tags); 0.75.0 is after it and after the fixes
for GHSA-mcj4-mphf-j9ff and GHSA-8rc5-4fr6-64pw.

Transitive Python dependencies in `requirements.lock` were resolved to the
latest versions on 2026-10-28 (pip-tools has no "exclude newer" option);
they are hash-pinned but not cooled down.

## Flags used and where they were verified (pinned versions, 2026-10-28)

| Tool | Flags | Verified with |
|---|---|---|
| osv-scanner | `scan source -r --no-ignore --no-resolve --config F --format sarif --output-file F` | `osv-scanner scan source --help` |
| semgrep | `scan --metrics=off --disable-version-check --disable-nosem --quiet --sarif-output=F --config DIR --exclude=PAT` | `semgrep scan --help` |
| gitleaks | `git --no-banner --redact --exit-code 0 --ignore-gitleaks-allow -c F -i DIR --log-opts=X --report-format sarif --report-path F` | `gitleaks --help`, `gitleaks git --help`; `[extend] useDefault = true` from the v8.30.1 README |
| zizmor | `--offline --no-config --no-ignores --no-progress --no-exit-codes --format sarif` | `zizmor --help` |
| actionlint | `-format TEMPLATE -shellcheck= -pyflakes= -config-file F` | `actionlint -h`; SARIF template is `testdata/format/sarif_template.txt` from rhysd/actionlint v1.7.12 (MIT), linked from its docs/usage.md |
| trivy | `fs --scanners misconfig --skip-check-update --ignorefile "" --disable-telemetry --skip-version-check --quiet --format sarif --output F` | `trivy fs --help` |
| syft | `scan dir:P -q -o cyclonedx-json=F --source-name N --source-version V`, env `SYFT_CHECK_FOR_APP_UPDATE=false` | `syft scan --help`; `syft config` lists `check-for-app-update` |
| claude | see `secscan/triage.py` docstring | `claude --help` (2.1.281) |

Behaviour notes found while building:
- osv-scanner applies `.gitignore` files of *enclosing* directories; `work/`
  is in this project's `.gitignore`, so without `--no-ignore` it scanned
  nothing. Fresh clones have no ignored files, so `--no-ignore` changes nothing else.
- osv-scanner `--no-resolve`: only versions written in the file are checked.
  For an unpinned `lxml>=5.0` that means 5.0 (the floor) is checked, which
  answers "can a user end up with a vulnerable version?". Resolution via
  deps.dev was dropped: it changes over time and fails on removed packages.
- osv-scanner's SARIF repeats some results; the runner drops exact duplicates.
- Semgrep rule ids carry the rules directory path; the runner strips
  everything up to `semgrep-rules.` so ids match across machines.
- zizmor reports paths relative to an *enclosing* repo when the scanned tree
  is a git worktree; the runner maps them back.
- actionlint's shellcheck/pyflakes integrations are off because those tools
  are not pinned here (their findings would depend on what is on PATH).
- Trivy `--skip-check-update` uses the checks embedded in the pinned binary
  (no download of the floating `trivy-checks:2` bundle).

## Neutralising repo-side ignores ("no silent ignores")

Accepted risks belong in `.security-scans.toml` (reason + expiry). A scanned
repo's tool-native ignores are switched off where the tool allows, and their
presence is always listed in `summary.md`:

| Mechanism | Handling |
|---|---|
| `# nosemgrep` comments | off (`--disable-nosem`) |
| `.semgrepignore` | **still honoured** (only an `[INTERNAL]` flag disables it); listed in summary |
| `gitleaks:allow` comments, `.gitleaksignore`, `.gitleaks.toml` | off (`--ignore-gitleaks-allow`, `-i <empty dir>`, `-c tools/config/gitleaks.toml`) |
| zizmor ignore comments / `zizmor.yml` | off (`--no-ignores --no-config`) |
| `.trivyignore`, `trivy.yaml` | off (`--ignorefile ""`, run outside the repo) |
| `osv-scanner.toml` | off (`--config tools/config/osv-scanner.toml`, empty) |
| `.github/actionlint.yaml` | off (`-config-file tools/config/actionlint.yaml`, empty) |
| Trivy inline `trivy:ignore` comments | not handled (known gap) |

## Updating a pin

1. Pick a release at least 14 days old; edit `tools/versions.env`.
2. Binary tools: nothing else; `make tools` downloads and verifies it.
3. semgrep / zizmor: also edit `tools/requirements.in`, then regenerate the lock
   in a throwaway venv (pip-tools is not part of the toolchain):
   `python3.12 -m venv /tmp/pt && /tmp/pt/bin/pip install pip-tools &&
   /tmp/pt/bin/pip-compile --generate-hashes --allow-unsafe --strip-extras
   --no-emit-index-url -o tools/requirements.lock tools/requirements.in`.
   `install-tools.sh` refuses to run if the lock and the manifest disagree.
4. semgrep-rules: set `SEMGREP_RULES_COMMIT` to a commit on `develop`.
5. Run `make scan` twice and `make diff`: findings that change are due to the
   new pin; note them in the commit message.

## macOS (UNTESTED: no Mac available while building)

- Default (`make tools`): the same pinned, checksum-verified darwin release
  binaries as Linux, Python tools in `tools/venv` from `python3.12`
  (`brew install python@3.12`). Asset names were checked on each release page.
- `scripts/install-tools.sh --brew`: Homebrew formulae `osv-scanner gitleaks
  actionlint trivy syft semgrep zizmor python@3.12` (names verified via
  https://formulae.brew.sh/api/formula/<name>.json). Homebrew cannot pin
  versions; the script warns on any drift from `tools/versions.env`. On
  2026-10-28 brew would install trivy 0.76.1, syft 1.55.0, semgrep 1.182.0,
  zizmor 1.31.1 (newer than the pins).
- The scripts avoid GNU-only options (bash 3.2, `shasum` fallback, `sed -i.bak`).
