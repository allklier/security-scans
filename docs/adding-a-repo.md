# Adding a repo

Every repo is wired in **local** mode first. CI mode is an opt-in second step.

## 1. Local mode (default)

1. Add a `[[repo]]` entry to `repos.toml`:

   ```toml
   [[repo]]
   name = "Flame_MatteRefine_OFX"          # folder name under work/ and reports/
   github = "allklier/Flame_MatteRefine_OFX"
   mode = "local"
   languages = ["c", "python"]             # dirs in tools/rules/semgrep-rules with security rules
   exclude = ["third_party"]               # vendored code: kept out of SAST
   ```

   Language dirs available: `ls tools/rules/semgrep-rules` (e.g. `python`,
   `c`, `javascript`, `typescript`, `php`, `go`, `bash`, `generic`). A language
   without a `security` subfolder there gets no SAST (the summary says so).
   There is no `cpp` folder and the `c` rules are few, so C++ repos get little
   SAST from Semgrep (consider GitHub CodeQL there, free on public repos).
   GLSL has no Semgrep rules; such repos still get secrets, deps and CI checks.
2. `make scan REPO=<name>` and read `reports/<date>/<name>/run-*/summary.md`.
3. Check the **Lockfiles found** line. No lockfile = a `missing-lockfile`
   finding; decide whether to add one (preferred) or accept it.
4. Triage what's there (optionally `make triage REPO=<name>`), fix what's real.
5. Accepted risks: add `.security-scans.toml` to the repo root (format below)
   and commit it there. Until it's in the repo, a file in this project can be
   used instead: `suppressions = "tests/fixtures/suppressions/<name>.toml"`.
6. Scan again; the diff should show the accepted findings gone from "open".

## Accepted risks file: `.security-scans.toml`

One file, one format for all tools; the runner applies it after the tools
ran (see `secscan/suppress.py`). Every entry needs a reason and an expiry.

```toml
[[accept]]
fingerprint = "18b1847de7117ac2"   # from summary.md (exactly this finding)
reason = "Developer-only script; URL comes from the developer's own CLI arg"
expires = 2027-04-30               # TOML date; after it the finding is active again
owner = "allklier"                 # optional

[[accept]]                         # or by rule (+ optional tool and path glob)
tool = "trivy"
rule = "DS-0026"
path = "docker/*"
reason = "Healthcheck is done by the orchestrator"
expires = 2027-01-31
```

Why one file instead of `.semgrepignore`, `.trivyignore`, `osv-scanner.toml`...:
the native files have no common expiry/reason rule (most have none at all),
so "no silent ignores" can't be enforced across them; one runner-side file
can, and also covers the lockfile check, which has no native file. The native
files in a scanned repo are switched off where possible and always listed in
the summary (docs/tools.md).

An expired entry does not fail the scan; the finding returns as active,
marked "suppression expired <date>", and shows up as **new** in the diff.

## 2. CI mode (opt-in, per repo)

Prerequisite: `allklier/security-scans` published as a **public** repo (a
reusable workflow can be called from another owner's repo only if public).

1. Copy `examples/security-scan-caller.yml` to the repo as
   `.github/workflows/security-scan.yml`.
2. Replace every all-zero SHA with the same full commit SHA of
   security-scans (`git ls-remote https://github.com/allklier/security-scans main`).
3. Set `languages` (and `exclude` if there is vendored code).
4. Keep or remove the `upload` job: code scanning upload is free on public
   repos; private repos need GitHub Code Security.
5. Set `mode = "ci"` for the repo in `repos.toml` (documentation only;
   `make scan` still scans it on demand).
6. Open a PR with the workflow: the PR run is the first test. Then run it once
   by hand (Actions -> security-scan -> Run workflow) for the full mode.

What CI does:

| Trigger | Mode | Fails when |
|---|---|---|
| `pull_request` | `pr`: scans base and head with the same tools; secrets only in the PR's commits | a finding is new on head and at or above `fail-on` (default `high`), or a tool errored |
| `schedule` (weekly), `workflow_dispatch` | `full`: whole tree + full git history | only when a tool errors (findings are reported, not failed) |

Reports are kept as a workflow artifact (`security-scan-pr` / `-full`, 30 days)
and the summary is written to the job summary. Updating the scanner in a repo
= bumping both SHAs in its caller workflow (Dependabot can do this).
