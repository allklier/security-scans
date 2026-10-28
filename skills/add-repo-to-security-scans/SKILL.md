---
name: add-repo-to-security-scans
description: Wire a GitHub repo into the security-scans project (~/ClaudeCode/security-scans), in local mode (registry entry + first scan + accepted-risks file) or CI mode (caller workflow calling the reusable scan workflow). Use when the user asks to add, onboard or wire a repo into security scanning, or to switch a repo to CI scanning.
---

# Add a repo to security-scans

Project: `~/ClaudeCode/security-scans` (read its `CLAUDE.md` and
`docs/adding-a-repo.md` first; they win over this file).

## Ask first (do not guess)

- Which repo (`owner/name`) and which mode: **local** (default) or **ci**?
- Any vendored third-party code to keep out of SAST (e.g. `third_party/`)?
- CI mode only: is `allklier/security-scans` published, and which commit SHA
  should callers pin? Should the repo upload SARIF to code scanning (free on
  public repos, paid Code Security on private ones)?

Never push, open PRs, change repo settings or create repos without the user's
explicit go-ahead. Never modify the user's own working copy of the target
repo; the scanner works on its own clone under `work/`.

## Local mode

1. Look at the repo read-only: `gh api repos/<owner>/<name> --jq '.language,.visibility,.default_branch'`
   and its file list, to choose `languages` (folders in
   `tools/rules/semgrep-rules` that have `**/security` subfolders) and `exclude`.
2. Add a `[[repo]]` entry to `repos.toml` (keys: name, github, mode,
   languages, exclude, suppressions; anything else is rejected).
3. `make scan REPO=<name>`; read `reports/<date>/<name>/run-*/summary.md`.
   Report: tool statuses (any `error` must be explained), lockfile line,
   tool-native ignore files listed, active findings by severity.
4. Optionally `make triage REPO=<name>` (uses the user's Claude account; ask
   before running; one run).
5. For findings the user decides to accept: draft `.security-scans.toml`
   entries (fingerprint or rule+path, reason, expires <= 6 months out).
   Put the draft in `tests/fixtures/suppressions/<name>.toml` and tell the
   user it belongs at the root of the target repo; only the user (or a PR they
   approve) adds it there.
6. `make scan REPO=<name>` again; `make diff REPO=<name>` should show the
   accepted findings no longer open and nothing else changed.

## CI mode

1. Repo must already work in local mode (above).
2. Copy `examples/security-scan-caller.yml` into the target repo's
   `.github/workflows/security-scan.yml` **on a branch in a clone outside the
   user's working copy**, replace every all-zero SHA with the agreed
   security-scans SHA, set `languages`/`exclude`, keep or drop the `upload` job.
3. Validate: `make lint-ci`-style check on that file:
   `source tools/env.sh && actionlint -shellcheck= -pyflakes= <file> && zizmor --offline --persona auditor <file>`.
4. Hand the diff to the user; they push/open the PR. The PR run is the first
   real test; then a manual `workflow_dispatch` run checks full mode.
5. Set `mode = "ci"` in `repos.toml`.

## Done when

- `make scan REPO=<name>` runs with no tool errors and the summary was shown
  to the user.
- Any accepted risks have a reason and an expiry, and the user knows which
  file to add to the target repo.
- CI mode: the caller file passes actionlint + zizmor, and the user has the
  diff to push.
