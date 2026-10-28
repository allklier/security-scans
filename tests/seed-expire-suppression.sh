#!/usr/bin/env bash
# Acceptance #5 helper: move the seeded repo's still-valid suppression
# (trivy DS-0026, expires 2099-12-31) to a past date. The next scan must show
# that finding as active again ("new" in the diff, marked "suppression expired").
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${1:-$ROOT/test-work/seeded-repo}"
export GIT_AUTHOR_DATE="2026-01-04T00:00:00Z" GIT_COMMITTER_DATE="2026-01-04T00:00:00Z"
sed -i.bak 's/^expires = 2099-12-31$/expires = 2026-10-01/' .security-scans.toml && rm -f .security-scans.toml.bak
git commit -q -am "seeded: let the DS-0026 acceptance expire"
echo "seeded repo now at $(git rev-parse --short HEAD)"
