#!/usr/bin/env bash
# Acceptance #4 helper: commit a new finding to the seeded repo AND shift every
# existing line of app.py down, so the next scan should show exactly the new
# finding(s) as "new" and the shifted ones still "open" (fingerprints don't use
# line numbers alone).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${1:-$ROOT/test-work/seeded-repo}"
export GIT_AUTHOR_DATE="2026-01-03T00:00:00Z" GIT_COMMITTER_DATE="2026-01-03T00:00:00Z"
{ printf '# shifted down by tests/seed-new-finding.sh\n# (line numbers change, findings must not)\n\n'; cat app.py; } > app.py.new
mv app.py.new app.py
cat >> app.py <<'PY'


@app.route("/calc")
def calc():
    return str(eval(request.args.get("expr")))
PY
git commit -q -am "seeded: add eval endpoint (new finding), shift lines"
echo "seeded repo now at $(git rev-parse --short HEAD)"
