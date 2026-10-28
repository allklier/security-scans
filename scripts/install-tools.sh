#!/usr/bin/env bash
# Install the pinned scanner toolchain (see tools/versions.env).
#
#   scripts/install-tools.sh            # Linux: conda env "secscan" (or a venv if no conda)
#                                       # macOS: same pinned release downloads + venv (UNTESTED)
#   scripts/install-tools.sh --brew     # macOS: Homebrew formulae instead (UNTESTED; cannot pin)
#
# Single-binary tools come from each project's GitHub release at the pinned
# version and are verified against that release's published checksum file
# before they are unpacked into tools/bin/. Python tools are installed from
# tools/requirements.lock with --require-hashes. Nothing is installed system-wide.
#
# Writes tools/env.sh, which the Makefile sources (PATH + SECSCAN_PYTHON).
# Bash 3.2 compatible (macOS /bin/bash).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/tools/bin"
RULES_DIR="$ROOT/tools/rules/semgrep-rules"
# shellcheck source=../tools/versions.env
. "$ROOT/tools/versions.env"

USE_BREW=0
PY_MODE="${SECSCAN_PY_MODE:-auto}"   # auto | conda | venv
for arg in "$@"; do
  case "$arg" in
    --brew) USE_BREW=1 ;;
    --venv) PY_MODE=venv ;;
    --conda) PY_MODE=conda ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

log() { printf '[install] %s\n' "$*"; }
die() { printf '[install] ERROR: %s\n' "$*" >&2; exit 1; }

case "$(uname -s)" in
  Linux) OS=linux ;;
  Darwin) OS=darwin ;;
  *) die "unsupported OS $(uname -s)" ;;
esac
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  arm64|aarch64) ARCH=arm64 ;;
  *) die "unsupported arch $(uname -m)" ;;
esac
[ "$USE_BREW" = 1 ] && [ "$OS" != darwin ] && die "--brew is only for macOS"

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

# fetch_verified <repo> <tag> <asset> <checksums-asset> <dest-file>
# Downloads the asset and the release's checksum file into a fresh temp dir,
# and fails unless the asset's sha256 is listed for that exact file name.
fetch_verified() {
  local repo="$1" tag="$2" asset="$3" sums="$4" dest="$5" tmp want got
  tmp="$(mktemp -d)"
  local base="https://github.com/$repo/releases/download/$tag"
  curl -fsSL --retry 3 -o "$tmp/$asset" "$base/$asset" || die "download failed: $base/$asset"
  curl -fsSL --retry 3 -o "$tmp/$sums" "$base/$sums" || die "download failed: $base/$sums"
  want="$(awk -v f="$asset" '{n=$2; sub(/^\*/,"",n); if (n==f) print $1}' "$tmp/$sums")"
  [ -n "$want" ] || die "$asset not listed in $sums"
  got="$(sha256_of "$tmp/$asset")"
  [ "$want" = "$got" ] || die "checksum mismatch for $asset: want $want got $got"
  log "verified $asset sha256=$got"
  mv "$tmp/$asset" "$dest"
  rm -rf "$tmp"
}

# install_bin <name> <version> <repo> <tag> <asset> <sums> <kind: raw|tgz> [member]
install_bin() {
  local name="$1" ver="$2" repo="$3" tag="$4" asset="$5" sums="$6" kind="$7" member="${8:-$1}"
  local stamp="$BIN/.$name.version"
  if [ -x "$BIN/$name" ] && [ "$(cat "$stamp" 2>/dev/null)" = "$ver" ]; then
    log "$name $ver already installed"; return
  fi
  local work; work="$(mktemp -d)"
  fetch_verified "$repo" "$tag" "$asset" "$sums" "$work/$asset"
  if [ "$kind" = tgz ]; then
    mkdir "$work/x"
    tar -xzf "$work/$asset" -C "$work/x" "$member"
    mv "$work/x/$member" "$BIN/$name"
  else
    mv "$work/$asset" "$BIN/$name"
  fi
  chmod 0755 "$BIN/$name"
  echo "$ver" > "$stamp"
  rm -rf "$work"
  log "installed $name $ver"
}

install_release_binaries() {
  mkdir -p "$BIN"
  local gl_arch tv_os tv_arch
  # Asset names as published on each release page (checked 2026-10-28 with
  # `gh api repos/<repo>/releases/tags/<tag> --jq '.assets[].name'`).
  install_bin osv-scanner "$OSV_SCANNER_VERSION" google/osv-scanner "v$OSV_SCANNER_VERSION" \
    "osv-scanner_${OS}_${ARCH}" "osv-scanner_SHA256SUMS" raw
  if [ "$ARCH" = amd64 ]; then gl_arch=x64; else gl_arch=arm64; fi
  install_bin gitleaks "$GITLEAKS_VERSION" gitleaks/gitleaks "v$GITLEAKS_VERSION" \
    "gitleaks_${GITLEAKS_VERSION}_${OS}_${gl_arch}.tar.gz" "gitleaks_${GITLEAKS_VERSION}_checksums.txt" tgz gitleaks
  install_bin actionlint "$ACTIONLINT_VERSION" rhysd/actionlint "v$ACTIONLINT_VERSION" \
    "actionlint_${ACTIONLINT_VERSION}_${OS}_${ARCH}.tar.gz" "actionlint_${ACTIONLINT_VERSION}_checksums.txt" tgz actionlint
  if [ "$OS" = linux ]; then tv_os=Linux; else tv_os=macOS; fi
  if [ "$ARCH" = amd64 ]; then tv_arch=64bit; else tv_arch=ARM64; fi
  install_bin trivy "$TRIVY_VERSION" aquasecurity/trivy "v$TRIVY_VERSION" \
    "trivy_${TRIVY_VERSION}_${tv_os}-${tv_arch}.tar.gz" "trivy_${TRIVY_VERSION}_checksums.txt" tgz trivy
  install_bin syft "$SYFT_VERSION" anchore/syft "v$SYFT_VERSION" \
    "syft_${SYFT_VERSION}_${OS}_${ARCH}.tar.gz" "syft_${SYFT_VERSION}_checksums.txt" tgz syft
}

check_lock_matches_manifest() {
  grep -q "^semgrep==$SEMGREP_VERSION " "$ROOT/tools/requirements.lock" \
    || die "tools/requirements.lock does not pin semgrep==$SEMGREP_VERSION (see docs/tools.md, Updating a pin)"
  grep -q "^zizmor==$ZIZMOR_VERSION " "$ROOT/tools/requirements.lock" \
    || die "tools/requirements.lock does not pin zizmor==$ZIZMOR_VERSION (see docs/tools.md, Updating a pin)"
}

# Sets PYDIR (directory holding python, semgrep, zizmor).
install_python_tools() {
  check_lock_matches_manifest
  local mode="$PY_MODE" conda_bin="" py
  if [ "$mode" = auto ]; then
    conda_bin="$(command -v conda || true)"
    [ -z "$conda_bin" ] && [ -x "$HOME/anaconda3/bin/conda" ] && conda_bin="$HOME/anaconda3/bin/conda"
    if [ "$OS" = linux ] && [ -n "$conda_bin" ]; then mode=conda; else mode=venv; fi
  fi
  if [ "$mode" = conda ]; then
    [ -n "$conda_bin" ] || conda_bin="$(command -v conda || echo "$HOME/anaconda3/bin/conda")"
    local envdir
    envdir="$("$conda_bin" env list --json | python3 -c 'import json,sys; print(next((p for p in json.load(sys.stdin)["envs"] if p.rstrip("/").endswith("/envs/secscan")), ""))')"
    if [ -z "$envdir" ]; then
      log "creating conda env secscan (python=$PYTHON_VERSION)"
      "$conda_bin" create -y -n secscan "python=$PYTHON_VERSION" pip
      envdir="$("$conda_bin" run -n secscan python -c 'import sys; print(sys.prefix)')"
    fi
    PYDIR="$envdir/bin"
  else
    py="${SECSCAN_BOOTSTRAP_PYTHON:-python$PYTHON_VERSION}"
    command -v "$py" >/dev/null || die "need $py for the venv (macOS: brew install python@$PYTHON_VERSION)"
    [ -x "$ROOT/tools/venv/bin/python" ] || "$py" -m venv "$ROOT/tools/venv"
    PYDIR="$ROOT/tools/venv/bin"
  fi
  log "installing Python tools into $PYDIR (hash-locked)"
  "$PYDIR/python" -m pip install --quiet --disable-pip-version-check \
    --require-hashes --no-deps -r "$ROOT/tools/requirements.lock"
}

# macOS Homebrew mode (UNTESTED). Formula names verified 2026-10-28 via
# https://formulae.brew.sh/api/formula/<name>.json. Homebrew installs the
# formula's *current* version, so versions can drift from tools/versions.env;
# drift is reported below, never silently accepted.
install_brew() {
  command -v brew >/dev/null || die "Homebrew not found"
  brew install osv-scanner gitleaks actionlint trivy syft semgrep zizmor "python@$PYTHON_VERSION"
  PYDIR="$(brew --prefix "python@$PYTHON_VERSION")/libexec/bin"
  local t want have drift=0
  for t in osv-scanner:"$OSV_SCANNER_VERSION" gitleaks:"$GITLEAKS_VERSION" actionlint:"$ACTIONLINT_VERSION" \
           trivy:"$TRIVY_VERSION" syft:"$SYFT_VERSION" semgrep:"$SEMGREP_VERSION" zizmor:"$ZIZMOR_VERSION"; do
    want="${t#*:}"; t="${t%%:*}"
    have="$(brew list --versions "$t" | awk '{print $2}')"
    if [ "$have" != "$want" ]; then log "WARNING: $t brew=$have manifest=$want"; drift=1; fi
  done
  [ "$drift" = 0 ] || log "WARNING: Homebrew versions differ from tools/versions.env; findings may differ from Linux runs"
}

install_rules() {
  if [ "$(git -C "$RULES_DIR" rev-parse HEAD 2>/dev/null || true)" = "$SEMGREP_RULES_COMMIT" ]; then
    log "semgrep-rules $SEMGREP_RULES_COMMIT already present"; return
  fi
  rm -rf "$RULES_DIR"; mkdir -p "$RULES_DIR"
  git -C "$RULES_DIR" init -q
  git -C "$RULES_DIR" fetch -q --depth 1 "$SEMGREP_RULES_REPO" "$SEMGREP_RULES_COMMIT"
  git -C "$RULES_DIR" -c advice.detachedHead=false checkout -q FETCH_HEAD
  [ "$(git -C "$RULES_DIR" rev-parse HEAD)" = "$SEMGREP_RULES_COMMIT" ] || die "semgrep-rules commit mismatch"
  log "semgrep-rules pinned at $SEMGREP_RULES_COMMIT"
}

PYDIR=""
if [ "$USE_BREW" = 1 ]; then
  install_brew
else
  install_release_binaries
  install_python_tools
fi
install_rules

if [ "$USE_BREW" = 1 ]; then PATH_DIRS="$PYDIR"; else PATH_DIRS="$BIN:$PYDIR"; fi
cat > "$ROOT/tools/env.sh" <<EOF
# generated by scripts/install-tools.sh; sourced by the Makefile
export SECSCAN_PYTHON="$PYDIR/python"
export PATH="$PATH_DIRS:\$PATH"
EOF
log "wrote tools/env.sh"
