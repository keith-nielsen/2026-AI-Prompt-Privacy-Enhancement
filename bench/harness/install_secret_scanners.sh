#!/usr/bin/env bash
# Install the secret-scanner baselines for the CredData bench (bench/2026-10-17-creddata.md):
#   Gitleaks 8.30.1 (MIT), the release binary, kept only if its sha256 matches the pin below;
#   detect-secrets 1.5.0 (Apache-2.0), its own venv, every package hash-pinned.
# Both run offline (bench/harness/run_secret_scanners.sh); neither is a PPE dependency.
#
# usage: bench/harness/install_secret_scanners.sh        (from the repository root; needs network)
set -euo pipefail

GITLEAKS_VERSION=8.30.1
GITLEAKS_SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb  # linux_x64 tarball
HERE=bench/harness
UV="${UV:-$HOME/ai-env/bin/uv}"

dest="$HERE/tools/gitleaks-$GITLEAKS_VERSION"
if [ ! -x "$dest/gitleaks" ]; then
  tmp=$(mktemp -d)
  tgz="$tmp/gitleaks.tar.gz"
  curl -sSL -o "$tgz" \
    "https://github.com/gitleaks/gitleaks/releases/download/v$GITLEAKS_VERSION/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
  echo "$GITLEAKS_SHA256  $tgz" | sha256sum -c --quiet
  mkdir -p "$dest"
  tar -xzf "$tgz" -C "$dest" gitleaks LICENSE
  rm -rf "$tmp"
fi
"$dest/gitleaks" version

[ -x "$HERE/dsvenv/bin/python" ] || "$UV" venv -q --python 3.12 "$HERE/dsvenv"
"$UV" pip install -q --python "$HERE/dsvenv/bin/python" --require-hashes --only-binary :all: \
  -r "$HERE/requirements-detect-secrets.txt"
"$HERE/dsvenv/bin/detect-secrets" --version
