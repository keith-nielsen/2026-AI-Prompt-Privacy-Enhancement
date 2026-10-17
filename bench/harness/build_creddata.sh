#!/usr/bin/env bash
# Build Samsung CredData at a pinned commit, the way `ppe evaluate run creddata` expects it.
#
# CredData ships labels (meta/*.csv) and a script that fetches the labelled files from 337 GitHub
# repositories at pinned commits, then replaces every true credential with a seeded random look-alike
# (obfuscate_creds.py). PPE never runs dataset code itself; this one-off build does, after the script
# and the modules it imports (download_data.py, meta_row.py, constants.py, obfuscate_creds.py) were
# read in full at the pinned commit (2026-10-17). It never runs code from the fetched repositories.
#
# Isolation: its own venv with one hash-pinned dependency; no global or system git config (keeps the
# host's git-lfs filter and any other settings out); Git LFS downloads skipped; no credential prompts;
# memory-capped, lowest priority, cores 5-7. Output stays under DIR. The obfuscation is seeded, so the
# build is byte-identical on every run: `ppe evaluate run creddata` checks it against the pinned
# manifest hash.
#
# usage: build_creddata.sh /media/administrator/DATA/datasets      (needs network to github.com)
set -euo pipefail

COMMIT=218aa1708441b2edbd006b98f143c267a16850f0
PYBASE62_SHA256=60539ad956ec9e9de091bc7ae88c9550bc2fa17f503050cf34d021b75e73cb27
DIR="$1/Samsung-CredData"
UV="${UV:-$HOME/ai-env/bin/uv}"

[ -e "$DIR" ] && { echo "$DIR exists: remove it or build elsewhere" >&2; exit 1; }
mkdir -p "$DIR"
git -c core.hooksPath=/dev/null clone -q https://github.com/Samsung/CredData.git "$DIR/repo"
git -C "$DIR/repo" -c core.hooksPath=/dev/null checkout -q "$COMMIT"

printf 'pybase62==1.0.0 --hash=sha256:%s\n' "$PYBASE62_SHA256" > "$DIR/requirements-build.txt"
"$UV" venv -q --python 3.12 "$DIR/venv"
"$UV" pip install -q --python "$DIR/venv/bin/python" --require-hashes --only-binary :all: \
  -r "$DIR/requirements-build.txt"

# The script reads meta/, snapshot.json and word_in_path.json from its working directory and imports
# its sibling modules, so it runs from the checkout (none of them shadows a standard-library module).
cd "$DIR/repo"
env GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_LFS_SKIP_SMUDGE=1 GIT_TERMINAL_PROMPT=0 \
  systemd-run --user --scope -q -p MemoryMax=4G -p MemorySwapMax=0 \
  nice -n 19 taskset -c 5-7 "$DIR/venv/bin/python" -E -s download_data.py --data_dir data --jobs 4 \
  > "$DIR/build.log" 2>&1
echo "built: $DIR/repo/data (log $DIR/build.log); tmp/ holds the full checkouts and can be removed"
