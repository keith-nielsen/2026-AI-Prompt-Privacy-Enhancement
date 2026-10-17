#!/usr/bin/env bash
# Run Gitleaks and detect-secrets on CredData with their default rules, offline, and score them like
# PPE (bench/2026-10-17-creddata.md). Install them first: bench/harness/install_secret_scanners.sh.
#
# Both run with no network at all (a new network namespace: `unshare -n`), so neither can verify a
# secret with its issuer. Memory-capped, lowest priority, cores 5-7. Gitleaks' raw report holds the
# values it found; it is written to WORK, turned into offsets, then deleted. Only offsets (WORK) and
# counts (OUT) remain; OUT is in the repository, WORK must not be.
#
# usage: bench/harness/run_secret_scanners.sh <creddata-repo> <work-dir> <out-dir>
#   e.g. bench/harness/run_secret_scanners.sh /media/administrator/DATA/datasets/Samsung-CredData/repo \
#          /tmp/creddata-work bench/results/2026-10-17-creddata
set -euo pipefail

ROOT=$(realpath "$1")
WORK=$(realpath "$2")
OUT=$3
HERE=bench/harness
GITLEAKS=$HERE/tools/gitleaks-8.30.1/gitleaks
SANDBOX=(systemd-run --user --scope -q -p MemoryMax=6G -p MemorySwapMax=0
  unshare --map-current-user -n -- nice -n 19 taskset -c 5-7)
mkdir -p "$WORK" "$OUT"

# Gitleaks: default config (no --config, no GITLEAKS_CONFIG*, and no .gitleaks.toml under data/).
env -u GITLEAKS_CONFIG -u GITLEAKS_CONFIG_TOML /usr/bin/time -f '%e s, %M KB' -o "$WORK/gitleaks.time" \
  "${SANDBOX[@]}" "$GITLEAKS" dir "$ROOT/data" --no-banner --no-color --log-level error \
  --exit-code 0 --report-format json --report-path "$WORK/gitleaks-raw.json"
python3 -I $HERE/secret_scanner_spans.py gitleaks "$ROOT" "$WORK/gitleaks-raw.json" "$WORK/gitleaks.jsonl" \
  2> "$WORK/gitleaks.tally"
rm -f "$WORK/gitleaks-raw.json"

# detect-secrets: all plugins and default filters (`default_settings()`), no verification; three worker
# processes, progress every 500 files in $WORK/detect-secrets.tally.
/usr/bin/time -f '%e s, %M KB' -o "$WORK/detect-secrets.time" \
  "${SANDBOX[@]}" $HERE/dsvenv/bin/python -I $HERE/secret_scanner_spans.py detect-secrets "$ROOT" \
  "$WORK/detect-secrets.jsonl" 2> "$WORK/detect-secrets.tally"

for tool in gitleaks detect-secrets; do
  echo "$tool: $(cat "$WORK/$tool.time"); located $(tail -n 1 "$WORK/$tool.tally")"
done
