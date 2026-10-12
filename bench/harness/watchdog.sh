#!/usr/bin/env bash
# usage: watchdog.sh <pid> <swap_baseline_mb> <log>
pid=$1; base=$2; log=$3
while kill -0 "$pid" 2>/dev/null; do
  now=$(free -m | awk '/Swap/{print $3}')
  if [ $((now - base)) -gt 1024 ]; then kill "$pid"; echo "WATCHDOG2: swap grew $((now - base)) MB, stopped" >> "$log"; exit; fi
  sleep 5
done
