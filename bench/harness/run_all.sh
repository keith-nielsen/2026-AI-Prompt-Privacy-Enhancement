#!/usr/bin/env bash
# Pinned to cores 5-7, nice 19. Skips a run if Kent's llama-server is busy (>20% CPU over 2 s).
cd "$(dirname "$0")"
LLAMA=2209076
busy() { bvenv/bin/python -c "import psutil,sys;p=psutil.Process($LLAMA);p.cpu_percent();import time;time.sleep(2);sys.exit(0 if p.cpu_percent()>20 else 1)" 2>/dev/null; }
for cfg in "$@"; do
  model=${cfg%:*}; th=${cfg#*:}
  if busy; then echo "{\"model\":\"$model\",\"threads\":$th,\"skipped\":\"kent busy\"}"; continue; fi
  cores=$( [ "$th" = 1 ] && echo 7 || ([ "$th" = 2 ] && echo 6-7 || echo 5-7) )
  /usr/bin/time -f '{"maxrss_mb":%M}' nice -n 19 taskset -c $cores bvenv/bin/python bench_one.py "$model" "$th" 2>time.err | tail -1
  tail -1 time.err | awk '{gsub(/[^0-9]/,"");printf "  maxrss_mb=%d\n",$0/1024}'
done
