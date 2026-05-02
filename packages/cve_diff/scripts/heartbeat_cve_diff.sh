#!/usr/bin/env bash
# heartbeat_cve_diff.sh — one-line bench status per fire.
#
# Designed to be called by a Monitor heartbeat loop:
#
#   ( while kill -0 $BENCH_PID 2>/dev/null; do
#       ./scripts/heartbeat_cve_diff.sh /tmp/bench_X
#       sleep 300
#     done ) &
#   tail -F /tmp/bench_X.log | grep --line-buffered -E '<filter>'
#
# Usage: heartbeat_cve_diff.sh <bench_output_dir>
#   Reads <bench_output_dir>.log (the bench's stdout log).
#   Emits 3 lines summarizing progress, recent CVEs, cost+disk.
#
# Per-fire output (~3 lines):
#   [HH:MM:SS] N/M · PASS=P FAIL=F (rate%) · pace=p/min · ETA ~m
#     recent: ✓ CVE-A · ✓ CVE-B · ✗ CVE-C
#     cost: $X · disk: NGi free
#
# Filter pattern for the companion `tail -F | grep` invocation:
#   '^\[[0-9]+/[0-9]+\] FAIL|^=== [0-9]+/[0-9]+ passed|Traceback|PerCveTimeout|DiskBudgetExceeded|Killed|llm_error|429|529'

set -u
BENCH_DIR="${1:?usage: heartbeat_cve_diff.sh <bench_output_dir>}"
LOG="${BENCH_DIR}.log"
TS="$(date '+%H:%M:%S')"

if [ ! -f "$LOG" ]; then
    echo "[$TS] (no log at $LOG)"
    exit 0
fi

# Latest progress line — extract done_n / total
last_line=$(grep -E "^\[[0-9]+/[0-9]+\]" "$LOG" | tail -1)
if [ -z "$last_line" ]; then
    echo "[$TS] bench starting (no CVE results yet)"
    exit 0
fi

done_n=$(echo "$last_line" | sed -E 's|^\[([0-9]+)/.*|\1|')
total=$(echo "$last_line" | sed -E 's|^\[[0-9]+/([0-9]+)\].*|\1|')

# Outcome counts
pass_count=$(grep -cE "^\[[0-9]+/[0-9]+\] PASS" "$LOG" || true)
fail_count=$(grep -cE "^\[[0-9]+/[0-9]+\] FAIL" "$LOG" || true)
rate=$(( done_n > 0 ? pass_count * 100 / done_n : 0 ))

# Pace + ETA from log mtime (proxy for bench start)
launched_ts=$(stat -f "%B" "$LOG" 2>/dev/null || stat -c "%Y" "$LOG" 2>/dev/null || echo 0)
now=$(date +%s)
elapsed=$(( now - launched_ts ))
if [ "$elapsed" -gt 5 ] && [ "$done_n" -gt 0 ]; then
    pace=$(awk "BEGIN { printf \"%.1f\", $done_n * 60.0 / $elapsed }")
    remaining=$(( total - done_n ))
    eta_min=$(awk "BEGIN { printf \"%d\", $remaining * $elapsed / $done_n / 60 }")
else
    pace="?"
    eta_min="?"
fi

# Recent 3 CVEs (compact format)
recent=$(grep -E "^\[[0-9]+/[0-9]+\]" "$LOG" | tail -3 | awk '{
    if ($2 == "PASS") printf "✓ %s · ", $3
    else printf "✗ %s · ", $3
}' | sed 's/ · $//')

# Cost (only present after bench end via summary.json)
cost="(in flight)"
if [ -f "${BENCH_DIR}/summary.json" ]; then
    cost=$(python3 -c "
import json
try:
    d = json.load(open('${BENCH_DIR}/summary.json'))
    c = sum(r.get('agent_cost_usd', 0) or 0 for r in d.get('results', []))
    print('\$' + format(c, '.2f'))
except: print('?')
" 2>/dev/null || echo "?")
fi

# Disk free on /tmp
disk=$(df -h /tmp 2>/dev/null | tail -1 | awk '{print $4}')

echo "[$TS] $done_n/$total · PASS=$pass_count FAIL=$fail_count (${rate}%) · pace=${pace}/min · ETA ~${eta_min}m"
echo "  recent: ${recent:-(none)}"
echo "  cost: ${cost} · disk: ${disk:-?} free"
