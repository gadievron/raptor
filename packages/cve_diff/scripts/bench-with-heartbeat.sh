#!/usr/bin/env bash
# bench-with-heartbeat.sh — launch `cve-diff bench` with Monitor-ready wiring.
#
# Wraps `cve-diff bench` so every long bench gets live progress notifications
# via the Monitor tool. Eliminates the "I forgot to wire heartbeat" discipline
# gap.
#
# Usage:
#   ./scripts/bench-with-heartbeat.sh --sample <X> --output-dir <Y> [-w N] [--disk-limit-pct P] [--filter <regex>]
#
# What it does:
#   1. Validates args, ensures heartbeat script is executable
#   2. Launches `cve-diff bench` in the background, captures PID
#   3. Prints the BENCH_PID + a copy-pasteable Monitor command block
#
# After running, paste the printed Monitor command into the Monitor tool with
# persistent: true and timeout_ms: 3600000 (1h) or longer.
#
# Defaults:
#   - heartbeat interval: 300s (override with HEARTBEAT_INTERVAL env)
#   - filter pattern: catches FAIL + bench-end + every crash signature
#     (override with --filter or FILTER env)

set -u

# --- Arg parsing ---
SAMPLE=""
OUTPUT_DIR=""
WORKERS="${WORKERS:-2}"
DISK_LIMIT="${DISK_LIMIT:-95}"
FILTER="${FILTER:-^\[[0-9]+/[0-9]+\] FAIL|^=== [0-9]+/[0-9]+ passed|Traceback|PerCveTimeout|DiskBudgetExceeded|Killed|llm_error|429|529}"
INTERVAL="${HEARTBEAT_INTERVAL:-300}"

while [ $# -gt 0 ]; do
    case "$1" in
        --sample)         SAMPLE="$2";          shift 2 ;;
        --output-dir|-o)  OUTPUT_DIR="$2";      shift 2 ;;
        -w|--workers)     WORKERS="$2";         shift 2 ;;
        --disk-limit-pct) DISK_LIMIT="$2";      shift 2 ;;
        --filter)         FILTER="$2";          shift 2 ;;
        --interval)       INTERVAL="$2";        shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 1 ;;
    esac
done

[ -n "$SAMPLE" ]     || { echo "ERROR: --sample required" >&2; exit 1; }
[ -n "$OUTPUT_DIR" ] || { echo "ERROR: --output-dir required" >&2; exit 1; }

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HEARTBEAT="$REPO_ROOT/scripts/heartbeat_cve_diff.sh"
[ -x "$HEARTBEAT" ] || { echo "ERROR: heartbeat not executable: $HEARTBEAT" >&2; exit 1; }

# Sanity
[ -f "$SAMPLE" ] || { echo "ERROR: sample not found: $SAMPLE" >&2; exit 1; }
mkdir -p "$OUTPUT_DIR"

# Compute log path next to output dir
LOG="${OUTPUT_DIR}.log"

# --- Launch bench in background ---
ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-$(cat ~/.cve-diff-agent-key 2>/dev/null)}"
GITHUB_TOKEN="${GITHUB_TOKEN:-$(gh auth token 2>/dev/null)}"

[ -n "$ANTHROPIC_API_KEY" ] || { echo "ERROR: ANTHROPIC_API_KEY not set" >&2; exit 1; }
[ -n "$GITHUB_TOKEN" ]      || { echo "ERROR: GITHUB_TOKEN not set" >&2; exit 1; }

ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" GITHUB_TOKEN="$GITHUB_TOKEN" \
    "$REPO_ROOT/.venv/bin/cve-diff" bench \
        --sample "$SAMPLE" \
        --output-dir "$OUTPUT_DIR" \
        -w "$WORKERS" \
        --disk-limit-pct "$DISK_LIMIT" \
        > "$LOG" 2>&1 &
BENCH_PID=$!

# Persist PID for the Monitor command to find
echo "$BENCH_PID" > "${OUTPUT_DIR}.pid"

# --- Emit Monitor-ready command ---
cat <<EOF
=== bench launched ===
  pid:       $BENCH_PID
  sample:    $SAMPLE
  output:    $OUTPUT_DIR
  log:       $LOG
  workers:   $WORKERS
  disk gate: ${DISK_LIMIT}%
  heartbeat: every ${INTERVAL}s

=== paste this into the Monitor tool (persistent: true, timeout_ms: 3600000) ===

( while kill -0 $BENCH_PID 2>/dev/null; do
    $HEARTBEAT $OUTPUT_DIR
    sleep $INTERVAL
  done
  echo "[heartbeat] bench PID $BENCH_PID exited at \$(date '+%H:%M:%S')"
) &
HB=\$!
trap "kill \$HB 2>/dev/null" EXIT
tail -n +1 -F $LOG 2>/dev/null | grep --line-buffered -E '$FILTER'

EOF
