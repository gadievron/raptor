#!/usr/bin/env bash
#
# zkpox regression harness — runs the prover binary against every
# witness in ./witnesses/ and asserts both gadgets' verdicts:
#
#   *-benign.bin   crash_only=false  AND  oob_detected=false
#   *-crash.bin    crash_only=true   AND  oob_detected=true
#   *-fn.bin       crash_only=false  AND  oob_detected=true
#                  (deliberate canarymatch witness — crash_only is blind
#                  to it; oob_write *must* catch it. If oob_write also
#                  misses, that's a real regression.)
#
# Usage:
#   ./run-tests.sh                       # execute mode (fast)
#   ./run-tests.sh --prove               # full prove mode (slow!)
#   ./run-tests.sh --binary path/to/elf

set -uo pipefail
# NB: no `set -e` — we want to keep iterating after individual failures
# so the summary is informative.

cd "$(dirname "$0")"

MODE="--execute"
# Default binary path: ../target/release/zkpox-prove (workspace target dir
# at core/zkpox/target/, this script runs from core/zkpox/test/).
BIN="../target/release/zkpox-prove"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --prove) MODE="--prove"; shift ;;
        --execute) MODE="--execute"; shift ;;
        --binary) BIN="$2"; shift 2 ;;
        -h|--help) sed -n '2,/^$/p' "$0"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

if [[ ! -x "$BIN" ]]; then
    echo "harness not built: $BIN" >&2
    echo "build it with: (cd harness/host && cargo build --release)" >&2
    exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "jq is required" >&2
    exit 2
fi

pass=0
fail=0
declare -a failures=()

shopt -s nullglob
for w in witnesses/*.bin; do
    base=$(basename "$w" .bin)
    # Filename schema: <NN>-<descriptor>-<verdict>.bin where NN is the
    # target id ("01" or "02"); see witnesses/generate.py.
    target="${base:0:2}"
    case "$target" in
        01|02) ;;
        *) echo "skip: $base (no target prefix)"; continue ;;
    esac
    case "$base" in
        *-benign) expected_crash="false" expected_oob="false" ;;
        *-crash)  expected_crash="true"  expected_oob="true"  ;;
        *-fn)     expected_crash="false" expected_oob="true"  ;;
        *) echo "skip: $base (no verdict suffix)"; continue ;;
    esac

    out=$("$BIN" --witness "$w" "--target=$target" $MODE --tag "regression:$base" 2>/dev/null) || {
        printf '  [ERROR]    %-40s harness exited non-zero\n' "$base"
        failures+=("$base (harness error)")
        fail=$((fail + 1))
        continue
    }

    crash=$(echo "$out" | jq -r '.verdicts.crash_only_crashed')
    oob=$(echo "$out" | jq -r '.verdicts.oob_detected')
    oob_count=$(echo "$out" | jq -r '.verdicts.oob_count')
    oob_offset=$(echo "$out" | jq -r '.verdicts.oob_first_offset')
    target_id=$(echo "$out" | jq -r '.verdicts.target_id')
    metric=$(echo "$out" | jq -r '.cycles // .wall_secs')

    # Soundness check: the guest must echo back the target id we sent.
    expected_target_id=$((10#$target))
    if [[ "$target_id" != "$expected_target_id" ]]; then
        printf '  [FAIL] %-38s target_id=%s/%s (guest dispatch wrong)\n' \
            "$base" "$target_id" "$expected_target_id"
        failures+=("$base (target_id=$target_id/$expected_target_id)")
        fail=$((fail + 1))
        continue
    fi

    if [[ "$crash" == "$expected_crash" && "$oob" == "$expected_oob" ]]; then
        printf '  [PASS] %-38s t=%s crash_only=%-5s oob=%-5s n=%s @off=%s metric=%s\n' \
            "$base" "$target_id" "$crash" "$oob" "$oob_count" "$oob_offset" "$metric"
        pass=$((pass + 1))
    else
        printf '  [FAIL] %-38s crash_only=%s/%s oob=%s/%s\n' \
            "$base" "$crash" "$expected_crash" "$oob" "$expected_oob"
        failures+=("$base (crash_only=$crash/$expected_crash oob=$oob/$expected_oob)")
        fail=$((fail + 1))
    fi
done

echo
echo "----- summary -----"
echo "passed: $pass"
echo "failed: $fail"

if (( fail > 0 )); then
    printf '\nfailures:\n'
    printf '  - %s\n' "${failures[@]}"
    exit 1
fi
