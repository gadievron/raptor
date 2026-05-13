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
CI_SUBSET=0
# Default binary path: ../target/release/zkpox-prove (workspace target dir
# at core/zkpox/target/, this script runs from core/zkpox/test/).
BIN="../target/release/zkpox-prove"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --prove) MODE="--prove"; shift ;;
        --execute) MODE="--execute"; shift ;;
        --binary) BIN="$2"; shift 2 ;;
        --ci-subset) CI_SUBSET=1; shift ;;
        -h|--help) sed -n '2,/^$/p' "$0"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

if [[ ! -x "$BIN" ]]; then
    echo "prover not built: $BIN" >&2
    echo "build it with: cargo build --release --manifest-path core/zkpox/Cargo.toml" >&2
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
if (( CI_SUBSET )); then
    # PR-tier CI subset — the *brutal* minimum that still validates
    # each target's gadget story end-to-end. Each SP1 SDK startup is
    # ~20-25 s in CI, so every witness here is paid for. Goal: keep
    # the sweep portion under ~4 min so the cold-cache build (~20
    # min) plus sweep fits inside the 25-min job timeout.
    #
    # The full 40-witness corpus runs on the schedule /
    # workflow_dispatch / merge_group tier (force_full=true) where
    # wall-clock isn't capped — see the workflow's `force_full`
    # branching.
    #
    # Coverage rationale (one line per witness):
    #   01-overflow1-crash         — T01 catches the canonical BOF
    #   01-canarymatch-deep-fn     — position-varying gadget catches
    #                                 uniform-canary's blind spot (T01)
    #   02-overflow1-crash         — T02 catches the canonical off-by-one
    #   02-canarymatch-fn          — same gadget-upgrade probe for T02
    #   03-noprefix-benign         — T03 bug is inert without a prefix
    #   03-overflow1-crash         — T03 catches CVE-2017-9047
    #   03-nulprefix-benign        — soundness probe: bug requires
    #                                 non-NUL prefix (real CVE property)
    #   03-nullname-crash          — bug fires with zero-name + non-NUL
    #                                 prefix; covers a different byte
    #                                 pattern than 03-overflow1
    witness_set=(
        witnesses/01-overflow1-crash.bin
        witnesses/01-canarymatch-deep-fn.bin
        witnesses/02-overflow1-crash.bin
        witnesses/02-canarymatch-fn.bin
        witnesses/03-noprefix-benign.bin
        witnesses/03-overflow1-crash.bin
        witnesses/03-nulprefix-benign.bin
        witnesses/03-nullname-crash.bin
    )
else
    witness_set=(witnesses/*.bin)
fi

# Parallel sweep: the SP1 SDK startup is ~20-25 s per invocation, so a
# sequential sweep of 8 witnesses is ~11 min wall-clock — the long pole
# on CI. We fan out the SP1 invocations across N background jobs (cap
# ZKPOX_TEST_PARALLEL, default 4), capture each witness's stdout and
# exit code into a temp file, then walk the witness list in order to
# print verdicts deterministically. Wall-clock drops to ~ceil(W/N) ×
# per-witness, e.g. 8 witnesses @ N=4 → ~3 min.
#
# Throttling pattern is "batch wait" rather than `wait -n` so the script
# stays compatible with bash 3.2 (macOS default). Slight efficiency hit
# vs `wait -n` — we wait for the whole batch's slowest, not just any one
# job — but on a homogeneous witness corpus the difference is small and
# the portability win is real.
PARALLEL="${ZKPOX_TEST_PARALLEL:-4}"
TMPDIR=$(mktemp -d -t zkpox-regression-XXXXXX)
trap "rm -rf '$TMPDIR'" EXIT

# Phase 1: spawn all SP1 invocations in parallel (throttled), one
# stdout + rc file per witness. Skip witnesses with no target prefix
# entirely (no SP1 cost).
batch=0
for w in "${witness_set[@]}"; do
    base=$(basename "$w" .bin)
    target="${base:0:2}"
    case "$target" in
        01|02|03) ;;
        *) continue ;;
    esac

    (
        "$BIN" --witness "$w" "--target=$target" $MODE \
                --tag "regression:$base" \
            > "$TMPDIR/$base.out" 2>/dev/null
        echo "$?" > "$TMPDIR/$base.rc"
    ) &

    batch=$((batch + 1))
    if (( batch % PARALLEL == 0 )); then
        wait
    fi
done
wait

# Phase 2: walk witnesses in deterministic order. Each iteration is
# now cheap — just file reads + jq parses. Pass/fail counters live
# here so the existing summary block at the bottom of the script
# works unchanged.
for w in "${witness_set[@]}"; do
    base=$(basename "$w" .bin)
    # Filename schema: <NN>-<descriptor>-<verdict>.bin where NN is the
    # target id ("01", "02", or "03"); see witnesses/generate.py.
    target="${base:0:2}"
    case "$target" in
        01|02|03) ;;
        *) echo "skip: $base (no target prefix)"; continue ;;
    esac
    case "$base" in
        *-benign) expected_crash="false" expected_oob="false" ;;
        *-crash)  expected_crash="true"  expected_oob="true"  ;;
        *-fn)     expected_crash="false" expected_oob="true"  ;;
        *) echo "skip: $base (no verdict suffix)"; continue ;;
    esac

    rc=$(cat "$TMPDIR/$base.rc" 2>/dev/null || echo "missing")
    if [[ "$rc" != "0" ]]; then
        printf '  [ERROR]    %-40s harness exited %s\n' "$base" "$rc"
        failures+=("$base (harness error rc=$rc)")
        fail=$((fail + 1))
        continue
    fi
    out=$(cat "$TMPDIR/$base.out")

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
