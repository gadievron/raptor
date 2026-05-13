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
    # each target's bug end-to-end. Each SP1 SDK startup is ~85 s in
    # CI sequential, so every witness here is paid for. Goal: keep
    # the sweep portion under ~6 min so the cold-cache build (~2
    # min) plus sweep stays comfortably inside the 25-min timeout.
    #
    # The full 40-witness corpus runs on the schedule /
    # workflow_dispatch / merge_group tier (force_full=true) where
    # wall-clock isn't capped — see the workflow's `force_full`
    # branching. That tier covers the soundness probes (T03-no-prefix,
    # T03-nul-prefix, T03-null-name) and the redundant T02 gadget-
    # upgrade witness dropped from this PR subset.
    #
    # Coverage rationale (one line per witness):
    #   01-overflow1-crash         — T01 catches the canonical BOF
    #   01-canarymatch-deep-fn     — position-varying gadget catches
    #                                 uniform-canary's blind spot (the
    #                                 only -fn witness in PR-tier; if
    #                                 oob_write regresses to uniform-
    #                                 canary semantics, this is the
    #                                 witness that catches it)
    #   02-overflow1-crash         — T02 catches the canonical off-by-one
    #   03-overflow1-crash         — T03 catches CVE-2017-9047
    witness_set=(
        witnesses/01-overflow1-crash.bin
        witnesses/01-canarymatch-deep-fn.bin
        witnesses/02-overflow1-crash.bin
        witnesses/03-overflow1-crash.bin
    )
else
    witness_set=(witnesses/*.bin)
fi

# Sequential sweep. The earlier parallel approach (ac14b53, fbec21b)
# OOM'd the GitHub 4-core/16-GB runner: 4 concurrent SP1 invocations
# pushed memory past the cgroup limit and systemd-oomd SIGTERM'd the
# whole tree. RAYON_NUM_THREADS=1 didn't help because each SP1 process
# pre-allocates several GB regardless of thread count. The win from
# parallelism wasn't worth the OOM-risk surface — sequential is
# predictable. To recover CI time we instead trim the PR-tier subset
# (see --ci-subset above); the full corpus still runs on schedule /
# workflow_dispatch / merge_group.
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
