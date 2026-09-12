#!/usr/bin/env bash
# Sandbox feature-matrix runner: execute the core/sandbox test tiers
# inside docker lanes that genuinely lack kernel sandbox features
# (Landlock faked to ENOSYS, user namespaces denied), empirically probe
# what each lane actually provides, and report a lane x probed-features
# x results matrix. The matrix keys on PROBED capabilities: a lane whose
# probe diverges from its intended feature shape fails the run loudly.
#
# Usage:
#   run-matrix.sh [--repo PATH] [--ref REF] [--image 24|26|both]
#                 [--lanes l1,l2,...] [--e2e | --full]
#                 [--skip-build] [--lane-timeout SECS]
#                 [--py-version X.Y.Z] [--results DIR]
#                 [--self-test]
#
# Defaults: repo = the checkout containing this script, ref = HEAD,
# both images, all lanes, default tier (core/sandbox tests minus e2e).
# Results are written OUTSIDE the repo (never committed):
#   ${RAPTOR_MATRIX_RESULTS:-${RUNNER_TEMP:-/tmp}/raptor-sandbox-matrix}/<timestamp>
#
# Network use (image build only): proxies are read from the calling
# environment; APT_MIRROR from RAPTOR_MATRIX_APT_MIRROR when the
# default archives are unreachable. The GitHub-runner-shaped python
# interpreter is resolved from actions/python-versions'
# versions-manifest.json at build time.
#
# --self-test: docker-free wiring check — generates the lane seccomp
# profiles, runs the feature probe on the host, and exercises the
# report aggregator on synthetic fixtures (clean + shape-diverged).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DEFAULT="$(cd "$HERE/../../../.." && pwd)"

# ---- self-test (no docker, no network) ----------------------------------
if [ "${1:-}" = "--self-test" ]; then
    TMP=$(mktemp -d)
    trap 'rm -rf "$TMP"' EXIT
    echo "== profiles generate + parse"
    python3 "$HERE/profiles/make_profiles.py" --out "$TMP/profiles"
    python3 - "$TMP/profiles" <<'PYEOF'
import json, sys, pathlib
for name in ("no-landlock", "no-userns", "no-both"):
    p = json.loads((pathlib.Path(sys.argv[1]) / f"{name}.json").read_text())
    assert p["syscalls"], name
print("profiles ok")
PYEOF
    echo "== probe runs and emits a complete shape"
    SXV_LANE=self-test python3 "$HERE/bin/probe.py" > "$TMP/probe.json"
    python3 - "$TMP/probe.json" <<'PYEOF'
import json, sys
shape = json.load(open(sys.argv[1]))["shape"]
for key in ("landlock", "userns", "mount_in_userns",
            "proc_mount_in_userns", "pivot_root_in_userns", "seccomp"):
    assert key in shape, key
print("probe ok:", shape)
PYEOF
    echo "== report aggregates and gates on shape divergence"
    for verdict in clean diverged; do
        L="$TMP/run-$verdict/u24/full"
        mkdir -p "$L"
        if [ "$verdict" = clean ]; then
            cp "$TMP/probe.json" "$L/probe.json"
            python3 - "$L/probe.json" "$HERE/profiles" <<'PYEOF'
import json, sys
sys.path.insert(0, sys.argv[2])
from lanes import _MNT
d = json.load(open(sys.argv[1]))
# match the dynamic lane expectation (host AppArmor sysctl is kernel-wide)
d["shape"] = {"landlock": "present", "userns": "ok",
              "mount_in_userns": _MNT, "proc_mount_in_userns": _MNT,
              "pivot_root_in_userns": _MNT, "seccomp": "ok"}
json.dump(d, open(sys.argv[1], "w"))
PYEOF
        else
            python3 - "$L/probe.json" <<'PYEOF'
import json, sys
json.dump({"shape": {"landlock": "enosys", "userns": "denied",
                     "mount_in_userns": "fail",
                     "proc_mount_in_userns": "fail",
                     "pivot_root_in_userns": "fail", "seccomp": "ok"},
           "landlock": {"abi": None}}, open(sys.argv[1], "w"))
PYEOF
        fi
        printf '<testsuites><testsuite name="pytest" tests="2" failures="0" errors="0" skipped="0"><testcase classname="x" name="a"/><testcase classname="x" name="b"/></testsuite></testsuites>' \
            > "$L/junit-1.xml"
        printf '{"rc": 0, "duration_s": 1}' > "$L/meta.json"
    done
    python3 "$HERE/bin/report.py" "$TMP/run-clean" >/dev/null \
        || { echo "self-test FAIL: clean fixture reported non-zero" >&2; exit 1; }
    if python3 "$HERE/bin/report.py" "$TMP/run-diverged" >/dev/null; then
        echo "self-test FAIL: shape divergence not gated" >&2; exit 1
    fi
    echo "== report gates empty and stray-lane runs"
    mkdir -p "$TMP/run-empty"
    if python3 "$HERE/bin/report.py" "$TMP/run-empty" >/dev/null 2>&1; then
        echo "self-test FAIL: empty run dir not gated" >&2; exit 1
    fi
    mkdir -p "$TMP/run-stray/u24/not-a-lane"
    cp -r "$TMP/run-clean/u24/full" "$TMP/run-stray/u24/full"
    if python3 "$HERE/bin/report.py" "$TMP/run-stray" >/dev/null; then
        echo "self-test FAIL: stray lane dir not gated" >&2; exit 1
    fi
    echo "== container entry chain references shipped files"
    for f in $(grep -o '/harness/[a-z_.-]*' "$HERE/bin/entry.sh" | sort -u); do
        [ -f "$HERE/bin/$(basename "$f")" ] \
            || { echo "self-test FAIL: entry.sh references missing $f" >&2; exit 1; }
    done
    echo "self-test OK"
    exit 0
fi

# ---- docker access ------------------------------------------------------
if ! docker info >/dev/null 2>&1; then
    if [ "${SXV_SG_REEXEC:-0}" = "1" ]; then
        echo "ERROR: no docker access even under 'sg docker'" >&2
        exit 2
    fi
    exec sg docker -c "SXV_SG_REEXEC=1 $(printf '%q ' "${BASH_SOURCE[0]}" "$@")"
fi

# ---- args ---------------------------------------------------------------
REPO="$REPO_DEFAULT"
REF=HEAD
IMAGE_SEL=both
LANES="$(python3 "$HERE/profiles/lanes.py" list | paste -sd, -)"
TIER=default
SKIP_BUILD=0
LANE_TIMEOUT=3600
PY_VERSION=3.14.7
RESULTS_BASE="${RAPTOR_MATRIX_RESULTS:-${RUNNER_TEMP:-/tmp}/raptor-sandbox-matrix}"
while [ $# -gt 0 ]; do
    case "$1" in
        --repo)         REPO="$2"; shift 2 ;;
        --ref)          REF="$2"; shift 2 ;;
        --image)        IMAGE_SEL="$2"; shift 2 ;;
        --lanes)        LANES="$2"; shift 2 ;;
        --e2e)          TIER=e2e; shift ;;
        --full)         TIER=full; shift ;;
        --skip-build)   SKIP_BUILD=1; shift ;;
        --lane-timeout) LANE_TIMEOUT="$2"; shift 2 ;;
        --py-version)   PY_VERSION="$2"; shift 2 ;;
        --results)      RESULTS_BASE="$2"; shift 2 ;;
        -h|--help)      sed -n '2,30p' "$0"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

case "$IMAGE_SEL" in
    24)   IMAGES=(u24) ;;
    26)   IMAGES=(u26) ;;
    both) IMAGES=(u24 u26) ;;
    *) echo "--image must be 24|26|both" >&2; exit 2 ;;
esac

# Validate every requested lane UP FRONT. A bogus lane name must abort
# here: the per-lane `lanes.py args` call runs in a process
# substitution whose failure `set -e` cannot see, and an empty option
# list would silently run the tier under stock confinement while the
# report (which keys on the known lane set) dropped the results — a
# green run that tested nothing.
KNOWN_LANES="$(python3 "$HERE/profiles/lanes.py" list)"
IFS=',' read -r -a _LANE_CHECK <<< "$LANES"
for _l in "${_LANE_CHECK[@]}"; do
    grep -qx "$_l" <<< "$KNOWN_LANES" \
        || { echo "ERROR: unknown lane '$_l' (known: $(paste -sd, - <<< "$KNOWN_LANES"))" >&2; exit 2; }
done

TS="$(date +%Y%m%d-%H%M%S)"
RUN="$RESULTS_BASE/$TS"
mkdir -p "$RUN"
echo "== sandbox-matrix run $TS  (tier=$TIER lanes=$LANES images=${IMAGES[*]})"
echo "== results: $RUN"
T0=$(date +%s)

# ---- pristine checkout (never mutates the source repo) -----------------
SHA=$(git -C "$REPO" rev-parse --verify -q "$REF^{commit}") \
    || { echo "ERROR: ref '$REF' not found in $REPO" >&2; exit 2; }
echo "== cloning $REPO @ $SHA"
git clone -q --no-checkout "$REPO" "$RUN/repo"
git -C "$RUN/repo" checkout -q --detach "$SHA"
tar -C "$RUN/repo" -cf "$RUN/repo.tar" .

REQHASH=$(cat "$RUN/repo/pyproject.toml" "$RUN/repo/uv.lock" \
          | sha256sum | cut -d' ' -f1)

# ---- lane seccomp profiles ----------------------------------------------
python3 "$HERE/profiles/make_profiles.py" --out "$RUN/profiles"

# ---- images (requirements refreshed from the checkout at build time) ----
declare -A DOCKERFILE=([u24]=Dockerfile [u26]=Dockerfile.26)
if [ "$SKIP_BUILD" = 0 ]; then
    echo "== resolving python $PY_VERSION artifact (actions/python-versions)"
    PY_URL=$(curl -fsSL \
        https://raw.githubusercontent.com/actions/python-versions/main/versions-manifest.json \
        | python3 -c "
import json, sys
want = '$PY_VERSION'
for rel in json.load(sys.stdin):
    if rel['version'] != want:
        continue
    for f in rel['files']:
        if (f.get('platform') == 'linux'
                and f.get('platform_version') == '24.04'
                and f.get('arch') == 'x64'):
            print(f['download_url']); raise SystemExit
raise SystemExit('no linux-24.04 x64 artifact for ' + want)
")
    echo "== python artifact: $PY_URL"
    CTX="$RUN/build-ctx"
    mkdir -p "$CTX"
    cp "$HERE/images/rustup-proxy.c" "$CTX/"
    cp "$HERE/images/Dockerfile" "$HERE/images/Dockerfile.26" "$CTX/"
    cp "$RUN/repo/pyproject.toml" "$RUN/repo/uv.lock" "$CTX/"
    for img in "${IMAGES[@]}"; do
        echo "== building raptor-sandbox-matrix:$img (${DOCKERFILE[$img]})"
        docker build -t "raptor-sandbox-matrix:$img" \
            -f "$CTX/${DOCKERFILE[$img]}" \
            --label "sxv.reqhash=$REQHASH" \
            --build-arg PY_URL="$PY_URL" \
            --build-arg PY_VERSION="$PY_VERSION" \
            --build-arg APT_MIRROR="${RAPTOR_MATRIX_APT_MIRROR:-}" \
            --build-arg http_proxy="${http_proxy:-${HTTP_PROXY:-}}" \
            --build-arg https_proxy="${https_proxy:-${HTTPS_PROXY:-}}" \
            "$CTX" > "$RUN/build-$img.log" 2>&1 \
            || { echo "IMAGE BUILD FAILED ($img) — see $RUN/build-$img.log" >&2
                 tail -30 "$RUN/build-$img.log" >&2; exit 3; }
    done
    rm -rf "$CTX"
fi

# ---- lane runs -----------------------------------------------------------
IFS=',' read -r -a LANE_ARR <<< "$LANES"
for img in "${IMAGES[@]}"; do
    TAG="raptor-sandbox-matrix:$img"
    if ! docker image inspect "$TAG" >/dev/null 2>&1; then
        echo "ERROR: image $TAG missing (run without --skip-build first)" >&2
        exit 3
    fi
    IMG_HASH=$(docker image inspect -f '{{index .Config.Labels "sxv.reqhash"}}' "$TAG")
    MATCH=0; [ "$IMG_HASH" = "$REQHASH" ] && MATCH=1
    [ "$MATCH" = 1 ] || echo "NOTE: $TAG requirements drift -> lanes build fresh venvs (slow)"

    for lane in "${LANE_ARR[@]}"; do
        LANE_DIR="$RUN/$img/$lane"
        mkdir -p "$LANE_DIR"
        chmod 777 "$LANE_DIR"   # container writes as uid 1001
        mapfile -t LANE_OPTS < <(python3 "$HERE/profiles/lanes.py" args "$lane" \
                                 --profiles "$RUN/profiles")
        echo "== [$img/$lane] docker opts: ${LANE_OPTS[*]:-<stock>}"
        L0=$(date +%s); RC=0
        # NB: no --init — docker's --init bind-mounts docker-init under
        # /usr/sbin (via the /sbin symlink), planting a locked submount
        # beneath /usr that shifts the (real, /etc-locked-submount)
        # container mount behaviour onto /usr and muddies the probe.
        timeout -k 30 "$LANE_TIMEOUT" docker run --rm \
            --name "sxvmx-$TS-$img-$lane" --hostname sxv-lane \
            -v "$RUN/repo.tar":/repo.tar:ro \
            -v "$HERE/bin":/harness:ro \
            -v "$LANE_DIR":/results \
            -e SXV_LANE="$lane" -e SXV_TIER="$TIER" \
            -e SXV_REQHASH_MATCH="$MATCH" \
            -e http_proxy -e https_proxy -e no_proxy \
            -e HTTP_PROXY -e HTTPS_PROXY -e NO_PROXY \
            "${LANE_OPTS[@]}" "$TAG" /harness/entry.sh \
            > "$LANE_DIR/container.log" 2>&1 || RC=$?
        if [ "$RC" = 124 ]; then  # lane timeout: reap the orphaned container
            docker rm -f "sxvmx-$TS-$img-$lane" >/dev/null 2>&1 || true
            echo "LANE TIMEOUT after ${LANE_TIMEOUT}s" >> "$LANE_DIR/container.log"
        fi
        L1=$(date +%s)
        RC="$RC" DUR="$((L1 - L0))" LANE="$lane" IMG="$TAG" SHA="$SHA" \
        OPTS="${LANE_OPTS[*]:-}" TIERV="$TIER" MATCHV="$MATCH" \
        python3 -c 'import json,os; json.dump({
            "rc": int(os.environ["RC"]), "duration_s": int(os.environ["DUR"]),
            "lane": os.environ["LANE"], "image": os.environ["IMG"],
            "repo_sha": os.environ["SHA"], "tier": os.environ["TIERV"],
            "docker_opts": os.environ["OPTS"].split(),
            "venv_reused": os.environ["MATCHV"] == "1"},
            open("/dev/stdout","w"), indent=1)' > "$LANE_DIR/meta.json"
        echo "== [$img/$lane] rc=$RC $((L1 - L0))s"
        tail -3 "$LANE_DIR/container.log" | sed 's/^/   | /'
    done
done

# keep the tarball for manual lane re-runs; drop the working clone
rm -rf "$RUN/repo"

# ---- report ---------------------------------------------------------------
echo
REPORT_RC=0
python3 "$HERE/bin/report.py" "$RUN" || REPORT_RC=$?
echo "== total runtime: $(( $(date +%s) - T0 ))s   results: $RUN"
exit "$REPORT_RC"
