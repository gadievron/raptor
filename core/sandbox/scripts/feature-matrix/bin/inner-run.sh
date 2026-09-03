#!/bin/sh
# In-container lane executor. Runs as the image's unprivileged `runner`
# user (uid 1001). Mounted ro at /harness; results dir mounted rw at
# /results; pristine repo tarball ro at /repo.tar.
#
# Steps: probe -> extract repo -> select venv -> run tier -> record rc.
# Exits non-zero only on HARNESS errors; test failures are conveyed via
# junit xml + pytest-N.rc files so the driver can tell the two apart.
set -eu
umask 022

RES=/results
LANE="${SXV_LANE:?}"
TIER="${SXV_TIER:-default}"

echo "[inner] lane=$LANE tier=$TIER uid=$(id -u) kernel=$(uname -r)"

# --- 1. empirical feature probe (system python3, before anything else) --
python3 /harness/probe.py > "$RES/probe.json" 2> "$RES/probe.err" || {
    echo "PROBE_FAILED rc=$?" >> "$RES/probe.err"
    echo "[inner] FATAL: probe failed" >&2
    exit 3
}

# --- 2. pristine repo ---------------------------------------------------
WORK="$HOME/work/raptor/raptor"
mkdir -p "$WORK"
cd "$WORK"
tar -xf /repo.tar
echo "[inner] repo: $(git rev-parse --short HEAD 2>/dev/null || echo '?') at $WORK"

# --- 3. venv: reuse image-baked when lockfile hash matched ---------------
if [ "${SXV_REQHASH_MATCH:-0}" = "1" ] && [ -x "$WORK/.venv/bin/python" ]; then
    VENV="$WORK/.venv"
    echo "[inner] venv: image-baked (lockfile hash match)"
else
    echo "[inner] venv: lockfile drift -> building fresh (see uv.log)"
    UV_PROJECT_ENVIRONMENT="$HOME/venv-fresh" \
        uv sync --locked --python "${MATRIX_PY:?}" \
        > "$RES/uv.log" 2>&1 || { echo "[inner] FATAL: uv sync failed" >&2; exit 4; }
    VENV="$HOME/venv-fresh"
fi

# --- 4. CI-shaped env, proxy vars dropped before tests ------------------
# (proxy vars are only needed for pip; CI runners have no proxy env and
# RAPTOR's egress code reads these, so they must not leak into the tier)
unset http_proxy https_proxy no_proxy HTTP_PROXY HTTPS_PROXY NO_PROXY || true
export RAPTOR_MAX_TEST_SECONDS=10
PATH="$VENV/bin:$PATH"
export PATH

# --- 5. tier ------------------------------------------------------------
run_pytest() {
    n="$1"; shift
    echo "[inner] pytest invocation $n: $*"
    rc=0
    "$VENV/bin/python" -m pytest "$@" -n auto -p no:cacheprovider -r fE \
        --junitxml="$RES/junit-$n.xml" > "$RES/pytest-$n.out" 2>&1 || rc=$?
    echo "$rc" > "$RES/pytest-$n.rc"
    echo "[inner] pytest invocation $n exit=$rc"
}

case "$TIER" in
    default)
        # fast sandbox tier: unit + non-e2e (pytest.ini already deselects
        # integration- and slow-marked tests)
        run_pytest 1 core/sandbox/tests \
            --ignore=core/sandbox/tests/test_e2e_sandbox.py
        ;;
    e2e)
        # adds test_e2e_sandbox.py + integration-marked sandbox tests
        # (-m overrides the pytest.ini deselection, keeps `not slow`)
        run_pytest 1 core/sandbox/tests -m "not slow"
        ;;
    full)
        # e2e sandbox shape + the whole fast tier (CI: pytest core packages)
        run_pytest 1 core/sandbox/tests -m "not slow"
        run_pytest 2 core packages --ignore=core/sandbox/tests
        ;;
    *)
        echo "[inner] FATAL: unknown tier '$TIER'" >&2
        exit 5
        ;;
esac

echo "[inner] done"
