"""Root-level pytest config.

libexec/ scripts now refuse to run without one of CLAUDECODE,
_RAPTOR_TRUSTED, or RAPTOR_DIR set in the environment (see the
trust-marker block at the top of each script). Several test suites
subprocess-invoke libexec scripts and inherit env from this test
runner — set the marker once here so every test is treated as a
trusted caller by default.

Tests that exercise the refusal path explicitly pop the marker from
the subprocess env when they spawn the wrapper.

`RAPTOR_DIR` is also set here. Modules that follow the project's
"hard lookup, no fallbacks" path-safety rule (CLAUDE.md, e.g.
packages/recon/agent.py) read `os.environ["RAPTOR_DIR"]` at
import time and KeyError if unset. CI runners and developer
shells that don't pre-export RAPTOR_DIR would otherwise fail
test collection. Set it here to the project root (the directory
this conftest.py lives in) so the import-time lookup succeeds
in every test invocation, while production code paths still
require operators to set it explicitly per the launcher rule.
"""

import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("_RAPTOR_TRUSTED", "1")

# Disable reach_verdict_log atexit flush during tests so the synthetic
# inventories that test suites build don't pollute the operator-facing
# sidecar (the cross-project verdict-frequency log is supposed to
# reflect real operator runs, not the test corpus). Tests that
# exercise the log directly opt back in via ``RAPTOR_REACH_VERDICT_LOG``
# pointing at a tmp file (see core/analysis/tests/test_reach_verdict_log.py).
os.environ.setdefault("RAPTOR_REACH_VERDICT_LOG_DISABLED", "1")

# Force RAPTOR_DIR to point at THIS worktree, not whatever the
# developer's login shell exports. ``setdefault`` is a no-op when the
# env var is already set, so a developer with multiple checkouts who
# exports ``RAPTOR_DIR=/home/me/other-raptor`` in their profile would
# silently run the test SUBPROCESS bootstrap (e.g.
# core/sandbox/tests/test_fork_safe_warn*.py) against the wrong tree
# — failing with "No module named core.sandbox._fork_safe_warn" when
# the module is new on this branch but missing from the other tree.
#
# CI environments that pre-export RAPTOR_DIR correctly are unaffected
# (the path already matches). Mismatch surfaces as a one-line warning
# on stderr so the developer notices the divergence.
_conftest_dir = str(Path(__file__).resolve().parent)
_existing = os.environ.get("RAPTOR_DIR")
if _existing and _existing != _conftest_dir:
    print(
        f"conftest: overriding RAPTOR_DIR ({_existing!r} → {_conftest_dir!r}) "
        f"to match the worktree this test run lives in",
        file=sys.stderr,
    )
os.environ["RAPTOR_DIR"] = _conftest_dir

# The operator's real ``~/.config/raptor/models.json`` must never
# steer tests: a configured API-served primary (e.g. a Bedrock entry)
# flips model selection, egress enablement and provider construction
# for every test that builds a real ``LLMConfig`` — observed as a
# full-suite hang when the egress proxy dutifully allowed the
# configured Bedrock host and a test's SDK call attempted a live
# connection. Pin ``RAPTOR_CONFIG`` at a nonexistent in-tree path;
# tests that exercise config parsing set ``RAPTOR_CONFIG`` to their
# own tmp file (monkeypatch wins over this default). ``setdefault``
# keeps a deliberately exported RAPTOR_CONFIG usable for
# operator-driven runs against real config.
os.environ.setdefault(
    "RAPTOR_CONFIG",
    str(Path(_conftest_dir) / ".pytest-no-operator-models.json"),
)

# Put the repo root on sys.path so ``from core.X import Y`` and
# ``from packages.Y.Z import W`` resolve during pytest collection.
# pytest.ini's ``pythonpath`` only lists a handful of package-standalone
# roots; ``--import-mode=importlib`` deliberately declines to auto-insert
# rootdir. Without this, parent-package ``__init__.py`` files that import
# from ``core.*`` fail collection whenever an xdist worker's batch starts
# with a test that hasn't already transitively imported something from
# ``core.*``. Insert at position 0 to shadow any environment-inherited
# ``core``/``packages`` on PYTHONPATH — the worktree conftest.py lives in
# is the source of truth per the RAPTOR_DIR block above.
if _conftest_dir not in sys.path:
    sys.path.insert(0, _conftest_dir)


# ---------------------------------------------------------------------------
# Git hermeticity — operator config must not steer tests; tests must
# never touch the operator's config.
# ---------------------------------------------------------------------------
#
# Incident class this kills: a test fixture whose ``cd`` / path
# resolution failed ran ``git config user.name "Test"`` with the real
# checkout as ambient cwd and wrote it into the operator's repo-level
# ``.git/config`` (and any other git command — commit, tag,
# ``checkout -b`` — could have hit the real repo the same way).
# Two-sided containment, logic in core/testing/git_hermeticity.py:
#
#  * Env pinning (here, import time, inherited by every subprocess):
#    ``GIT_CONFIG_GLOBAL`` / ``GIT_CONFIG_SYSTEM`` -> /dev/null and
#    ambient ``GIT_*`` identity/redirection variables stripped, so
#    operator config (init.defaultBranch, commit.gpgsign, an exported
#    GIT_DIR, ...) cannot change test outcomes, and a stray
#    ``git config --global`` from a test can never reach the operator's
#    real config. Forced, not setdefault — hermeticity must hold on
#    every host. A test that genuinely needs the ambient values opts
#    out per-test with ``@pytest.mark.ambient_git_config`` (registered
#    in pytest.ini; nothing needs it today — the marker exists so the
#    next legitimate case doesn't weaken the default).
#
#  * Ambient-config drift guard (pytest_sessionstart /
#    pytest_sessionfinish below): fingerprint the config file(s) a
#    repo-level ``git config`` write from inside this checkout would
#    land in (common-dir config, plus ``config.worktree`` for linked
#    worktrees), re-check at session end, and FAIL the session with a
#    loud summary on drift. Read-only — the guard itself never touches
#    the repo beyond reading those files.

from core.testing import git_hermeticity as _git_hermeticity  # noqa: E402

# xdist workers (and any nested pytest) inherit the controller's
# ALREADY-PINNED environment, so calling pin_git_env() there would
# record the pinned values as "ambient" and make the escape-hatch
# marker silently restore /dev/null instead of the operator's real
# values. The first (top-level) session therefore publishes the true
# displaced snapshot through an env var; every descendant session
# parses it instead of re-capturing.
import json as _json  # noqa: E402

_AMBIENT_GIT_ENV_HANDOFF = "RAPTOR_GIT_AMBIENT_ENV"
if os.environ.get(_AMBIENT_GIT_ENV_HANDOFF):
    _ambient_git_env = _json.loads(os.environ[_AMBIENT_GIT_ENV_HANDOFF])
    _git_hermeticity.pin_git_env()  # re-assert; idempotent
else:
    _ambient_git_env = _git_hermeticity.pin_git_env()
    os.environ[_AMBIENT_GIT_ENV_HANDOFF] = _json.dumps(_ambient_git_env)


@pytest.fixture(autouse=True)
def _ambient_git_config_escape(request):
    """Escape hatch: restore the operator's git env for tests marked
    ``@pytest.mark.ambient_git_config``; re-pin afterwards."""
    if request.node.get_closest_marker("ambient_git_config") is None:
        yield
        return
    pinned_state = {k: v for k, v in os.environ.items()
                    if k.startswith("GIT_")}
    _git_hermeticity.restore_git_env(_ambient_git_env)
    try:
        yield
    finally:
        # Exact re-pin: wipe every GIT_* — including vars outside the
        # strip list that the marked test may have set — then reinstate
        # the pinned state byte-for-byte.
        for _key in [k for k in os.environ if k.startswith("GIT_")]:
            del os.environ[_key]
        os.environ.update(pinned_state)


# ---------------------------------------------------------------------------
# System-tmp containment
# ---------------------------------------------------------------------------
#
# Test suites (and the production code they exercise) create scratch
# via raw ``tempfile.mkdtemp`` / ``TemporaryDirectory`` in hundreds of
# call sites. Context-managed sites clean up on normal exit, but a
# SIGKILLed / OOM-killed session leaks every dir live at that moment
# as an anonymous ``$TMP/tmpXXXXXXXX`` nobody can attribute or safely
# sweep (shared multi-session hosts forbid a generic /tmp/tmp* sweep).
#
# Containment instead of per-site chasing: point the session's TMPDIR
# and ``tempfile.tempdir`` at ONE ``core.run.scratch`` dir with the
# reaper-listed ``raptor-pytest-`` prefix. Everything raw tempfile
# creates in-process lands inside it, as does the litter of
# subprocesses that inherit this environment (the mount-ns sandbox
# re-creates ``$TMPDIR`` inside its private tmpfs, step 7b). Children
# spawned through ``get_safe_env()`` are NOT contained — that scrubber
# strips TMPDIR by design (DANGEROUS_ENV_VARS) — which is the status
# quo those tools already handle with their own reaper-listed
# prefixes. Normal exit removes the whole dir; a killed session leaks
# one ``raptor-pytest-*`` dir per pytest process (one per xdist
# worker under ``-n N``), each reclaimed by ``core.run.tmp_reaper``
# past the age floor (swept at every raptor ``start_run`` and once at
# the start of every later test session, below).
#
# pytest's own ``tmp_path`` basetemp is pinned under the REAL system
# tmp first (``getbasetemp()`` before the redirect), so pytest's
# keep-last-3-runs retention for post-mortem debugging is preserved.
#
# Sites that must NOT be contained (AF_UNIX 108-char path cap) already
# pass ``dir="/tmp"`` explicitly and are unaffected.

@pytest.fixture(autouse=True, scope="session")
def _contained_system_tmp(tmp_path_factory: pytest.TempPathFactory):
    import tempfile

    from core.run import tmp_reaper
    from core.run.scratch import scratch_dir

    # Resolve pytest's basetemp against the real system tmp before the
    # redirect below can capture it.
    tmp_path_factory.getbasetemp()
    # Reclaim orphans of earlier killed sessions (age-gated, liveness-
    # probed, own-prefixes-only, never raises).
    tmp_reaper.reap_stale_tmp()

    prior_env = os.environ.get("TMPDIR")
    prior_cached = tempfile.tempdir
    with scratch_dir("raptor-pytest-", env=os.environ) as session_tmp:
        tempfile.tempdir = str(session_tmp)
        try:
            yield
        finally:
            tempfile.tempdir = prior_cached
            if prior_env is None:
                os.environ.pop("TMPDIR", None)
            else:
                os.environ["TMPDIR"] = prior_env


# ---------------------------------------------------------------------------
# Build-ID binary cache isolation
# ---------------------------------------------------------------------------
#
# ``core.audit.build_id_cache.load_build_id_cache()`` defaults to
# ``RaptorConfig.REPO_ROOT / ".cache/binary"`` — the install root, i.e.
# THIS checkout under pytest (RAPTOR_DIR is pinned above). Any test that
# exercises binary-oracle enrichment (``core.inventory.builder`` with
# ``BINARY_ORACLE_PATHS`` set, the audit orchestrator's binary bridge)
# would populate the operator-facing cache with test artifacts and leave
# an untracked ``.cache/`` in the source tree, tripping the
# tree-changed-mid-run sentinel below. ``RAPTOR_BINARY_CACHE_DIR`` is the
# documented override and is re-read on every ``load_build_id_cache()``
# call, so one session-scoped redirect covers every code path — including
# subprocess-invoked CLIs, which inherit this process's environment.
# ``setdefault`` semantics: a deliberately exported cache dir still wins.

@pytest.fixture(autouse=True, scope="session")
def _binary_cache_in_tmp(tmp_path_factory):
    if os.environ.get("RAPTOR_BINARY_CACHE_DIR"):
        yield
        return
    cache_dir = tmp_path_factory.mktemp("binary-cache")
    os.environ["RAPTOR_BINARY_CACHE_DIR"] = str(cache_dir)
    yield
    os.environ.pop("RAPTOR_BINARY_CACHE_DIR", None)


# ---------------------------------------------------------------------------
# Default-tier slow-test guard
# ---------------------------------------------------------------------------
#
# Preventive backstop for the "a default-tier test is slow because it
# does real I/O it should mock" class — real subprocess / network /
# time.sleep / sandbox setup that turns a 30ms unit test into a 30s one.
# faulthandler_timeout (set in tests.yml) catches a *hang*; this catches
# slow-but-finishes, the day it lands, instead of in a later --durations
# sweep.
#
# Activated ONLY when RAPTOR_MAX_TEST_SECONDS is set — tests.yml sets it
# for the default-tier matrix; nightly.yml deliberately does NOT (its
# `-m "slow or integration"` tests are legitimately slow), and local
# `pytest` is unaffected. The guard FLAGS, it does not kill: every test
# still runs to completion; the session then fails at the end naming the
# offenders, so the signal is "this test got slow", not "killed mid-run".
#
# A genuinely-heavy test is not a bug — mark it @pytest.mark.slow (moves
# it to the nightly tier, out of this guard's scope).

# ---------------------------------------------------------------------------
# Randomised test order
# ---------------------------------------------------------------------------
#
# When RAPTOR_RANDOMISE_TESTS is set (to any value, or a numeric seed),
# shuffle the collected test items so order-dependent failures surface
# early.  No external plugin required.
#
# Deterministic: same seed → same order.  The seed is printed in the
# terminal header so a failure can be reproduced.

_RANDOMISE_SEED_RAW = os.environ.get("RAPTOR_RANDOMISE_TESTS")


def pytest_collection_modifyitems(items):
    if _RANDOMISE_SEED_RAW is None:
        return
    import random as _random
    try:
        seed = int(_RANDOMISE_SEED_RAW)
    except (ValueError, TypeError):
        seed = int.from_bytes(
            _RANDOMISE_SEED_RAW.encode()[:8], "little"
        ) % 2**31
    _random.Random(seed).shuffle(items)


def pytest_report_header():
    if _RANDOMISE_SEED_RAW is None:
        return []
    return [f"raptor: randomised test order (seed={_RANDOMISE_SEED_RAW})"]


_MAX_TEST_SECONDS = os.environ.get("RAPTOR_MAX_TEST_SECONDS")
_slow_test_threshold = float(_MAX_TEST_SECONDS) if _MAX_TEST_SECONDS else None
_slow_test_overruns: "list[tuple[str, float]]" = []


def pytest_runtest_logreport(report):
    """Record any test whose CALL phase exceeds the threshold."""
    if _slow_test_threshold is None:
        return
    if report.when == "call" and report.duration > _slow_test_threshold:
        _slow_test_overruns.append((report.nodeid, report.duration))


def pytest_sessionfinish(session, exitstatus):
    """Fail an otherwise-green session if any test overran the threshold
    or mutated the ambient checkout's repo-level git config."""
    _check_git_config_drift(session)
    if _slow_test_threshold is None or not _slow_test_overruns:
        return
    if session.exitstatus == 0:
        session.exitstatus = 1


# ---------------------------------------------------------------------------
# Ambient git-config drift guard (fails the session).
#
# Companion to the git-hermeticity env pinning above: env pins cannot
# stop a test from running git against the REAL checkout when its
# cwd/-C resolves to the ambient repo instead of its tmp fixture. This
# guard detects the incident class of that failure — repo-level
# ``git config`` writes — by fingerprinting the config file(s) at
# session start and comparing at session end, failing loudly on drift.
# (Ref/index/hook mutations are outside its scope; the audit found no
# pytest-reachable write-class git against the ambient repo at all —
# the fix pattern addresses the cause, this guard alarms on its most
# damaging symptom.) Controller-only under xdist (workers skip; the
# controller's sessionfinish runs after all workers, so any test's
# mutation is caught). Git-less environments skip silently, matching
# the tree-fingerprint convention.
# ---------------------------------------------------------------------------

_git_config_at_start = None
_git_config_drift: "list[str]" = []


def _check_git_config_drift(session):
    if getattr(session.config, "workerinput", None) is not None:
        return
    if _git_config_at_start is None:
        return
    now = _git_hermeticity.config_fingerprint(Path(_conftest_dir))
    if now is None or now == _git_config_at_start:
        return
    _git_config_drift.extend(
        _git_hermeticity.describe_drift(_git_config_at_start, now))
    if session.exitstatus == 0:
        session.exitstatus = 1


def _git_config_drift_summary(terminalreporter):
    if not _git_config_drift:
        return
    tr = terminalreporter
    tr.section("git hermeticity guard FAILED", red=True, bold=True)
    tr.write_line(
        "The ambient checkout's repo-level git config changed during "
        "this session (sha256 drift on the file(s) below). Most likely "
        "cause is the git-touching-tests-must-be-hermetic class: a "
        "test ran git against the REAL checkout instead of its tmp "
        "fixture — usually a cwd/-C that fell through to the ambient "
        "repo. (On a shared-config multi-worktree setup it can also "
        "be another session writing the common config mid-run.)"
    )
    for line in _git_config_drift:
        tr.write_line(f"  {line}")
    tr.write_line(
        "Fix the test to pin every git call to its own tmp repo (use "
        "core.testing.gitrepo), then inspect and repair the file(s) "
        "above (git config --local --list). The session exit status "
        "has been forced to 1."
    )


def pytest_terminal_summary(terminalreporter):
    _tree_drift_summary(terminalreporter)
    _git_config_drift_summary(terminalreporter)
    if _slow_test_threshold is None or not _slow_test_overruns:
        return
    tr = terminalreporter
    tr.section("default-tier slow-test guard FAILED", red=True, bold=True)
    tr.write_line(
        f"{len(_slow_test_overruns)} test(s) exceeded "
        f"RAPTOR_MAX_TEST_SECONDS={_slow_test_threshold}s in the default tier."
    )
    tr.write_line(
        "A default-tier test this slow is almost always real I/O that "
        "should be mocked (subprocess / network / time.sleep / sandbox "
        "setup). Fix it — or, if the cost is genuine, mark it "
        "@pytest.mark.slow so it runs in the nightly tier instead.",
    )
    for nodeid, dur in sorted(_slow_test_overruns, key=lambda x: -x[1]):
        tr.write_line(f"  {dur:7.1f}s  {nodeid}")


# ---------------------------------------------------------------------------
# Tree-changed-mid-run guard (warning only).
#
# A test session whose source tree is edited WHILE it runs (multi-agent
# checkouts, a patch series being applied mid-suite) produces failures
# indistinguishable from real ones — collection saw one tree, execution
# another. Fingerprint the tree at session start and compare at the end;
# on drift, print one prominent banner. Never fails or skips anything:
# CI and normal runs see zero behaviour change, and git-less environments
# skip silently.
# ---------------------------------------------------------------------------

_tree_state_at_start = None


def _tree_fingerprint():
    import hashlib
    import subprocess as _sp
    try:
        head = _sp.run(
            ["git", "-C", _conftest_dir, "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=10, check=False,
        )
        if head.returncode != 0:
            return None
        dirty = _sp.run(
            ["git", "-C", _conftest_dir, "status", "--porcelain"],
            capture_output=True, text=True, timeout=30, check=False,
        )
        if dirty.returncode != 0:
            return None
        return (
            head.stdout.strip(),
            hashlib.sha256(dirty.stdout.encode()).hexdigest()[:16],
        )
    except (OSError, _sp.TimeoutExpired):
        return None


def pytest_sessionstart(session):
    global _tree_state_at_start, _git_config_at_start
    _tree_state_at_start = _tree_fingerprint()
    if getattr(session.config, "workerinput", None) is None:
        _git_config_at_start = _git_hermeticity.config_fingerprint(
            Path(_conftest_dir))


def _tree_drift_summary(terminalreporter):
    if _tree_state_at_start is None:
        return
    now = _tree_fingerprint()
    if now is None or now == _tree_state_at_start:
        return
    tr = terminalreporter
    tr.section("source tree changed during this session", yellow=True,
               bold=True)
    tr.write_line(
        "The checkout was edited while tests ran (HEAD or dirty state "
        "differs from session start). Failures above may be artifacts "
        "of a mid-run edit, not real regressions — re-run on a quiescent "
        "tree before investigating them."
    )
    tr.write_line(
        f"  start: HEAD {_tree_state_at_start[0][:12]} "
        f"dirty {_tree_state_at_start[1]}"
    )
    tr.write_line(f"  end:   HEAD {now[0][:12]} dirty {now[1]}")
