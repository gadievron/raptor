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

# Agent CLI transports are the models.json analog for hosts running
# inside (or alongside) a live Claude/Copilot session: availability
# detection can select a keyless CLI transport, and any test that reaches
# a real dispatch —
# observed: run_orchestrator's IRIS refine loop building its
# "library callers and tests" fallback client — spawns the OPERATOR'S
# live CLI and spends real model budget as a side effect of running a
# tier. Live-LLM invocation from tests is explicit opt-in: export
# RAPTOR_TEST_LIVE_LLM=1 to run deliberately-live tests; everything
# else gets the spawn-time kill switch (billed claude spawns raise a
# named error; detection, selection and mock-driven transport-shape
# tests are unaffected). Subprocesses inherit the switch, so
# CLI-invoking e2e tests are covered without per-file plumbing.
# Force-assigned, not setdefault: an ambient RAPTOR_CC_TRANSPORT_
# DISABLED=0 (the documented spelling for keeping the transport live
# in production) would otherwise defeat the hermetic default silently.
# RAPTOR_TEST_LIVE_LLM=1 is the ONE spelling that makes test sessions
# live; per-module spawn-machinery opt-outs go through the
# cc_spawn_machinery_enabled fixture below.
if os.environ.get("RAPTOR_TEST_LIVE_LLM") != "1":
    os.environ["RAPTOR_CC_TRANSPORT_DISABLED"] = "1"
    os.environ["RAPTOR_COPILOT_TRANSPORT_DISABLED"] = "1"

# Semgrep phones home on any invocation (semgrep.dev version check,
# anonymous metrics) unless suppressed; tests that shell out to a real
# semgrep — directly or through libexec — otherwise burn connect
# retries against the egress deny and trip the session-end leak
# tripwire. Production spawns get the same pair from get_safe_env().
os.environ.setdefault("SEMGREP_ENABLE_VERSION_CHECK", "0")
os.environ.setdefault("SEMGREP_SEND_METRICS", "off")

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
import itertools as _itertools  # noqa: E402
import json as _json  # noqa: E402
import tempfile as _tempfile  # noqa: E402

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
            # Multiprocessing roots its PROCESS-LIFETIME temp dir
            # (``pymp-*`` — the forkserver socket lives there) under
            # whatever tempdir is current at first use, i.e. inside
            # THIS soon-to-be-removed scratch dir, and removes it via
            # an atexit finalizer at INTERPRETER exit — after the
            # ``with`` below has already deleted the parent. The
            # finalizer then crashed process exit with
            # FileNotFoundError (traceback after the pytest summary,
            # corrupted exit status on composed single-process runs).
            # Redirecting tempdir breaks multiprocessing's lifetime
            # assumption, so the redirect's owner reconciles: run
            # multiprocessing's own exit function NOW, while the
            # parent still exists. It is atexit-idempotent (the
            # ``_exiting`` guard makes the real-exit invocation a
            # no-op) and this is session teardown — no pools or
            # children may legitimately outlive this point.
            if "multiprocessing.util" in sys.modules:
                sys.modules["multiprocessing.util"]._exit_function()
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


# The session registry (~/.local/share/raptor/sessions.d) is REAL user
# state: start_run appends run-ledger records for the owning claude
# session, /project use|create write binding entries, and a battery
# running inside a live claude session would otherwise perturb the
# operator's actual entries (and accrete records pointing at pytest
# temp dirs). PER-TEST isolation: each test gets a fresh registry dir,
# so one test's binding writes can never poison another's layered
# get_active() resolution. Session identity is also neutralised by
# default — the tree walk finding the developer's real claude ancestor
# would make batch behaviour differ between "run inside claude" and CI.
# Tests that exercise resolution patch resolve_session_pid (or the
# walk) explicitly, as the registry suites already do.

@pytest.fixture(autouse=True)
def _llm_egress_env_hermetic():
    """Restore the process proxy env after any test that enabled the
    in-process LLM egress chokepoint.

    ``LLMClient.__init__`` → ``enable_llm_egress`` points
    HTTP(S)_PROXY at the loopback chokepoint PROCESS-WIDE by design.
    In a test process that mutation outlives the test: every later
    subprocess that honours proxy env and phones a host outside the
    LLM allowlist (observed: ``semgrep --validate``'s version check →
    ``semgrep.dev`` → proxy DENY → ~90s of retries → non-zero exit)
    inherits a chokepoint meant only for the SDKs. Snapshot the proxy
    vars up front; after each test that flipped the enable flag,
    restore them and reset the flag. The proxy thread itself is
    harmless once nothing routes through it.
    """
    import os as _os
    from core.llm import egress as _egress
    before = {k: _os.environ.get(k) for k in _egress._PROXY_VAR_NAMES}
    enabled_before = _egress._enabled
    yield
    if _egress._enabled and not enabled_before:
        for k, v in before.items():
            if v is None:
                _os.environ.pop(k, None)
            else:
                _os.environ[k] = v
        _egress._reset_for_tests()


@pytest.fixture
def cc_spawn_machinery_enabled(monkeypatch):
    """Clear the claude-CLI transport kill switch for tests that
    exercise the SPAWN MACHINERY itself against test-local fake
    children (``python -c`` scripts, mocked ``subprocess.run``) — no
    real ``claude`` is reachable from them. The root conftest sets
    ``RAPTOR_CC_TRANSPORT_DISABLED`` for every test session unless the
    operator opts into live LLM tests; files that opt out via this
    fixture must never dispatch the real CLI (declare fakes in the
    module docstring)."""
    monkeypatch.delenv("RAPTOR_CC_TRANSPORT_DISABLED", raising=False)


@pytest.fixture
def copilot_spawn_machinery_enabled(monkeypatch):
    """Enable test-local fake Copilot spawn machinery without live calls."""
    monkeypatch.setenv("RAPTOR_COPILOT_TRANSPORT_DISABLED", "0")


_SESSIONS_DIR_SEQ = _itertools.count()


@pytest.fixture(autouse=True)
def _sessions_registry_in_tmp(monkeypatch):
    # The redirect target is a UNIQUE PATH, not a pytest ``tmp_path``:
    # requesting ``tmp_path`` here made every test in the suite allocate
    # a numbered dir under the session basetemp, and pytest's
    # ``make_numbered_dir`` scans the basetemp per allocation — a cost
    # that grows with every test the session has already run (~30ms per
    # SETUP by the 10k-test mark, minutes of pure setup overhead across
    # a full single-process run). Nothing here needs a directory up
    # front: registry writers ``mkdir(parents=True)`` on demand and
    # readers treat a missing dir as an empty registry, so a fresh
    # never-created path per test keeps the write-isolation guarantee
    # at zero allocation cost. Created dirs land under the contained
    # session tmp (``_contained_system_tmp``) and are removed with it.
    from core.project import sessions as _sessions
    unique = (
        Path(_tempfile.gettempdir())
        / f"raptor-test-sessions-{os.getpid()}-{next(_SESSIONS_DIR_SEQ)}"
    )
    monkeypatch.setattr(_sessions, "SESSIONS_DIR", unique / "sessions.d")
    monkeypatch.setattr(_sessions, "_walk_session_pid", lambda: None)
    monkeypatch.delenv(_sessions.ENV_SESSION_PID, raising=False)
    monkeypatch.delenv(_sessions.ENV_SESSION_TOKEN, raising=False)
    # The pin freeze cache is process-global by design (sealed at
    # start_run); across TESTS it would leak one test's pin into the
    # next test's resolution — clear it per test.
    from core.run import pin as _pin
    _pin._frozen_pins.clear()


@pytest.fixture(autouse=True)
def _projects_registry_in_tmp(monkeypatch):
    """Pin the RAPTOR projects registry (~/.raptor/projects) to a
    fresh per-test path.

    Two-sided, same doctrine as the sessions-registry redirect above:
    the operator's REAL project store must never steer tests (an
    active project or a project whose output_path matches a test dir
    changes resolution behaviour — the static-analysis suite already
    carried this fixture locally after exactly that incident), and a
    test that creates projects must never write into the operator's
    store. It is also a measured perf chokepoint: ``resolve_run_pin``
    consults ``is_project_output_dir`` per walk level, each of which
    ``list_projects()``-loads EVERY json in the store — against a
    populated operator store (hundreds of projects) that is tens of
    milliseconds per resolve, times 8+ resolves per audit-prep
    fixture, across thousands of tests. ``ProjectManager`` reads the module global at call time and
    creates the dir on demand, so a never-created unique path is
    sufficient. Suites that need a populated registry pass their own
    ``projects_dir`` / patch (monkeypatch wins over this default).
    """
    unique = (
        Path(_tempfile.gettempdir())
        / f"raptor-test-projects-{os.getpid()}-{next(_SESSIONS_DIR_SEQ)}"
    )
    monkeypatch.setattr(
        "core.project.project.PROJECTS_DIR", unique / "projects",
    )
    # core.startup keeps its own import-time copies (PROJECTS_DIR and
    # the derived ACTIVE_LINK) for the light no-ProjectManager readers
    # (get_active_name and the expiry probe) — patch both so the light
    # path resolves the same isolated store as the manager path.
    monkeypatch.setattr(
        "core.startup.PROJECTS_DIR", unique / "projects",
    )
    monkeypatch.setattr(
        "core.startup.ACTIVE_LINK", unique / "projects" / ".active",
    )


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
# randomise the collected test order so order-dependent failures
# surface early.  No external plugin required.
#
# Scope-grouped: the MODULE order is shuffled, then the class-bucket
# order within each module, then the test order within each bucket.  A
# flat item shuffle scattered every module across the session, so
# pytest re-ran module- and class-scoped fixtures once per contiguous
# fragment — observed as 4-6 re-runs of the multi-second audit-prep
# module fixtures per shuffled session (and the same fragmentation for
# expensive class fixtures within their module), a pure fixture-cost
# multiplier on the single-process nightly tier.  Grouping bounds every
# module and class fixture to one setup per session while keeping the
# order-dependence classes the tier has actually caught: cross-module
# state leaks (module order still random), cross-class coupling (class
# order within the module still random), and intra-class coupling
# (item order still random).  What it no longer exercises is one
# scope's test running in the MIDDLE of another scope's fragment —
# pairs of that shape are covered per-worker in the xdist PR tier,
# where distribution interleaves scopes anyway.
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
    rng = _random.Random(seed)

    # module path → ordered class-buckets → items.  The bucket key is
    # the nodeid minus its final component: module-level functions
    # bucket per module, class methods per class (parametrised ids
    # keep their function's bucket).
    module_order: list[str] = []
    module_buckets: dict[str, dict[str, list]] = {}
    for item in items:
        parts = item.nodeid.split("::")
        module_key = parts[0]
        bucket_key = "::".join(parts[:-1]) or module_key
        buckets = module_buckets.get(module_key)
        if buckets is None:
            module_buckets[module_key] = buckets = {}
            module_order.append(module_key)
        buckets.setdefault(bucket_key, []).append(item)
    rng.shuffle(module_order)
    reordered = []
    for module_key in module_order:
        buckets = module_buckets[module_key]
        bucket_order = list(buckets)
        rng.shuffle(bucket_order)
        for bucket_key in bucket_order:
            bucket = buckets[bucket_key]
            rng.shuffle(bucket)
            reordered.extend(bucket)
    items[:] = reordered


def pytest_report_header():
    if _RANDOMISE_SEED_RAW is None:
        return []
    return [f"raptor: randomised test order (seed={_RANDOMISE_SEED_RAW})"]


_MAX_TEST_SECONDS = os.environ.get("RAPTOR_MAX_TEST_SECONDS")
_slow_test_threshold = float(_MAX_TEST_SECONDS) if _MAX_TEST_SECONDS else None
_slow_test_overruns: "list[tuple[str, str, float]]" = []

# Pre-emption band: at HALF the failure budget (5s at the CI default),
# a test is one load spike away from the cliff — the guard's own
# incident history is tests discovered AT the threshold, not
# approaching it. Overruns of the warn band get a loud terminal
# listing (never a failure) so the drift is visible run-over-run.
_slow_test_warnings: "list[tuple[str, str, float]]" = []

# Per-TIER wallclock tripwire, companion to the per-test guard above:
# RAPTOR_MAX_TEST_SECONDS catches one slow test; this catches the
# aggregate drift no single test explains (suite growth, a fixture
# cost multiplied across thousands of tests). Activated only when the
# workflow sets RAPTOR_MAX_SESSION_SECONDS to that tier's measured
# baseline plus headroom; flags at session end (never kills), so the
# failure names the budget instead of dying as an opaque runner-level
# job timeout. Local runs are unaffected.

_MAX_SESSION_SECONDS = os.environ.get("RAPTOR_MAX_SESSION_SECONDS")
_session_budget = float(_MAX_SESSION_SECONDS) if _MAX_SESSION_SECONDS else None
_session_started_at: "float | None" = None
_session_overrun: "float | None" = None


def pytest_runtest_logreport(report):
    """Record any test whose SETUP or CALL phase exceeds a band.

    Setup counts the same as call: fixture work is test work (the
    audit-prep fixtures have historically been the heaviest phase in
    the tier), and a 10s setup reds a shard exactly like a 10s call.
    Teardown is deliberately out of both bands — nothing in the tier
    has a nontrivial teardown today, and adding a new failure surface
    for cleanup cost should be its own decision.
    """
    if _slow_test_threshold is None:
        return
    if report.when not in ("setup", "call"):
        return
    if report.duration > _slow_test_threshold:
        _slow_test_overruns.append(
            (report.nodeid, report.when, report.duration))
    elif report.duration > _slow_test_threshold / 2:
        _slow_test_warnings.append(
            (report.nodeid, report.when, report.duration))


def pytest_sessionfinish(session, exitstatus):
    """Fail an otherwise-green session if any test overran the threshold,
    the session overran its tier wallclock budget, mutated the ambient
    checkout's repo-level git config, or leaked the LLM-egress proxy
    env past the end of the session."""
    _check_git_config_drift(session)
    _check_egress_leak(session)
    _check_session_budget(session)
    # The leak-marker dir has served its purpose once the controller's
    # check above merged it (workers never remove it — their controller
    # still needs it). Findings live on in _egress_leaks for the
    # terminal summary. SIGKILLed sessions leak one reaper-prefixed
    # dir, reclaimed by tmp_reaper past the age floor.
    if _egress_leak_dir_owner and _egress_leak_dir:
        import shutil as _shutil
        _shutil.rmtree(_egress_leak_dir, ignore_errors=True)
    if _slow_test_threshold is None or not _slow_test_overruns:
        return
    if session.exitstatus == 0:
        session.exitstatus = 1


def _check_session_budget(session):
    global _session_overrun
    if _session_budget is None or _session_started_at is None:
        return
    # Workers under xdist are partial views; the controller session
    # spans the whole tier run and is the one that enforces.
    if getattr(session.config, "workerinput", None) is not None:
        return
    import time as _time
    elapsed = _time.monotonic() - _session_started_at
    if elapsed <= _session_budget:
        return
    _session_overrun = elapsed
    if session.exitstatus == 0:
        session.exitstatus = 1


def _session_budget_summary(terminalreporter):
    if _session_overrun is None:
        return
    tr = terminalreporter
    tr.section("tier wallclock budget FAILED", red=True, bold=True)
    tr.write_line(
        f"This session took {_session_overrun:.0f}s against a "
        f"RAPTOR_MAX_SESSION_SECONDS budget of {_session_budget:.0f}s."
    )
    tr.write_line(
        "The budget is the tier's measured baseline plus headroom (set "
        "in the calling workflow). No single test need be slow for this "
        "to fire — look for suite-wide drift: a fixture cost multiplied "
        "across thousands of tests, heavyweight tests landing in bulk, "
        "or a starved runner. Compare --durations output against the "
        "baseline table in the workflow file, then either fix the drift "
        "or consciously raise the budget alongside the new baseline."
    )


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


# ---------------------------------------------------------------------------
# LLM-egress leak guard (fails the session).
#
# enable_llm_egress (an LLMClient.__init__ side effect) points the
# HTTP(S)_PROXY family at an in-process loopback proxy. A test that
# constructs a real client without the shared reset fixture
# (core.testing.reset_llm_egress_state) leaks that dead pointer into
# every later suite in the same process — observed as sandbox proxy
# tests tunnelling via a long-gone upstream and mocked-client tests
# burning connect timeouts. The per-directory conftests fix known
# constructors; this guard makes the NEXT uncovered directory fail
# loudly at session end instead of poisoning combined runs.
#
# ENFORCED under xdist too: worker exitstatus propagation is weak, so
# a leaking worker additionally drops a marker file into a directory
# the spawning (controller) process created and published through the
# environment (same handoff pattern as the ambient-git-env snapshot).
# The controller reads the markers at ITS sessionfinish — which runs
# after every worker has completed — merges them into its own
# findings, and fails the run. Every non-worker pytest process creates
# a FRESH dir and re-publishes it, so nested pytest sessions (tests
# that spawn pytest) never write into an outer session's dir. Cost:
# one env scan per session + one empty-dir listing on the controller;
# core.llm.egress is looked up via sys.modules, never imported, so
# sessions that never touch LLM code pay nothing.
# ---------------------------------------------------------------------------

_egress_leaks: "list[str]" = []

_EGRESS_LEAK_DIR_ENV = "RAPTOR_EGRESS_LEAK_DIR"
_egress_leak_dir: "str | None" = None
_egress_leak_dir_owner = False


def pytest_configure(config):
    """Mint or adopt the egress-guard marker dir.

    Worker-ness is decided from ``config.workerinput`` — authoritative
    for THIS session — never from the inheritable PYTEST_XDIST_WORKER
    env var: a pytest child spawned from inside an xdist worker's test
    inherits that var, and an env-based check made such a child adopt
    (and its own workers contaminate) the OUTER session's guard dir.
    With workerinput, any non-worker session — top-level or a nested
    controller spawned by a test, under any parent shape — mints a
    fresh dir and re-publishes it, so marker files can only ever flow
    worker → own controller. xdist spawns workers after the
    controller's configure, so the published dir is always this
    controller's. The reaper-listed raptor-pytest- prefix covers the
    SIGKILL-leak case (normal exits remove it in sessionfinish).
    """
    global _egress_leak_dir, _egress_leak_dir_owner
    if getattr(config, "workerinput", None) is not None:
        _egress_leak_dir = os.environ.get(_EGRESS_LEAK_DIR_ENV)
        _egress_leak_dir_owner = False
    else:
        _egress_leak_dir = _tempfile.mkdtemp(prefix="raptor-pytest-egress-")
        os.environ[_EGRESS_LEAK_DIR_ENV] = _egress_leak_dir
        _egress_leak_dir_owner = True


def _check_egress_leak(session):
    import sys as _sys

    for key, value in os.environ.items():
        if key.upper() in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY") \
                and "127.0.0.1" in value:
            _egress_leaks.append(f"{key}={value}")
    egress_mod = _sys.modules.get("core.llm.egress")
    if egress_mod is not None and getattr(egress_mod, "_enabled", False):
        _egress_leaks.append("core.llm.egress._enabled is still True")

    is_worker = getattr(session.config, "workerinput", None) is not None
    if is_worker:
        # Report to the controller — its sessionfinish runs after every
        # worker completes and is the one whose exit status the run
        # keeps. Best-effort: a write failure degrades to the old
        # print-only worker behaviour rather than masking the tests.
        if _egress_leaks and _egress_leak_dir:
            worker_id = os.environ.get("PYTEST_XDIST_WORKER", "gw?")
            try:
                marker = Path(_egress_leak_dir) / f"{worker_id}-{os.getpid()}.leak"
                marker.write_text(
                    "".join(f"{line}\n" for line in _egress_leaks),
                    encoding="utf-8",
                )
            except (OSError, ValueError):
                # ValueError covers UnicodeEncodeError from a
                # surrogate-bearing env value; degrade to the old
                # print-only worker behaviour, never mask tests.
                pass
    else:
        # Controller: merge every worker's report before deciding.
        if _egress_leak_dir:
            try:
                for marker in sorted(Path(_egress_leak_dir).glob("*.leak")):
                    worker_id = marker.name.rsplit("-", 1)[0]
                    for line in marker.read_text(
                            encoding="utf-8").splitlines():
                        _egress_leaks.append(f"[worker {worker_id}] {line}")
            except OSError:
                pass

    if not _egress_leaks:
        return
    if session.exitstatus == 0:
        session.exitstatus = 1


def _egress_leak_summary(terminalreporter):
    if not _egress_leaks:
        return
    tr = terminalreporter
    tr.section("LLM-egress hermeticity guard FAILED", red=True, bold=True)
    tr.write_line(
        "The in-process LLM egress proxy env leaked past session end — "
        "some test constructed a real LLMClient (enable_llm_egress) in "
        "a directory whose conftest does not wrap "
        "core.testing.reset_llm_egress_state:"
    )
    for line in _egress_leaks:
        tr.write_line(f"  {line}")
    tr.write_line(
        "Add the autouse reset fixture to that directory's conftest "
        "(see core/llm/tests/conftest.py for the pattern). The session "
        "exit status has been forced to 1."
    )


def pytest_terminal_summary(terminalreporter):
    _tree_drift_summary(terminalreporter)
    _git_config_drift_summary(terminalreporter)
    _egress_leak_summary(terminalreporter)
    _session_budget_summary(terminalreporter)
    if _slow_test_threshold is None:
        return
    tr = terminalreporter
    if _slow_test_warnings:
        tr.section("default-tier slow-test guard WARNING", yellow=True,
                   bold=True)
        tr.write_line(
            f"{len(_slow_test_warnings)} test phase(s) exceeded HALF the "
            f"RAPTOR_MAX_TEST_SECONDS={_slow_test_threshold}s budget — "
            "one load spike from the failure cliff. Not a failure; "
            "pre-empt now (mock the I/O, or mark @pytest.mark.slow if "
            "the cost is genuine) instead of meeting these again at "
            "the threshold."
        )
        for nodeid, phase, dur in sorted(
                _slow_test_warnings, key=lambda x: -x[2]):
            tr.write_line(f"  {dur:7.1f}s  {phase:5}  {nodeid}")
    if not _slow_test_overruns:
        return
    tr.section("default-tier slow-test guard FAILED", red=True, bold=True)
    tr.write_line(
        f"{len(_slow_test_overruns)} test phase(s) exceeded "
        f"RAPTOR_MAX_TEST_SECONDS={_slow_test_threshold}s in the default "
        "tier (setup counts the same as call: fixture work is test work)."
    )
    tr.write_line(
        "A default-tier test this slow is almost always real I/O that "
        "should be mocked (subprocess / network / time.sleep / sandbox "
        "setup). Fix it — or, if the cost is genuine, mark it "
        "@pytest.mark.slow so it runs in the nightly tier instead.",
    )
    for nodeid, phase, dur in sorted(
            _slow_test_overruns, key=lambda x: -x[2]):
        tr.write_line(f"  {dur:7.1f}s  {phase:5}  {nodeid}")


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
    global _tree_state_at_start, _git_config_at_start, _session_started_at
    import time as _time
    _session_started_at = _time.monotonic()
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
