"""The containment-floor contract: lattice, entry check, dispatch
assertions.

Four load-bearing properties, each pinned here:

1. The tier lattice is a total order per platform, and floors resolve
   per caller class exactly as the per-lane gates they subsumed
   demanded (consent-chain matrix).
2. Every dispatch site carries a declared tier and a hard pre-exec
   floor check (source tripwire), so a FUTURE lane wired into the
   demotion ladder without a thought for the contract fails closed
   (the fake-lane simulation) — under the old per-lane-gate
   architecture it silently executed.
3. The assertion is a runtime raise, not a debug artifact: python -O
   cannot strip it, no flag skips it, and the error type inherits the
   BaseException fail-loud semantics.
4. The mount and mountless spawn lanes stamp the same posture surface,
   differing exactly as declared (parity contract).
"""

import os
import subprocess
import sys
import textwrap
import types
from pathlib import Path

import pytest

from core.sandbox import tiers as _tiers
from core.sandbox.errors import SandboxFloorError, SandboxSetupError
from core.sandbox.tiers import ContainmentTier

_REPO_ROOT = Path(__file__).resolve().parents[3]


# ---------------------------------------------------------- unit tier

def test_lattice_is_total_and_strictly_ordered_per_platform():
    linux = [ContainmentTier.BARE, ContainmentTier.LANDLOCK_ONLY,
             ContainmentTier.NS_NOMOUNT, ContainmentTier.MOUNTLESS_NS,
             ContainmentTier.MOUNT_NS]
    assert linux == sorted(linux)
    assert len({int(t) for t in linux}) == len(linux)
    # macOS values live far above the Linux band so an accidental
    # cross-platform compare is loudly wrong rather than subtly wrong.
    assert ContainmentTier.SEATBELT > ContainmentTier.MOUNT_NS


def test_tier_labels_round_trip():
    for tier in ContainmentTier:
        assert _tiers.label_tier(_tiers.tier_label(tier)) is tier
    with pytest.raises(KeyError):
        _tiers.label_tier("no-such-tier")


def test_floor_class_defaults_per_platform(monkeypatch):
    assert _tiers.untrusted_default_floor() in (
        ContainmentTier.MOUNT_NS, ContainmentTier.SEATBELT)
    monkeypatch.setattr(_tiers, "sys",
                        types.SimpleNamespace(platform="darwin"))
    assert _tiers.untrusted_default_floor() is ContainmentTier.SEATBELT
    assert _tiers.waived_untrusted_floor() is ContainmentTier.BARE
    monkeypatch.setattr(_tiers, "sys",
                        types.SimpleNamespace(platform="linux"))
    assert _tiers.untrusted_default_floor() is ContainmentTier.MOUNT_NS
    assert _tiers.waived_untrusted_floor() is (
        ContainmentTier.LANDLOCK_ONLY)


def test_consent_chain_matrix(monkeypatch):
    """Every (disable × contract-flag × workload) cell resolves to
    exactly the floor the subsumed gates demanded: operator disable is
    globally authoritative (BARE), the resolved contract gets the
    platform's untrusted floor, waived untrusted work gets the frozen
    env-var mapping (LANDLOCK_ONLY on Linux, BARE on macOS — the
    documented arm-3 semantics), and plain trusted calls get BARE with
    the default source. Nothing consents untrusted work to BARE on
    Linux."""
    monkeypatch.setattr(_tiers, "sys",
                        types.SimpleNamespace(platform="linux"))
    cases = {
        # (disabled, require_fresh_procfs, untrusted, waiver_active):
        #     (floor, source)
        (True, True, True, True): (ContainmentTier.BARE,
                                   "operator-disable"),
        (True, None, False, False): (ContainmentTier.BARE,
                                     "operator-disable"),
        (False, True, True, False): (ContainmentTier.MOUNT_NS,
                                     "default"),
        (False, True, False, False): (ContainmentTier.MOUNT_NS,
                                      "default"),
        # Kwarg present-but-zeroed under the waiver: the lowered floor
        # is attributed to the env consent source.
        (False, False, True, True): (ContainmentTier.LANDLOCK_ONLY,
                                     "env"),
        (False, False, False, True): (ContainmentTier.LANDLOCK_ONLY,
                                      "env"),
        # Same shape WITHOUT the waiver (caller-level literal False):
        # same floor, but no "env" attribution — no banner or
        # waiver-named warning may fire for consent nobody gave.
        (False, False, True, False): (ContainmentTier.LANDLOCK_ONLY,
                                      "default"),
        (False, False, False, False): (ContainmentTier.LANDLOCK_ONLY,
                                       "default"),
        # Untrusted-marked call that never derived the contract kwarg:
        # fail CLOSED at the class default — the waived floor belongs
        # only to callers that carried the env-var-honouring
        # derivation through; the resolver must not attribute consent
        # nobody verified.
        (False, None, True, True): (ContainmentTier.MOUNT_NS,
                                    "default"),
        (False, None, True, False): (ContainmentTier.MOUNT_NS,
                                     "default"),
        (False, None, False, False): (ContainmentTier.BARE, "default"),
    }
    for (disabled, rfp, untrusted, waiver), expected in cases.items():
        got = _tiers.resolve_call_floor(
            operator_disabled=disabled, require_fresh_procfs=rfp,
            untrusted_workload=untrusted, waiver_active=waiver)
        assert got == expected, (disabled, rfp, untrusted, waiver, got)
    monkeypatch.setattr(_tiers, "sys",
                        types.SimpleNamespace(platform="darwin"))
    assert _tiers.resolve_call_floor(
        operator_disabled=False, require_fresh_procfs=True,
        untrusted_workload=True) == (ContainmentTier.SEATBELT, "default")
    assert _tiers.resolve_call_floor(
        operator_disabled=False, require_fresh_procfs=False,
        untrusted_workload=True,
        waiver_active=True) == (ContainmentTier.BARE, "env")


def test_rfp_kwarg_falsy_literals_normalise_to_false(
        tmp_path, monkeypatch):
    """A literal falsy require_fresh_procfs (0, '') must resolve like
    the derived False (waived-class floor), not like an absent kwarg —
    the tri-state boundary normalises before resolution. The floor
    SOURCE follows the env truth: "env" only when the waiver really
    is set; a bare literal gets the same floor with the default
    source (no banner in the waiver's name).

    The waived-class floor is PLATFORM-RESOLVED: 'landlock' on Linux
    (the waiver's frozen meaning) and 'none' on macOS — there is no
    Landlock tier to hold there, and the waiver's documented macOS
    semantics accept rlimits-only containment (the alternative would
    be that untrusted work can never run on a seatbelt-broken mac,
    which is the DEFAULT the waiver exists to escape). The mapping
    itself is pinned platform-explicitly by
    test_floor_class_defaults_per_platform and the consent matrix;
    this test asserts the run() plumbing against the resolved value.
    On macOS the Linux spawn stub is inert and the platform's real
    backend serves the call — the floor stamps are lane-independent.
    """
    import subprocess as _subprocess

    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx

    def ok_spawn(cmd, **kwargs):
        return _subprocess.CompletedProcess(cmd, returncode=0,
                                            stdout="", stderr="")

    monkeypatch.setattr(_spawn_mod, "run_sandboxed", ok_spawn)
    monkeypatch.delenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", raising=False)
    waived_label = _tiers.tier_label(_tiers.waived_untrusted_floor())
    try:
        r = _ctx.run(["true"], target=str(tmp_path),
                     output=str(tmp_path), timeout=60,
                     require_fresh_procfs=0)
    except BaseException as e:  # noqa: BLE001 — host capability gate
        pytest.skip(f"sandbox lane unavailable on this host: {e}")
    assert r.sandbox_info["floor_source"] == "default"
    assert r.sandbox_info["containment_floor"] == waived_label

    monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")
    r = _ctx.run(["true"], target=str(tmp_path),
                 output=str(tmp_path), timeout=60,
                 require_fresh_procfs=0)
    assert r.sandbox_info["floor_source"] == "env"
    assert r.sandbox_info["containment_floor"] == waived_label


def test_assert_floor_semantics():
    """For every (delivered, floor) pair exactly one of {returns,
    SandboxFloorError} by ``delivered >= floor`` — never a run below
    floor, never a refusal at/above it."""
    linux = [ContainmentTier.BARE, ContainmentTier.LANDLOCK_ONLY,
             ContainmentTier.NS_NOMOUNT, ContainmentTier.MOUNTLESS_NS,
             ContainmentTier.MOUNT_NS]
    for delivered in linux:
        for floor in linux:
            if delivered >= floor:
                _tiers.assert_floor(delivered, floor, lane="t")
            else:
                with pytest.raises(SandboxFloorError) as excinfo:
                    _tiers.assert_floor(delivered, floor, lane="t")
                assert excinfo.value.achievable is delivered
                assert excinfo.value.floor is floor


def test_assert_floor_chains_cause_and_lifts_category():
    cause = SandboxSetupError("backend died", setup_category="U")
    with pytest.raises(SandboxFloorError) as excinfo:
        _tiers.assert_floor(
            ContainmentTier.LANDLOCK_ONLY, ContainmentTier.MOUNT_NS,
            lane="fallback", cause=cause, detail="why-text",
            remedy="set THE_OVERRIDE")
    e = excinfo.value
    assert e.__cause__ is cause
    assert e.setup_category == "U"     # lifted from the cause
    assert "why-text" in str(e)
    assert "set THE_OVERRIDE" in str(e)
    assert isinstance(e, SandboxSetupError)   # subtype, existing catches
    assert isinstance(e, BaseException) and not isinstance(e, Exception)


def test_assert_floor_survives_python_O():
    """The floor assertion is a plain runtime raise — optimized
    bytecode (-O, which strips ``assert`` statements and
    ``__debug__`` blocks) cannot remove it."""
    code = textwrap.dedent("""
        import os, sys
        sys.path.insert(0, os.environ["RAPTOR_DIR"])
        from core.sandbox.tiers import ContainmentTier, assert_floor
        from core.sandbox.errors import SandboxFloorError
        try:
            assert_floor(ContainmentTier.LANDLOCK_ONLY,
                         ContainmentTier.MOUNT_NS, lane="probe")
        except SandboxFloorError:
            print("floor-held-under-O")
    """)
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "RAPTOR_DIR": str(_REPO_ROOT),
    }
    r = subprocess.run([sys.executable, "-O", "-c", code], env=env,
                       capture_output=True, text=True, timeout=60,
                       check=False)
    assert r.returncode == 0, r.stderr
    assert "floor-held-under-O" in r.stdout


def test_no_debug_gating_in_contract_source():
    """Source pin: neither the lattice nor the dispatch checks hide
    behind ``__debug__`` or an ``assert`` statement, so no bytecode
    optimisation level and no flag can disable the boundary."""
    tiers_src = (_REPO_ROOT / "core/sandbox/tiers.py").read_text(
        encoding="utf-8")
    assert "__debug__" not in tiers_src
    assert "\nassert " not in tiers_src.replace("    assert_floor", "")
    ctx_src = (_REPO_ROOT / "core/sandbox/context.py").read_text(
        encoding="utf-8")
    check_def = ctx_src[ctx_src.index("def _dispatch_floor_check"):]
    check_def = check_def[:check_def.index("\n        # NOTE")
                          if "\n        # NOTE" in check_def[:4000]
                          else 4000]
    assert "__debug__" not in check_def
    assert "_tiers.assert_floor" in check_def


def test_no_bare_executor_calls_outside_the_checked_dispatch():
    """Structural executor gate (AST, not a lexical window): every
    process-spawning call in context.py must live inside the
    ``executor=`` thunk of a ``_dispatch_floor_check`` call — the
    checked dispatch chokepoint that performs the floor assertion and
    then invokes the executor — or inside one of the two named
    executor-implementation defs it dispatches
    (``_run_teardown_first_timeout``, ``_run_spawn_backend``). A
    future lane that spawns a process any other way IN THIS MODULE
    (bare subprocess.run/Popen, os.exec*, a new in-file helper)
    fails this gate regardless of where in the file it sits — closing
    the lexical-window and anchor-spelling evasions a plain grep
    tripwire allows. An executor hidden in ANOTHER module is out of
    this gate's sight by construction; the runtime dominance stamp
    (run()'s epilogue rejects unstamped results — see
    test_unstamped_result_is_refused_at_the_epilogue) is the
    cross-module backstop."""
    import ast as _ast

    src = (_REPO_ROOT / "core/sandbox/context.py").read_text(
        encoding="utf-8")
    tree = _ast.parse(src)
    parents: dict = {}
    for node in _ast.walk(tree):
        for child in _ast.iter_child_nodes(node):
            parents[child] = node

    def _is_spawn_call(call: "_ast.Call") -> "str | None":
        func = call.func
        if isinstance(func, _ast.Attribute):
            attr = func.attr
            base = (func.value.id
                    if isinstance(func.value, _ast.Name) else None)
            if base == "subprocess" and attr in (
                    "run", "Popen", "check_output", "check_call",
                    "call"):
                return f"subprocess.{attr}"
            if base == "os" and (
                    attr == "system" or attr.startswith("exec")
                    or attr.startswith("spawn")
                    or attr.startswith("posix_spawn")):
                return f"os.{attr}"
            if attr in ("run_sandboxed", "run_landlock_audit"):
                return f"{base or '?'}.{attr}"
            return None
        if isinstance(func, _ast.Name) and func.id in (
                "_run_teardown_first_timeout", "_run_spawn_backend",
                "run_landlock_audit", "run_sandboxed"):
            return func.id
        return None

    violations: list = []
    for node in _ast.walk(tree):
        if not isinstance(node, _ast.Call):
            continue
        spawn = _is_spawn_call(node)
        if spawn is None:
            continue
        cur = node
        ok = False
        while cur in parents:
            cur = parents[cur]
            if (isinstance(cur, _ast.FunctionDef)
                    and cur.name in ("_run_teardown_first_timeout",
                                     "_run_spawn_backend")):
                # The named executor implementations — reachable only
                # through the checked dispatch's executor thunks.
                ok = True
                break
            if isinstance(cur, _ast.Lambda):
                kw = parents.get(cur)
                outer = parents.get(kw) if kw is not None else None
                if (isinstance(kw, _ast.keyword)
                        and kw.arg == "executor"
                        and isinstance(outer, _ast.Call)
                        and isinstance(outer.func, _ast.Name)
                        and outer.func.id == "_dispatch_floor_check"):
                    ok = True
                    break
        if not ok:
            violations.append((node.lineno, spawn))
    assert not violations, (
        f"process-spawning calls outside the checked dispatch "
        f"chokepoint: {violations} — route them through "
        f"_dispatch_floor_check(lane, executor=...) so the floor "
        f"assertion cannot be bypassed")
    # Anti-aliasing: the spawn-name matcher above keys on the literal
    # `subprocess.` / `os.` bases, so re-binding either module to
    # another name (or importing spawn callables directly) would blind
    # it. Refuse the aliasing shapes themselves.
    for node in _ast.walk(tree):
        if isinstance(node, _ast.Assign) and isinstance(
                node.value, _ast.Name) and node.value.id in (
                    "subprocess", "os"):
            pytest.fail(f"context.py:{node.lineno} re-binds the "
                        f"{node.value.id} module — this would blind "
                        f"the executor gate")
        if isinstance(node, _ast.ImportFrom) and node.module in (
                "subprocess", "os"):
            spawny = [a.name for a in node.names
                      if a.name in ("run", "Popen", "check_output",
                                    "check_call", "call", "system")
                      or a.name.startswith(("exec", "spawn",
                                            "posix_spawn"))]
            assert not spawny, (
                f"context.py:{node.lineno} imports spawn callables "
                f"directly ({spawny}) — this would blind the "
                f"executor gate")
        if isinstance(node, _ast.Import):
            for a in node.names:
                if a.name in ("subprocess", "os") and a.asname:
                    pytest.fail(
                        f"context.py:{node.lineno} imports "
                        f"{a.name} under an alias — this would "
                        f"blind the executor gate")
    # Sanity: the gate actually saw the real dispatch sites.
    thunked = sum(
        1 for node in _ast.walk(tree)
        if isinstance(node, _ast.Call)
        and isinstance(node.func, _ast.Name)
        and node.func.id == "_dispatch_floor_check"
    )
    assert thunked >= 6, f"expected >=6 checked dispatches, saw {thunked}"


def test_lane_registry_covers_every_lane_and_matches_the_lattice():
    """The deleted unshare-CLI lane must never resurface as a registry
    entry: NS_NOMOUNT is delivered only as a ``cap=`` on the mountless
    spawn (the Landlock-absent mode), never by a lane of its own."""
    from core.sandbox import context as _ctx
    expected = {
        "seatbelt spawn": ContainmentTier.SEATBELT,
        "mount-ns spawn": ContainmentTier.MOUNT_NS,
        "mountless namespace backend": ContainmentTier.MOUNTLESS_NS,
        "Landlock-only subprocess": ContainmentTier.LANDLOCK_ONLY,
    }
    assert _ctx._LANE_TIERS == expected


# --------------------------------------------------- integration tier

def _untrusted_preflight(ctx_mod, spawn_mod, monkeypatch, tmp_path):
    """Prove run_untrusted() reaches the spawn dispatch on this host
    with a stubbed-successful backend; skip (host environment) if not."""

    def ok_spawn(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, returncode=0,
                                           stdout="", stderr="")

    monkeypatch.setattr(spawn_mod, "run_sandboxed", ok_spawn)
    try:
        r = ctx_mod.run_untrusted(["true"], target=str(tmp_path),
                                  output=str(tmp_path), timeout=60)
    except BaseException as e:  # noqa: BLE001 — includes SandboxSetupError
        pytest.skip(f"untrusted lane unavailable on this host: {e}")
    if r.returncode != 0:
        pytest.skip("untrusted lane pre-flight did not run cleanly")


@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_future_below_floor_lane_is_caught_by_the_dispatch_assert(
        tmp_path, monkeypatch):
    """THE contract test: someone adds (or reroutes to) a demotion lane
    below the floor and forgets every gate. Simulated by injecting the
    environmental spawn-exception shape and re-declaring the fallback
    lane's tier as LANDLOCK_ONLY in the lane registry — the dispatch
    site itself carries the declaration and the assertion, so the stub
    lane cannot execute the sentinel: SandboxFloorError with the
    structured fields, the injected error chained, exactly one spawn
    attempt, sentinel absent. Under the per-lane-gate architecture this
    scenario silently executed."""
    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx
    monkeypatch.delenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", raising=False)
    _untrusted_preflight(_ctx, _spawn_mod, monkeypatch, tmp_path)

    injected = OSError("forced spawn setup failure")
    attempts: list[int] = []
    sentinel = tmp_path / "future-lane-ran.marker"

    def raising_spawn(cmd, **kwargs):
        attempts.append(1)
        raise injected

    monkeypatch.setattr(_spawn_mod, "run_sandboxed", raising_spawn)
    # The "future lane": with the unshare-CLI namespace fallback
    # deleted, the ladder's only fallback IS a below-floor lane
    # (Landlock-only). A future rewrite that re-tagged it stronger
    # would be caught by the registry pin; here the floor must refuse
    # the demotion outright.
    with pytest.raises(SandboxFloorError) as excinfo:
        _ctx.run_untrusted(["touch", str(sentinel)],
                           target=str(tmp_path), output=str(tmp_path),
                           timeout=60)
    e = excinfo.value
    assert e.floor is ContainmentTier.MOUNT_NS
    assert e.achievable is ContainmentTier.LANDLOCK_ONLY
    assert e.__cause__ is injected
    assert "RAPTOR_ALLOW_DEGRADED_UNTRUSTED" in str(e)
    assert len(attempts) == 1, "expected exactly one spawn attempt"
    assert not sentinel.exists(), (
        "the below-floor stub lane executed the target")


@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_mount_and_mountless_lanes_stamp_the_same_posture_surface(
        tmp_path, monkeypatch):
    """Parity contract: the mount and mountless spawn lanes produce the
    same sandbox_info posture keys with the same truth values,
    differing exactly as declared — containment_tier names the lane's
    tier, the mountless lane additionally stamps its backend, and
    mount_ns_active flips."""
    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx
    # Pin the Landlock probe: the parity under test is the mount vs
    # mountless POSTURE surface; on a Landlock-less matrix lane the
    # tolerance mode would (correctly) re-cap the mountless lane at
    # ns-only, which is the ported lane's own contract, covered in
    # test_landlock_absent_ns_lane.
    monkeypatch.setattr(_ctx, "check_landlock_available", lambda: True)
    calls: list[dict] = []
    fail_first = [False]

    def fake_spawn(cmd, **kwargs):
        calls.append(kwargs)
        cp = subprocess.CompletedProcess(cmd, returncode=0,
                                         stdout="", stderr="")
        cp._setup_status = (
            ("M", "forced mount-ns failure")
            if fail_first[0] and len(calls) == 1 else None)
        return cp

    monkeypatch.setattr(_spawn_mod, "run_sandboxed", fake_spawn)
    try:
        mount_r = _ctx.run(["true"], target=str(tmp_path),
                           output=str(tmp_path), timeout=60)
    except BaseException as e:  # noqa: BLE001 — host capability gate
        pytest.skip(f"mount-ns lane unavailable: {e}")
    if not mount_r.sandbox_info.get("mount_ns_active"):
        pytest.skip("mount-ns lane not taken on this host")

    calls.clear()
    fail_first[0] = True
    mountless_r = _ctx.run(["true"], target=str(tmp_path),
                           output=str(tmp_path), timeout=60)

    mi, li = mount_r.sandbox_info, mountless_r.sandbox_info
    assert mi["containment_tier"] == "mount-ns"
    assert li["containment_tier"] == "mountless-ns"
    assert mi["containment_floor"] == li["containment_floor"] == "none"
    assert mi["floor_source"] == li["floor_source"] == "default"
    assert mi["mount_ns_active"] is True
    assert li["mount_ns_active"] is False
    assert "backend" not in mi
    assert li["backend"] == "landlock-pidns"
    # Same posture surface otherwise: every floor-contract key present
    # in one is present in the other with the same shape.
    for key in ("containment_tier", "containment_floor", "floor_source",
                "mount_ns_active", "restrict_reads"):
        assert key in mi and key in li, key
    # Symmetric key-set parity: the two lanes may differ ONLY by the
    # declared asymmetries — a new posture key stamped on one lane
    # but not the other is a parity regression.
    allowed_asymmetry = {
        "backend", "fresh_procfs", "mount_ns_degraded",
        "landlock_metadata_ops_unrestricted",
        "landlock_truncate_unrestricted", "private_scratch",
    }
    assert set(mi) ^ set(li) <= allowed_asymmetry, (
        sorted(set(mi) ^ set(li)))


@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_delivered_tier_stamps_follow_the_lane(tmp_path, monkeypatch):
    """containment_tier / containment_floor / floor_source stamp on
    every result: the trusted default floor is BARE ('none'), the
    unwaived untrusted contract records the mount-tier floor, and the
    operator disable records its own source."""
    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx

    def ok_spawn(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, returncode=0,
                                           stdout="", stderr="")

    monkeypatch.setattr(_spawn_mod, "run_sandboxed", ok_spawn)
    monkeypatch.delenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", raising=False)
    try:
        r = _ctx.run_untrusted(["true"], target=str(tmp_path),
                               output=str(tmp_path), timeout=60)
    except BaseException as e:  # noqa: BLE001 — host capability gate
        pytest.skip(f"untrusted lane unavailable: {e}")
    assert r.sandbox_info["containment_tier"] == "mount-ns"
    assert r.sandbox_info["containment_floor"] == "mount-ns"
    assert r.sandbox_info["floor_source"] == "default"

    disabled = _ctx.run(["true"], disabled=True, timeout=60)
    assert disabled.sandbox_info["containment_tier"] == "none"
    assert disabled.sandbox_info["containment_floor"] == "none"
    assert disabled.sandbox_info["floor_source"] == "operator-disable"


@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_skip_pid_ns_caps_spawn_lane_tier_and_warning(
        tmp_path, monkeypatch, caplog):
    """skip_pid_ns keeps the HOST procfs on both spawn lanes (the
    fresh-proc remount rides the pid-ns grandchild fork), so the
    declared tier, the posture stamp, AND the consented-degrade
    warning must all cap such a run at the POLICY-LAYER tier
    (landlock) — under the redefined ns-only tier, which PROMISES a
    fresh procfs, even an ns-only label would overstate delivery,
    and a mountless-ns label would silence the per-call warning on a
    genuinely host-procfs-visible waived run."""
    import logging as _logging
    import subprocess as _subprocess

    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx

    def ok_spawn(cmd, **kwargs):
        return _subprocess.CompletedProcess(cmd, returncode=0,
                                            stdout="", stderr="")

    monkeypatch.setattr(_spawn_mod, "run_sandboxed", ok_spawn)
    # Pin the Landlock probe: the skip_pid_ns cap is landlock/none
    # keyed on it, and this test's subject is the CAP logic, which
    # must behave identically on Landlock-less matrix lanes.
    monkeypatch.setattr(_ctx, "check_landlock_available", lambda: True)
    try:
        trusted = _ctx.run(["true"], target=str(tmp_path),
                           output=str(tmp_path), timeout=60,
                           skip_mount_ns=True, skip_pid_ns=True)
    except BaseException as e:  # noqa: BLE001 — host capability gate
        pytest.skip(f"spawn lane unavailable: {e}")
    assert trusted.sandbox_info["containment_tier"] == "landlock"

    # Waived untrusted-class shape on the same lane: the capped
    # delivered tier sits BELOW ns-only (host procfs visible), so the
    # per-call HOST process table warning must fire.
    monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")
    with caplog.at_level(_logging.WARNING, logger="core.sandbox.context"):
        waived = _ctx.run(["true"], target=str(tmp_path),
                          output=str(tmp_path), timeout=60,
                          skip_mount_ns=True, skip_pid_ns=True,
                          require_fresh_procfs=False)
    assert waived.sandbox_info["containment_tier"] == "landlock"
    assert waived.sandbox_info["floor_source"] == "env"
    assert any("HOST process table" in rec.getMessage()
               for rec in caplog.records), caplog.text


@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_run_posture_record_carries_weakest_tier(tmp_path, monkeypatch):
    """record_run_posture merges containment tier/floor weakest-wins,
    like the existing posture booleans."""
    from core.sandbox import summary as _summary
    _summary.record_run_posture(
        tmp_path, mount_ns_active=True, restrict_reads=True,
        containment_tier="mount-ns", containment_floor="mount-ns")
    _summary.record_run_posture(
        tmp_path, mount_ns_active=False, restrict_reads=True,
        containment_tier="landlock", containment_floor="landlock")
    _summary.record_run_posture(
        tmp_path, mount_ns_active=True, restrict_reads=True,
        containment_tier="mountless-ns", containment_floor="mount-ns")
    posture = _summary.get_run_posture(tmp_path)
    assert posture is not None
    assert posture["containment_tier"] == "landlock"
    assert posture["containment_floor"] == "landlock"


@pytest.mark.skipif(sys.platform != "linux", reason="linux probe seam")
def test_floor_lowered_banner_fires_once_per_process(
        tmp_path, monkeypatch, caplog):
    """The consent banner names the lowered floor and its source once
    per process when the env waiver is in force for untrusted-class
    work."""
    import logging as _logging
    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx
    from core.sandbox import state

    def ok_spawn(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, returncode=0,
                                           stdout="", stderr="")

    monkeypatch.setattr(_spawn_mod, "run_sandboxed", ok_spawn)
    monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")
    state.reset_warn_once("_floor_lowered_banner_warned")
    with caplog.at_level(_logging.WARNING, logger="core.sandbox.context"):
        try:
            _ctx.run_untrusted(["true"], target=str(tmp_path),
                               output=str(tmp_path), timeout=60)
            _ctx.run_untrusted(["true"], target=str(tmp_path),
                               output=str(tmp_path), timeout=60)
        except BaseException as e:  # noqa: BLE001 — host capability gate
            pytest.skip(f"untrusted lane unavailable: {e}")
    banners = [rec for rec in caplog.records
               if "containment floor lowered" in rec.getMessage()]
    assert len(banners) == 1, caplog.text
    assert "RAPTOR_ALLOW_DEGRADED_UNTRUSTED" in banners[0].getMessage()


@pytest.mark.skipif(sys.platform != "linux", reason="linux netns lanes")
def test_inherit_netns_drop_is_stamped_warned_and_floor_gated(
        tmp_path, monkeypatch, caplog):
    """inherit_netns=True keeps the caller's netns, dropping the
    requested network block from every Linux lane. That drop is now
    explicit: stamped per run (netns_inherited), warned once per
    process, and REFUSED for the untrusted contract (whose network
    block cannot be inherited away) — pre-fix a 'network-blocked'
    trusted run silently kept host interfaces and the host TCP table
    with nothing in sandbox_info."""
    import logging as _logging
    import subprocess as _subprocess

    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx
    from core.sandbox import state

    def ok_spawn(cmd, **kwargs):
        return _subprocess.CompletedProcess(cmd, returncode=0,
                                            stdout="", stderr="")

    _simulate_capable_host(monkeypatch)
    monkeypatch.setattr(_spawn_mod, "run_sandboxed", ok_spawn)
    monkeypatch.delenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", raising=False)
    state.reset_warn_once("_inherit_netns_block_warned")
    with caplog.at_level(_logging.WARNING, logger="core.sandbox.context"):
        try:
            r = _ctx.run(["true"], block_network=True,
                         inherit_netns=True, target=str(tmp_path),
                         output=str(tmp_path), timeout=60)
        except BaseException as e:  # noqa: BLE001 — host capability gate
            pytest.skip(f"spawn lane unavailable: {e}")
    assert r.sandbox_info["netns_inherited"] is True
    assert any("inherit_netns" in rec.getMessage()
               for rec in caplog.records), caplog.text

    # A run without the network block inherits nothing away — no stamp.
    plain = _ctx.run(["true"], block_network=False,
                     inherit_netns=True, target=str(tmp_path),
                     output=str(tmp_path), timeout=60)
    assert "netns_inherited" not in plain.sandbox_info

    # The untrusted contract refuses the drop outright (run_untrusted*
    # already reject the kwarg at their allowlist; this pins the
    # direct-caller path).
    with pytest.raises(SandboxFloorError) as excinfo:
        _ctx.run(["true"], block_network=True, inherit_netns=True,
                 target=str(tmp_path), output=str(tmp_path),
                 timeout=60, require_fresh_procfs=True)
    assert "inherited away" in str(excinfo.value)


def _simulate_capable_host(monkeypatch):
    """Patch the capability probes at their module seams so the
    dispatch routes run on hosts that cannot create namespaces —
    exactly the CI class the contract protects. No real namespace
    work happens (the spawn backend is always stubbed alongside)."""
    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx
    from core.sandbox import probes as _probes_mod
    from core.sandbox import seccomp as _seccomp_mod
    if not _seccomp_mod.check_seccomp_available():
        # libseccomp is a real dependency of the filter BUILDER (a
        # patched-True probe would hand the preexec a null lib) —
        # namespaces are the constrained axis these simulations
        # exercise, so require the library for real.
        pytest.skip("libseccomp required for the simulated-host tests")
    monkeypatch.setattr(_ctx, "check_net_available", lambda: True)
    monkeypatch.setattr(_ctx, "check_mount_available", lambda: True)
    monkeypatch.setattr(_ctx, "check_landlock_available", lambda: True)
    monkeypatch.setattr(_ctx, "_get_landlock_abi", lambda: 4)
    monkeypatch.setattr(_spawn_mod, "mount_ns_available", lambda: True)
    monkeypatch.setattr(_probes_mod, "check_unshare_engages",
                        lambda flags: (True, ""))


@pytest.mark.skipif(sys.platform != "linux", reason="linux probe seam")
def test_future_below_floor_lane_caught_on_constrained_hosts(
        tmp_path, monkeypatch):
    """The future-lane guarantee, exercised with SIMULATED host
    capability (probe seams patched, backend stubbed) so the dispatch
    route runs even on namespace-less CI hosts where the live variant
    skips."""
    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx
    monkeypatch.delenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", raising=False)
    _simulate_capable_host(monkeypatch)

    injected = OSError("forced spawn setup failure")
    sentinel = tmp_path / "future-lane-constrained.marker"

    def raising_spawn(cmd, **kwargs):
        raise injected

    monkeypatch.setattr(_spawn_mod, "run_sandboxed", raising_spawn)
    with pytest.raises(SandboxFloorError) as excinfo:
        _ctx.run_untrusted(["touch", str(sentinel)],
                           target=str(tmp_path), output=str(tmp_path),
                           timeout=60)
    e = excinfo.value
    assert e.floor is ContainmentTier.MOUNT_NS
    assert e.achievable is ContainmentTier.LANDLOCK_ONLY
    assert e.__cause__ is injected
    assert not sentinel.exists()


@pytest.mark.skipif(sys.platform != "linux", reason="linux probe seam")
@pytest.mark.parametrize("cell", [
    "uns-denied", "mount-denied", "uidmap-missing", "ll-enosys",
    "ll-enosys-mount-denied", "healthy",
])
def test_matrix_cells_unwaived_untrusted_outcomes(
        tmp_path, monkeypatch, cell):
    """The degraded-environment matrix cells, as entry-contract test
    vectors for the unwaived untrusted class: every cell that cannot
    deliver the mount-tier floor REFUSES up front (no spawn attempt,
    no execution); the healthy cell runs. This is the post-lattice
    truth for the sandbox feature-matrix sweep's untrusted rows."""
    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx
    monkeypatch.delenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", raising=False)
    _simulate_capable_host(monkeypatch)
    spawns: list = []

    def ok_spawn(cmd, **kwargs):
        spawns.append(1)
        return subprocess.CompletedProcess(cmd, returncode=0,
                                           stdout="", stderr="")

    monkeypatch.setattr(_spawn_mod, "run_sandboxed", ok_spawn)
    if cell == "uns-denied":
        # The consent-resolver entry gate (_require_userns_or_optin,
        # kept per the phase-2 scope) fires before the entry contract
        # for the run_untrusted class — its message is the cell truth.
        monkeypatch.setattr(_ctx, "check_net_available", lambda: False)
        expect = "cannot create unprivileged user namespaces"
    elif cell == "mount-denied":
        monkeypatch.setattr(_ctx, "check_mount_available", lambda: False)
        expect = "mount-namespace backend is unavailable"
    elif cell == "uidmap-missing":
        monkeypatch.setattr(_spawn_mod, "mount_ns_available",
                            lambda: False)
        expect = "mount-namespace backend is unavailable"
    elif cell == "ll-enosys":
        # Landlock-less but mount-capable: the bind tree is the
        # filesystem enforcement, so the mount lane still delivers
        # the floor — the cell RUNS at mount-ns.
        monkeypatch.setattr(_ctx, "check_landlock_available",
                            lambda: False)
        expect = None
    elif cell == "ll-enosys-mount-denied":
        # Landlock-less AND mount-less: nothing can enforce the
        # requested filesystem policy — the construction-time
        # enforceability refusal (kept verbatim, not a floor) fires.
        monkeypatch.setattr(_ctx, "check_landlock_available",
                            lambda: False)
        monkeypatch.setattr(_ctx, "check_mount_available", lambda: False)
        expect = "Landlock is unavailable"
    else:
        expect = None

    if expect is None:
        r = _ctx.run_untrusted(["true"], target=str(tmp_path),
                               output=str(tmp_path), timeout=60)
        assert r.returncode == 0
        assert r.sandbox_info["containment_tier"] == "mount-ns"
        assert len(spawns) == 1
        return
    with pytest.raises(SandboxSetupError) as excinfo:
        _ctx.run_untrusted(["true"], target=str(tmp_path),
                           output=str(tmp_path), timeout=60)
    assert expect in str(excinfo.value), str(excinfo.value)
    assert not spawns, "a refused matrix cell reached the spawn backend"


@pytest.mark.skipif(sys.platform != "linux", reason="linux probe seam")
def test_unstamped_result_is_refused_at_the_epilogue(
        tmp_path, monkeypatch):
    """Runtime dominance backstop: a result produced by an executor
    the chokepoint never saw (e.g. a lane added in ANOTHER module,
    out of the AST gate's sight) must not survive run()'s epilogue —
    the bypass converts to a loud typed failure at first use.
    Simulated by stripping the chokepoint's stamp."""
    import subprocess as _subprocess

    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx

    def ok_spawn(cmd, **kwargs):
        return _subprocess.CompletedProcess(cmd, returncode=0,
                                            stdout="", stderr="")

    _simulate_capable_host(monkeypatch)
    monkeypatch.setattr(_spawn_mod, "run_sandboxed", ok_spawn)
    try:
        baseline = _ctx.run(["true"], target=str(tmp_path),
                            output=str(tmp_path), timeout=60)
    except BaseException as e:  # noqa: BLE001 — host capability gate
        pytest.skip(f"spawn lane unavailable: {e}")
    assert getattr(baseline, "_floor_checked", False) is True

    class _Unstamped(_subprocess.CompletedProcess):
        # Refuses the stamp: the chokepoint's setattr is silently
        # dropped, modelling a result object minted outside it.
        __slots__ = ()

        def __setattr__(self, name, value):
            if name == "_floor_checked":
                return
            super().__setattr__(name, value)

    def unstampable_spawn(cmd, **kwargs):
        return _Unstamped(cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(_spawn_mod, "run_sandboxed", unstampable_spawn)
    with pytest.raises(SandboxFloorError) as excinfo:
        _ctx.run(["true"], target=str(tmp_path), output=str(tmp_path),
                 timeout=60)
    assert "checked-dispatch chokepoint" in str(excinfo.value)


@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_refused_mx_run_does_not_pollute_the_speculative_cache(
        tmp_path, monkeypatch):
    """A refused unwaived-untrusted M/X run must not write the
    speculative-failure cache — the cache steers every LATER call for
    the same binary (trusted ones included) onto the mountless lane,
    so a refusal would silently demote future trusted runs."""
    import subprocess as _subprocess

    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx
    from core.sandbox import state
    from core.sandbox.errors import SandboxFloorError
    monkeypatch.delenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", raising=False)
    monkeypatch.setattr(state, "_speculative_failure_cache", {})

    def fail_bind(cmd, **kwargs):
        cp = _subprocess.CompletedProcess(cmd, returncode=126,
                                          stdout="", stderr="")
        cp._setup_status = ("M", "forced mount-ns failure")
        return cp

    _simulate_capable_host(monkeypatch)
    monkeypatch.setattr(_spawn_mod, "run_sandboxed", fail_bind)
    try:
        with pytest.raises(SandboxFloorError):
            _ctx.run_untrusted(["true"], target=str(tmp_path),
                               output=str(tmp_path), timeout=60)
    except (pytest.skip.Exception, pytest.fail.Exception):
        raise
    except Exception as e:  # noqa: BLE001 — host capability gate
        pytest.skip(f"mount-ns lane unavailable: {e}")
    assert state._speculative_failure_cache == {}, (
        "a refused run polluted the speculative-failure cache and "
        "would demote future trusted runs")
