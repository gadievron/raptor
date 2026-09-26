"""Battery census reuse: the consistency prepass already builds the
census; the mechanical battery rebuilding it paid the per-site
scope-walk cost twice per run. Reuse is gated on coverage,
completeness, and cache provenance — see _reusable_prepass_census.

Two wiring pins guard the seam itself, not just the helper:

* the prep ORDER pin drives the real ``_compute_audit_prep`` and
  asserts the census is already stashed on config when the battery
  phase is invoked (the reuse is dead code if the battery runs
  first — the original review blocker);
* the kwargs-capture pin drives the real
  ``_run_mechanical_detectors`` and asserts the stashed census object
  reaches ``detect_callsite_deviations`` (and that a superset
  census's out-of-set deviations never enter the battery's records).
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path
from types import SimpleNamespace


from core.audit.orchestrator import _reusable_prepass_census

_RAPTOR_DIR = Path(__file__).resolve().parents[3]
_CHECKLIST_CLI = str(_RAPTOR_DIR / "libexec" / "raptor-build-checklist")


def _cfg(census, keys, *, cached=False):
    return SimpleNamespace(
        consistency_census=census,
        consistency_census_keys=(
            frozenset(keys) if keys is not None else None
        ),
        consistency_census_cached=cached,
    )


def _census_entry(truncated: bool = False):
    return SimpleNamespace(truncated=truncated)


class TestReusablePrepassCensus:
    def test_superset_coverage_reuses(self):
        census = {"helper": _census_entry()}
        cfg = _cfg(census, {"a.c", "b.c"})
        assert _reusable_prepass_census(cfg, {"a.c": ""}) is census

    def test_equal_coverage_reuses(self):
        census = {"helper": _census_entry()}
        cfg = _cfg(census, {"a.c"})
        assert _reusable_prepass_census(cfg, {"a.c": ""}) is census

    def test_under_coverage_rebuilds(self):
        # The prepass census misses b.c: reusing it would under-count
        # sites and skew majorities — must rebuild.
        cfg = _cfg({"helper": _census_entry()}, {"a.c"})
        assert _reusable_prepass_census(
            cfg, {"a.c": "", "b.c": ""}) is None

    def test_absent_census_or_keys_rebuilds(self):
        assert _reusable_prepass_census(
            _cfg(None, {"a.c"}), {"a.c": ""}) is None
        assert _reusable_prepass_census(
            _cfg({"h": _census_entry()}, None), {"a.c": ""}) is None
        assert _reusable_prepass_census(
            SimpleNamespace(), {"a.c": ""}) is None

    def test_truncated_census_rebuilds(self):
        # A capped/deadlined census carries partial per-callee counts:
        # its majorities must not stand in for the battery's build.
        census = {"ok": _census_entry(),
                  "capped": _census_entry(truncated=True)}
        cfg = _cfg(census, {"a.c"})
        assert _reusable_prepass_census(cfg, {"a.c": ""}) is None

    def test_frozen_keys_not_live_texts_gate_coverage(self):
        # Coverage is judged against the snapshot frozen at build
        # time — a live source-texts dict that grew since must not
        # widen the census's claimed coverage.
        census = {"helper": _census_entry()}
        cfg = _cfg(census, {"a.c"})
        cfg.consistency_source_texts = {"a.c": "", "b.c": ""}
        assert _reusable_prepass_census(
            cfg, {"a.c": "", "b.c": ""}) is None

    def test_cache_reloaded_census_with_live_joern_rebuilds(self):
        # A prep-cache-reloaded census may lack the cross-file
        # supplement a live server adds; the battery's fresh build
        # (which WOULD be supplemented) wins.
        census = {"helper": _census_entry()}
        cfg = _cfg(census, {"a.c"}, cached=True)
        assert _reusable_prepass_census(
            cfg, {"a.c": ""}, joern_server=object()) is None
        # Without a live server there is nothing to supplement with:
        # the cached census is as good as a fresh storeless build.
        assert _reusable_prepass_census(
            cfg, {"a.c": ""}) is census


def _write_target(target: Path) -> None:
    parts = []
    for i in range(4):
        parts.append(textwrap.dedent(f"""\
            int caller_{i}(void) {{
                if (do_auth() != 0)
                    return -1;
                return 0;
            }}
        """))
    parts.append(textwrap.dedent("""\
        int caller_dev(void) {
            do_auth();
            return 0;
        }
    """))
    (target / "callers.c").write_text("\n".join(parts))


def _built_config(tmp_path_factory):
    target = tmp_path_factory.mktemp("census_reuse_target")
    _write_target(target)
    # Nested run dir: prep's cross-run readers scan out_dir.parent —
    # a private parent keeps that scan away from the session-shared
    # pytest tmp root (see test_consistency_wiring for the history).
    out = tmp_path_factory.mktemp("census_reuse_out") / "run"
    out.mkdir()
    env = dict(
        os.environ,
        CLAUDECODE="1",
        _RAPTOR_TRUSTED="1",
        PYTHONPATH=str(_RAPTOR_DIR),
    )
    r = subprocess.run(
        [sys.executable, _CHECKLIST_CLI, str(target), str(out)],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 0, f"build-checklist failed: {r.stderr}"
    from core.audit.orchestrator import OrchestratorConfig

    return target, out, OrchestratorConfig(
        target_path=target,
        out_dir=out,
        resume=False,
        force=True,
        include_stale=False,
        enable_session_context=False,
        propagate_constraints=False,
    )


class TestPrepOrderPin:
    def test_census_is_stashed_before_the_battery_runs(
        self, tmp_path_factory,
    ):
        """The reuse seam is DEAD CODE if the battery runs before the
        prepass stashes the census (the original review blocker: the
        helper worked, its input never existed at consult time). The
        battery stub asserts the stash — with its reuse-guard facts —
        is populated at invocation."""
        import core.audit.orchestrator as orch
        from core.audit.orchestrator import _compute_audit_prep

        _, _, config = _built_config(tmp_path_factory)
        seen: dict[str, object] = {}

        def _battery_stub(gaps, cfg, **kwargs):
            seen["census"] = getattr(cfg, "consistency_census", None)
            seen["keys"] = getattr(
                cfg, "consistency_census_keys", None,
            )
            return {}, set()

        _real = orch._run_mechanical_detectors
        orch._run_mechanical_detectors = _battery_stub
        try:
            prep = _compute_audit_prep(config)
        finally:
            orch._run_mechanical_detectors = _real
        assert prep is not None
        assert "census" in seen, "battery phase never ran"
        assert seen["census"], (
            "battery invoked with no stashed census: the prepass ran "
            "after the battery (or its stash was dropped) — census "
            "reuse is dead code"
        )
        assert isinstance(seen["keys"], frozenset) and seen["keys"], (
            "reuse-guard coverage keys missing or not frozen at "
            "stash time"
        )
        assert "callers.c" in {Path(k).name for k in seen["keys"]}


class TestBatteryKwargsCapture:
    def test_stashed_census_reaches_the_detector(
        self, tmp_path_factory, monkeypatch,
    ):
        """Through the REAL battery: the stashed census object itself
        must arrive as detect_callsite_deviations' census kwarg, and
        a superset census's out-of-set deviations must never enter
        the battery's records (they are the prepass's business)."""
        import core.audit.callsite_consistency as cc
        from core.audit.orchestrator import _run_mechanical_detectors

        target, _, config = _built_config(tmp_path_factory)
        census = {"do_auth": SimpleNamespace(truncated=False)}
        config.consistency_census = census
        config.consistency_census_keys = frozenset(
            ["callers.c", "elsewhere.c"],
        )
        config.consistency_census_cached = False

        captured: dict[str, object] = {}

        def _capture(source_texts, **kwargs):
            captured.update(kwargs)
            captured["source_texts"] = source_texts
            return [
                SimpleNamespace(
                    file="callers.c", enclosing_function="caller_dev",
                    line=2, callee="do_auth", discarded_count=1,
                    total_sites=5,
                ),
                # Superset-census phantom: a deviation for a file the
                # battery never reviewed. Must be filtered.
                SimpleNamespace(
                    file="elsewhere.c", enclosing_function="ghost_fn",
                    line=9, callee="do_auth", discarded_count=1,
                    total_sites=5,
                ),
            ]

        monkeypatch.setattr(cc, "detect_callsite_deviations", _capture)
        gaps = [{"file": "callers.c", "name": "caller_dev"}]
        findings, _clean = _run_mechanical_detectors(gaps, config)
        assert captured.get("census") is census, (
            "stashed census did not reach detect_callsite_deviations "
            "through the battery"
        )
        flat = [f for lst in findings.values() for f in lst
                if f.get("detector") == "callsite_deviation"]
        assert any(f["file"] == "callers.c" for f in flat)
        assert not any(f["file"] == "elsewhere.c" for f in flat), (
            "out-of-set deviation from a superset census leaked into "
            "the battery's records"
        )

    def test_no_stash_means_detector_builds_its_own(
        self, tmp_path_factory, monkeypatch,
    ):
        # Reuse absent → census kwarg None → detect_callsite_deviations
        # keeps its historical build-inside behavior.
        import core.audit.callsite_consistency as cc
        from core.audit.orchestrator import _run_mechanical_detectors

        _, _, config = _built_config(tmp_path_factory)
        captured: dict[str, object] = {}

        def _capture(source_texts, **kwargs):
            captured.update(kwargs)
            return []

        monkeypatch.setattr(cc, "detect_callsite_deviations", _capture)
        gaps = [{"file": "callers.c", "name": "caller_dev"}]
        _run_mechanical_detectors(gaps, config)
        assert captured.get("census") is None
