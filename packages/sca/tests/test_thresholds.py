"""Tests for ``packages.sca.thresholds`` (the CI gate logic).

Replaces the legacy ``test_gate.py`` after the gate binary was folded
into the main scan / render flows as ``--fail-on-*`` flags.

Two layers:

  - Pure-function tests of ``evaluate``: shape + threshold semantics.
  - Integration tests via ``cli.py``: argparse wiring, exit codes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List


from packages.sca import render, thresholds


# ---------------------------------------------------------------------------
# Pure-function tests of evaluate()
# ---------------------------------------------------------------------------

def _vuln(severity="high", *, kev=False, suppressed=False, desc="boom") -> dict:
    """Minimal-but-renderable vulnerable_dependency finding."""
    return {
        "id": "GHSA-test-0001",
        "vuln_type": "sca:vulnerable_dependency",
        "severity": severity,
        "description": desc,
        "suppressed": suppressed,
        "sca": {
            "ecosystem": "PyPI", "name": "pkg", "version": "1.0",
            "in_kev": kev,
            "advisory": {"id": "GHSA-test-0001", "aliases": []},
        },
    }


def _supply(severity="high", desc="curl|sh") -> dict:
    return {
        "vuln_type": "sca:supply_chain:install_hook_suspicious",
        "severity": severity,
        "description": desc,
    }


def _hygiene(severity="high", desc="drift") -> dict:
    return {
        "vuln_type": "sca:hygiene:lockfile_drift",
        "severity": severity,
        "description": desc,
    }


def test_inactive_config_passes_with_any_findings() -> None:
    """When no thresholds are set, evaluate is a no-op pass."""
    cfg = thresholds.ThresholdConfig()
    assert not cfg.is_active
    rows = [_vuln("critical", kev=True), _supply("critical")]
    passed, fails = thresholds.evaluate(rows, cfg)
    assert passed is True
    assert fails == []


def test_severity_floor_fails_above_threshold() -> None:
    cfg = thresholds.ThresholdConfig(fail_on_severity="high")
    rows = [_vuln("critical")]
    passed, fails = thresholds.evaluate(rows, cfg)
    assert passed is False
    assert len(fails) == 1
    assert "[critical]" in fails[0]


def test_severity_floor_passes_below_threshold() -> None:
    cfg = thresholds.ThresholdConfig(fail_on_severity="high")
    rows = [_vuln("low"), _vuln("medium")]
    passed, fails = thresholds.evaluate(rows, cfg)
    assert passed is True
    assert fails == []


def test_kev_overrides_below_severity_floor() -> None:
    """A KEV-listed CVE flags even when its severity is below the floor."""
    cfg = thresholds.ThresholdConfig(fail_on_severity="high", fail_on_kev=True)
    rows = [_vuln("low", kev=True)]
    passed, fails = thresholds.evaluate(rows, cfg)
    assert passed is False
    assert "[KEV]" in fails[0]


def test_supply_chain_threshold_independent() -> None:
    """Supply-chain only fails when its own threshold is set."""
    rows = [_supply("high")]
    cfg_off = thresholds.ThresholdConfig(fail_on_severity="critical")
    cfg_on = thresholds.ThresholdConfig(
        fail_on_severity="critical", fail_on_supply_chain="high",
    )
    assert thresholds.evaluate(rows, cfg_off) == (True, [])
    passed, fails = thresholds.evaluate(rows, cfg_on)
    assert passed is False
    assert "supply-chain" in fails[0]


def test_hygiene_threshold_independent() -> None:
    rows = [_hygiene("high")]
    cfg_off = thresholds.ThresholdConfig(fail_on_severity="critical")
    cfg_on = thresholds.ThresholdConfig(
        fail_on_severity="critical", fail_on_hygiene="high",
    )
    assert thresholds.evaluate(rows, cfg_off) == (True, [])
    passed, fails = thresholds.evaluate(rows, cfg_on)
    assert passed is False
    assert "hygiene" in fails[0]


def test_unknown_vuln_type_ignored() -> None:
    """Findings from other tools (vuln_type not starting with sca:) skipped."""
    cfg = thresholds.ThresholdConfig(fail_on_severity="info")
    rows = [{"vuln_type": "scan:something_else",
             "severity": "critical", "description": "from another tool"}]
    passed, fails = thresholds.evaluate(rows, cfg)
    assert passed is True
    assert fails == []


def test_suppressed_skipped_by_default() -> None:
    cfg = thresholds.ThresholdConfig(fail_on_severity="high")
    rows = [_vuln("critical", suppressed=True)]
    passed, fails = thresholds.evaluate(rows, cfg)
    assert passed is True


def test_suppressed_evaluated_with_include_suppressed() -> None:
    cfg = thresholds.ThresholdConfig(
        fail_on_severity="high", include_suppressed=True,
    )
    rows = [_vuln("critical", suppressed=True)]
    passed, fails = thresholds.evaluate(rows, cfg)
    assert passed is False


# ---------------------------------------------------------------------------
# Integration tests — render path with --fail-on-* flags
# ---------------------------------------------------------------------------

def _write_findings(tmp_path: Path, rows: List[dict]) -> Path:
    p = tmp_path / "findings.json"
    p.write_text(json.dumps(rows), encoding="utf-8")
    return p


def test_render_no_outputs_returns_2_before_threshold(
    tmp_path: Path, capsys,
) -> None:
    """``--no-md --no-sarif`` together short-circuits to "nothing to do"
    (exit 2) before the threshold check runs. Documents the precedence:
    output-existence is validated first, threshold evaluation second.
    """
    p = _write_findings(tmp_path, [_vuln("low")])
    rc = render.main([str(p), "--no-md", "--no-sarif",
                      "--fail-on-severity", "high"])
    assert rc == 2


def test_render_emit_and_pass_below_threshold(
    tmp_path: Path, capsys,
) -> None:
    p = _write_findings(tmp_path, [_vuln("low")])
    rc = render.main([str(p), "--out-md", str(tmp_path / "r.md"),
                      "--no-sarif", "--fail-on-severity", "high"])
    assert rc == 0


def test_render_fails_above_threshold(tmp_path: Path, capsys) -> None:
    p = _write_findings(tmp_path, [_vuln("critical")])
    rc = render.main([str(p), "--out-md", str(tmp_path / "r.md"),
                      "--no-sarif", "--fail-on-severity", "high"])
    assert rc == 1
    err = capsys.readouterr().err
    assert "fail" in err
    assert "[critical]" in err


def test_render_fail_on_kev_below_severity(tmp_path: Path, capsys) -> None:
    """KEV catches things below the severity floor."""
    p = _write_findings(tmp_path, [_vuln("low", kev=True)])
    rc = render.main([str(p), "--out-md", str(tmp_path / "r.md"),
                      "--no-sarif",
                      "--fail-on-severity", "high",
                      "--fail-on-kev"])
    assert rc == 1


def test_render_no_thresholds_set_always_passes(
    tmp_path: Path, capsys,
) -> None:
    """Without --fail-on-*, render exits 0 even with critical findings."""
    p = _write_findings(tmp_path, [_vuln("critical", kev=True)])
    rc = render.main([str(p), "--out-md", str(tmp_path / "r.md"),
                      "--no-sarif"])
    assert rc == 0


# ---------------------------------------------------------------------------
# image_capability_drift threshold knobs
# ---------------------------------------------------------------------------

def _drift_finding(
    *, severity="medium", added_buckets=None, desc="drift",
) -> dict:
    return {
        "vuln_type": "sca:supply_chain:image_capability_drift",
        "severity": severity,
        "description": desc,
        "evidence": {"added_buckets": added_buckets or []},
    }


def test_fail_on_capability_drift_fires_regardless_of_severity() -> None:
    """The dedicated drift flag ignores the supply-chain severity
    ladder — a single low-severity drift finding fails the build."""
    cfg = thresholds.ThresholdConfig(fail_on_capability_drift=True)
    rows = [_drift_finding(severity="low", added_buckets=["alloc"])]
    passed, fails = thresholds.evaluate(rows, cfg)
    assert passed is False
    assert "[capability-drift]" in fails[0]


def test_fail_on_capability_drift_no_drift_passes() -> None:
    cfg = thresholds.ThresholdConfig(fail_on_capability_drift=True)
    # Non-drift findings present, no drift finding → passes
    rows = [_vuln("critical"), _supply("critical")]
    passed, fails = thresholds.evaluate(rows, cfg)
    assert passed is True
    assert fails == []


def test_max_added_capability_buckets_fires_when_exceeded() -> None:
    """N=2 → 3 added buckets is over → fail."""
    cfg = thresholds.ThresholdConfig(max_added_capability_buckets=2)
    rows = [_drift_finding(
        added_buckets=["alloc", "exec", "network"]),
    ]
    passed, fails = thresholds.evaluate(rows, cfg)
    assert passed is False
    assert "+3 buckets > max 2" in fails[0]


def test_max_added_capability_buckets_passes_at_threshold() -> None:
    """Strictly-greater semantics — N=2, 2 added buckets is at limit."""
    cfg = thresholds.ThresholdConfig(max_added_capability_buckets=2)
    rows = [_drift_finding(added_buckets=["alloc", "exec"])]
    passed, fails = thresholds.evaluate(rows, cfg)
    assert passed is True


def test_max_added_capability_buckets_zero_means_any_drift_fails() -> None:
    """N=0 → any added bucket fails."""
    cfg = thresholds.ThresholdConfig(max_added_capability_buckets=0)
    rows = [_drift_finding(added_buckets=["alloc"])]
    passed, fails = thresholds.evaluate(rows, cfg)
    assert passed is False


def test_max_added_capability_buckets_zero_passes_when_no_added() -> None:
    """Drift finding with no added buckets (only removals or arch
    changes) → N=0 still passes."""
    cfg = thresholds.ThresholdConfig(max_added_capability_buckets=0)
    rows = [_drift_finding(added_buckets=[])]
    passed, fails = thresholds.evaluate(rows, cfg)
    assert passed is True


def test_drift_flag_independent_of_supply_chain_floor() -> None:
    """When both --fail-on-supply-chain critical AND
    --fail-on-capability-drift are set, a medium drift finding
    fails via the drift flag (supply-chain floor would not catch
    it on its own)."""
    cfg = thresholds.ThresholdConfig(
        fail_on_supply_chain="critical",
        fail_on_capability_drift=True,
    )
    rows = [_drift_finding(severity="medium", added_buckets=["exec"])]
    passed, fails = thresholds.evaluate(rows, cfg)
    assert passed is False
    assert any("capability-drift" in f for f in fails)


def test_drift_flag_active_in_is_active() -> None:
    """Smoke: setting only the drift flag activates the config."""
    cfg = thresholds.ThresholdConfig(fail_on_capability_drift=True)
    assert cfg.is_active is True
    cfg2 = thresholds.ThresholdConfig(max_added_capability_buckets=0)
    assert cfg2.is_active is True


def test_drift_threshold_args_round_trip(tmp_path: Path) -> None:
    """add_threshold_args + cfg_from_args round-trips the new flags."""
    import argparse
    p = argparse.ArgumentParser()
    thresholds.add_threshold_args(p)
    args = p.parse_args([
        "--fail-on-capability-drift",
        "--max-added-capability-buckets", "3",
    ])
    cfg = thresholds.cfg_from_args(args)
    assert cfg.fail_on_capability_drift is True
    assert cfg.max_added_capability_buckets == 3


def test_drift_evidence_missing_added_buckets_field_treated_as_empty() -> None:
    """Malformed drift finding (no evidence.added_buckets) shouldn't
    crash — treat as zero added buckets."""
    cfg = thresholds.ThresholdConfig(max_added_capability_buckets=0)
    rows = [{
        "vuln_type": "sca:supply_chain:image_capability_drift",
        "severity": "medium",
        "description": "no evidence field at all",
    }]
    passed, fails = thresholds.evaluate(rows, cfg)
    assert passed is True


def test_drift_evidence_non_dict_treated_as_empty() -> None:
    """A third-party emitter or hand-edited findings.json can land
    with ``evidence`` as a string / int / list. Don't crash the
    build gate — treat as no added buckets."""
    cfg = thresholds.ThresholdConfig(max_added_capability_buckets=0)
    for bad_ev in ("a string", 42, ["a", "list"], None):
        rows = [{
            "vuln_type": "sca:supply_chain:image_capability_drift",
            "severity": "medium",
            "description": "weird evidence",
            "evidence": bad_ev,
        }]
        passed, fails = thresholds.evaluate(rows, cfg)
        assert passed is True, (
            f"expected pass on evidence={bad_ev!r}, got fails={fails!r}"
        )


def test_drift_added_buckets_non_list_treated_as_empty() -> None:
    """``evidence.added_buckets`` is a string/int/dict → don't
    fall back to ``len(str)`` semantics (which would surprise
    operators by counting characters)."""
    cfg = thresholds.ThresholdConfig(max_added_capability_buckets=0)
    for bad_added in ("a-string-with-23-chars", 5, {"k": "v"}, None):
        rows = [{
            "vuln_type": "sca:supply_chain:image_capability_drift",
            "severity": "medium",
            "description": "weird added_buckets",
            "evidence": {"added_buckets": bad_added},
        }]
        passed, fails = thresholds.evaluate(rows, cfg)
        assert passed is True, (
            f"expected pass on added_buckets={bad_added!r}, "
            f"got fails={fails!r}"
        )
