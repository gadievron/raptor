"""Phase 15.1 (2026-05-12): outcome JSON serialization regression test.

Phase 12.1 added per-stage cost telemetry fields (`stage_costs`,
`stage_calls`, `over_budget_stages_list`) to the ``Outcome`` dataclass
in ``models.py``. The fields WERE populated at outcome construction
in ``loop.py`` — but the sidecar JSON written by ``cli.py`` is a
MANUAL whitelist of fields (lines 87-103). The Phase 12.1 additions
were never propagated to the sidecar dict; the empirical evidence
is `output/bench/bench50-20260512-135101/CVE-2024-1061.json` which
has NO `stage_costs` key.

This test asserts every Phase 12.x telemetry field that was added
to ``Outcome`` is also serialized to the sidecar `outcome_dict`.

Detection strategy: parse `cli.py` source for the `outcome_dict = {`
block, extract its keys, then compare against the Phase 12.x field
list. Future Phase 12.x extensions can add to ``_PHASE_12_FIELDS``
to enforce parity.
"""
from __future__ import annotations

import re
from pathlib import Path

import cve_env

# Package source dir (layout-independent); cli.py lives directly under it.
SHIP_FINAL = Path(cve_env.__file__).resolve().parent
CLI_PY = SHIP_FINAL / "cli.py"

# Phase 12.x fields that MUST appear in cli.py's outcome_dict.
# Add to this list when shipping new outcome telemetry.
_PHASE_12_FIELDS: frozenset[str] = frozenset({
    "stage_costs",          # Phase 12.1
    "stage_calls",          # Phase 12.1
    "over_budget_stages_list",  # Phase 12.2
})


def _read_outcome_dict_keys() -> set[str]:
    """Parse `outcome_dict = { ... }` in cli.py; extract string keys."""
    src = CLI_PY.read_text()
    # Find the outcome_dict literal. Permissive across formatting changes.
    m = re.search(r"outcome_dict\s*=\s*\{(.+?)\n\s*\}\s*\n", src, re.DOTALL)
    if not m:
        raise AssertionError(
            f"could not locate `outcome_dict = {{...}}` in {CLI_PY}"
        )
    body = m.group(1)
    # Extract quoted keys (each line is `"key": expression,`).
    keys = re.findall(r'^\s*"([^"]+)":', body, re.MULTILINE)
    return set(keys)


def test_phase_15_1_outcome_dict_includes_phase_12_telemetry() -> None:
    """Phase 15.1: every Phase 12.x outcome field must be in the
    sidecar `outcome_dict` so it reaches the persisted JSON.

    If this fails: a Phase 12.x field was added to ``Outcome`` but
    not to ``cli.py``'s outcome_dict. Add the new field to BOTH the
    Outcome dataclass AND cli.py's outcome_dict, then update
    ``_PHASE_12_FIELDS`` in this test to lock the parity.
    """
    keys = _read_outcome_dict_keys()
    missing = _PHASE_12_FIELDS - keys
    assert not missing, (
        f"Phase 12.x telemetry fields missing from "
        f"{CLI_PY.relative_to(SHIP_FINAL)}'s outcome_dict: "
        f"{sorted(missing)}. Add them to the dict between the existing "
        f"`refusals` line and the closing brace."
    )


def test_phase_15_1_outcome_dict_nonempty() -> None:
    """Sanity: outcome_dict must contain the core fields."""
    keys = _read_outcome_dict_keys()
    for required in ("cve_id", "status", "total_cost_usd"):
        assert required in keys, (
            f"core field {required!r} missing from cli.py outcome_dict"
        )


# ── #6 (2026-06-01): build-method derivation + sidecar propagation ──
# `method` was absent from the sidecar outcome JSON: update_corpus.py only
# passes a 'method' key through IF present, and nothing produced it. Derive it
# from the tool trail, mirroring scripts/heartbeat_status.sh's method detection.


def test_derive_build_method_taxonomy() -> None:
    """Mirrors scripts/heartbeat_status.sh method detection — KEEP IN SYNC."""
    from cve_env.models import derive_build_method

    assert derive_build_method(["nvd_lookup", "source_build", "verify"]) == "source-build"
    assert derive_build_method(["image_resolve", "docker_compose_up"]) == "vulhub-compose"
    assert (
        derive_build_method(["dockerfile_gen", "docker_build", "docker_run"])
        == "custom-dockerfile"
    )
    assert derive_build_method(["image_resolve", "docker_run", "verify"]) == "vulhub-image"
    assert derive_build_method(["nvd_lookup", "github_fetch"]) == "researching"
    assert derive_build_method([]) == "researching"
    # cascade: order preserved, comma-joined
    assert (
        derive_build_method(["source_build", "docker_compose_up"])
        == "source-build, vulhub-compose"
    )
    # custom-dockerfile suppressed when source-build present (matches heartbeat)
    assert (
        derive_build_method(["source_build", "dockerfile_gen", "docker_build"])
        == "source-build"
    )
    # vulhub-image suppressed when a real build tool ran (matches heartbeat)
    assert (
        derive_build_method(["image_resolve", "docker_run", "dockerfile_gen", "docker_build"])
        == "custom-dockerfile"
    )


def test_method_serialized_to_outcome_dict() -> None:
    """#6: the sidecar outcome_dict must include 'method'."""
    assert "method" in _read_outcome_dict_keys()


# ── #1a (2026-06-02): propagate daemon_corruption to the per-CVE outcome JSON ──
# So the bench heal + bench_select_retry can detect containerd corruption from a
# reliable greppable field, not by parsing the audit JSONL. Mirrors the #6 method
# pattern (state flag -> Outcome field -> cli.py outcome_dict whitelist).


def test_daemon_corruption_in_outcome_dict() -> None:
    """The sidecar outcome_dict must carry 'daemon_corruption'."""
    assert "daemon_corruption" in _read_outcome_dict_keys()


def test_outcome_has_daemon_corruption_field() -> None:
    from cve_env.models import Outcome

    o = Outcome(cve_id="CVE-2099-0001", status="unresolvable", verify_passed=False)
    assert o.daemon_corruption is False  # defaults off
    o2 = Outcome(cve_id="CVE-2099-0002", status="unresolvable",
                 verify_passed=False, daemon_corruption=True)
    assert o2.daemon_corruption is True
