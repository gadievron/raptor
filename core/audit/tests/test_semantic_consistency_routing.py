"""Wiring tests: check_semantic_consistency input hydration + routing.

Two historical wire gaps, both covered here through the real prep
phase (`_compute_audit_prep` on a checklist built by the libexec CLI):

1. The source map fed to ``check_semantic_consistency`` was built from
   the raw checklist gaps, which carry line spans but no text — so the
   check always saw an empty map and returned nothing.
2. Its findings were stored on shared state with no consumer — they
   never reached ``mechanical-findings.json`` or the review prompt.

No LLM calls; the review loop never runs (prep only).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

_RAPTOR_DIR = Path(__file__).resolve().parents[3]
_CHECKLIST_CLI = str(_RAPTOR_DIR / "libexec" / "raptor-build-checklist")

# Four verb-prefix siblings in one directory (peer-group layer L5).
# Three check permissions before acting; handle_delta does not — the
# CWE-862 outlier shape check_semantic_consistency exists to catch.
_HANDLERS_SRC = textwrap.dedent('''\
    """Request handlers."""


    def handle_alpha(request):
        """Serve alpha."""
        if not check_permission(request.user):
            return None
        payload = build_payload(request)
        return render(payload)


    def handle_beta(request):
        """Serve beta."""
        if not check_permission(request.user):
            return None
        payload = build_payload(request)
        return render(payload)


    def handle_gamma(request):
        """Serve gamma."""
        if not check_permission(request.user):
            return None
        payload = build_payload(request)
        return render(payload)


    def handle_delta(request):
        """Serve delta."""
        payload = build_payload(request)
        return render(payload)
''')


@pytest.fixture(scope="module")
def prep_result(tmp_path_factory):
    target = tmp_path_factory.mktemp("semantic_target")
    (target / "handlers.py").write_text(_HANDLERS_SRC)

    # Nested below the mktemp allocation so out_dir.parent is a
    # private empty dir: prep's cross-run readers (sibling_run_dirs,
    # domain-model/coverage lookups) scan the parent, and the
    # session-shared pytest tmp root grows by one dir per test —
    # tens of thousands of stat calls late in a full run (observed
    # as 7-11s fixture setups on CI). Also makes hermeticity
    # structural: no other test's run dir can be a sibling.
    out = tmp_path_factory.mktemp("semantic_out") / "run"
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
    assert (out / "checklist.json").exists()

    from unittest import mock

    from core.audit.capabilities import AuditCapabilities
    from core.audit.orchestrator import (
        OrchestratorConfig,
        _compute_audit_prep,
    )

    config = OrchestratorConfig(
        target_path=target,
        out_dir=out,
        resume=False,
        force=True,
        include_stale=False,
        enable_session_context=False,
        propagate_constraints=False,
    )
    # Pin external tooling to all-absent for the prep run. The wiring
    # under test (source-map hydration → check_semantic_consistency →
    # mechanical-findings routing) is pure Python and never consults a
    # tool; letting prep probe the host instead made the fixture take
    # a different (and multi-second — angr import probe, joern CPG
    # build via a JVM, semgrep startup) path on every host with those
    # tools installed. All-absent matches the minimal-host CI path and
    # keeps this a wiring test, not a tool-availability integration.
    no_caps = AuditCapabilities(
        joern=False,
        joern_issues=("pinned absent for this wiring test",),
        r2=False,
        frida=False,
        semgrep=False,
        coccinelle=False,
        codeql=False,
        ghidra=False,
        cxxfilt=False,
        objdump=False,
        readelf=False,
        binary_available=False,
        dwarf_available=False,
        angr=False,
    )
    with mock.patch(
        "core.audit.capabilities.probe_capabilities",
        return_value=no_caps,
    ), mock.patch(
        # run_joern_pre_sweep's own availability gate (independent of
        # the capability probe): without this, hosts with joern on
        # PATH pay a doomed JVM CPG build inside the fixture.
        "packages.joern.prereqs.is_available",
        return_value=False,
    ):
        prep = _compute_audit_prep(config)
    assert prep is not None, "prep returned None (checklist missing?)"
    return prep, out


class TestSemanticConsistencyInput:
    def test_outlier_detected_from_hydrated_sources(self, prep_result):
        """The check must run on hydrated function bodies — an empty
        source map (the raw-gap regression) yields no findings."""
        prep, _ = prep_result
        deviants = {
            f.get("function") for f in prep["semantic_findings"]
        }
        assert "handle_delta" in deviants

    def test_conforming_siblings_not_flagged(self, prep_result):
        prep, _ = prep_result
        deviants = {
            f.get("function") for f in prep["semantic_findings"]
        }
        assert "handle_alpha" not in deviants
        assert "handle_beta" not in deviants
        assert "handle_gamma" not in deviants


class TestSemanticConsistencyRouting:
    def test_findings_routed_into_mechanical_findings(self, prep_result):
        prep, _ = prep_result
        entries = prep["mechanical_findings"].get(
            "handlers.py:handle_delta", [],
        )
        semantic = [
            e for e in entries
            if e.get("detector") == "semantic_consistency"
        ]
        assert semantic, (
            "semantic-consistency outlier did not reach "
            f"mechanical_findings: {entries}"
        )
        assert "CWE-862" in semantic[0]["description"]

    def test_findings_persisted_to_disk(self, prep_result):
        _, out = prep_result
        path = out / "mechanical-findings.json"
        assert path.exists()
        data = json.loads(path.read_text())
        entries = data.get("handlers.py:handle_delta", [])
        assert any(
            e.get("detector") == "semantic_consistency" for e in entries
        )
