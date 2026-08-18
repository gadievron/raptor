"""Wiring test: the prep phase feeds the study domain model to the
peer-group resolver's L3 layer.

resolve_peer_groups has accepted ``domain_model`` since the layered
resolver landed, but the prep-phase call site never passed it — the
L3 (domain-concept) layer was dead in production. This exercises the
real ``_compute_audit_prep`` with a domain-model.json on disk.
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

# Two functions with unrelated names — no verb-prefix (L5) or paired
# (L6) layer can group them, so a group can only come from the domain
# model (L3).
_SRC = textwrap.dedent('''\
    def frobnicate(data):
        """One."""
        payload = shape(data)
        return payload


    def quuxify(data):
        """Two."""
        payload = shape(data)
        return payload
''')

_DOMAIN_MODEL = {
    "concepts": [
        {
            "name": "payload-shapers",
            "description": "Both shape untrusted payloads.",
            "functions": ["frobnicate", "quuxify"],
        },
    ],
    "invariants": [],
}


@pytest.fixture()
def prep_with_domain_model(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "shapers.py").write_text(_SRC)

    out = tmp_path / "out"
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

    (out / "domain-model.json").write_text(json.dumps(_DOMAIN_MODEL))

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
    prep = _compute_audit_prep(config)
    assert prep is not None
    return prep


class TestDomainModelPeerGroupWiring:
    def test_l3_domain_concept_group_formed(self, prep_with_domain_model):
        groups = prep_with_domain_model["peer_groups"]
        domain_groups = [
            g for g in groups if g.group_id.startswith("domain:")
        ]
        assert domain_groups, (
            "no L3 domain-concept peer group formed: "
            f"{[g.group_id for g in groups]}"
        )
        members = {s.function for s in domain_groups[0].siblings}
        assert members == {"frobnicate", "quuxify"}
