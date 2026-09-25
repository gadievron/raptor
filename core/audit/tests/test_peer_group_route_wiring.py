"""Wiring test: the prep phase feeds route models to the peer-group
resolver's L10 (route-family) layer.

Exercises the real ``_compute_audit_prep`` over a Flask-shaped
Python target: the checklist's per-file registration facts feed
``route_models_for_prep``, the resolver forms the route family, and
the members carry the auth-decorator presence stamp the interface
dimension folds into its ``auth_check`` vote.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from core.analysis.peer_groups import (
    GROUP_TYPE_ROUTE_FAMILY,
    ROUTE_AUTH_PROPERTY,
)

_RAPTOR_DIR = Path(__file__).resolve().parents[3]
_CHECKLIST_CLI = str(_RAPTOR_DIR / "libexec" / "raptor-build-checklist")

# Handler names carry no shared verb prefix, no pair stem, and no
# shared type annotation — a group can only come from the route
# models (L10).
_SRC = textwrap.dedent('''\
    from flask import Flask

    app = Flask(__name__)


    def login_required(f):
        return f


    @app.route("/api/records")
    @login_required
    def records_index():
        return "r"


    @app.route("/api/summary")
    @login_required
    def summary_view():
        return "s"


    @app.route("/api/wipe")
    def wipe_everything():
        return "w"
''')


@pytest.fixture()
def prep_with_routes(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "webapp.py").write_text(_SRC)

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


class TestRouteFamilyPeerGroupWiring:
    def test_l10_route_family_formed_with_presence_stamps(
        self, prep_with_routes,
    ):
        groups = prep_with_routes["peer_groups"]
        fams = [g for g in groups
                if g.sibling_type == GROUP_TYPE_ROUTE_FAMILY]
        assert fams, (
            "no L10 route-family peer group formed: "
            f"{[g.group_id for g in groups]}"
        )
        fam = fams[0]
        assert fam.group_id == "route_family:flask:decorator:api"
        props = {s.function: dict(s.properties) for s in fam.siblings}
        assert set(props) == {
            "records_index", "summary_view", "wipe_everything",
        }
        assert props["records_index"] == {ROUTE_AUTH_PROPERTY: True}
        assert props["summary_view"] == {ROUTE_AUTH_PROPERTY: True}
        # Two-valued decoration fact: the undecorated member carries
        # an explicit False vote.
        assert props["wipe_everything"] == {ROUTE_AUTH_PROPERTY: False}
