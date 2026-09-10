"""Repo-trust tri-state setup for the standalone analysis agent."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

import core.security.cc_trust as cct
import core.security.codeql_trust as qlt
from packages.llm_analysis import agent as agent_mod


@pytest.fixture(autouse=True)
def _reset_overrides():
    cct.set_trust_override(None)
    qlt.set_trust_override(None)
    yield
    cct.set_trust_override(None)
    qlt.set_trust_override(None)


def _run_main(tmp_path: Path, flags: list[str]) -> tuple[bool | None, bool | None]:
    cct.set_trust_override(True)
    qlt.set_trust_override(True)
    argv = [
        "agent.py",
        "--repo", str(tmp_path),
        "--sarif", str(tmp_path / "findings.sarif"),
        *flags,
    ]
    with patch.object(sys, "argv", argv), \
            patch(
                "core.project.trust.active_project_trust",
                return_value=({}, None),
            ), \
            patch.object(
                agent_mod,
                "AutonomousSecurityAgentV2",
                side_effect=agent_mod.AgentCLITrustError("stop after setup"),
            ), \
            pytest.raises(SystemExit) as exc:
        agent_mod.main()
    assert exc.value.code == 2
    return qlt._trust_override_set, cct._trust_override_set


@pytest.mark.parametrize(
    ("flags", "expected"),
    [
        (["--trust-repo"], True),
        (["--no-trust-repo"], False),
        (["--trust-repo", "--no-trust-repo"], False),
        ([], None),
    ],
)
def test_standalone_analysis_trust_matrix(tmp_path, flags, expected):
    ql, cc = _run_main(tmp_path, flags)
    assert ql is expected
    assert cc is expected


def test_unspecified_analysis_inherits_authenticated_session(
    tmp_path, monkeypatch,
):
    ql, cc = _run_main(tmp_path, [])
    assert ql is None
    assert cc is None
    monkeypatch.setattr(
        "core.project.sessions.session_repo_trusted",
        lambda repo: Path(repo).resolve() == tmp_path.resolve(),
    )
    assert cct.is_trust_overridden(tmp_path)
