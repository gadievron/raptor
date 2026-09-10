"""Repo-trust tri-state setup for the standalone CodeQL workflow."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

import core.security.cc_trust as cct
import core.security.codeql_trust as qlt
import raptor_codeql


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
    argv = ["raptor_codeql.py", "--repo", str(tmp_path), *flags]
    with patch.object(sys, "argv", argv), \
            patch(
                "core.project.trust.active_project_trust",
                return_value=({}, None),
            ), \
            patch(
                "core.analysis.binary_oracle_cli.apply_to_config",
            ), \
            patch.object(raptor_codeql, "run_autonomous_workflow"):
        raptor_codeql.main()
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
def test_standalone_codeql_trust_matrix(tmp_path, flags, expected):
    ql, cc = _run_main(tmp_path, flags)
    assert ql is expected
    assert cc is expected


def test_unspecified_codeql_inherits_authenticated_session(
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
