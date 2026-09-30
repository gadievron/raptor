"""The invalid-override corridor in active-project resolution.

``core.run.output._resolve_active_project`` swallows resolution
failures by design (warn, proceed projectless) so a corrupt project
JSON or an unreadable registry never blocks a run. The operator-set
``RAPTOR_REGISTRY_HOME`` override is the one exception: a
present-but-invalid value (non-absolute — refused by the seam,
``core.project.registry_home``) is an explicit instruction that could
not be honoured, and proceeding projectless would silently place the
run in the default ``out/`` dir instead of the registry the operator
named. Invalid values are a hard error, never a fallback — the same
doctrine ``ProjectArgvError`` already follows through this corridor.

These tests pin: the seam failure escalates (both through
``_resolve_active_project`` and its ``resolve_default_target``
consumer — the run-lifecycle ``start`` corridor); the escalation is
NARROW (any other ``ValueError`` still falls back projectless); and
the seam's distinct subtype stays a ``ValueError`` so existing
``except ValueError`` / ``pytest.raises(ValueError)`` sites keep
working.
"""

from __future__ import annotations

import logging

import pytest

import core.startup as startup
from core.project import project as project_mod
from core.project import registry_home
from core.project import sessions as sessions_mod
from core.run import output as output_mod


@pytest.fixture(autouse=True)
def _bare_seam(monkeypatch: pytest.MonkeyPatch) -> None:
    """Clear the override env and the module-dict registry shadows
    (the root conftest's autouse pins) so resolution reaches the seam;
    ``monkeypatch`` restores both layers afterwards."""
    monkeypatch.delenv(registry_home.ENV_REGISTRY_HOME, raising=False)
    monkeypatch.delattr(project_mod, "PROJECTS_DIR", raising=False)
    monkeypatch.delattr(sessions_mod, "SESSIONS_DIR", raising=False)
    monkeypatch.delattr(startup, "PROJECTS_DIR", raising=False)
    monkeypatch.delattr(startup, "ACTIVE_LINK", raising=False)


def test_invalid_registry_home_is_a_hard_error(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(registry_home.ENV_REGISTRY_HOME, "relative/dir")
    with pytest.raises(ValueError, match="RAPTOR_REGISTRY_HOME"):
        output_mod._resolve_active_project()


def test_invalid_registry_home_fails_default_target_resolution(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(registry_home.ENV_REGISTRY_HOME, "relative/dir")
    with pytest.raises(ValueError, match="RAPTOR_REGISTRY_HOME"):
        output_mod.resolve_default_target()


def test_seam_error_is_a_valueerror_subtype() -> None:
    # Existing catchers and raises-assertions spell ``ValueError`` —
    # the distinct escalation type must stay substitutable for it.
    assert issubclass(registry_home.RegistryHomeError, ValueError)
    assert registry_home.RegistryHomeError is not ValueError


def test_seam_raises_its_distinct_subtype(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(registry_home.ENV_REGISTRY_HOME, "relative/dir")
    with pytest.raises(registry_home.RegistryHomeError):
        registry_home.registry_home()


def test_other_valueerrors_still_fall_back_projectless(
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture) -> None:
    """Only the operator-override seam escalates: a plain ValueError
    from elsewhere in resolution (e.g. ``json.JSONDecodeError`` from a
    corrupt project file) keeps the warn-and-projectless corridor."""

    class _Broken:
        def __init__(self) -> None:
            raise ValueError("synthetic resolution failure")

    monkeypatch.setattr("core.project.project.ProjectManager", _Broken)
    with caplog.at_level(logging.WARNING, logger="core.run.output"):
        assert output_mod._resolve_active_project() is None
    assert any("active project resolution failed" in rec.message
               for rec in caplog.records)
