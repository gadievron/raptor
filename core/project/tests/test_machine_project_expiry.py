"""Auto-expiry for machine-generated (corpus-*) projects.

Receipt: a session booted with a stale ``corpus-*`` project (target
/tmp) still active from a crashed corpus run; a no-path /audit would
have audited /tmp under the default-target rules. Machine-generated
projects now carry a creation-time TTL marker consumed at ``.active``
resolution. Projects are operator artifacts: expiry applies ONLY to
the machine naming pattern AND only when the marker is stamped, and
an explicit ``/project use`` clears the marker.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from core.project.project import (
    Project,
    ProjectManager,
    is_machine_project_name,
)


def _mgr(tmp_path):
    return ProjectManager(projects_dir=tmp_path / "projects")


def _iso(delta_hours: float) -> str:
    return (
        datetime.now(timezone.utc) + timedelta(hours=delta_hours)
    ).isoformat()


class TestIsExpiredMachineProject:
    def test_expired_corpus_project(self):
        p = Project(name="corpus-123", target="/tmp", output_dir="o",
                    expires_at=_iso(-1))
        assert p.is_expired_machine_project() is True

    def test_unexpired_corpus_project(self):
        p = Project(name="corpus-123", target="/tmp", output_dir="o",
                    expires_at=_iso(+1))
        assert p.is_expired_machine_project() is False

    def test_operator_named_project_never_expires(self):
        """Even a stamped expires_at is inert on an operator name."""
        p = Project(name="myapp", target="/x", output_dir="o",
                    expires_at=_iso(-1))
        assert p.is_expired_machine_project() is False

    def test_no_marker_never_expires(self):
        p = Project(name="corpus-123", target="/tmp", output_dir="o")
        assert p.is_expired_machine_project() is False

    def test_malformed_marker_fails_open(self):
        p = Project(name="corpus-123", target="/tmp", output_dir="o",
                    expires_at="not-a-timestamp")
        assert p.is_expired_machine_project() is False

    def test_machine_name_pattern(self):
        assert is_machine_project_name("corpus-1787231329")
        assert not is_machine_project_name("myapp")
        assert not is_machine_project_name("my-corpus-project")


class TestExpiresAtPersistence:
    def test_round_trips_through_dict(self):
        ts = _iso(+2)
        p = Project(name="corpus-1", target="/tmp", output_dir="o",
                    expires_at=ts)
        assert Project.from_dict(p.to_dict()).expires_at == ts

    def test_legacy_files_default_empty(self):
        p = Project.from_dict({"name": "x", "target": "/t",
                               "output_dir": "o"})
        assert p.expires_at == ""


class TestActiveResolutionConsumesExpiry:
    def test_expired_corpus_project_deactivated(self, tmp_path, caplog):
        mgr = _mgr(tmp_path)
        mgr.create("corpus-99", target="/tmp", resolve_target=False)
        proj = mgr.load("corpus-99")
        proj.expires_at = _iso(-1)
        mgr._save(proj)
        mgr.set_active("corpus-99")

        with caplog.at_level(logging.WARNING):
            assert mgr.get_active() is None
        # Symlink consumed — subsequent resolutions are clean.
        assert mgr.get_active() is None
        assert not (mgr.projects_dir / ".active").is_symlink()
        assert "auto-expiry" in caplog.text
        # The project FILE survives — only the active pointer is
        # consumed; the operator can still /project use it.
        assert mgr.load("corpus-99") is not None

    def test_unexpired_corpus_project_stays_active(self, tmp_path):
        mgr = _mgr(tmp_path)
        mgr.create("corpus-98", target="/tmp", resolve_target=False)
        proj = mgr.load("corpus-98")
        proj.expires_at = _iso(+24)
        mgr._save(proj)
        mgr.set_active("corpus-98")
        assert mgr.get_active() == "corpus-98"

    def test_operator_project_untouched(self, tmp_path):
        mgr = _mgr(tmp_path)
        mgr.create("myapp", target="/does/not/matter",
                   resolve_target=False)
        mgr.set_active("myapp")
        assert mgr.get_active() == "myapp"


class TestCorpusRunnerStampsTtl:
    def test_corpus_project_context_stamps_expiry(
        self, tmp_path, monkeypatch,
    ):
        import core.audit.corpus.run_corpus as rc
        mgr = _mgr(tmp_path)
        monkeypatch.setattr(
            "core.project.project.ProjectManager",
            lambda projects_dir=None: mgr if projects_dir is None
            else ProjectManager(projects_dir),
        )
        with rc._corpus_project_context("tag1") as name:
            proj = mgr.load(name)
            assert name == "corpus-tag1"
            assert proj.expires_at
            expiry = datetime.fromisoformat(proj.expires_at)
            hours = (
                expiry - datetime.now(timezone.utc)
            ).total_seconds() / 3600
            assert 23 < hours <= rc._CORPUS_PROJECT_TTL_HOURS
        # Context exit restored the previous (no) active project.
        assert mgr.get_active() is None


class TestExplicitUseClearsMarker:
    def test_cli_use_clears_expiry(self, tmp_path, monkeypatch, capsys):
        mgr = _mgr(tmp_path)
        mgr.create("corpus-77", target="/tmp", resolve_target=False)
        proj = mgr.load("corpus-77")
        proj.expires_at = _iso(+1)
        mgr._save(proj)

        from core.project.cli import main
        monkeypatch.setattr(
            "core.project.project.PROJECTS_DIR", mgr.projects_dir,
        )
        monkeypatch.setattr(
            "core.project.sessions.record_session", lambda *_a: None,
        )
        monkeypatch.setattr(
            "core.project.sessions.awareness_lines",
            lambda *_a, **_kw: [],
        )
        monkeypatch.setattr(
            "sys.argv", ["raptor-project", "use", "corpus-77"],
        )
        main()

        out = capsys.readouterr().out
        assert "auto-expiry marker" in out
        assert mgr.load("corpus-77").expires_at == ""
        assert mgr.get_active() == "corpus-77"
