"""Run-root ``output=`` seam warning + the work-subdir helper.

Both directions are pinned: ``output=`` naming a run-directory root
(a dir carrying ``.raptor-run.json``) warns at sandbox() construction,
and each documented silent shape stays silent — the
``output_run_root_ok=True`` acknowledgement, a non-run-root output, a
work subdirectory minted by :func:`hostile_work_subdir`, and the
operator-disabled lane (no containment seam to flag). The warning is
once per (process, realpath), and any non-printables in the quoted
path are escaped before the text reaches the operator terminal.
"""

from __future__ import annotations

import os
import stat
import sys

import pytest

from core.sandbox import context as _ctx
from core.sandbox.work_dir import hostile_work_subdir, is_run_root

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="Linux sandbox lanes")


@pytest.fixture(autouse=True)
def _fresh_warn_registry(monkeypatch):
    """The once-per-process registry must not couple test outcomes."""
    monkeypatch.setattr(_ctx, "_run_root_output_warned", set())


def _run_root(tmp_path, name: str = "run") -> str:
    d = tmp_path / name
    d.mkdir()
    (d / ".raptor-run.json").write_text("{}", encoding="utf-8")
    return str(d)


class TestSeamWarning:
    def test_run_root_output_warns(self, tmp_path, caplog):
        out = _run_root(tmp_path)
        with caplog.at_level("WARNING"):
            with _ctx.sandbox(output=out):
                pass
        assert "run-directory root" in caplog.text
        assert "output_run_root_ok" in caplog.text
        assert "hostile_work_subdir" in caplog.text

    def test_ack_suppresses_warning(self, tmp_path, caplog):
        out = _run_root(tmp_path)
        with caplog.at_level("WARNING"):
            with _ctx.sandbox(output=out, output_run_root_ok=True):
                pass
        assert "run-directory root" not in caplog.text

    def test_non_run_root_output_is_silent(self, tmp_path, caplog):
        out = tmp_path / "scratch"
        out.mkdir()
        with caplog.at_level("WARNING"):
            with _ctx.sandbox(output=str(out)):
                pass
        assert "run-directory root" not in caplog.text

    def test_work_subdir_output_is_silent(self, tmp_path, caplog):
        run_dir = _run_root(tmp_path)
        work = hostile_work_subdir(run_dir, "target")
        with caplog.at_level("WARNING"):
            with _ctx.sandbox(output=str(work)):
                pass
        assert "run-directory root" not in caplog.text

    def test_disabled_lane_is_silent(self, tmp_path, caplog):
        # --sandbox none delivers a bare subprocess: there is no
        # containment seam, so the seam warning must not fire.
        out = _run_root(tmp_path)
        with caplog.at_level("WARNING"):
            with _ctx.sandbox(disabled=True, output=out):
                pass
        assert "run-directory root" not in caplog.text

    def test_warns_once_per_path(self, tmp_path, caplog):
        out = _run_root(tmp_path)
        with caplog.at_level("WARNING"):
            with _ctx.sandbox(output=out):
                pass
            with _ctx.sandbox(output=out):
                pass
        assert caplog.text.count("run-directory root") == 1

    def test_nonprintable_path_is_escaped(self, tmp_path, caplog):
        # Run dirs can embed target-derived name segments; a control
        # char in the path must reach the log as an escape sequence,
        # never as the raw byte.
        d = tmp_path / "run\x1b]0;evil\x07"
        d.mkdir()
        (d / ".raptor-run.json").write_text("{}", encoding="utf-8")
        with caplog.at_level("WARNING"):
            with _ctx.sandbox(output=str(d)):
                pass
        assert "run-directory root" in caplog.text
        assert "\x1b" not in caplog.text
        assert "\\x1b" in caplog.text

    def test_networked_helper_accepts_and_forwards_ack(
            self, tmp_path, monkeypatch):
        # run_untrusted_networked's kwarg allowlist must admit the
        # acknowledgement and hand it to run() — trusted-agent
        # dispatches write the run's own artifacts by contract.
        captured: dict = {}

        def spy_run(cmd, **kw):
            captured.update(kw)

            class _R:
                returncode = 0
            return _R()

        monkeypatch.setattr(_ctx, "run", spy_run)
        monkeypatch.setattr(
            _ctx, "_require_userns_or_optin",
            lambda *a, **kw: False)
        monkeypatch.setattr(
            _ctx, "_untrusted_stdio_write_only",
            lambda *a, **kw: [])
        out = _run_root(tmp_path)
        _ctx.run_untrusted_networked(
            ["/bin/true"], output=out,
            proxy_hosts=["api.example.invalid"],
            output_run_root_ok=True)
        assert captured.get("output_run_root_ok") is True

    def test_run_untrusted_forwards_ack(self, tmp_path, monkeypatch):
        captured: dict = {}

        def spy_run(cmd, **kw):
            captured.update(kw)

            class _R:
                returncode = 0
            return _R()

        monkeypatch.setattr(_ctx, "run", spy_run)
        monkeypatch.setattr(
            _ctx, "_require_userns_or_optin",
            lambda *a, **kw: False)
        monkeypatch.setattr(
            _ctx, "_untrusted_stdio_write_only",
            lambda *a, **kw: [])
        out = _run_root(tmp_path)
        _ctx.run_untrusted(
            ["/bin/true"], output=out, output_run_root_ok=True)
        assert captured.get("output_run_root_ok") is True


class TestIsRunRoot:
    def test_marker_dir_is_run_root(self, tmp_path):
        assert is_run_root(_run_root(tmp_path))

    def test_plain_dir_is_not(self, tmp_path):
        assert not is_run_root(tmp_path)

    def test_missing_path_is_not(self, tmp_path):
        assert not is_run_root(tmp_path / "nope")

    def test_marker_must_be_a_file(self, tmp_path):
        d = tmp_path / "run"
        (d / ".raptor-run.json").mkdir(parents=True)
        assert not is_run_root(d)

    def test_nul_in_path_answers_false(self, tmp_path):
        assert not is_run_root(str(tmp_path) + "\x00x")


class TestHostileWorkSubdir:
    def test_creates_private_subdir(self, tmp_path):
        work = hostile_work_subdir(tmp_path, "target")
        assert work == tmp_path / "work-target"
        st = os.stat(work)
        assert stat.S_ISDIR(st.st_mode)
        assert st.st_mode & 0o077 == 0, "work subdir leaks group/other"

    def test_idempotent(self, tmp_path):
        first = hostile_work_subdir(tmp_path, "target")
        second = hostile_work_subdir(tmp_path, "target")
        assert first == second

    def test_work_subdir_is_not_a_run_root(self, tmp_path):
        run_dir = _run_root(tmp_path)
        assert not is_run_root(hostile_work_subdir(run_dir, "target"))

    @pytest.mark.parametrize("label", [
        "", ".", "..", "../x", "a/b", "a b", "a\x00b", "-lead",
        "x" * 65,
    ])
    def test_bad_labels_refused(self, tmp_path, label):
        with pytest.raises(ValueError, match="label"):
            hostile_work_subdir(tmp_path, label)

    def test_symlink_plant_refused(self, tmp_path):
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        (tmp_path / "work-target").symlink_to(elsewhere)
        with pytest.raises(ValueError, match="not a regular directory"):
            hostile_work_subdir(tmp_path, "target")

    def test_regular_file_plant_refused(self, tmp_path):
        (tmp_path / "work-target").write_text("", encoding="utf-8")
        with pytest.raises(ValueError, match="not a regular directory"):
            hostile_work_subdir(tmp_path, "target")
