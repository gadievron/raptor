"""Ancestor include dirs must be readable inside the dry-run sandbox.

The ancestor ``-I`` rescue adds include dirs that are OUTSIDE
repo_path by construction, while ``_dry_run`` executes the build
script under ``restrict_reads=True, target=repo_path``. Unless the
discovered dirs are carved out via ``readable_paths``, the sandboxed
compiler EACCESes on every ancestor header for exactly the case the
rescue exists for — the dry-run reports failures a CC flag-suggest
retry can never fix, burning a paid dispatch per run.
"""

from __future__ import annotations

from pathlib import Path
from unittest import mock

from core.build.build_detector import BuildDetector


def _fake_run_capture(captured: dict):
    def fake_run(cmd, **kwargs):
        captured.update(kwargs)
        r = mock.MagicMock()
        r.returncode = 0
        r.stdout = ""
        r.stderr = ""
        return r
    return fake_run


class TestDryRunExtraReadable:
    def test_extra_readable_reaches_sandbox(self, tmp_path):
        captured: dict = {}
        with mock.patch(
            "core.build.build_detector._sandbox_run",
            side_effect=_fake_run_capture(captured),
        ):
            BuildDetector(tmp_path)._dry_run(
                tmp_path / "script.py",
                extra_readable=["/opt/proj/include"],
            )
        assert "/opt/proj/include" in (captured.get("readable_paths") or [])

    def test_no_extra_readable_keeps_default(self, tmp_path):
        captured: dict = {}
        with mock.patch(
            "core.build.build_detector._sandbox_run",
            side_effect=_fake_run_capture(captured),
        ):
            BuildDetector(tmp_path)._dry_run(tmp_path / "script.py")
        assert captured.get("readable_paths") is None


class TestSynthesiseThreadsAncestorDirs:
    def test_ancestor_include_dirs_passed_to_dry_run(self, tmp_path):
        # Layout: proj/include/api.h (ancestor rescue target) +
        # proj/src/*.c (the scanned subdir).
        proj = tmp_path / "proj"
        inc = proj / "include"
        inc.mkdir(parents=True)
        (inc / "api.h").write_text("// header\n", encoding="utf-8")
        src = proj / "src"
        src.mkdir()
        (src / "main.c").write_text(
            '#include <api.h>\nint main(void){return 0;}\n',
            encoding="utf-8",
        )

        detector = BuildDetector(src)
        calls: list[dict] = []

        def fake_dry_run(script_path, language=None, extra_readable=None):
            calls.append({"extra_readable": list(extra_readable or [])})
            return []

        with mock.patch.object(detector, "_dry_run", side_effect=fake_dry_run):
            bs = detector.synthesise_build_command("cpp")

        assert bs is not None
        assert calls, "synthesise_build_command never dry-ran the script"
        resolved_inc = str(inc.resolve())
        assert resolved_inc in calls[0]["extra_readable"], (
            "discovered ancestor include dir was not carved out for the "
            "dry-run read sandbox"
        )
        # Tidy the synthesised artifacts (the contract hands cleanup
        # to the caller).
        import shutil
        for p in bs.cleanup_paths:
            p_path = Path(p)
            if p_path.is_dir():
                shutil.rmtree(p_path, ignore_errors=True)
            elif p_path.exists():
                p_path.unlink()
