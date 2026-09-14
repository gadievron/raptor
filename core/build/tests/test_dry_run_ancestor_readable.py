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


class TestSupersetGrantRefused:
    """A hostile `include` symlink that resolves to a filesystem root
    or to a directory CONTAINING the repo must never become a compile
    -I flag or a dry-run readable grant — that is a superset of the
    target, not the sibling-include shape the rescue exists for."""

    def test_discovery_refuses_include_containing_repo(self, tmp_path):
        import os

        base = tmp_path / "base"
        repo = base / "box" / "src"
        repo.mkdir(parents=True)
        (repo / "main.c").write_text("int main(void){}\n", encoding="utf-8")
        (base / "hdr.h").write_text("// header\n", encoding="utf-8")
        # box/include resolves to base, which CONTAINS the repo.
        os.symlink(base, base / "box" / "include")

        found = BuildDetector(repo)._discover_ancestor_includes()
        assert str(base.resolve()) not in found

    def test_discovery_refuses_filesystem_root(self, tmp_path):
        import os

        proj = tmp_path / "proj"
        repo = proj / "src"
        repo.mkdir(parents=True)
        (repo / "main.c").write_text("int main(void){}\n", encoding="utf-8")
        os.symlink("/", proj / "include")

        found = BuildDetector(repo)._discover_ancestor_includes()
        assert "/" not in found

    def test_discovery_refuses_out_of_tree_system_dir(self, tmp_path):
        # `include -> /usr` is not a repo-superset and not on the
        # blocked-prefix list, but it is OUTSIDE the ancestor subtree
        # the candidate was found in — an out-of-tree read grant the
        # operator never scoped in.
        import os

        proj = tmp_path / "proj"
        repo = proj / "src"
        repo.mkdir(parents=True)
        (repo / "main.c").write_text("int main(void){}\n", encoding="utf-8")
        os.symlink("/usr", proj / "include")

        found = BuildDetector(repo)._discover_ancestor_includes()
        assert "/usr" not in found

    def test_discovery_refuses_foreign_out_of_tree_dir(self, tmp_path):
        # A foreign dir that neither contains the repo nor is a system
        # path (the `/home/<other>` shape) — still out-of-tree.
        import os

        foreign = tmp_path / "foreign"
        (foreign / "sub").mkdir(parents=True)
        (foreign / "hdr.h").write_text("// header\n", encoding="utf-8")
        box = tmp_path / "box"
        repo = box / "proj" / "src"
        repo.mkdir(parents=True)
        (repo / "main.c").write_text("int main(void){}\n", encoding="utf-8")
        os.symlink(foreign, box / "proj" / "include")

        found = BuildDetector(repo)._discover_ancestor_includes()
        assert str(foreign.resolve()) not in found

    def test_discovery_keeps_legitimate_sibling_include(self, tmp_path):
        # Control: the real rescue shape (proj/include next to
        # proj/src) keeps working under the containment.
        proj = tmp_path / "proj"
        inc = proj / "include"
        inc.mkdir(parents=True)
        (inc / "api.h").write_text("// header\n", encoding="utf-8")
        repo = proj / "src"
        repo.mkdir()
        (repo / "main.c").write_text("int main(void){}\n", encoding="utf-8")

        found = BuildDetector(repo)._discover_ancestor_includes()
        assert str(inc.resolve()) in found

    def test_grant_site_refuses_out_of_tree_dirs(self, tmp_path):
        proj = tmp_path / "proj"
        src = proj / "src"
        src.mkdir(parents=True)
        (src / "main.c").write_text("int main(void){}\n", encoding="utf-8")
        inc = proj / "include"
        inc.mkdir()
        (inc / "api.h").write_text("// header\n", encoding="utf-8")

        detector = BuildDetector(src)
        calls: list[list[str]] = []

        def fake_dry_run(script_path, language=None, extra_readable=None):
            calls.append(list(extra_readable or []))
            return []

        with mock.patch.object(
            detector, "_discover_ancestor_includes",
            return_value=["/usr", str(inc.resolve())],
        ), mock.patch.object(
            detector, "_dry_run", side_effect=fake_dry_run,
        ), mock.patch.object(
            detector, "detect_missing_config_headers", return_value=[],
        ):
            bs = detector.synthesise_build_command("cpp")

        assert bs is not None and calls
        assert "/usr" not in calls[0]
        assert str(inc.resolve()) in calls[0]  # in-tree grant survives
        import shutil
        for p in bs.cleanup_paths:
            p_path = Path(p)
            if p_path.is_dir():
                shutil.rmtree(p_path, ignore_errors=True)
            elif p_path.exists():
                p_path.unlink()

    def test_grant_site_refuses_superset_even_if_discovered(
        self, tmp_path,
    ):
        # Defense in depth: even if a hostile dir slips into the -I
        # flags (discovery raced, symlink swapped), the readable grant
        # re-vets the CURRENT resolution.
        proj = tmp_path / "proj"
        src = proj / "src"
        src.mkdir(parents=True)
        (src / "main.c").write_text("int main(void){}\n", encoding="utf-8")

        detector = BuildDetector(src)
        calls: list[list[str]] = []

        def fake_dry_run(script_path, language=None, extra_readable=None):
            calls.append(list(extra_readable or []))
            return []

        with mock.patch.object(
            detector, "_discover_ancestor_includes",
            return_value=["/", str(tmp_path)],
        ), mock.patch.object(
            detector, "_dry_run", side_effect=fake_dry_run,
        ), mock.patch.object(
            # The config-header diagnostic walks ancestor includes
            # too; the point of THIS test is the grant site, so keep
            # the mocked hostile dirs out of that unrelated walk.
            detector, "detect_missing_config_headers", return_value=[],
        ):
            bs = detector.synthesise_build_command("cpp")

        assert bs is not None and calls
        assert "/" not in calls[0]
        assert str(tmp_path) not in calls[0]  # contains the repo
        import shutil
        for p in bs.cleanup_paths:
            p_path = Path(p)
            if p_path.is_dir():
                shutil.rmtree(p_path, ignore_errors=True)
            elif p_path.exists():
                p_path.unlink()
