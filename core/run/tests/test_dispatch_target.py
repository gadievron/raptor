"""Tests for raptor.py's per-mode default-target resolution.

The lifecycle wrapper back-fills --repo from the active project /
RAPTOR_CALLER_DIR — but only for the modes whose child actually
parses --repo. fuzz needs --binary and web needs --url; injecting a
project source dir there either crashed the child's argparse or made
fuzz treat a directory as the binary, leaving a spurious failed run
dir behind. Missing required flags must error BEFORE any run dir is
created.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

_RAPTOR_ROOT = Path(__file__).resolve().parents[3]


def _import_raptor():
    if "raptor" not in sys.modules:
        sys.path.insert(0, str(_RAPTOR_ROOT))
    import raptor
    return raptor


class TestResolveTargetForCommand:
    def test_explicit_target_passes_through(self):
        raptor = _import_raptor()
        target, args, err = raptor._resolve_target_for_command(
            "scan", ["--repo", "/x"], "/x",
        )
        assert (target, args, err) == ("/x", ["--repo", "/x"], None)

    def test_repo_mode_backfills_from_default(self):
        raptor = _import_raptor()
        for mode in ("scan", "agentic", "codeql"):
            with patch("core.run.output.resolve_default_target_with_kind",
                       return_value=("/proj/target", None)):
                target, args, err = raptor._resolve_target_for_command(
                    mode, [], None,
                )
            assert err is None
            assert target == "/proj/target"
            assert args == ["--repo", "/proj/target"]

    def test_fuzz_never_backfills_repo(self):
        raptor = _import_raptor()
        with patch("core.run.output.resolve_default_target_with_kind",
                   return_value=("/proj/target", None)):
            target, args, err = raptor._resolve_target_for_command(
                "fuzz", ["--duration", "60"], None,
            )
        assert target is None
        assert "--repo" not in args
        assert err is not None
        assert "--binary" in err

    def test_web_missing_url_errors(self):
        raptor = _import_raptor()
        with patch("core.run.output.resolve_default_target_with_kind",
                   return_value=("/proj/target", None)):
            _target, args, err = raptor._resolve_target_for_command(
                "web", [], None,
            )
        assert "--repo" not in args
        assert err is not None
        assert "--url" in err

    def test_fuzz_utility_modes_run_without_binary(self):
        raptor = _import_raptor()
        for utility_args in (
            ["--export-seed-corpus", "/tmp/x"],
            ["--export-seed-corpus=/tmp/x"],
            ["--prepare-corpus", "/tmp/y"],
        ):
            _target, _args, err = raptor._resolve_target_for_command(
                "fuzz", utility_args, None,
            )
            assert err is None, utility_args

    def test_fuzz_with_binary_passes_through(self):
        raptor = _import_raptor()
        target, _args, err = raptor._resolve_target_for_command(
            "fuzz", ["--binary", "/bin/app"], "/bin/app",
        )
        assert err is None
        assert target == "/bin/app"


class TestFirmwareProjectRouting:
    """A project with target-kind=firmware routes bare /scan and
    /agentic into firmware mode; /codeql errors before a run dir."""

    def test_firmware_project_injects_firmware_root(self):
        raptor = _import_raptor()
        for mode in ("scan", "agentic"):
            with patch("core.run.output.resolve_default_target_with_kind",
                       return_value=("/proj/fw-root", "firmware")):
                target, args, err = raptor._resolve_target_for_command(
                    mode, [], None,
                )
            assert err is None
            assert target == "/proj/fw-root"
            assert args == ["--firmware-root", "/proj/fw-root"]

    def test_firmware_project_refuses_codeql(self):
        raptor = _import_raptor()
        with patch("core.run.output.resolve_default_target_with_kind",
                   return_value=("/proj/fw-root", "firmware")):
            target, args, err = raptor._resolve_target_for_command(
                "codeql", [], None,
            )
        assert err is not None and "firmware" in err
        assert target is None

    def test_non_firmware_project_unchanged(self):
        raptor = _import_raptor()
        with patch("core.run.output.resolve_default_target_with_kind",
                   return_value=("/proj/src", "application")):
            target, args, err = raptor._resolve_target_for_command(
                "scan", [], None,
            )
        assert args == ["--repo", "/proj/src"]

    def test_explicit_firmware_root_bypasses_backfill(self):
        raptor = _import_raptor()
        target, args, err = raptor._resolve_target_for_command(
            "scan", ["--firmware-root", "/x"], "/x",
        )
        assert (target, args, err) == ("/x", ["--firmware-root", "/x"], None)


class TestExplicitRepoOnFirmwareProject:
    """The slash-command dispatch substitutes the project target into
    --repo verbatim; on a firmware project that explicit flag must be
    rewritten, while a --repo pointing elsewhere is a real override."""

    def test_explicit_repo_equal_to_firmware_target_rewritten(self, tmp_path):
        raptor = _import_raptor()
        root = str(tmp_path)
        with patch("core.run.output.resolve_default_target_with_kind",
                   return_value=(root, "firmware")):
            for argv in ([ "--repo", root], [f"--repo={root}"]):
                target, args, err = raptor._resolve_target_for_command(
                    "agentic", list(argv), root,
                )
                assert err is None
                assert "--repo" not in " ".join(args).replace(
                    "--firmware-root", "")
                assert ("--firmware-root" in args
                        or f"--firmware-root={root}" in args)

    def test_explicit_repo_elsewhere_passes_through(self, tmp_path):
        raptor = _import_raptor()
        other = str(tmp_path / "other-src")
        with patch("core.run.output.resolve_default_target_with_kind",
                   return_value=(str(tmp_path), "firmware")):
            target, args, err = raptor._resolve_target_for_command(
                "scan", ["--repo", other], other,
            )
        assert args == ["--repo", other]

    def test_explicit_firmware_root_not_double_rewritten(self, tmp_path):
        raptor = _import_raptor()
        root = str(tmp_path)
        with patch("core.run.output.resolve_default_target_with_kind",
                   return_value=(root, "firmware")):
            target, args, err = raptor._resolve_target_for_command(
                "agentic", ["--firmware-root", root], root,
            )
        assert args == ["--firmware-root", root]

    def test_explicit_repo_codeql_on_firmware_refused(self, tmp_path):
        raptor = _import_raptor()
        root = str(tmp_path)
        with patch("core.run.output.resolve_default_target_with_kind",
                   return_value=(root, "firmware")):
            target, args, err = raptor._resolve_target_for_command(
                "codeql", ["--repo", root], root,
            )
        assert err is not None and "firmware" in err
