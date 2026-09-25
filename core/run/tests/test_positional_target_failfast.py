"""Stray-positional target gate in the raptor.py lifecycle wrapper.

``raptor.py scan /path/app.zip`` (positional target — the child
parsers only define ``--repo``) pre-fix had the wrapper back-fill the
active project's target (or RAPTOR_CALLER_DIR) as ``--repo``: it
sealed a failed run dir inside the WRONG project when the child
exited 2 on the unrecognised token, and was one tolerant child away
from scanning the wrong codebase outright. The gate fails fast with
the canonical ``--repo`` hint BEFORE any run dir exists — with and
without an active project default.
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


class TestStrayTargetToken:
    def test_existing_path_token_is_found(self, tmp_path):
        raptor = _import_raptor()
        zippath = tmp_path / "app.zip"
        zippath.write_bytes(b"PK\x03\x04")
        assert raptor._stray_target_token([str(zippath)]) == str(zippath)

    def test_archive_named_token_found_even_when_missing(self):
        raptor = _import_raptor()
        assert (raptor._stray_target_token(["/nonexistent/app.tar.gz"])
                == "/nonexistent/app.tar.gz")

    def test_value_flag_argument_is_never_a_stray(self, tmp_path):
        raptor = _import_raptor()
        cfg = tmp_path / "rules.yml"
        cfg.write_text("x", encoding="utf-8")
        assert raptor._stray_target_token(["--extra-config",
                                           str(cfg)]) is None

    def test_inline_flag_value_does_not_swallow_next_token(self, tmp_path):
        raptor = _import_raptor()
        d = tmp_path / "src"
        d.mkdir()
        args = ["--languages=python", str(d)]
        assert raptor._stray_target_token(args) == str(d)

    def test_plain_nonexistent_token_is_left_to_the_child(self):
        raptor = _import_raptor()
        assert raptor._stray_target_token(["frobnicate"]) is None

    def test_empty_args(self):
        raptor = _import_raptor()
        assert raptor._stray_target_token([]) is None


class TestResolveTargetFailFast:
    def test_stray_token_errors_with_active_project_default(self, tmp_path):
        """The wrong-project pollution shape: a project default must
        NOT be back-filled around a stray positional target."""
        raptor = _import_raptor()
        zippath = tmp_path / "app.zip"
        zippath.write_bytes(b"PK\x03\x04")
        with patch.object(raptor, "resolve_default_target",
                          return_value="/some/project/target") as rdt:
            target, args, err = raptor._resolve_target_for_command(
                "scan", [str(zippath)], None)
        assert target is None
        assert err is not None
        assert f"--repo {zippath}" in err
        assert args == [str(zippath)]  # no back-fill happened
        assert not rdt.called  # gate fires BEFORE default resolution

    def test_stray_token_errors_without_any_default(self, tmp_path):
        raptor = _import_raptor()
        d = tmp_path / "src"
        d.mkdir()
        with patch.object(raptor, "resolve_default_target",
                          return_value=None):
            target, args, err = raptor._resolve_target_for_command(
                "agentic", [str(d)], None)
        assert target is None
        assert err is not None and "--repo" in err

    def test_clean_args_still_back_fill_the_default(self):
        raptor = _import_raptor()
        with patch.object(raptor, "resolve_default_target",
                          return_value="/proj/code"):
            target, args, err = raptor._resolve_target_for_command(
                "scan", ["--codeql"], None)
        assert err is None
        assert target == "/proj/code"
        assert args == ["--codeql", "--repo", "/proj/code"]

    def test_explicit_repo_bypasses_the_gate(self, tmp_path):
        raptor = _import_raptor()
        d = tmp_path / "src"
        d.mkdir()
        target, args, err = raptor._resolve_target_for_command(
            "scan", ["--repo", str(d)], str(d))
        assert err is None and target == str(d)


class TestLifecycleNeverSealsARunDir:
    def test_wrapper_fails_before_output_dir_resolution(self, tmp_path):
        raptor = _import_raptor()
        zippath = tmp_path / "app.zip"
        zippath.write_bytes(b"PK\x03\x04")
        with patch.object(raptor, "get_output_dir",
                          side_effect=AssertionError(
                              "run dir must never be resolved")) as god, \
                patch.object(raptor, "resolve_default_target",
                             return_value="/some/project/target"):
            rc = raptor._run_with_lifecycle(
                "scan", Path("/nonexistent/child.py"),
                [str(zippath)], "label")
        assert rc == 2
        assert not god.called
