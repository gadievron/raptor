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
            with patch.object(raptor, "resolve_default_target",
                              return_value="/proj/target"):
                target, args, err = raptor._resolve_target_for_command(
                    mode, [], None,
                )
            assert err is None
            assert target == "/proj/target"
            assert args == ["--repo", "/proj/target"]

    def test_fuzz_never_backfills_repo(self):
        raptor = _import_raptor()
        with patch.object(raptor, "resolve_default_target",
                          return_value="/proj/target"):
            target, args, err = raptor._resolve_target_for_command(
                "fuzz", ["--duration", "60"], None,
            )
        assert target is None
        assert "--repo" not in args
        assert err is not None
        assert "--binary" in err

    def test_web_missing_url_errors(self):
        raptor = _import_raptor()
        with patch.object(raptor, "resolve_default_target",
                          return_value="/proj/target"):
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
