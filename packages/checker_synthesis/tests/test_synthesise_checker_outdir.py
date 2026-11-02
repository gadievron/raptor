"""``libexec/raptor-synthesise-checker`` output-dir resolution.

The default must be RAPTOR-side, never inside the target repo: a
hostile repo could pre-plant ``out`` as a symlink and steer artifact
writes anywhere, and run output must not pollute the scanned tree.
"""

from __future__ import annotations

import importlib.util
import sys
from importlib.machinery import SourceFileLoader
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "libexec" / "raptor-synthesise-checker"


@pytest.fixture(scope="module")
def cli():
    loader = SourceFileLoader("raptor_synthesise_checker", str(SCRIPT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    with pytest.MonkeyPatch.context() as mp, patch.object(sys, "path", sys.path.copy()):
        mp.setenv("_RAPTOR_TRUSTED", "1")
        loader.exec_module(mod)
    return mod


class TestResolveOutDir:
    def test_default_is_raptor_side(self, cli, tmp_path: Path):
        raptor = tmp_path / "raptor"
        raptor.mkdir()
        out = cli._resolve_out_dir(None, raptor)
        assert out == raptor / "out" / "checker-synthesis"

    def test_symlinked_default_refuses(self, cli, tmp_path: Path,
                                       capsys):
        raptor = tmp_path / "raptor"
        (raptor / "out").mkdir(parents=True)
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        (raptor / "out" / "checker-synthesis").symlink_to(elsewhere)
        assert cli._resolve_out_dir(None, raptor) is None
        assert "refusing" in capsys.readouterr().err

    def test_symlinked_out_parent_refuses(self, cli, tmp_path: Path,
                                          capsys):
        raptor = tmp_path / "raptor"
        raptor.mkdir()
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        (raptor / "out").symlink_to(elsewhere)
        assert cli._resolve_out_dir(None, raptor) is None

    def test_explicit_out_passes_through(self, cli, tmp_path: Path):
        assert cli._resolve_out_dir(str(tmp_path / "x"), tmp_path) == \
            tmp_path / "x"


class TestNoWritesOnRefusedInvocation:
    def test_traversal_file_creates_nothing(self, cli, tmp_path: Path,
                                            monkeypatch, capsys):
        """A refused --file must not have created any output dir —
        the old order did mkdir first (in the TARGET repo, by
        default)."""
        import sys
        repo = tmp_path / "repo"
        repo.mkdir()
        monkeypatch.setattr(sys, "argv", [
            "raptor-synthesise-checker",
            "--file", "../evil.c", "--function", "f",
            "--lines", "1-2", "--cwe", "CWE-787",
            "--reasoning", "r", "--repo", str(repo),
        ])
        rc = cli.main()
        assert rc == 1
        assert "repo-relative" in capsys.readouterr().err
        assert not (repo / "out").exists()
        assert not list(repo.iterdir())
