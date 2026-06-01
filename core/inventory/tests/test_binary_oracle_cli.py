"""Tests for binary-oracle CLI plumbing — defaults, opt-out, the
git-tracked provenance gate, and the explicit-vs-default-on autodetect
message split."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from core.inventory.binary_oracle_cli import (
    _filter_locally_built,
    add_binary_args,
    resolve_binary_paths,
)


def _args(**overrides):
    """Build a SimpleNamespace with the binary-flag attributes
    populated to safe defaults. Mirrors argparse's namespace shape
    so resolve_binary_paths can read each ``getattr`` safely."""
    base = {
        "binary": None,
        "binary_auto": False,
        "binary_edges": False,
        "no_binary_oracle": False,
        "target_kind": "auto",
    }
    base.update(overrides)
    return SimpleNamespace(**base)


class TestArgparseSurface:
    """The flags exist and parse cleanly."""

    def test_no_binary_oracle_flag_registered(self):
        import argparse
        ap = argparse.ArgumentParser()
        add_binary_args(ap)
        ns = ap.parse_args(["--no-binary-oracle"])
        assert ns.no_binary_oracle is True

    def test_default_is_off(self):
        import argparse
        ap = argparse.ArgumentParser()
        add_binary_args(ap)
        ns = ap.parse_args([])
        assert ns.no_binary_oracle is False


class TestNoBinaryOracleOptOut:
    """``--no-binary-oracle`` returns an empty tuple unconditionally."""

    @patch("core.inventory.binary_oracle_cli._project_binaries",
           return_value=([], None))
    def test_opt_out_returns_empty(self, _mock_proj, tmp_path):
        result = resolve_binary_paths(
            _args(no_binary_oracle=True), tmp_path, "auto",
        )
        assert result == ()

    @patch("core.inventory.binary_oracle_cli._project_binaries",
           return_value=([], None))
    @patch("core.inventory.binary_oracle_cli._autodetect_binaries")
    def test_opt_out_skips_autodetect(self, mock_auto, _mock_proj, tmp_path):
        resolve_binary_paths(
            _args(no_binary_oracle=True), tmp_path, "auto",
        )
        mock_auto.assert_not_called()

    @patch("core.inventory.binary_oracle_cli._project_binaries",
           return_value=([], None))
    @patch("core.inventory.binary_oracle_cli._validate_explicit_paths",
           return_value=[Path("/tmp/explicit-bin")])
    def test_opt_out_overrides_explicit_binary_with_warning(
        self, _mock_validate, _mock_proj, tmp_path, caplog,
    ):
        result = resolve_binary_paths(
            _args(no_binary_oracle=True,
                  binary=["/tmp/explicit-bin"]),
            tmp_path, "auto",
        )
        assert result == ()
        assert any("no-binary-oracle" in r.message.lower()
                   for r in caplog.records)

    @patch("core.inventory.binary_oracle_cli._project_binaries",
           return_value=([Path("/proj/lib.so")], "myproj"))
    def test_opt_out_skips_project_binaries(self, _mock_proj, tmp_path):
        # Opt-out is comprehensive: even project-persisted binaries
        # bypass when oracle is disabled.
        result = resolve_binary_paths(
            _args(no_binary_oracle=True), tmp_path, "auto",
        )
        assert result == ()


class TestDefaultOnAutodetect:
    """Autodetect runs by default when neither --binary nor
    --no-binary-oracle is set."""

    @patch("core.inventory.binary_oracle_cli._project_binaries",
           return_value=([], None))
    @patch("core.inventory.binary_oracle_cli._autodetect_binaries",
           return_value=[Path("/build/example")])
    def test_no_flags_triggers_autodetect(
        self, mock_auto, _mock_proj, tmp_path,
    ):
        result = resolve_binary_paths(_args(), tmp_path, "auto")
        mock_auto.assert_called_once()
        # ``explicit=False`` so the soft hint fires on the
        # nothing-found path.
        kwargs = mock_auto.call_args.kwargs
        assert kwargs.get("explicit") is False
        assert result == ("/build/example",)

    @patch("core.inventory.binary_oracle_cli._project_binaries",
           return_value=([], None))
    @patch("core.inventory.binary_oracle_cli._autodetect_binaries",
           return_value=[Path("/build/example")])
    def test_binary_auto_flag_marks_explicit(
        self, mock_auto, _mock_proj, tmp_path,
    ):
        resolve_binary_paths(
            _args(binary_auto=True), tmp_path, "auto",
        )
        kwargs = mock_auto.call_args.kwargs
        assert kwargs.get("explicit") is True

    @patch("core.inventory.binary_oracle_cli._project_binaries",
           return_value=([], None))
    @patch("core.inventory.binary_oracle_cli._autodetect_binaries")
    @patch("core.inventory.binary_oracle_cli._validate_explicit_paths",
           return_value=[Path("/tmp/explicit-bin")])
    def test_explicit_binary_skips_autodetect(
        self, _mock_validate, mock_auto, _mock_proj, tmp_path,
    ):
        resolve_binary_paths(
            _args(binary=["/tmp/explicit-bin"]), tmp_path, "auto",
        )
        mock_auto.assert_not_called()


class TestGitTrackedProvenanceGate:
    """The provenance filter: binaries tracked by git (committed to the
    source tree) are dropped; only untracked binaries (build artifacts
    the operator just produced) survive. Defends against attacker-
    planted and stale-committed binaries lying about what's present."""

    def _git_init(self, tmp_path: Path) -> Path:
        import subprocess
        subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
        subprocess.run(["git", "config", "user.email", "t@example.com"],
                       cwd=tmp_path, check=True)
        subprocess.run(["git", "config", "user.name", "Test"],
                       cwd=tmp_path, check=True)
        return tmp_path

    def test_untracked_binary_passes_filter(self, tmp_path):
        self._git_init(tmp_path)
        # Untracked file under build/.
        build = tmp_path / "build"
        build.mkdir()
        binary = build / "example"
        binary.write_bytes(b"\x7fELF")
        locally_built, repo_committed = _filter_locally_built(
            tmp_path, [binary],
        )
        assert locally_built == [binary]
        assert repo_committed == []

    def test_tracked_binary_dropped(self, tmp_path):
        import subprocess
        self._git_init(tmp_path)
        # Commit a binary into the repo tree.
        binary = tmp_path / "prebuilt"
        binary.write_bytes(b"\x7fELF")
        subprocess.run(["git", "add", "prebuilt"], cwd=tmp_path, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "prebuilt"], cwd=tmp_path,
            check=True,
        )
        locally_built, repo_committed = _filter_locally_built(
            tmp_path, [binary],
        )
        assert locally_built == []
        assert repo_committed == [binary]

    def test_mixed_set_splits_correctly(self, tmp_path):
        import subprocess
        self._git_init(tmp_path)
        committed = tmp_path / "prebuilt"
        committed.write_bytes(b"\x7fELF")
        subprocess.run(["git", "add", "prebuilt"], cwd=tmp_path, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "p"], cwd=tmp_path, check=True,
        )
        # Untracked sibling under build/.
        build = tmp_path / "build"
        build.mkdir()
        fresh = build / "fresh-build"
        fresh.write_bytes(b"\x7fELF")
        locally_built, repo_committed = _filter_locally_built(
            tmp_path, [committed, fresh],
        )
        assert locally_built == [fresh]
        assert repo_committed == [committed]

    def test_non_git_repo_treats_all_as_unverified(self, tmp_path):
        # tmp_path has no .git — provenance unverifiable, so the
        # conservative path fires: all candidates land in the
        # ``repo_committed`` bucket (gets dropped from the resolved
        # set in production; the operator can opt back in via
        # explicit --binary when they know their builds are
        # trustworthy).
        binary = tmp_path / "example"
        binary.write_bytes(b"\x7fELF")
        locally_built, repo_committed = _filter_locally_built(
            tmp_path, [binary],
        )
        assert locally_built == []
        assert repo_committed == [binary]

    def test_empty_candidates_is_noop(self, tmp_path):
        locally_built, repo_committed = _filter_locally_built(
            tmp_path, [],
        )
        assert locally_built == []
        assert repo_committed == []


class TestAutodetectIntegratesGate:
    """End-to-end: _autodetect_binaries returns only locally-built
    binaries even when detect_binaries finds repo-committed ones."""

    @patch("core.inventory.binary_oracle_autodetect.detect_binaries")
    def test_autodetect_drops_repo_committed(
        self, mock_detect, tmp_path, caplog,
    ):
        # Set up: git repo with a tracked binary + an untracked one.
        import subprocess
        subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
        subprocess.run(["git", "config", "user.email", "t@example.com"],
                       cwd=tmp_path, check=True)
        subprocess.run(["git", "config", "user.name", "Test"],
                       cwd=tmp_path, check=True)
        committed = tmp_path / "prebuilt"
        committed.write_bytes(b"\x7fELF")
        subprocess.run(["git", "add", "prebuilt"], cwd=tmp_path, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "p"], cwd=tmp_path, check=True,
        )
        build = tmp_path / "build"
        build.mkdir()
        fresh = build / "fresh"
        fresh.write_bytes(b"\x7fELF")

        mock_detect.return_value = [committed, fresh]
        from core.inventory.binary_oracle_cli import _autodetect_binaries
        result = _autodetect_binaries(tmp_path, "auto", explicit=False)
        # Only the untracked binary survives.
        assert result == [fresh]
        # Operator-facing warning fires for the dropped one.
        assert any("repo-committed" in r.message.lower()
                   for r in caplog.records)
