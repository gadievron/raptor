"""Tests for binary-oracle CLI plumbing — defaults, opt-out, the
git-tracked provenance gate, and the explicit-vs-default-on autodetect
message split."""

from __future__ import annotations

import shutil
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from core.analysis.binary_oracle_cli import (
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

    @patch("core.analysis.binary_oracle_cli._project_binaries",
           return_value=([], None))
    def test_opt_out_returns_empty(self, _mock_proj, tmp_path):
        result = resolve_binary_paths(
            _args(no_binary_oracle=True), tmp_path, "auto",
        )
        assert result == ()

    @patch("core.analysis.binary_oracle_cli._project_binaries",
           return_value=([], None))
    @patch("core.analysis.binary_oracle_cli._autodetect_binaries")
    def test_opt_out_skips_autodetect(self, mock_auto, _mock_proj, tmp_path):
        resolve_binary_paths(
            _args(no_binary_oracle=True), tmp_path, "auto",
        )
        mock_auto.assert_not_called()

    @patch("core.analysis.binary_oracle_cli._project_binaries",
           return_value=([], None))
    @patch("core.analysis.binary_oracle_cli._validate_explicit_paths",
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

    @patch("core.analysis.binary_oracle_cli._project_binaries",
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

    @patch("core.analysis.binary_oracle_cli._project_binaries",
           return_value=([], None))
    @patch("core.analysis.binary_oracle_cli._autodetect_binaries",
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

    @patch("core.analysis.binary_oracle_cli._project_binaries",
           return_value=([], None))
    @patch("core.analysis.binary_oracle_cli._autodetect_binaries",
           return_value=[Path("/build/example")])
    def test_binary_auto_flag_marks_explicit(
        self, mock_auto, _mock_proj, tmp_path,
    ):
        resolve_binary_paths(
            _args(binary_auto=True), tmp_path, "auto",
        )
        kwargs = mock_auto.call_args.kwargs
        assert kwargs.get("explicit") is True

    @patch("core.analysis.binary_oracle_cli._project_binaries",
           return_value=([], None))
    @patch("core.analysis.binary_oracle_cli._autodetect_binaries")
    @patch("core.analysis.binary_oracle_cli._validate_explicit_paths",
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
        if not shutil.which("git"):
            pytest.skip("git not available")
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

    def test_submodule_committed_binary_dropped(self, tmp_path):
        """A binary INSIDE a committed-submodule path is repo content
        pinned by the parent repo (gitlink entry, mode 160000). The
        old per-path ``--error-unmatch`` probe exited 1 ('did not
        match') for such paths and let an attacker-committed
        submodule ELF pass the provenance filter as locally built."""
        import subprocess
        self._git_init(tmp_path)
        (tmp_path / "vendor").mkdir()
        # Manufacture the gitlink directly — same index entry a real
        # ``git submodule add`` produces; the commit object need not
        # exist in the parent's store (it never does for submodules).
        subprocess.run(
            ["git", "update-index", "--add", "--cacheinfo",
             "160000," + "a" * 40 + ",vendor"],
            cwd=tmp_path, check=True,
        )
        binary = tmp_path / "vendor" / "prebuilt"
        binary.write_bytes(b"\x7fELF")
        # Two-direction: an untracked sibling OUTSIDE the submodule
        # still reads locally built.
        build = tmp_path / "build"
        build.mkdir()
        fresh = build / "fresh"
        fresh.write_bytes(b"\x7fELF")
        locally_built, repo_committed = _filter_locally_built(
            tmp_path, [binary, fresh],
        )
        assert repo_committed == [binary]
        assert locally_built == [fresh]

    def test_submodule_prefix_is_path_segment_aware(self, tmp_path):
        """``vendorx/bin`` is not under a ``vendor`` gitlink — the
        prefix match must not swallow same-prefix sibling dirs."""
        import subprocess
        self._git_init(tmp_path)
        (tmp_path / "vendor").mkdir()
        subprocess.run(
            ["git", "update-index", "--add", "--cacheinfo",
             "160000," + "a" * 40 + ",vendor"],
            cwd=tmp_path, check=True,
        )
        vendorx = tmp_path / "vendorx"
        vendorx.mkdir()
        binary = vendorx / "bin"
        binary.write_bytes(b"\x7fELF")
        locally_built, repo_committed = _filter_locally_built(
            tmp_path, [binary],
        )
        assert locally_built == [binary]
        assert repo_committed == []

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


class TestProvenanceGateSandboxed:
    """The provenance probe parses hostile repo state — git on an
    untrusted clone can execute repo-controlled code via hooks /
    fsmonitor / per-repo config — so it must route through
    ``core.sandbox`` with the strict read-only argv posture, and a
    sandbox refusal must land on the conservative split."""

    def test_git_routes_through_sandbox(self, tmp_path, monkeypatch):
        import core.sandbox.context as sbx_context

        calls: list[dict] = []

        def fake_run(cmd, **kwargs):
            record = dict(kwargs)
            record["cmd"] = list(cmd)
            calls.append(record)
            return SimpleNamespace(
                returncode=0,
                stdout=b"100644 " + b"a" * 40 + b" 0\tprebuilt\0",
                stderr=b"",
            )

        monkeypatch.setattr(sbx_context, "run", fake_run)
        monkeypatch.setattr(
            shutil, "which",
            lambda name, *a, **k: (
                "/usr/bin/git" if name == "git" else None),
        )
        committed = tmp_path / "prebuilt"
        committed.write_bytes(b"\x7fELF")
        fresh = tmp_path / "fresh"
        fresh.write_bytes(b"\x7fELF")

        locally_built, repo_committed = _filter_locally_built(
            tmp_path, [committed, fresh],
        )

        assert repo_committed == [committed]
        assert locally_built == [fresh]
        [sb] = calls
        assert sb["cmd"][0] == "/usr/bin/git"
        assert "ls-files" in sb["cmd"]
        # Strict read-only posture rides on the argv.
        assert any("protocol.allow=never" in part for part in sb["cmd"])
        assert sb["block_network"] is True
        assert sb["target"] == str(tmp_path)
        assert sb["output"]
        assert sb["env"]["LC_ALL"] == "C"
        assert sb["env_caller_filtered"] is True

    def test_sandbox_refusal_is_conservative(self, tmp_path, monkeypatch):
        """Refusal (BaseException by design) maps to the same
        all-candidates-unverified split as not-a-repo — never a bare
        run, never an abort."""
        import subprocess

        import core.sandbox.context as sbx_context
        from core.sandbox.errors import SandboxSetupError

        if not shutil.which("git"):
            pytest.skip("git not available")
        subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
        binary = tmp_path / "build-out"
        binary.write_bytes(b"\x7fELF")

        def refusing_run(cmd, **kwargs):
            raise SandboxSetupError("floor refused")

        monkeypatch.setattr(sbx_context, "run", refusing_run)
        locally_built, repo_committed = _filter_locally_built(
            tmp_path, [binary],
        )
        assert locally_built == []
        assert repo_committed == [binary]


class TestAutodetectIntegratesGate:
    """End-to-end: _autodetect_binaries returns only locally-built
    binaries even when detect_binaries finds repo-committed ones."""

    @patch("core.analysis.binary_oracle_autodetect.detect_binaries")
    def test_autodetect_drops_repo_committed(
        self, mock_detect, tmp_path, caplog,
    ):
        # Set up: git repo with a tracked binary + an untracked one.
        import subprocess
        if not shutil.which("git"):
            pytest.skip("git not available")
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
        from core.analysis.binary_oracle_cli import _autodetect_binaries
        result = _autodetect_binaries(tmp_path, "auto", explicit=False)
        # Only the untracked binary survives.
        assert result == [fresh]
        # Operator-facing warning fires for the dropped one.
        assert any("repo-committed" in r.message.lower()
                   for r in caplog.records)


class TestHostileNamesSanitisedOnTerminal:
    """Auto-detected build-tree paths and env-build output are
    target-derived — terminal prints and log records must escape
    non-printables (a crafted filename can carry OSC/CSI)."""

    def test_autodetected_path_print_is_sanitised(
            self, monkeypatch, tmp_path, capsys):
        import core.analysis.binary_oracle_cli as cli
        hostile = tmp_path / "build" / "bin\x1b]0;pwn\x07ary"
        monkeypatch.setattr(
            "core.analysis.binary_oracle_autodetect.detect_binaries",
            lambda repo, kind, path_filter=None: [hostile],
        )
        monkeypatch.setattr(
            cli, "_filter_locally_built", lambda repo, paths: (paths, []),
        )
        out = cli._autodetect_binaries(tmp_path, "auto")
        assert out == [hostile]
        captured = capsys.readouterr().out
        assert "\x1b" not in captured
        assert "\\x1b" in captured

    def test_dropped_committed_warning_is_escaped(
            self, monkeypatch, tmp_path, caplog):
        import logging

        import core.analysis.binary_oracle_cli as cli
        hostile = tmp_path / "build" / "evil\x1b[2J"
        monkeypatch.setattr(
            "core.analysis.binary_oracle_autodetect.detect_binaries",
            lambda repo, kind, path_filter=None: [],
        )
        monkeypatch.setattr(
            cli, "_filter_locally_built",
            lambda repo, paths: ([], [hostile] if paths else []),
        )
        with caplog.at_level(logging.WARNING):
            cli._autodetect_binaries(tmp_path, "auto")
        # The drop path runs inside detect_binaries' path_filter in
        # production; drive the wrapper directly for the log shape.
        joined = " ".join(r.getMessage() for r in caplog.records)
        assert "\x1b" not in joined


class TestDeclaredOut:
    """``declared_out`` collects the operator-declared subset only:
    explicit --binary paths and project-store binaries. Auto-detected
    paths are never declared (they stay floor-subject)."""

    @patch("core.analysis.binary_oracle_cli._project_binaries",
           return_value=([], None))
    @patch("core.analysis.binary_oracle_cli._autodetect_binaries",
           return_value=[])
    @patch("core.analysis.binary_oracle_cli._validate_explicit_paths",
           return_value=[Path("/tmp/explicit-bin")])
    def test_explicit_paths_are_declared(
        self, _mock_validate, _mock_auto, _mock_proj, tmp_path,
    ):
        declared: list = []
        resolve_binary_paths(
            _args(binary=["/tmp/explicit-bin"]), tmp_path, "auto",
            declared_out=declared,
        )
        assert declared == ["/tmp/explicit-bin"]

    @patch("core.analysis.binary_oracle_cli._autodetect_binaries",
           return_value=[Path("/build/example")])
    def test_project_binaries_are_declared_autodetect_is_not(
        self, _mock_auto, tmp_path,
    ):
        proj_bin = tmp_path / "lib.so"
        proj_bin.write_bytes(b"\x7fELF")
        with patch(
            "core.analysis.binary_oracle_cli._project_binaries",
            return_value=([proj_bin], "myproj"),
        ):
            declared: list = []
            result = resolve_binary_paths(
                _args(), tmp_path, "auto", declared_out=declared,
            )
        assert str(proj_bin) in declared
        assert "/build/example" in result
        assert "/build/example" not in declared

    @patch("core.analysis.binary_oracle_cli._project_binaries",
           return_value=([], None))
    @patch("core.analysis.binary_oracle_cli._autodetect_binaries",
           return_value=[])
    @patch("core.analysis.binary_oracle_cli._validate_explicit_paths",
           side_effect=lambda b, parser=None: [Path(p) for p in (b or [])])
    def test_apply_to_config_assigns_declared(
        self, _mock_validate, _mock_auto, _mock_proj, tmp_path,
    ):
        from core.analysis.binary_oracle_cli import apply_to_config
        from core.config import RaptorConfig
        prev = (RaptorConfig.BINARY_ORACLE_PATHS,
                RaptorConfig.BINARY_ORACLE_NO_SUPPRESS,
                RaptorConfig.BINARY_ORACLE_DECLARED,
                RaptorConfig.BINARY_ORACLE_IDENTITY_PINS,
                RaptorConfig.BINARY_ORACLE_EDGES)
        try:
            # Seed a stale pin: apply_to_config must ALWAYS re-assign
            # the identity channel, same as the path tuple.
            RaptorConfig.BINARY_ORACLE_IDENTITY_PINS = {
                "/stale": (1, 2, 3, "0" * 64)}
            apply_to_config(
                _args(binary=["/tmp/explicit-bin"]), tmp_path)
            assert RaptorConfig.BINARY_ORACLE_DECLARED == (
                "/tmp/explicit-bin",)
            # Explicit --binary carries no store witness — no pin.
            assert RaptorConfig.BINARY_ORACLE_IDENTITY_PINS == {}
            # Always re-assigned: a declared-less run clears it.
            apply_to_config(_args(), tmp_path)
            assert RaptorConfig.BINARY_ORACLE_DECLARED == ()
            assert RaptorConfig.BINARY_ORACLE_IDENTITY_PINS == {}
        finally:
            (RaptorConfig.BINARY_ORACLE_PATHS,
             RaptorConfig.BINARY_ORACLE_NO_SUPPRESS,
             RaptorConfig.BINARY_ORACLE_DECLARED,
             RaptorConfig.BINARY_ORACLE_IDENTITY_PINS,
             RaptorConfig.BINARY_ORACLE_EDGES) = prev


class TestProjectBinaryWitnessGate:
    """Content-witness re-verification at the store's load seam.

    ``/project binary add`` pins sha256 of the bytes the operator
    pointed at (the assertion travels with the CONTENT); a persisted
    path can sit inside a run dir's write grant, so anything with that
    grant could otherwise swap the file after add and have its DWARF
    drive ``absent``-verdict hard-suppression on every later run.

    The verification is FD-HONEST: one O_NOFOLLOW open, fstat of that
    fd, hash of that fd — never a by-name re-hash that races a swap
    between check and use. Verified entries export an identity pin
    ``(st_dev, st_ino, st_size, sha256)`` from that same fd; failed
    entries DEMOTE (load for hint-tier enrichment, ``None`` pin — the
    enrichment strips their suppression authority) rather than
    hard-refuse the run."""

    def _load(self, binaries, witnesses, no_suppress=None,
              identity=None):
        from core.analysis.binary_oracle_cli import _project_binaries

        proj = SimpleNamespace(binaries=binaries,
                               binary_witnesses=witnesses)

        class _Mgr:
            def load(self, name):
                return proj

        with patch("core.project.project.ProjectManager", _Mgr), \
             patch("core.project.trust._context_project_name",
                   return_value="myproj"):
            paths, name = _project_binaries(no_suppress_out=no_suppress,
                                            identity_out=identity)
        assert name == "myproj"
        return paths

    def test_matching_witness_loads_with_identity_pin(self, tmp_path):
        import os
        from core.hash import sha256_file
        b = tmp_path / "app.debug"
        b.write_bytes(b"\x7fELF" + b"\x00" * 28)
        key = str(b.resolve())
        digest = sha256_file(b)
        no_suppress: list = []
        identity: dict = {}
        paths = self._load([key], {key: digest},
                           no_suppress=no_suppress, identity=identity)
        assert paths == [b.resolve()]
        assert no_suppress == []
        st = os.stat(b)
        assert identity == {
            key: (st.st_dev, st.st_ino, st.st_size, digest)}

    def test_swapped_content_demoted_not_refused(self, tmp_path):
        # File replaced after the operator's add — the pinned witness
        # no longer matches. Posture: DEMOTE, not refuse — the entry
        # still loads (enrichment promotions keep findings alive) but
        # its identity pin records None, which strips absent-verdict
        # suppression authority downstream.
        from core.hash import sha256_file
        b = tmp_path / "app.debug"
        b.write_bytes(b"\x7fELF" + b"\x00" * 28)
        pinned = sha256_file(b)
        b.write_bytes(b"\x7fELF" + b"\xff" * 28)
        key = str(b.resolve())
        no_suppress: list = []
        identity: dict = {}
        paths = self._load([key], {key: pinned},
                           no_suppress=no_suppress, identity=identity)
        assert paths == [b.resolve()]
        assert identity == {key: None}
        # Demotion rides the identity channel, NOT the guessed-build
        # channel — summary accounting must say what happened.
        assert no_suppress == []

    def test_symlink_plant_with_matching_content_demoted(self, tmp_path):
        # A symlink swapped in at the stored name, pointing at a file
        # whose CONTENT matches the witness. A by-name re-hash follows
        # the link and grants full suppression authority; the
        # fd-honest open (O_NOFOLLOW) refuses to verify through it, so
        # the entry demotes to enrichment-only.
        from core.hash import sha256_file
        real = tmp_path / "real.debug"
        real.write_bytes(b"\x7fELF" + b"\x00" * 28)
        digest = sha256_file(real)
        slot = tmp_path / "app.debug"
        slot.symlink_to(real)
        key = str(slot)  # store names the (unresolved) slot path
        identity: dict = {}
        paths = self._load([key], {key: digest}, identity=identity)
        resolved = str(slot.resolve())
        assert paths == [Path(resolved)]
        assert identity == {resolved: None}

    def test_fifo_plant_demoted_without_hanging(self, tmp_path):
        # A reader-less FIFO at the stored name: a plain by-name open
        # blocks forever; open_regular's O_NONBLOCK + fstat(S_ISREG)
        # returns promptly and refuses, so the entry demotes.
        import os
        fifo = tmp_path / "app.debug"
        os.mkfifo(fifo)
        key = str(fifo)
        identity: dict = {}
        paths = self._load([key], {key: "0" * 64}, identity=identity)
        assert paths == [fifo.resolve()]
        assert identity == {str(fifo.resolve()): None}

    def test_read_error_after_open_records_the_none_pin(self, tmp_path):
        # The fd-honest open SUCCEEDED but the read raised (I/O
        # error, truncation race).
        # The demote warning alone is not enough — without the None
        # pin record the path is merely UNPINNED: the enrichment
        # brackets nothing and the binary keeps full absent-verdict
        # suppression authority despite an unverifiable witness.
        import core.source as source_mod

        b = tmp_path / "app.debug"
        b.write_bytes(b"\x7fELF" + b"\x00" * 28)
        key = str(b.resolve())

        real_open = source_mod.open_regular

        class _BrokenRead:
            def __init__(self, fh):
                self._fh = fh

            def fileno(self):
                return self._fh.fileno()

            def read(self, *a, **kw):
                raise OSError(5, "Input/output error")

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                self._fh.close()
                return False

        def breaking_open(path, *a, **kw):
            fh = real_open(path, *a, **kw)
            return _BrokenRead(fh) if fh is not None else None

        identity: dict = {}
        with patch.object(source_mod, "open_regular", breaking_open):
            paths = self._load([key], {key: "0" * 64},
                               identity=identity)
        # Loaded for hint-tier enrichment, but the unverifiable
        # witness MUST ride the identity channel as a None pin.
        assert paths == [b.resolve()]
        assert identity == {key: None}

    def test_witnessed_but_missing_skips_but_accounts(self, tmp_path):
        # ENOENT is not a plant — a deleted artifact stays SKIPPED
        # (nothing to classify, the run continues) — but the skip is
        # accounted: deleting a witnessed binary silently narrows the
        # "absent from every declared binary" quantifier, so the
        # missing path must ride the identity channel as a None
        # pin.
        key = str((tmp_path / "gone.debug").resolve())
        identity: dict = {}
        assert self._load([key], {key: "0" * 64},
                          identity=identity) == []
        assert identity == {key: None}

    def test_legacy_unwitnessed_is_enrichment_only(self, tmp_path):
        # Pre-witness store entries still load (no forced re-buy of
        # every store) but join the no-suppress channel: enrichment
        # verdicts count, ``absent`` never hard-suppresses off them.
        # No witness -> nothing to pin: the identity channel stays
        # empty.
        b = tmp_path / "app.debug"
        b.write_bytes(b"\x7fELF" + b"\x00" * 28)
        key = str(b.resolve())
        no_suppress: list = []
        identity: dict = {}
        paths = self._load([key], {}, no_suppress=no_suppress,
                           identity=identity)
        assert paths == [b.resolve()]
        assert no_suppress == [key]
        assert identity == {}

    def test_witness_consumed_on_the_opened_fd_not_by_name(
            self, tmp_path):
        # Same-fd pinning (race-hook): the slot is swapped to the
        # witnessed content immediately AFTER the fd-honest open
        # returns — the exact check-to-use window. The fd the gate
        # opened holds UNWITNESSED bytes, so the entry must demote;
        # only a by-name re-hash (re-opening the path: the TOCTOU
        # this seam closes) would see the matching bytes and grant
        # authority.
        import os
        import core.source as source_mod
        from core.hash import sha256_file
        trusted = tmp_path / "trusted.debug"
        trusted.write_bytes(b"\x7fELF" + b"\x00" * 28)
        digest = sha256_file(trusted)
        slot = tmp_path / "app.debug"
        slot.write_bytes(b"\x7fELF" + b"\xff" * 28)
        key = str(slot.resolve())
        real_open = source_mod.open_regular

        def swapping_open(path, *args, **kwargs):
            fh = real_open(path, *args, **kwargs)
            if fh is not None:
                os.replace(trusted, slot)
            return fh

        identity: dict = {}
        with patch("core.source.open_regular", swapping_open):
            paths = self._load([key], {key: digest},
                               identity=identity)
        assert paths == [Path(key)]
        assert identity == {key: None}

    def test_identity_pin_is_the_opened_fds_identity(self, tmp_path):
        # Complement direction of the same-fd property: the witness
        # matches the OPENED fd; the name is swapped to impostor
        # bytes before anything could re-read it. Fd-honest
        # consumption keeps authority and pins the fd's own inode —
        # a by-name re-hash would instead demote the operator's
        # genuine binary off bytes it never opened.
        import os
        import core.source as source_mod
        from core.hash import sha256_file
        slot = tmp_path / "app.debug"
        slot.write_bytes(b"\x7fELF" + b"\x00" * 28)
        digest = sha256_file(slot)
        st0 = os.stat(slot)
        impostor = tmp_path / "impostor.debug"
        impostor.write_bytes(b"\x7fELF" + b"\xee" * 28)
        key = str(slot.resolve())
        real_open = source_mod.open_regular

        def swapping_open(path, *args, **kwargs):
            fh = real_open(path, *args, **kwargs)
            if fh is not None:
                os.replace(impostor, slot)
            return fh

        identity: dict = {}
        with patch("core.source.open_regular", swapping_open):
            paths = self._load([key], {key: digest},
                               identity=identity)
        assert paths == [Path(key)]
        # The pin is the fd's identity, not the impostor's now at
        # the name.
        assert identity == {
            key: (st0.st_dev, st0.st_ino, st0.st_size, digest)}
        assert os.stat(slot).st_ino != st0.st_ino

    def test_demoted_alias_is_sticky_across_duplicates(self, tmp_path):
        # Two store entries resolving to ONE file: a planted symlink
        # alias (demotes) followed by the direct path (verifies).
        # Demotion must be sticky — last-writer-wins on the pin dict
        # would let alias ordering restore the authority the plant
        # stripped.
        from core.hash import sha256_file
        b = tmp_path / "app.debug"
        b.write_bytes(b"\x7fELF" + b"\x00" * 28)
        digest = sha256_file(b)
        alias = tmp_path / "alias.debug"
        alias.symlink_to(b)
        key = str(b.resolve())
        identity: dict = {}
        paths = self._load([str(alias), key],
                           {str(alias): digest, key: digest},
                           identity=identity)
        assert paths == [b.resolve(), b.resolve()]
        assert identity == {key: None}
