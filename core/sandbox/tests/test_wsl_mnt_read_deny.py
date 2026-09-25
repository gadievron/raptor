"""WSL /mnt default-deny in the restricted read allowlist.

On a WSL host the automount family under /mnt IS the Windows
filesystem; an ambient entry there in the composed read allowlist
(a derived readable_paths value, a tool resolved through the
Windows-interop PATH) would hand a restricted child the whole
Windows drive as a readable exfil surface.

Semantics under test (the profile-assembly chokepoint in
core.sandbox.context):

* scope — ``restrict_reads=True`` on a detected-WSL host; inert
  everywhere else (off-WSL the composed allowlist is untouched).
* denied — composed read-allowlist / tool_paths entries at or below
  /mnt, on the canonical bind-path spelling.
* exempt — the run's target/output trees and the operator's
  ``--sandbox-readable-path`` / ``--sandbox-tool-path`` CLI entries:
  explicit grants stay, the deny is for the ambient surface only.

Unit tests pin the split semantics; functional probes run the real
mount-ns lane both directions (mocked WSL detection is inherited by
the forked sandbox child). Target-on-/mnt exemption is unit-covered
only — planting a target under a real /mnt needs a WSL box
([verify-live] there); the exemption logic is pure path algebra.
"""

from __future__ import annotations

import logging
import os
import sys
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from core.sandbox import context as sandbox_context
from core.sandbox import state
from core.startup import wsl as startup_wsl

pytestmark = [
    pytest.mark.skipif(sys.platform != "linux",
                       reason="WSL is a Linux-host concern"),
    pytest.mark.wsl,
]

_PY = "/usr/bin/python3"

_split = sandbox_context._split_wsl_ambient_mnt_reads


def _mock_wsl(monkeypatch, *, wsl: bool) -> None:
    """Pin both flavour predicates coherently (a mocked WSL host is a
    WSL2 host, so the WSL1 refusal never engages here); the fork-based
    spawn backend inherits the mocked module state."""
    monkeypatch.setattr(startup_wsl, "is_wsl",
                        lambda kernel_id=None: wsl)
    monkeypatch.setattr(startup_wsl, "is_wsl2",
                        lambda kernel_id=None: wsl)


class TestSplitSemantics:
    def test_mnt_root_and_subpaths_dropped(self):
        kept, dropped = _split(["/mnt", "/mnt/c", "/mnt/c/tools"], [])
        assert kept == []
        assert dropped == ["/mnt", "/mnt/c", "/mnt/c/tools"]

    def test_non_mnt_paths_kept(self):
        paths = ["/usr", "/opt/toolchain", "/mnt-data", "/home/x"]
        kept, dropped = _split(paths, [])
        assert kept == paths
        assert dropped == []

    def test_target_tree_exempt_both_directions(self):
        # The load-bearing exemption: a target on /mnt/c stays
        # analysable — the target itself and entries WITHIN its tree
        # are kept; a sibling outside the tree is still denied.
        kept, dropped = _split(
            ["/mnt/c/repo", "/mnt/c/repo/vendor", "/mnt/c/other"],
            ["/mnt/c/repo"],
        )
        assert kept == ["/mnt/c/repo", "/mnt/c/repo/vendor"]
        assert dropped == ["/mnt/c/other"]

    def test_exempt_root_does_not_leak_upward(self):
        # Exempting a deep tree never exempts its ancestors: an
        # ambient "/mnt" or "/mnt/c" grant beside a /mnt/c/repo
        # target would re-open the whole drive.
        kept, dropped = _split(["/mnt", "/mnt/c"], ["/mnt/c/repo"])
        assert kept == []
        assert dropped == ["/mnt", "/mnt/c"]

    def test_double_slash_spelling_cannot_evade(self):
        # canonical_bind_path collapses the POSIX two-slash prefix —
        # "//mnt/c" names the same tree and must be denied; original
        # spellings are preserved in the outputs.
        kept, dropped = _split(["//mnt/c"], [])
        assert kept == []
        assert dropped == ["//mnt/c"]

    def test_exempt_root_spelling_normalised(self):
        kept, dropped = _split(["/mnt/c/repo/x"], ["//mnt/c/repo"])
        assert kept == ["/mnt/c/repo/x"]
        assert dropped == []

    def test_prefix_cousin_not_denied(self):
        # "/mnt-backup" shares the string prefix but not the tree.
        kept, dropped = _split(["/mnt-backup/x"], [])
        assert kept == ["/mnt-backup/x"]

    def test_empty_and_falsy_entries_kept(self):
        kept, dropped = _split(["", "/mnt/c"], [])
        assert kept == [""]
        assert dropped == ["/mnt/c"]

    def test_dot_and_trailing_and_triple_slash_spellings_denied(self):
        # Lexical-normalisation shapes (reviewer probe set): every
        # spelling of the same /mnt tree is denied.
        paths = ["/mnt/./c", "/mnt/", "/mnt/c/", "///mnt/c"]
        kept, dropped = _split(paths, [])
        assert kept == []
        assert dropped == paths

    def test_dotdot_out_of_exempt_tree_denied(self):
        # "/mnt/c/repo/../../d" lexically starts with the exempt root
        # but names /mnt/d — normalisation runs before containment.
        kept, dropped = _split(["/mnt/c/repo/../../d"], ["/mnt/c/repo"])
        assert kept == []
        assert dropped == ["/mnt/c/repo/../../d"]


class TestSymlinkSpellings:
    """The bind machinery mounts the RESOLVED source, so the deny
    must hold on the destination spelling too (and the exemption
    must hold for symlink-spelled targets — realpath both sides)."""

    def test_symlink_to_mnt_denied(self, tmp_path):
        # Reviewer repro shape: a link whose destination is /mnt is
        # lexically outside /mnt but IS a /mnt grant.
        link = tmp_path / "wlink"
        link.symlink_to("/mnt")
        kept, dropped = _split([str(link)], [])
        assert kept == []
        assert dropped == [str(link)]

    def test_symlink_into_mnt_subtree_denied(self, tmp_path):
        # Destination need not exist: realpath normalises the
        # nonexistent tail component-wise.
        link = tmp_path / "clink"
        link.symlink_to("/mnt/c/tools")
        kept, dropped = _split([str(link)], [])
        assert dropped == [str(link)]

    def test_symlink_spelled_exempt_target_keeps_tree(self, tmp_path):
        # ~/repo -> /mnt/c/repo as the run's target: entries within
        # the tree stay exempt on BOTH spellings (through the link
        # and at the destination), siblings outside stay denied.
        target_link = tmp_path / "repo"
        target_link.symlink_to("/mnt/c/repo")
        entries = [
            str(target_link / "vendor"),   # link-spelled, in tree
            "/mnt/c/repo/src",             # destination-spelled
            "/mnt/c/other",                # sibling, out of tree
        ]
        kept, dropped = _split(entries, [str(target_link)])
        assert kept == [str(target_link / "vendor"), "/mnt/c/repo/src"]
        assert dropped == ["/mnt/c/other"]

    def test_symlink_inside_exempt_tree_cannot_smuggle(self, tmp_path):
        # Exemption is realpath-only on the ENTRY side: a link parked
        # inside the exempt (off-/mnt) target tree whose destination
        # is an out-of-tree /mnt path must not ride its parent's
        # exemption into a Windows-drive grant.
        target = tmp_path / "target"
        target.mkdir()
        evil = target / "evil"
        evil.symlink_to("/mnt/d")
        kept, dropped = _split([str(evil)], [str(target)])
        assert kept == []
        assert dropped == [str(evil)]


class TestFunctionalMountNs:
    def _run(self, tmp_path, monkeypatch, *, wsl: bool,
             readable=("/mnt",), cli_readable=None):
        from core.sandbox import run
        _mock_wsl(monkeypatch, wsl=wsl)
        if cli_readable is not None:
            monkeypatch.setattr(
                state, "_cli_sandbox_readable_paths", list(cli_readable))
        target = tmp_path / "target"
        output = tmp_path / "output"
        target.mkdir(exist_ok=True)
        output.mkdir(exist_ok=True)
        child = textwrap.dedent("""
            import os
            print("MNT_VISIBLE", os.path.exists("/mnt"))
        """)
        return run(
            [_PY, "-c", child],
            target=str(target), output=str(output),
            restrict_reads=True,
            readable_paths=list(readable),
            capture_output=True, text=True, timeout=60,
        )

    @staticmethod
    def _require_mount_ns_taken(r) -> None:
        info = getattr(r, "sandbox_info", None) or {}
        if not info.get("mount_ns_active"):
            pytest.skip("mount-ns lane not taken on this host")

    @staticmethod
    def _host_has_mnt() -> bool:
        return os.path.isdir("/mnt")

    @pytest.mark.linux_native
    def test_ambient_mnt_dropped_under_mocked_wsl(
            self, monkeypatch, tmp_path, caplog):
        if not self._host_has_mnt():
            pytest.skip("host has no /mnt")
        with caplog.at_level(logging.WARNING, logger="core.sandbox.context"):
            r = self._run(tmp_path, monkeypatch, wsl=True)
        self._require_mount_ns_taken(r)
        assert r.returncode == 0, r.stderr
        assert "MNT_VISIBLE False" in r.stdout, r.stdout
        warnings = [rec.getMessage() for rec in caplog.records
                    if "dropping ambient read grant" in rec.getMessage()]
        assert warnings, "no /mnt-deny warning fired"
        assert "/mnt" in warnings[0]
        assert "--sandbox-readable-path" in warnings[0]

    @pytest.mark.linux_native
    def test_same_grant_binds_off_wsl(self, monkeypatch, tmp_path, caplog):
        # Inertness pin, functional direction: the identical call
        # off-WSL keeps its /mnt read grant (bound into the view).
        if not self._host_has_mnt():
            pytest.skip("host has no /mnt")
        with caplog.at_level(logging.WARNING, logger="core.sandbox.context"):
            r = self._run(tmp_path, monkeypatch, wsl=False)
        self._require_mount_ns_taken(r)
        assert r.returncode == 0, r.stderr
        assert "MNT_VISIBLE True" in r.stdout, r.stdout
        assert not any("dropping ambient read grant" in rec.getMessage()
                       for rec in caplog.records)

    @pytest.mark.linux_native
    def test_symlink_grant_dropped_under_mocked_wsl(
            self, monkeypatch, tmp_path, caplog):
        # Functional leg of the reviewer's symlink repro, fixed: an
        # ambient readable path spelled as a link to /mnt is dropped
        # (warned) and nothing is bound at the link path.
        if not self._host_has_mnt():
            pytest.skip("host has no /mnt")
        from core.sandbox import run
        _mock_wsl(monkeypatch, wsl=True)
        link = tmp_path / "wlink"
        link.symlink_to("/mnt")
        target = tmp_path / "target"
        output = tmp_path / "output"
        target.mkdir()
        output.mkdir()
        child = textwrap.dedent(f"""
            import os
            try:
                os.listdir({str(link)!r})
                print("LINK_LISTED")
            except OSError as e:
                print("LINK_DENIED", e.errno)
        """)
        with caplog.at_level(logging.WARNING,
                             logger="core.sandbox.context"):
            r = run(
                [_PY, "-c", child],
                target=str(target), output=str(output),
                restrict_reads=True, readable_paths=[str(link)],
                capture_output=True, text=True, timeout=60,
            )
        self._require_mount_ns_taken(r)
        assert r.returncode == 0, r.stderr
        assert "LINK_DENIED" in r.stdout, r.stdout
        assert any("dropping ambient read grant" in rec.getMessage()
                   and str(link) in rec.getMessage()
                   for rec in caplog.records), "no drop warning"

    @pytest.mark.linux_native
    def test_cli_readable_path_is_exempt(self, monkeypatch, tmp_path):
        # --sandbox-readable-path is the operator override: the same
        # /mnt entry arriving through the CLI slot stays granted on a
        # mocked-WSL host.
        if not self._host_has_mnt():
            pytest.skip("host has no /mnt")
        r = self._run(tmp_path, monkeypatch, wsl=True,
                      readable=(), cli_readable=["/mnt"])
        self._require_mount_ns_taken(r)
        assert r.returncode == 0, r.stderr
        assert "MNT_VISIBLE True" in r.stdout, r.stdout
