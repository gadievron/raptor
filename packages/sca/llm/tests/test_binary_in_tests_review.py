"""Tests for the binary-in-tests LLM review's context gatherer.

``_gather_test_context`` walks an UNTRUSTED repo and everything it
returns is embedded verbatim in an off-host LLM prompt — these pins
hold the containment line: no repo-planted symlink, absolute path,
or traversal-shaped evidence path may pull host file content into
the prompt, and no planted oversize file may be buffered.
"""

from __future__ import annotations

from pathlib import Path

from packages.sca.llm.binary_in_tests_review import _gather_test_context


def _plant_repo(base: Path) -> Path:
    """Hostile repo: a fake ELF named ``RSA`` (the attacker names the
    binary a string guaranteed to appear in the exfil target) plus a
    tests dir for planted readers."""
    repo = base / "hostile-repo"
    tests = repo / "tests"
    tests.mkdir(parents=True)
    (tests / "RSA").write_bytes(b"\x7fELF fake binary")
    return repo


class TestSymlinkContainment:
    def test_out_of_root_symlink_content_never_reaches_context(
        self, tmp_path: Path,
    ) -> None:
        secret = tmp_path / "outside-secret.txt"
        secret.write_text("RSA PRIVATE KEY hunter2 MATERIAL\n")
        repo = _plant_repo(tmp_path)
        (repo / "tests" / "test_loader.py").symlink_to(secret)
        ctx = _gather_test_context(repo, "tests/RSA")
        assert "hunter2" not in ctx
        assert ctx == ""

    def test_in_root_symlink_still_contributes(
        self, tmp_path: Path,
    ) -> None:
        """Monorepo layouts symlink shared files WITHIN the tree —
        the containment fix must not refuse those."""
        repo = _plant_repo(tmp_path)
        shared = repo / "shared" / "test_common.py"
        shared.parent.mkdir()
        shared.write_text("load('RSA')\n")
        (repo / "tests" / "test_link.py").symlink_to(shared)
        ctx = _gather_test_context(repo, "tests/RSA")
        assert "load('RSA')" in ctx

    def test_symlinked_tests_dir_out_of_root_refused(
        self, tmp_path: Path,
    ) -> None:
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "test_host.py").write_text("RSA hostfile hunter2\n")
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "tests").symlink_to(outside, target_is_directory=True)
        (outside / "RSA").write_bytes(b"\x7fELF")
        ctx = _gather_test_context(repo, "tests/RSA")
        assert "hunter2" not in ctx
        assert ctx == ""


class TestEvidencePathContainment:
    def test_absolute_evidence_path_refused(self, tmp_path: Path) -> None:
        repo = _plant_repo(tmp_path)
        outside = tmp_path / "elsewhere"
        outside.mkdir()
        (outside / "RSA").write_bytes(b"\x7fELF")
        (outside / "test_x.py").write_text("RSA hunter2\n")
        assert _gather_test_context(repo, str(outside / "RSA")) == ""

    def test_traversal_evidence_path_refused(self, tmp_path: Path) -> None:
        repo = _plant_repo(tmp_path)
        outside = tmp_path / "elsewhere"
        outside.mkdir()
        (outside / "RSA").write_bytes(b"\x7fELF")
        (outside / "test_x.py").write_text("RSA hunter2\n")
        # Must degrade to no-context, not raise out of the
        # enrichment stage.
        assert _gather_test_context(repo, "../elsewhere/RSA") == ""


class TestBoundedReads:
    def test_oversize_test_file_refused_not_buffered(
        self, tmp_path: Path,
    ) -> None:
        from packages.sca.llm.binary_in_tests_review import (
            _MAX_TEST_FILE_BYTES,
        )
        repo = _plant_repo(tmp_path)
        big = repo / "tests" / "test_big.py"
        big.write_text("RSA\n" + "A" * (_MAX_TEST_FILE_BYTES + 1))
        ctx = _gather_test_context(repo, "tests/RSA")
        assert ctx == ""

    def test_normal_context_still_gathered(self, tmp_path: Path) -> None:
        repo = _plant_repo(tmp_path)
        (repo / "tests" / "test_rsa.py").write_text(
            "def test_load():\n    parse('RSA')\n",
        )
        ctx = _gather_test_context(repo, "tests/RSA")
        assert "parse('RSA')" in ctx
        assert ctx.startswith("--- ")
