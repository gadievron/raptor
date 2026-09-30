"""Binary-engagement staleness — ``binary:<stem>`` rows against a file target.

On binary chains, ``target_path`` is the binary FILE and the understand
checklist row uses the synthetic ``binary:<stem>`` pseudo-path while its
``sha256`` is the binary's real hash. ``_find_stale_files`` must verify
such rows by hashing the target file itself — the pseudo-path never
exists on disk, so a path join under the file target can never be fresh.
"""

import hashlib
import json
from pathlib import Path

import pytest

from core.inventory.binary_builder import BINARY_PATH_PREFIX
from core.orchestration.understand_bridge import (
    _find_stale_files,
    _rank_candidates,
)

BINARY_CONTENT = b"\x7fELF-fake-binary-content"
BINARY_SHA = hashlib.sha256(BINARY_CONTENT).hexdigest()


@pytest.fixture
def binary_target(tmp_path: Path) -> Path:
    """A regular file standing in for the engaged binary."""
    binary = tmp_path / "qualys-scan-util"
    binary.write_bytes(BINARY_CONTENT)
    return binary


class TestBinaryRowsFileTarget:
    """binary:-prefixed rows verify against the target file's own hash."""

    def test_matching_hash_is_fresh(self, binary_target: Path) -> None:
        """Binary row whose sha256 matches the target file → NOT stale."""
        h1 = {BINARY_PATH_PREFIX + "qualys-scan-util": BINARY_SHA}
        assert _find_stale_files(h1, str(binary_target)) == set()

    def test_differing_hash_is_stale(self, binary_target: Path) -> None:
        """Binary row whose sha256 differs (binary rebuilt since the
        understand run) → stale, honestly."""
        rel = BINARY_PATH_PREFIX + "qualys-scan-util"
        h1 = {rel: hashlib.sha256(b"older build").hexdigest()}
        assert _find_stale_files(h1, str(binary_target)) == {rel}

    def test_non_binary_row_stays_stale(self, binary_target: Path) -> None:
        """A source pseudo-row can't be verified against a file target →
        stale (current behavior kept)."""
        h1 = {"src/main.c": hashlib.sha256(b"anything").hexdigest()}
        assert _find_stale_files(h1, str(binary_target)) == {"src/main.c"}

    def test_non_binary_row_with_coinciding_hash_still_stale(
        self, binary_target: Path,
    ) -> None:
        """A NON-binary row whose recorded hash EQUALS the target file's
        real hash must still be stale — the ``binary:`` prefix gate, not
        hash coincidence, decides whether a row verifies against the
        file target."""
        h1 = {"src/main.c": BINARY_SHA}
        assert _find_stale_files(h1, str(binary_target)) == {"src/main.c"}

    def test_unreadable_target_reads_stale_not_raise(
        self, binary_target: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``sha256_file`` raising OSError (target vanished or turned
        unreadable after the entry ``is_file()`` check) degrades to
        stale — the exception never escapes ``_find_stale_files``."""
        import core.hash

        def raising(path: Path, chunk_size: "int | None" = None) -> str:
            raise PermissionError(13, "Permission denied", str(path))

        monkeypatch.setattr(core.hash, "sha256_file", raising)
        rel = BINARY_PATH_PREFIX + "qualys-scan-util"
        h1 = {rel: BINARY_SHA}
        assert _find_stale_files(h1, str(binary_target)) == {rel}

    def test_target_hashed_at_most_once_per_call(
        self, binary_target: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """K distinct ``binary:`` rows hash the target at most once per
        call, while per-rel_path cache entries are still written (the
        cross-candidate reuse in ``_rank_candidates`` depends on them)."""
        import core.hash

        calls: list[Path] = []
        real = core.hash.sha256_file

        def counting(path: Path, chunk_size: "int | None" = None) -> str:
            calls.append(path)
            return real(path, chunk_size)

        monkeypatch.setattr(core.hash, "sha256_file", counting)
        rel_a = BINARY_PATH_PREFIX + "tool-a"
        rel_b = BINARY_PATH_PREFIX + "tool-b"
        rel_c = BINARY_PATH_PREFIX + "tool-c"
        h1 = {
            rel_a: BINARY_SHA,
            rel_b: hashlib.sha256(b"older build").hexdigest(),
            rel_c: BINARY_SHA,
        }
        cache: dict[str, "str | None"] = {}
        assert _find_stale_files(h1, str(binary_target), cache) == {rel_b}
        assert len(calls) == 1
        assert cache == {rel_a: BINARY_SHA, rel_b: BINARY_SHA, rel_c: BINARY_SHA}

    def test_mixed_rows_split_correctly(self, binary_target: Path) -> None:
        """Fresh binary row and unverifiable source row in one checklist."""
        bin_rel = BINARY_PATH_PREFIX + "qualys-scan-util"
        h1 = {
            bin_rel: BINARY_SHA,
            "src/main.c": hashlib.sha256(b"anything").hexdigest(),
        }
        assert _find_stale_files(h1, str(binary_target)) == {"src/main.c"}

    def test_cache_short_circuit_honored(
        self, binary_target: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A shared disk_hash_cache hashes the binary once across calls."""
        import core.hash

        calls: list[Path] = []
        real = core.hash.sha256_file

        def counting(path: Path, chunk_size: "int | None" = None) -> str:
            calls.append(path)
            return real(path, chunk_size)

        monkeypatch.setattr(core.hash, "sha256_file", counting)
        rel = BINARY_PATH_PREFIX + "qualys-scan-util"
        h1 = {rel: BINARY_SHA}
        cache: dict[str, "str | None"] = {}
        assert _find_stale_files(h1, str(binary_target), cache) == set()
        assert _find_stale_files(h1, str(binary_target), cache) == set()
        assert len(calls) == 1
        assert cache[rel] == BINARY_SHA

    def test_preseeded_cache_wins_over_disk(self, binary_target: Path) -> None:
        """A pre-seeded cache entry is used verbatim — no re-hash."""
        rel = BINARY_PATH_PREFIX + "qualys-scan-util"
        h1 = {rel: BINARY_SHA}
        cache: dict[str, "str | None"] = {rel: "not-the-real-hash"}
        assert _find_stale_files(h1, str(binary_target), cache) == {rel}


class TestDirTargetUnchanged:
    """Directory targets keep the join-and-contain path exactly as before."""

    def test_dir_target_fresh(self, tmp_path: Path) -> None:
        target = tmp_path / "target"
        target.mkdir()
        (target / "a.py").write_text("aaa")
        h1 = {"a.py": hashlib.sha256(b"aaa").hexdigest()}
        assert _find_stale_files(h1, str(target)) == set()

    def test_dir_target_stale(self, tmp_path: Path) -> None:
        target = tmp_path / "target"
        target.mkdir()
        (target / "a.py").write_text("MODIFIED")
        h1 = {"a.py": hashlib.sha256(b"aaa").hexdigest()}
        assert _find_stale_files(h1, str(target)) == {"a.py"}

    def test_dir_target_binary_prefixed_row_still_stale(
        self, tmp_path: Path,
    ) -> None:
        """A binary: row against a DIRECTORY target has no file to verify
        against — stays stale (the pseudo-path never exists on disk)."""
        target = tmp_path / "target"
        target.mkdir()
        (target / "a.py").write_text("aaa")
        rel = BINARY_PATH_PREFIX + "tool"
        h1 = {rel: hashlib.sha256(b"whatever").hexdigest()}
        assert _find_stale_files(h1, str(target)) == {rel}


class TestRankCandidatesBinaryTarget:
    """Ranking picks a candidate without excluding its binary-row data."""

    def test_fresh_binary_candidate_has_no_stale_files(
        self, tmp_path: Path, binary_target: Path,
    ) -> None:
        d1 = tmp_path / "understand-run"
        d1.mkdir()
        (d1 / "checklist.json").write_text(json.dumps({
            "files": [{
                "path": BINARY_PATH_PREFIX + "qualys-scan-util",
                "sha256": BINARY_SHA,
            }],
        }))
        result = _rank_candidates([d1], str(binary_target))
        assert result is not None
        best_dir, stale = result
        assert best_dir == d1
        assert stale == set()
