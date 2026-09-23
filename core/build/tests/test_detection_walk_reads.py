"""Hardened reads over detection-walk results.

``detect_missing_config_headers`` and ``_is_cmake_project_root`` read
files enumerated from the SCANNED (untrusted) repo in the unsandboxed
parent process. ``_walk_files`` yields every file type, so the reads
must carry the safe-read discipline the sibling readers already use:

  * a writer-less FIFO must not block ``open`` (it previously hung the
    detection phase forever — no timeout, nothing downstream to kill);
  * a symlinked entry is refused (never a host-file read oracle);
  * refusal degrades to skip, the same answer an unreadable file got.
"""

from __future__ import annotations

import os
import threading

import pytest

from core.build.build_detector import BuildDetector

pytestmark = pytest.mark.skipif(
    not hasattr(os, "mkfifo"), reason="os.mkfifo not available",
)


def _run_bounded(fn, timeout=15):
    """Run *fn* on a daemon thread; fail loud when it blocks."""
    result: list = []
    t = threading.Thread(target=lambda: result.append(fn()), daemon=True)
    t.start()
    t.join(timeout=timeout)
    assert not t.is_alive(), "detection-walk read blocked"
    return result[0]


class TestMissingConfigHeaderScanReads:
    def test_fifo_source_does_not_block_the_scan(self, tmp_path):
        """A FIFO named ``a.c`` sorts first into the scan set; the
        read must skip it and still report the REAL file's missing
        header (both directions: no hang, no lost signal)."""
        os.mkfifo(tmp_path / "a.c")
        (tmp_path / "b.c").write_text('#include "foo_config.h"\n')
        missing = _run_bounded(
            BuildDetector(tmp_path).detect_missing_config_headers,
        )
        assert [(h, p.name) for h, p in missing] == [("foo_config.h", "b.c")]

    def test_symlinked_source_is_not_read(self, tmp_path):
        """A symlink at a ``.c`` path is refused by the hardened
        reader — the scan must not follow repo-authored links."""
        outside = tmp_path / "outside.txt"
        outside.write_text('#include "link_config.h"\n')
        (tmp_path / "repo").mkdir()
        os.symlink(outside, tmp_path / "repo" / "a.c")
        missing = BuildDetector(tmp_path / "repo").detect_missing_config_headers()
        assert missing == []

    def test_oversized_source_is_head_scanned(self, tmp_path):
        """Files past the 64 KiB head budget are truncated, not
        refused — a big real source keeps its top-of-file signal."""
        big = '#include "big_config.h"\n' + ("x" * 70_000) + "\n"
        (tmp_path / "a.c").write_text(big)
        missing = BuildDetector(tmp_path).detect_missing_config_headers()
        assert [(h, p.name) for h, p in missing] == [("big_config.h", "a.c")]


class TestCMakeProjectRootReads:
    def test_fifo_cmakelists_does_not_block(self, tmp_path):
        fifo = tmp_path / "CMakeLists.txt"
        os.mkfifo(fifo)
        got = _run_bounded(
            lambda: BuildDetector._is_cmake_project_root(fifo),
        )
        assert got is False

    def test_real_project_root_still_detected(self, tmp_path):
        cml = tmp_path / "CMakeLists.txt"
        cml.write_text("cmake_minimum_required(VERSION 3.20)\nproject(x)\n")
        assert BuildDetector._is_cmake_project_root(cml) is True

    def test_subdirectory_fragment_still_rejected(self, tmp_path):
        cml = tmp_path / "CMakeLists.txt"
        cml.write_text("add_library(sub foo.c)\n")
        assert BuildDetector._is_cmake_project_root(cml) is False


class TestHeaderCaseDiscipline:
    """One case rule end to end: _walk_files collects header names
    case-sensitively, so both the include-grep and the include-dir
    probe must match case-sensitively too — the IGNORECASE grep
    reported 'missing' for spellings the collection never tracks."""

    def test_uppercase_include_spelling_not_reported(self, tmp_path):
        (tmp_path / "a.c").write_text('#include "Foo_Config.h"\n')
        missing = BuildDetector(tmp_path).detect_missing_config_headers()
        assert missing == []

    def test_lowercase_include_still_reported(self, tmp_path):
        (tmp_path / "a.c").write_text('#include "foo_config.h"\n')
        missing = BuildDetector(tmp_path).detect_missing_config_headers()
        assert [(h, p.name) for h, p in missing] == [("foo_config.h", "a.c")]

    def test_has_c_header_matches_walkfiles_case_rule(self, tmp_path):
        upper = tmp_path / "upper"
        upper.mkdir()
        (upper / "FOO.H").write_text("")
        lower = tmp_path / "lower"
        lower.mkdir()
        (lower / "foo.h").write_text("")
        assert BuildDetector._has_c_header(upper) is False
        assert BuildDetector._has_c_header(lower) is True
