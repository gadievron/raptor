"""Target-source reads are capped across the core/audit read paths.

The audit prep and sweep helpers read files from the SCANNED TREE — a
hostile trust class. Every read path here either refuses oversized
files up front (stat gate / capped read + refuse-on-truncate) or
reads through ``core.source.read_text_capped``, so a planted
multi-hundred-MB file can no longer drive peak memory to the file's
full size (and an unbounded per-run cache no longer accumulates the
whole tree). Refusals degrade exactly like the pre-existing
unreadable-file paths — no new verdict surface.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.audit.diagnostics import read_function_source
from core.audit.dispatch_completeness import _get_source
from core.audit.edge_review import _read_span
from core.audit.fix_history import _read_target_text
from core.audit.gaps import compute_gaps
from core.source import DEFAULT_MAX_SOURCE_CHARS


@pytest.fixture(scope="module")
def big_target(tmp_path_factory) -> Path:
    """A target tree with one file just over the default read cap
    and one small file. Module-scoped: the oversized write is paid
    once."""
    target = tmp_path_factory.mktemp("big-target")
    line = "int filler_%08d;\n"
    n = (DEFAULT_MAX_SOURCE_CHARS // len(line % 0)) + 64
    with (target / "big.c").open("w") as f:
        for i in range(n):
            f.write(line % i)
    (target / "small.c").write_text(
        "int check_pw(const char *pw) {\n"
        "    if (!pw)\n"
        "        return -1;\n"
        "    return 0;\n"
        "}\n"
    )
    return target


class TestDiagnosticsReadFunctionSource:
    def test_oversized_file_refused_without_full_read(
            self, tmp_path, monkeypatch):
        target = tmp_path
        (target / "huge.c").write_text("x" * 600_001)
        # The migration moved the read off Path.read_text (which
        # buffered the whole file before the size check) onto the
        # capped reader — a whole-file read here is a regression.
        def _no_full_read(self, *a, **k):
            raise AssertionError(
                "read_function_source must not whole-file read")
        monkeypatch.setattr(Path, "read_text", _no_full_read)
        assert read_function_source(target, "huge.c", "f", 1, 3) == ""

    def test_small_file_span_unchanged(self, tmp_path):
        (tmp_path / "a.c").write_text("l1\nl2\nl3\nl4\n")
        assert read_function_source(tmp_path, "a.c", "f", 2, 3) == "l2\nl3"
        assert read_function_source(
            tmp_path, "a.c", "f") == "l1\nl2\nl3\nl4\n"


class TestGapsFunctionSourceGate:
    def test_oversized_file_never_hydrated(self, tmp_path, monkeypatch):
        import core.audit.gaps as gaps_mod
        monkeypatch.setattr(gaps_mod, "_MAX_HYDRATED_FILE_BYTES", 16)
        target = tmp_path / "t"
        target.mkdir()
        (target / "a.c").write_text(
            "int f(void) { return 0; }\n" * 4)  # > 16 bytes
        checklist = {
            "target_path": str(target),
            "files": [{
                "path": "a.c",
                "language": "c",
                "items": [{
                    "name": "f", "kind": "function",
                    "line_start": 1, "line_end": 4,
                }],
            }],
        }
        hydrated: list[str] = []
        real = Path.read_text
        def spy(self, *a, **k):
            hydrated.append(self.name)
            return real(self, *a, **k)
        monkeypatch.setattr(Path, "read_text", spy)
        gaps = compute_gaps(checklist, [])
        # The gap itself survives (parser-shape degrades to
        # signature-only) but the oversized source is never read.
        assert any(g["name"] == "f" for g in gaps)
        assert "a.c" not in hydrated

    def test_in_cap_file_still_classified(self, tmp_path):
        target = tmp_path / "t"
        target.mkdir()
        (target / "a.c").write_text("int f(void) { return 0; }\n")
        checklist = {
            "target_path": str(target),
            "files": [{
                "path": "a.c",
                "language": "c",
                "items": [{
                    "name": "f", "kind": "function",
                    "line_start": 1, "line_end": 1,
                }],
            }],
        }
        gaps = compute_gaps(checklist, [])
        assert any(g["name"] == "f" for g in gaps)


class TestEdgeReviewReadSpan:
    def test_span_past_cap_refused(self, big_target):
        n_lines = sum(1 for _ in (big_target / "big.c").open())
        got = _read_span(big_target, "big.c", (n_lines - 2, n_lines))
        assert got == "(source not available)"

    def test_span_within_prefix_served(self, big_target):
        got = _read_span(big_target, "big.c", (1, 2))
        assert "filler_00000000" in got

    def test_small_file_span_unchanged(self, big_target):
        got = _read_span(big_target, "small.c", (1, 2))
        assert got == "int check_pw(const char *pw) {\n    if (!pw)"


class TestDispatchCompletenessGetSource:
    def test_oversized_file_refused(self, big_target):
        assert _get_source("big.c", None, big_target) is None

    def test_small_file_served(self, big_target):
        got = _get_source("small.c", None, big_target)
        assert got is not None and "check_pw" in got


class TestFixHistoryReadTargetText:
    def test_oversized_file_raises_into_degrade_path(self, big_target):
        with pytest.raises(OSError):
            _read_target_text(big_target / "big.c")

    def test_small_file_served(self, big_target):
        assert "check_pw" in _read_target_text(big_target / "small.c")


class TestExpandedCorpusCandidateGate:
    def test_oversized_candidate_skipped(self, tmp_path, big_target):
        from core.audit.expanded_semgrep import build_expanded_corpus
        target = tmp_path / "t"
        target.mkdir()
        # A macro invocation early in an oversized TU: without the
        # cap this file is a corpus candidate.
        with (target / "big.c").open("w") as f:
            f.write("#define G(x) guard(x)\nint f(void){ G(1); }\n")
            f.write((big_target / "big.c").read_text())
        corpus = build_expanded_corpus(
            target, tmp_path / "scratch", max_tus=4,
        )
        assert corpus.candidates_total == 0


class TestEdgeReviewNoNewlineBoundary:
    def test_mid_line_cut_final_prefix_line_refused(self, tmp_path):
        # A single-line file past the cap keeps a RAW mid-line-cut
        # prefix (there is no newline to trim back to) — quoting it
        # as the span would misrepresent the source.
        big = tmp_path / "one-line.c"
        with big.open("w") as f:
            f.write("int a_")
            f.write("x" * DEFAULT_MAX_SOURCE_CHARS)
            f.write(";")
        got = _read_span(tmp_path, "one-line.c", (1, 1))
        assert got == "(source not available)"
