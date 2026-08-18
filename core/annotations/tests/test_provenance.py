"""Tests for the annotation provenance substrate.

Covers: fd-context detection (isatty monkeypatched per stream), the
stored-stamp classifier (interactive / non-tty / legacy / tampered),
the human-grade predicate, write-time enum rejection, and legacy
(pre-stamp) files staying readable.
"""

from __future__ import annotations

import sys

import pytest

from core.annotations import (
    INTERACTIVE_TTY,
    LEGACY,
    NON_TTY,
    Annotation,
    classify_provenance,
    detect_invocation_context,
    is_human_grade,
    read_annotation,
    write_annotation,
)
from core.annotations.provenance import valid_tty_value


class _Stream:
    def __init__(self, tty: bool):
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


class _RaisingStream:
    def isatty(self) -> bool:
        raise ValueError("I/O operation on closed file")


def _patch_streams(monkeypatch, stdin, stdout, stderr):
    monkeypatch.setattr(sys, "stdin", stdin)
    monkeypatch.setattr(sys, "stdout", stdout)
    monkeypatch.setattr(sys, "stderr", stderr)


class TestDetectInvocationContext:
    def test_all_ttys(self, monkeypatch):
        _patch_streams(
            monkeypatch, _Stream(True), _Stream(True), _Stream(True),
        )
        ctx = detect_invocation_context()
        assert ctx == {
            "tty": "stdin,stdout,stderr",
            "provenance": INTERACTIVE_TTY,
        }

    def test_stdin_redirected_still_interactive(self, monkeypatch):
        # ``raptor-annotate add ... < notes.txt`` in a terminal:
        # stdin is a file but stdout/stderr are TTYs.
        _patch_streams(
            monkeypatch, _Stream(False), _Stream(True), _Stream(True),
        )
        ctx = detect_invocation_context()
        assert ctx["tty"] == "stdout,stderr"
        assert ctx["provenance"] == INTERACTIVE_TTY

    def test_single_tty_is_interactive(self, monkeypatch):
        # ``... | tee log``: only stderr remains a TTY.
        _patch_streams(
            monkeypatch, _Stream(False), _Stream(False), _Stream(True),
        )
        ctx = detect_invocation_context()
        assert ctx["tty"] == "stderr"
        assert ctx["provenance"] == INTERACTIVE_TTY

    def test_all_piped_is_non_tty(self, monkeypatch):
        _patch_streams(
            monkeypatch, _Stream(False), _Stream(False), _Stream(False),
        )
        ctx = detect_invocation_context()
        assert ctx == {"tty": "none", "provenance": NON_TTY}

    def test_detached_stream_counts_as_non_tty(self, monkeypatch):
        _patch_streams(monkeypatch, None, _Stream(False), _Stream(False))
        assert detect_invocation_context()["provenance"] == NON_TTY

    def test_closed_stream_counts_as_non_tty(self, monkeypatch):
        _patch_streams(
            monkeypatch, _RaisingStream(), _Stream(False), _Stream(False),
        )
        assert detect_invocation_context()["provenance"] == NON_TTY


class TestValidTtyValue:
    def test_accepts_none_and_fd_subsets(self):
        for v in ("none", "stdin", "stdout,stderr", "stdin,stdout,stderr"):
            assert valid_tty_value(v), v

    def test_rejects_garbage(self):
        for v in ("", "pty", "stdin,", "stdin,stdin", "stdin stdout", "None"):
            assert not valid_tty_value(v), v


class TestClassifyProvenance:
    def test_interactive_stamp(self):
        meta = {"provenance": INTERACTIVE_TTY, "tty": "stdin"}
        assert classify_provenance(meta) == INTERACTIVE_TTY

    def test_non_tty_stamp(self):
        meta = {"provenance": NON_TTY, "tty": "none"}
        assert classify_provenance(meta) == NON_TTY

    def test_no_stamp_is_legacy(self):
        assert classify_provenance({"source": "human"}) == LEGACY
        assert classify_provenance({}) == LEGACY
        assert classify_provenance(None) == LEGACY

    def test_tty_key_alone_is_interpreted(self):
        assert classify_provenance({"tty": "stderr"}) == INTERACTIVE_TTY
        assert classify_provenance({"tty": "none"}) == NON_TTY

    def test_garbage_stamp_fails_to_lower_tier(self):
        # A tampered / malformed stamp is never granted the
        # interactive tier — and is NOT legacy either.
        assert classify_provenance({"provenance": "trusted"}) == NON_TTY
        assert classify_provenance({"tty": "definitely-a-tty"}) == NON_TTY

    def test_recognised_tag_wins_over_tty_key(self):
        meta = {"provenance": NON_TTY, "tty": "stdin"}
        assert classify_provenance(meta) == NON_TTY


class TestIsHumanGrade:
    def test_human_with_interactive_stamp(self):
        assert is_human_grade(
            {"source": "human", "provenance": INTERACTIVE_TTY, "tty": "stdin"},
        )

    def test_legacy_human_gets_benefit_of_doubt(self):
        assert is_human_grade({"source": "human"})

    def test_forged_human_non_tty_demoted(self):
        assert not is_human_grade(
            {"source": "human", "provenance": NON_TTY, "tty": "none"},
        )

    def test_agent_never_human_grade(self):
        assert not is_human_grade(
            {"source": "agent", "provenance": INTERACTIVE_TTY, "tty": "stdin"},
        )
        assert not is_human_grade({"source": "agent"})

    def test_llm_never_human_grade(self):
        assert not is_human_grade({"source": "llm"})

    def test_no_source_never_human_grade(self):
        assert not is_human_grade({})
        assert not is_human_grade(None)


class TestWriteTimeEnumRejection:
    def _ann(self, tmp_path, metadata):
        return write_annotation(
            tmp_path,
            Annotation(file="src/a.py", function="f", metadata=metadata),
        )

    def test_valid_sources_accepted(self, tmp_path):
        for source in ("human", "llm", "agent"):
            assert self._ann(tmp_path, {"source": source}) is not None

    def test_invalid_source_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="invalid annotation source"):
            self._ann(tmp_path, {"source": "humman"})

    def test_invalid_provenance_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="invalid provenance tag"):
            self._ann(tmp_path, {"source": "human", "provenance": "trusted"})

    def test_invalid_tty_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="invalid tty stamp"):
            self._ann(tmp_path, {"source": "human", "tty": "pty0"})

    def test_valid_stamp_roundtrips(self, tmp_path):
        meta = {
            "source": "human",
            "provenance": INTERACTIVE_TTY,
            "tty": "stdout,stderr",
        }
        assert self._ann(tmp_path, meta) is not None
        ann = read_annotation(tmp_path, "src/a.py", "f")
        assert ann.metadata["provenance"] == INTERACTIVE_TTY
        assert ann.metadata["tty"] == "stdout,stderr"
        assert is_human_grade(ann.metadata)


class TestLegacyFilesStayReadable:
    def test_pre_stamp_file_parses_and_grades_legacy(self, tmp_path):
        # Hand-written legacy layout: version marker, no provenance
        # keys — exactly what pre-stamp CLI writes produced.
        d = tmp_path / "src"
        d.mkdir()
        (d / "a.py.md").write_text(
            "<!-- annotations-version: 1 -->\n"
            "# src/a.py\n\n"
            "## f\n"
            "<!-- meta: status=clean source=human -->\n\n"
            "Reviewed by hand long ago.\n",
            encoding="utf-8",
        )
        ann = read_annotation(tmp_path, "src/a.py", "f")
        assert ann is not None
        assert classify_provenance(ann.metadata) == LEGACY
        assert is_human_grade(ann.metadata)

    def test_unknown_source_still_readable_not_human_grade(self, tmp_path):
        d = tmp_path / "src"
        d.mkdir()
        (d / "a.py.md").write_text(
            "# src/a.py\n\n"
            "## f\n"
            "<!-- meta: status=clean source=humman -->\n",
            encoding="utf-8",
        )
        ann = read_annotation(tmp_path, "src/a.py", "f")
        assert ann is not None  # read path stays permissive
        assert not is_human_grade(ann.metadata)
