"""Tests for the annotation provenance substrate.

Covers: fd-context detection (isatty monkeypatched per stream), the
stored-stamp classifier (interactive / non-tty / legacy / tampered),
the human-grade predicate, write-time enum rejection, and legacy
(pre-stamp) files staying readable.
"""

from __future__ import annotations

import sys
from pathlib import Path

pathlib_root = Path(__file__).resolve().parents[3]

import pytest

from core.annotations import (
    IMPORTED,
    INTERACTIVE_TTY,
    LEGACY,
    NON_TTY,
    STAMP_ERA_START,
    Annotation,
    annotation_file_mtime,
    classify_provenance,
    detect_invocation_context,
    is_human_grade,
    read_annotation,
    write_annotation,
)
from core.annotations.provenance import (
    CORROBORATION_ERA_START,
    CORROBORATION_KEY,
    CORROBORATION_PRE_ERA,
    ENV_MARKERS_KEY,
    PARENTS_KEY,
    SID_INHERITED,
    SID_KEY,
    SID_SELF,
    valid_env_markers_value,
    valid_parents_value,
    valid_tty_value,
)

# A coherent, non-contradicting corroboration record — the shape a
# bare-shell operator invocation stamps.
CORROBORATED = {
    SID_KEY: SID_INHERITED,
    ENV_MARKERS_KEY: "trusted",
    PARENTS_KEY: "bash,sshd",
}


def _human_interactive(**extra):
    md = {"source": "human", "provenance": INTERACTIVE_TTY,
          "tty": "stdin", **CORROBORATED}
    md.update(extra)
    return md


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
        assert ctx["tty"] == "stdin,stdout,stderr"
        assert ctx["provenance"] == INTERACTIVE_TTY

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
        assert ctx["tty"] == "none"
        assert ctx["provenance"] == NON_TTY

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

    def test_garbage_tag_with_valid_tty_still_demotes(self):
        # Partial tamper: an unrecognised ``provenance`` value beside
        # a well-formed ``tty`` key must NOT fall through to the tty
        # interpretation — a garbage tag is tamper evidence, and the
        # elevated tier is never granted on tampered stamps.
        meta = {"provenance": "garbage-tag", "tty": "stdin",
                "source": "human"}
        assert classify_provenance(meta) == NON_TTY
        assert not is_human_grade(meta)
        # tty=none variant: still non-tty, still not human grade.
        meta_none = {"provenance": "garbage-tag", "tty": "none",
                     "source": "human"}
        assert classify_provenance(meta_none) == NON_TTY

    def test_imported_stamp_classifies_imported(self):
        assert classify_provenance({"provenance": IMPORTED}) == IMPORTED

    def test_recognised_tag_wins_over_tty_key(self):
        meta = {"provenance": NON_TTY, "tty": "stdin"}
        assert classify_provenance(meta) == NON_TTY


class TestIsHumanGrade:
    def test_human_with_corroborated_interactive_stamp(self):
        assert is_human_grade(_human_interactive())

    def test_bare_interactive_stamp_is_corroboration_era_fenced(self):
        # A stamp with NO corroboration keys predates their recording
        # (or was hand-written): it earns human grade only when the
        # annotation file's mtime predates CORROBORATION_ERA_START.
        md = {"source": "human", "provenance": INTERACTIVE_TTY,
              "tty": "stdin"}
        assert is_human_grade(
            md, note_mtime=CORROBORATION_ERA_START - 86400.0,
        )
        assert not is_human_grade(
            md, note_mtime=CORROBORATION_ERA_START + 86400.0,
        )
        assert not is_human_grade(md)  # no mtime -> fail low

    def test_legacy_human_benefit_of_doubt_is_date_fenced(self):
        # Stamp-less source=human earns human grade ONLY when the
        # caller proves the note predates the stamp era.
        pre_era = STAMP_ERA_START - 86400.0
        post_era = STAMP_ERA_START + 86400.0
        assert is_human_grade({"source": "human"}, note_mtime=pre_era)
        assert not is_human_grade({"source": "human"}, note_mtime=post_era)
        assert not is_human_grade(
            {"source": "human"}, note_mtime=STAMP_ERA_START,
        )

    def test_legacy_without_mtime_demotes(self):
        # No mtime → the fence cannot be established → fail toward
        # the lower tier. This is the bypass-by-omission closure:
        # a bare '<!-- meta: source=human -->' written directly to
        # disk no longer inherits operator authority.
        assert not is_human_grade({"source": "human"})

    def test_imported_never_human_grade(self):
        # Zip-restored notes carry provenance=imported; the archive
        # severed any provenance, so no tier upgrade — even with a
        # pre-era mtime (archives can carry any mtime story).
        meta = {"source": "human", "provenance": IMPORTED}
        assert not is_human_grade(meta)
        assert not is_human_grade(
            meta, note_mtime=STAMP_ERA_START - 86400.0,
        )

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


class TestDetectCorroborationFacts:
    def test_detect_records_all_corroboration_keys(self):
        ctx = detect_invocation_context()
        assert ctx[SID_KEY] in ("self", "inherited", "unknown")
        assert valid_env_markers_value(ctx[ENV_MARKERS_KEY])
        assert valid_parents_value(ctx[PARENTS_KEY])

    def test_claudecode_env_marker_recorded(self, monkeypatch):
        monkeypatch.setenv("CLAUDECODE", "1")
        ctx = detect_invocation_context()
        assert "claudecode" in ctx[ENV_MARKERS_KEY].split(",")

    def test_no_markers_records_none(self, monkeypatch):
        for var in ("CLAUDECODE", "_RAPTOR_TRUSTED", "SSH_TTY",
                    "SSH_CONNECTION"):
            monkeypatch.delenv(var, raising=False)
        assert detect_invocation_context()[ENV_MARKERS_KEY] == "none"

    def test_pytest_child_is_not_session_leader(self):
        # The suite process runs inside its launcher's session, so
        # the recorded shape is the legitimate one.
        assert detect_invocation_context()[SID_KEY] == "inherited"

    def test_session_leader_shape_detected(self):
        # A setsid'd child that IS its own session leader (the
        # ``script -qec`` exec shape) records sid=self.
        import os
        import subprocess
        import sys as _sys
        code = (
            "import sys; sys.path.insert(0, %r); "
            "from core.annotations.provenance import _detect_sid; "
            "print(_detect_sid())" % str(pathlib_root)
        )
        out = subprocess.run(
            [_sys.executable, "-c", code],
            preexec_fn=os.setsid, capture_output=True, text=True,
            check=True,
        )
        assert out.stdout.strip() == "self"


class TestValidCorroborationValues:
    def test_envm_values(self):
        for v in ("none", "claudecode", "trusted", "ssh",
                  "claudecode,trusted", "claudecode,trusted,ssh"):
            assert valid_env_markers_value(v), v
        for v in ("", "CLAUDECODE", "trusted,trusted", "agent",
                  "trusted "):
            assert not valid_env_markers_value(v), v

    def test_parents_values(self):
        for v in ("bash", "bash,sshd,systemd", "unknown", "a-b_c.d"):
            assert valid_parents_value(v), v
        for v in ("", "bash sshd", "x" * 200, "bash\n"):
            assert not valid_parents_value(v), v


class TestCorroborationGrading:
    """The pty-laundering closure: an interactive-tty stamp earns
    human grade only when the recorded corroboration supports it."""

    def test_session_leader_shape_demotes(self):
        # ``script -qec 'raptor-annotate add ...'`` execs the CLI as
        # the new session's leader; a shell-launched command never is.
        assert not is_human_grade(_human_interactive(sid=SID_SELF))

    def test_unknown_sid_fails_low(self):
        assert not is_human_grade(_human_interactive(sid="unknown"))

    def test_agent_session_env_marker_demotes(self):
        assert not is_human_grade(
            _human_interactive(envm="claudecode,trusted"),
        )
        assert not is_human_grade(_human_interactive(envm="claudecode"))

    def test_script_wrapper_in_parent_chain_demotes(self):
        assert not is_human_grade(
            _human_interactive(parents="script,bash"),
        )
        assert not is_human_grade(
            _human_interactive(parents="sh,script,bash,node"),
        )

    def test_partial_corroboration_fails_low(self):
        # The CLI records all three facts together; a partial set is
        # tamper evidence or a broken producer.
        md = {"source": "human", "provenance": INTERACTIVE_TTY,
              "tty": "stdin", SID_KEY: SID_INHERITED}
        assert not is_human_grade(md)
        md[ENV_MARKERS_KEY] = "trusted"
        assert not is_human_grade(md)
        md[PARENTS_KEY] = "bash"
        assert is_human_grade(md)

    def test_garbage_corroboration_fails_low(self):
        assert not is_human_grade(_human_interactive(sid="leader"))
        assert not is_human_grade(_human_interactive(envm="garbage"))
        assert not is_human_grade(
            _human_interactive(parents="bash sshd"),
        )

    def test_unknown_parents_passes(self):
        # /proc-less platforms record parents=unknown; the parent
        # chain is audit-trail first, so unknown does not demote.
        assert is_human_grade(_human_interactive(parents="unknown"))

    def test_pre_era_marker_grants_without_facts(self):
        md = {"source": "human", "provenance": INTERACTIVE_TTY,
              "tty": "stdin", CORROBORATION_KEY: CORROBORATION_PRE_ERA}
        assert is_human_grade(md)

    def test_garbage_marker_fails_low(self):
        md = {"source": "human", "provenance": INTERACTIVE_TTY,
              "tty": "stdin", CORROBORATION_KEY: "verified"}
        assert not is_human_grade(md)

    def test_recorded_facts_win_over_stale_marker(self):
        # An edit refreshes the facts; a stale pre-era marker beside
        # demoting fresh facts must not resurrect the grade.
        assert not is_human_grade(_human_interactive(
            sid=SID_SELF, corroboration=CORROBORATION_PRE_ERA,
        ))

    def test_ssh_marker_is_recorded_not_demoting(self):
        assert is_human_grade(_human_interactive(envm="trusted,ssh"))


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
            **CORROBORATED,
        }
        assert self._ann(tmp_path, meta) is not None
        ann = read_annotation(tmp_path, "src/a.py", "f")
        assert ann.metadata["provenance"] == INTERACTIVE_TTY
        assert ann.metadata["tty"] == "stdout,stderr"
        assert ann.metadata[SID_KEY] == SID_INHERITED
        assert is_human_grade(ann.metadata)

    def test_invalid_corroboration_values_rejected(self, tmp_path):
        base = {"source": "human", "provenance": INTERACTIVE_TTY,
                "tty": "stdin"}
        for k, v in ((SID_KEY, "leader"), (ENV_MARKERS_KEY, "agent"),
                     (PARENTS_KEY, "bash sshd"),
                     (CORROBORATION_KEY, "verified")):
            with pytest.raises(ValueError):
                self._ann(tmp_path, {**base, k: v})

    def test_valid_corroboration_values_accepted(self, tmp_path):
        meta = {"source": "human", "provenance": INTERACTIVE_TTY,
                "tty": "stdin", **CORROBORATED,
                CORROBORATION_KEY: CORROBORATION_PRE_ERA}
        assert self._ann(tmp_path, meta) is not None


class TestLegacyFilesStayReadable:
    def test_pre_stamp_file_parses_and_grades_legacy(self, tmp_path):
        # Hand-written legacy layout: version marker, no provenance
        # keys — exactly what pre-stamp CLI writes produced. The
        # date fence keys on the file's mtime: backdate it to the
        # pre-stamp era, the way a genuinely old file presents.
        import os

        d = tmp_path / "src"
        d.mkdir()
        md = d / "a.py.md"
        md.write_text(
            "<!-- annotations-version: 1 -->\n"
            "# src/a.py\n\n"
            "## f\n"
            "<!-- meta: status=clean source=human -->\n\n"
            "Reviewed by hand long ago.\n",
            encoding="utf-8",
        )
        pre_era = STAMP_ERA_START - 86400.0
        os.utime(md, (pre_era, pre_era))
        ann = read_annotation(tmp_path, "src/a.py", "f")
        assert ann is not None
        assert classify_provenance(ann.metadata) == LEGACY
        mtime = annotation_file_mtime(tmp_path, "src/a.py")
        assert mtime is not None
        assert is_human_grade(ann.metadata, note_mtime=mtime)

    def test_fresh_stamp_less_file_demotes(self, tmp_path):
        # The same bytes written TODAY (post-stamp-era mtime) do not
        # earn human grade — the bypass-by-omission laundering shape.
        d = tmp_path / "src"
        d.mkdir()
        (d / "a.py.md").write_text(
            "# src/a.py\n\n"
            "## f\n"
            "<!-- meta: status=clean source=human -->\n",
            encoding="utf-8",
        )
        ann = read_annotation(tmp_path, "src/a.py", "f")
        assert ann is not None
        assert classify_provenance(ann.metadata) == LEGACY
        mtime = annotation_file_mtime(tmp_path, "src/a.py")
        assert not is_human_grade(ann.metadata, note_mtime=mtime)

    def test_missing_file_mtime_is_none(self, tmp_path):
        assert annotation_file_mtime(tmp_path, "src/nope.py") is None

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
