"""Provenance gate on the annotation role source.

``_annotation_role`` grants ``grade=registry`` — promote-capable
evidence a single hit of which binds the role outright. Registry
grade demands human provenance (``core.annotations.provenance.
is_human_grade``): operator-tier authority belongs to ``source=human``
notes with an interactive-TTY stamp, exactly as the sibling annotation
consumers gate it. An agent-written note (or a ``source=human`` note
carrying the laundering-shaped ``non-tty`` stamp) still binds the
role, but at detection grade — hint tier, promote-capable only with
independent corroboration.
"""

from __future__ import annotations

from core.annotations.models import Annotation
from core.annotations.storage import write_annotation
from core.audit.fail_open_roles import (
    GRADE_DETECTION,
    GRADE_REGISTRY,
    RoleContext,
    _annotation_role,
)


def _write(ann_dir, metadata):
    ann_dir.mkdir(parents=True, exist_ok=True)
    write_annotation(ann_dir, Annotation(
        file="src/auth.c",
        function="verify_token",
        body="Checks the session token signature before use.",
        metadata=metadata,
    ))
    return ann_dir


def _resolve(ann_dir):
    return _annotation_role(
        ["verify_token"], "src/auth.c",
        RoleContext(annotations_dir=ann_dir),
    )


class TestAnnotationRoleProvenance:
    def test_human_tty_note_binds_registry_grade(self, tmp_path):
        ev = _resolve(_write(tmp_path / "ann", {
            "status": "trust_boundary", "source": "human",
            "provenance": "interactive-tty", "tty": "stdin",
             "sid": "inherited", "envm": "trusted",
             "parents": "bash",
        }))
        assert ev is not None
        assert ev.grade == GRADE_REGISTRY
        assert ev.confidence == "high"
        assert ev.kind == "trust_boundary"

    def test_agent_note_binds_detection_grade_only(self, tmp_path):
        ev = _resolve(_write(tmp_path / "ann", {
            "status": "trust_boundary", "source": "agent",
            "provenance": "non-tty", "tty": "none",
        }))
        assert ev is not None, "agent notes still bind — at hint tier"
        assert ev.grade == GRADE_DETECTION
        assert ev.confidence == "low"

    def test_human_source_with_non_tty_stamp_demotes(self, tmp_path):
        # The laundering shape: a non-interactive caller passing
        # --source human. The stamp contradicts it; readers demote.
        ev = _resolve(_write(tmp_path / "ann", {
            "status": "sink", "source": "human",
            "provenance": "non-tty", "tty": "none",
        }))
        assert ev is not None
        assert ev.grade == GRADE_DETECTION

    def test_stampless_fresh_note_demotes(self, tmp_path):
        # No stamp on a note whose file mtime is post-stamp-era:
        # the legacy grandfather clause must not apply.
        ev = _resolve(_write(tmp_path / "ann", {
            "status": "sink", "source": "human",
        }))
        assert ev is not None
        assert ev.grade == GRADE_DETECTION

    def test_no_matching_annotation_binds_nothing(self, tmp_path):
        ev = _annotation_role(
            ["unrelated_fn"], "src/auth.c",
            RoleContext(annotations_dir=_write(tmp_path / "ann", {
                "status": "sink", "source": "human",
                "provenance": "interactive-tty", "tty": "stdin",
             "sid": "inherited", "envm": "trusted",
             "parents": "bash",
            })),
        )
        assert ev is None
