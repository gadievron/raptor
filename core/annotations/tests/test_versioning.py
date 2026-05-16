"""Tests for annotation file format versioning.

Pin the marker shape, the legacy-no-marker behaviour, and the
forward-compat warning path. These guards catch regressions if
``CURRENT_VERSION`` is bumped or the marker pattern is changed
without updating the reader.
"""

from __future__ import annotations

import logging


from core.annotations import (
    Annotation,
    annotation_path,
    read_file_annotations,
    write_annotation,
)
from core.annotations.storage import CURRENT_VERSION


class TestVersionMarker:
    def test_writes_emit_current_version_marker(self, tmp_path):
        write_annotation(tmp_path, Annotation(
            file="src/foo.py", function="login", body="x",
        ))
        text = annotation_path(tmp_path, "src/foo.py").read_text()
        assert text.startswith(
            f"<!-- annotations-version: {CURRENT_VERSION} -->"
        )

    def test_marker_is_first_line(self, tmp_path):
        write_annotation(tmp_path, Annotation(
            file="src/foo.py", function="f", body="x",
        ))
        first_line = annotation_path(
            tmp_path, "src/foo.py",
        ).read_text().splitlines()[0]
        assert "annotations-version" in first_line


class TestLegacyFilesAreReadable:
    """Files written before the marker existed must still parse."""

    def test_legacy_v1_format_no_marker(self, tmp_path):
        path = tmp_path / "src" / "foo.py.md"
        path.parent.mkdir(parents=True)
        path.write_text(
            "# src/foo.py\n\n"
            "## login\n"
            "<!-- meta: status=clean -->\n\n"
            "Reviewed clean\n"
        )
        anns = read_file_annotations(tmp_path, "src/foo.py")
        assert len(anns) == 1
        assert anns[0].function == "login"
        assert anns[0].metadata["status"] == "clean"

    def test_legacy_round_trip_via_write(self, tmp_path):
        """Read a legacy file, write a new annotation, file gets
        upgraded to current format with marker."""
        path = tmp_path / "src" / "foo.py.md"
        path.parent.mkdir(parents=True)
        path.write_text(
            "# src/foo.py\n\n"
            "## old_func\n"
            "<!-- meta: status=clean -->\n\n"
            "legacy entry\n"
        )
        # Add a new annotation — siblings preserved, marker added.
        write_annotation(tmp_path, Annotation(
            file="src/foo.py", function="new_func", body="new",
            metadata={"status": "clean"},
        ))
        text = path.read_text()
        # Marker now present.
        assert "annotations-version: 1" in text
        # Legacy entry preserved.
        assert "legacy entry" in text


class TestForwardCompatWarning:
    """A future-version file should warn but still attempt to parse."""

    def test_future_version_warns(self, tmp_path, caplog):
        path = tmp_path / "src" / "foo.py.md"
        path.parent.mkdir(parents=True)
        path.write_text(
            "<!-- annotations-version: 999 -->\n"
            "# src/foo.py\n\n"
            "## f\n"
            "<!-- meta: status=clean -->\n\n"
            "future-format prose\n"
        )
        with caplog.at_level(logging.WARNING, logger="core.annotations.storage"):
            anns = read_file_annotations(tmp_path, "src/foo.py")
        assert any("declares version 999" in r.message for r in caplog.records)
        # Best-effort parse: our v1 parser found the section anyway.
        assert len(anns) == 1
        assert anns[0].function == "f"

    def test_current_version_no_warning(self, tmp_path, caplog):
        write_annotation(tmp_path, Annotation(
            file="src/foo.py", function="f", body="x",
        ))
        with caplog.at_level(logging.WARNING, logger="core.annotations.storage"):
            read_file_annotations(tmp_path, "src/foo.py")
        # No warnings about version drift.
        assert not any(
            "declares version" in r.message for r in caplog.records
        )

    def test_malformed_version_string_falls_back(self, tmp_path):
        """Non-numeric version → silently treated as current."""
        path = tmp_path / "src" / "foo.py.md"
        path.parent.mkdir(parents=True)
        path.write_text(
            "<!-- annotations-version: notanumber -->\n"
            "# src/foo.py\n\n"
            "## f\n"
            "<!-- meta: status=clean -->\n\n"
            "x\n"
        )
        # Marker regex requires \d+, so notanumber doesn't match —
        # treated as no-marker (legacy v1).
        anns = read_file_annotations(tmp_path, "src/foo.py")
        assert len(anns) == 1
