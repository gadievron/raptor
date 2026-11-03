"""Case-variant source paths are distinct annotation identities.

Case-sensitive stores can represent both files. Case-insensitive
stores must refuse the colliding write and preserve the original notes.
"""

from __future__ import annotations

import pytest

from core.annotations.models import Annotation
from core.annotations.storage import (
    AnnotationFileError,
    annotation_path,
    read_annotation,
    write_annotation,
)

pytestmark = pytest.mark.wsl


def test_case_variant_paths_are_distinct_identities(tmp_path):
    base = tmp_path / "annotations"
    upper = annotation_path(base, "src/Foo.c")
    lower = annotation_path(base, "src/foo.c")
    assert upper != lower

    write_annotation(base, Annotation(
        file="src/Foo.c", function="parse",
        body="upper-case spelling", metadata={"status": "clean"},
    ))
    if lower.exists():
        with pytest.raises(AnnotationFileError, match="case-colliding"):
            write_annotation(base, Annotation(
                file="src/foo.c", function="parse", body="lower-case spelling"))
        assert read_annotation(base, "src/foo.c", "parse") is None
        assert read_annotation(base, "src/Foo.c", "parse").body == "upper-case spelling"
        return
    write_annotation(base, Annotation(
        file="src/foo.c", function="parse",
        body="lower-case spelling", metadata={"status": "suspicious"},
    ))

    got_upper = read_annotation(base, "src/Foo.c", "parse")
    got_lower = read_annotation(base, "src/foo.c", "parse")
    assert got_upper is not None and got_lower is not None
    assert got_upper.body == "upper-case spelling"
    assert got_lower.body == "lower-case spelling"
    assert got_upper.metadata["status"] == "clean"
    assert got_lower.metadata["status"] == "suspicious"


def test_case_variant_functions_within_one_file_are_distinct(tmp_path):
    base = tmp_path / "annotations"
    write_annotation(base, Annotation(
        file="src/x.c", function="Init", body="A"))
    write_annotation(base, Annotation(
        file="src/x.c", function="init", body="B"))
    upper = read_annotation(base, "src/x.c", "Init")
    lower = read_annotation(base, "src/x.c", "init")
    assert upper is not None and upper.body == "A"
    assert lower is not None and lower.body == "B"


def test_case_colliding_heading_refuses_rewrite_without_losing_notes(tmp_path):
    """Reproduce a case-insensitive lookup even on a Linux test host."""
    base = tmp_path / "annotations"
    write_annotation(base, Annotation(file="src/Foo.c", function="parse", body="operator notes"))
    original = annotation_path(base, "src/Foo.c")
    colliding = annotation_path(base, "src/foo.c")
    text = original.read_text()
    # On a case-insensitive store these already refer to the same file.
    colliding.write_text(text)
    with pytest.raises(AnnotationFileError, match="case-colliding"):
        write_annotation(base, Annotation(file="src/foo.c", function="parse", body="replacement"))
    assert colliding.read_text() == text
    assert read_annotation(base, "src/foo.c", "parse") is None
