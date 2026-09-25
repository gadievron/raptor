"""Case-variant source paths are distinct annotation identities.

Pins CURRENT behavior: the annotation store keys on the source path
exactly as supplied, so ``src/Foo.c`` and ``src/foo.c`` are two
independent identities with two on-disk .md files. That is correct
on case-sensitive filesystems (two such files can genuinely coexist)
and is the accepted duplicate-identity shape on case-insensitive
stores (WSL drvfs mounts, macOS default APFS), where one real file
reachable under two case spellings yields two entries — noise in the
safe direction (nothing merges, nothing suppresses). A future change
that casefolds identities must decide per-store, not globally; this
fixture makes that a deliberate decision rather than a drift.
"""

from __future__ import annotations

import pytest

from core.annotations.models import Annotation
from core.annotations.storage import (
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
