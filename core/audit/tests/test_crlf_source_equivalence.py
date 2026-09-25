r"""CRLF-checkout equivalence for the audit function-source reader.

``diagnostics.read_function_source`` reads ``newline=""`` (raw-byte
line model) and rejoins through ``split_lines``, so a CRLF checkout
must hand detectors exactly the text an LF checkout hands them — on
BOTH shapes: the span slice and the whole-file fallback.  A bare
``\r`` (plantable byte) must stay inside its line on both shapes.
"""

from __future__ import annotations

from pathlib import Path

from core.audit.diagnostics import read_function_source

_C_BODY_LF = (
    "#include <stdio.h>\n"
    "\n"
    "int locked_path(int x) {\n"
    "    spin_lock(&lk);\n"
    "    if (x < 0)\n"
    "        return -1;\n"
    "    spin_unlock(&lk);\n"
    "    return 0;\n"
    "}\n"
)


def _twin_trees(tmp_path: Path) -> tuple[Path, Path]:
    lf = tmp_path / "lf"
    crlf = tmp_path / "crlf"
    for root, data in (
        (lf, _C_BODY_LF.encode()),
        (crlf, _C_BODY_LF.replace("\n", "\r\n").encode()),
    ):
        root.mkdir()
        (root / "src.c").write_bytes(data)
    return lf, crlf


def test_span_read_crlf_equivalence(tmp_path: Path) -> None:
    lf, crlf = _twin_trees(tmp_path)
    got_lf = read_function_source(lf, "src.c", "locked_path", 3, 9)
    got_crlf = read_function_source(crlf, "src.c", "locked_path", 3, 9)
    assert got_lf == got_crlf
    assert "\r" not in got_crlf
    assert got_lf.startswith("int locked_path")


def test_whole_file_read_crlf_equivalence(tmp_path: Path) -> None:
    lf, crlf = _twin_trees(tmp_path)
    got_lf = read_function_source(lf, "src.c", "locked_path")
    got_crlf = read_function_source(crlf, "src.c", "locked_path")
    assert got_lf == got_crlf
    assert "\r" not in got_crlf
    assert "spin_unlock" in got_crlf


def test_bare_cr_stays_in_line_both_shapes(tmp_path: Path) -> None:
    """The plantable-byte posture is unchanged: a bare \r is not a
    line break on either the span or the whole-file shape."""
    root = tmp_path / "t"
    root.mkdir()
    (root / "src.c").write_bytes(b"int a;\rint b;\nint c;\n")
    whole = read_function_source(root, "src.c", "x")
    span = read_function_source(root, "src.c", "x", 1, 1)
    assert whole.split("\n")[0] == "int a;\rint b;"
    assert span == "int a;\rint b;"


def test_detector_sees_identical_findings(tmp_path: Path) -> None:
    """One real detector through the chokepoint: same verdict, same
    line numbers, both checkouts."""
    from core.audit.condition_smt import check_lock_discipline

    lf, crlf = _twin_trees(tmp_path)
    results = [
        check_lock_discipline(
            read_function_source(root, "src.c", "locked_path", 3, 9),
        ).to_dict()
        for root in (lf, crlf)
    ]
    assert results[0] == results[1]
    # Non-vacuous: the fixture really trips the detector (z3-less
    # hosts still report the structural violation, so this holds
    # with or without the solver).
    assert results[0]["violation_found"] is True
