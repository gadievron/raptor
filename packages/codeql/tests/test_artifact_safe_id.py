"""Per-finding artifact naming — collision resistance.

Analysis / exploit / visualization artifacts are named from the
finding's safe id. The id must distinguish findings of the same rule
at the same line number in different files, or the later finding's
artifacts silently clobber the earlier one's.
"""

from __future__ import annotations

from packages.codeql.autonomous_analyzer import (
    CodeQLFinding,
    _artifact_safe_id,
)


def _finding(file_path: str, rule_id: str = "java/xss",
             start_line: int = 42) -> CodeQLFinding:
    return CodeQLFinding(
        rule_id=rule_id,
        rule_name="XSS",
        message="m",
        level="error",
        file_path=file_path,
        start_line=start_line,
        end_line=start_line,
        snippet="",
    )


def test_same_rule_same_line_different_files_distinct() -> None:
    a = _artifact_safe_id(_finding("src/a/LoginServlet.java"))
    b = _artifact_safe_id(_finding("src/b/SearchServlet.java"))
    assert a != b


def test_same_basename_different_directories_distinct() -> None:
    a = _artifact_safe_id(_finding("src/a/Servlet.java"))
    b = _artifact_safe_id(_finding("src/b/Servlet.java"))
    assert a != b


def test_id_is_stable_for_identical_finding() -> None:
    assert _artifact_safe_id(_finding("src/a/App.java")) == \
        _artifact_safe_id(_finding("src/a/App.java"))


def test_id_is_filesystem_safe() -> None:
    sid = _artifact_safe_id(
        _finding("dir with spaces/we ird$name.java", rule_id="cpp/over/flow"),
    )
    assert "/" not in sid
    assert " " not in sid
    assert "$" not in sid


def test_id_carries_rule_and_line() -> None:
    sid = _artifact_safe_id(_finding("src/App.java", start_line=7))
    assert sid.startswith("java_xss_")
    assert sid.endswith("_7")


def test_validator_compile_names_derive_from_artifact_safe_id() -> None:
    """The exploit validator's compile workspace (shared exploits/ dir,
    one <name>.cpp + binary per validation) must key on the same
    collision-safe id as the saved artifacts. A rule+line name let
    same-rule-same-line findings in different files clobber each
    other's compile source/binary. Mechanical closure over every
    validate_exploit call site in the module: a future site added with
    a hand-rolled key fails here."""
    import ast
    from pathlib import Path

    import packages.codeql.autonomous_analyzer as aa

    tree = ast.parse(Path(aa.__file__).read_text(encoding="utf-8"))
    sites = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "validate_exploit"
    ]
    assert sites, "expected validate_exploit call sites in the module"
    for node in sites:
        name_arg = ast.unparse(node.args[1])
        assert "_artifact_safe_id(finding)" in name_arg, name_arg
