"""Tests for the shared reachability-chokepoint helper.

The chokepoint helper is the single source of truth for "should this
finding be suppressed?" — both /agentic and /codeql consult it. The
adversarial review (P0-C-1, P0-C-2) flagged silent-drop risks from
copy-paste-reductionism in the prior /agentic implementation:
absolute paths, file:// URIs, and language-incorrect module strings.
"""

from __future__ import annotations

from pathlib import Path

from core.inventory.reach_chokepoint import (
    check_suppress,
    normalise_path,
    path_to_module,
)


# ---------------------------------------------------------------------------
# normalise_path
# ---------------------------------------------------------------------------

def test_normalise_path_strips_file_uri_prefix(tmp_path: Path) -> None:
    rel = normalise_path(f"file://{tmp_path}/src/util.c", tmp_path)
    assert rel == "src/util.c"


def test_normalise_path_makes_absolute_relative_to_repo(
    tmp_path: Path,
) -> None:
    rel = normalise_path(str(tmp_path / "lib" / "x.c"), tmp_path)
    assert rel == "lib/x.c"


def test_normalise_path_rejects_absolute_outside_repo(
    tmp_path: Path,
) -> None:
    """Absolute path that's not under repo_root → None. Suppression
    must NOT fire on files outside the analysed tree."""
    other = tmp_path.parent
    rel = normalise_path(str(other / "elsewhere" / "x.c"), tmp_path)
    assert rel is None


def test_normalise_path_strips_leading_dot_slash(tmp_path: Path) -> None:
    rel = normalise_path("./src/x.c", tmp_path)
    assert rel == "src/x.c"


def test_normalise_path_preserves_relative(tmp_path: Path) -> None:
    rel = normalise_path("src/util.c", tmp_path)
    assert rel == "src/util.c"


def test_normalise_path_empty_returns_none(tmp_path: Path) -> None:
    assert normalise_path("", tmp_path) is None


# ---------------------------------------------------------------------------
# path_to_module
# ---------------------------------------------------------------------------

def test_path_to_module_python() -> None:
    assert path_to_module("packages/foo/bar.py") == "packages.foo.bar"


def test_path_to_module_c() -> None:
    """Adversarial review P0-C-2: for non-Python languages, the prior
    /agentic hook passed the LITERAL path string as ``module`` because
    its derivation was python-only. The shared helper strips the
    extension uniformly across languages."""
    assert path_to_module("src/util.c") == "src.util"
    assert path_to_module("src/lib.cc") == "src.lib"
    assert path_to_module("src/lib.cpp") == "src.lib"


def test_path_to_module_rust() -> None:
    assert path_to_module("src/main.rs") == "src.main"


def test_path_to_module_no_extension_returns_none() -> None:
    """A path with no extension (Makefile, README) can't yield a
    sensible module — return None rather than fabricate one."""
    assert path_to_module("Makefile") is None
    assert path_to_module("") is None


# ---------------------------------------------------------------------------
# check_suppress — integration of override + path/module + verdict
# ---------------------------------------------------------------------------

def _checklist_with_absent_function(
    file_path: str, name: str, line: int = 1,
) -> dict:
    """Build a minimal checklist where the (file, name) function has
    a SOUND binary_oracle absent verdict (tier=full, binaries non-
    empty) — the chokepoint should suppress."""
    return {"files": [{
        "path": file_path, "language": "c",
        "items": [{
            "name": name, "kind": "function", "line_start": line,
            "metadata": {"binary_oracle": {
                "classification": "absent",
                "binaries": [{"tier": "full", "path": "/b"}],
            }},
        }],
    }]}


def test_check_suppress_fires_on_absent_full_tier(tmp_path: Path) -> None:
    checklist = _checklist_with_absent_function("src/util.c", "helper", 5)
    decision = check_suppress(
        checklist=checklist,
        file_path="src/util.c",
        function_name="helper",
        line=5,
        repo_root=tmp_path,
    )
    assert decision is not None
    verdict, reason = decision
    assert verdict == "binary_oracle_absent"
    assert "Reachability chokepoint" in reason


def test_check_suppress_respects_manual_override(tmp_path: Path) -> None:
    checklist = _checklist_with_absent_function("src/util.c", "helper", 5)
    decision = check_suppress(
        checklist=checklist,
        file_path="src/util.c",
        function_name="helper",
        line=5,
        repo_root=tmp_path,
        manual_override=True,
    )
    assert decision is None


def test_check_suppress_respects_allow_unreachable(
    tmp_path: Path,
) -> None:
    checklist = _checklist_with_absent_function("src/util.c", "helper", 5)
    decision = check_suppress(
        checklist=checklist,
        file_path="src/util.c",
        function_name="helper",
        line=5,
        repo_root=tmp_path,
        allow_unreachable=True,
    )
    assert decision is None


def test_check_suppress_handles_absolute_finding_path(
    tmp_path: Path,
) -> None:
    """Adversarial review P0-C-1: SARIF emitters often produce
    absolute paths; the chokepoint MUST normalise via the shared
    helper, not pass the absolute path verbatim to the inventory
    lookup (which would miss every time)."""
    checklist = _checklist_with_absent_function("src/util.c", "helper", 5)
    decision = check_suppress(
        checklist=checklist,
        file_path=str(tmp_path / "src" / "util.c"),  # ABSOLUTE
        function_name="helper",
        line=5,
        repo_root=tmp_path,
    )
    assert decision is not None
    assert decision[0] == "binary_oracle_absent"


def test_check_suppress_handles_file_uri_finding_path(
    tmp_path: Path,
) -> None:
    checklist = _checklist_with_absent_function("src/util.c", "helper", 5)
    decision = check_suppress(
        checklist=checklist,
        file_path=f"file://{tmp_path}/src/util.c",
        function_name="helper",
        line=5,
        repo_root=tmp_path,
    )
    assert decision is not None


def test_check_suppress_string_false_manual_override_is_not_truthy(
    tmp_path: Path,
) -> None:
    """``"false"`` (string) must be coerced to bool-False rather than
    treated as truthy (Python ``bool("false")`` is True). Otherwise an
    emitter writing ``"manual_override": "false"`` would accidentally
    bypass the chokepoint."""
    checklist = _checklist_with_absent_function("src/util.c", "helper", 5)
    decision = check_suppress(
        checklist=checklist,
        file_path="src/util.c",
        function_name="helper",
        line=5,
        repo_root=tmp_path,
        manual_override="false",
    )
    # "false" → False → suppression fires
    assert decision is not None
