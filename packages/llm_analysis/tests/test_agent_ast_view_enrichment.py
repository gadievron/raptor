"""Tests for the per-finding ast_view enrichment in
``packages.llm_analysis.agent`` — exercises the production helper
``_enrich_finding_with_ast_view`` directly.

The helper is private (underscore-prefixed) but importable from tests
— that's the right shape for a function with a narrow contract that
the wider package shouldn't depend on but that needs to be pinned by
behavioral tests rather than source-grep mirror tests.

The prompt-builder side is covered by ``test_prompt_ast_view``.
"""

from __future__ import annotations

from pathlib import Path

from packages.llm_analysis.agent import _enrich_finding_with_ast_view


def _project(tmp_path: Path, files: dict) -> Path:
    for rel, contents in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(contents)
    return tmp_path


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_enrich_python_function(tmp_path):
    target = _project(tmp_path, {
        "src/auth.py": (
            "def check(user, pw):\n"        # 1
            "    if user is None:\n"         # 2
            "        return -1\n"            # 3
            "    h = compute(pw)\n"          # 4
            "    return 0\n"                 # 5
        ),
    })
    finding = {
        "file_path": "src/auth.py",
        "start_line": 4,
        "metadata": {"name": "check"},
    }
    _enrich_finding_with_ast_view(finding, target)
    assert "ast_view" in finding
    av = finding["ast_view"]
    assert av["function"] == "check"
    assert av["language"] == "python"
    assert any(c["chain"] == ["compute"] for c in av["calls_made"])


# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------


def test_absolute_file_path_passes_through(tmp_path):
    target = _project(tmp_path, {"src/x.py": "def f(): return 1\n"})
    finding = {
        "file_path": str(target / "src" / "x.py"),  # absolute
        "start_line": 1,
        "metadata": {"name": "f"},
    }
    _enrich_finding_with_ast_view(finding, target)
    assert "ast_view" in finding
    assert finding["ast_view"]["function"] == "f"


def test_relative_file_path_resolved_under_repo(tmp_path):
    target = _project(tmp_path, {"src/x.py": "def f(): return 1\n"})
    finding = {
        "file_path": "src/x.py",  # relative
        "start_line": 1,
        "metadata": {"name": "f"},
    }
    _enrich_finding_with_ast_view(finding, target)
    assert "ast_view" in finding


# ---------------------------------------------------------------------------
# Function name resolution
# ---------------------------------------------------------------------------


def test_function_name_from_metadata(tmp_path):
    target = _project(tmp_path, {"src/x.py": "def alpha(): return 1\n"})
    finding = {
        "file_path": "src/x.py", "start_line": 1,
        "metadata": {"name": "alpha"},
    }
    _enrich_finding_with_ast_view(finding, target)
    assert finding["ast_view"]["function"] == "alpha"


def test_function_name_from_finding_field_when_metadata_missing(tmp_path):
    target = _project(tmp_path, {"src/x.py": "def beta(): return 1\n"})
    finding = {
        "file_path": "src/x.py", "start_line": 1,
        "function": "beta",  # no metadata
    }
    _enrich_finding_with_ast_view(finding, target)
    assert finding["ast_view"]["function"] == "beta"


def test_metadata_name_takes_precedence_over_function_field(tmp_path):
    target = _project(tmp_path, {
        "src/x.py": "def alpha(): return 1\ndef beta(): return 2\n",
    })
    finding = {
        "file_path": "src/x.py", "start_line": 1,
        "metadata": {"name": "alpha"},
        "function": "beta",  # should lose to metadata
    }
    _enrich_finding_with_ast_view(finding, target)
    assert finding["ast_view"]["function"] == "alpha"


def test_no_function_name_skips_enrichment(tmp_path):
    target = _project(tmp_path, {"src/x.py": "def f(): return 1\n"})
    finding = {
        "file_path": "src/x.py", "start_line": 1,
        # No name in metadata or finding
    }
    _enrich_finding_with_ast_view(finding, target)
    assert "ast_view" not in finding


def test_no_file_path_skips_enrichment(tmp_path):
    target = _project(tmp_path, {"src/x.py": "def f(): return 1\n"})
    finding = {
        "start_line": 1,
        "metadata": {"name": "f"},
        # No file_path
    }
    _enrich_finding_with_ast_view(finding, target)
    assert "ast_view" not in finding


# ---------------------------------------------------------------------------
# Field-name fallbacks
# ---------------------------------------------------------------------------


def test_file_field_used_when_file_path_absent(tmp_path):
    """Some scanners emit ``file`` instead of ``file_path`` — the
    helper accepts either."""
    target = _project(tmp_path, {"src/x.py": "def f(): return 1\n"})
    finding = {
        "file": "src/x.py",  # not file_path
        "start_line": 1,
        "metadata": {"name": "f"},
    }
    _enrich_finding_with_ast_view(finding, target)
    assert "ast_view" in finding


def test_startLine_field_used_when_start_line_absent(tmp_path):
    """Some scanners emit the SARIF camelCase ``startLine``."""
    target = _project(tmp_path, {"src/x.py": "def f(): return 1\n"})
    finding = {
        "file_path": "src/x.py",
        "startLine": 1,  # not start_line
        "metadata": {"name": "f"},
    }
    _enrich_finding_with_ast_view(finding, target)
    assert "ast_view" in finding


# ---------------------------------------------------------------------------
# Idempotency + overwrite policy
# ---------------------------------------------------------------------------


def test_existing_ast_view_not_overwritten(tmp_path):
    target = _project(tmp_path, {"src/x.py": "def f(): return 1\n"})
    pre_existing = {"function": "preset", "schema_version": 1}
    finding = {
        "file_path": "src/x.py", "start_line": 1,
        "metadata": {"name": "f"},
        "ast_view": pre_existing,
    }
    _enrich_finding_with_ast_view(finding, target)
    # Pre-existing value preserved verbatim (object identity).
    assert finding["ast_view"] is pre_existing
    assert finding["ast_view"]["function"] == "preset"


def test_idempotent_re_run(tmp_path):
    target = _project(tmp_path, {"src/x.py": "def f(): return 1\n"})
    finding = {
        "file_path": "src/x.py", "start_line": 1,
        "metadata": {"name": "f"},
    }
    _enrich_finding_with_ast_view(finding, target)
    first = finding["ast_view"]
    _enrich_finding_with_ast_view(finding, target)
    # Second call sees existing ast_view and is a no-op → object
    # identity preserved.
    assert finding["ast_view"] is first


# ---------------------------------------------------------------------------
# Graceful degradation
# ---------------------------------------------------------------------------


def test_function_not_found_skips_enrichment(tmp_path):
    target = _project(tmp_path, {"src/x.py": "def f(): return 1\n"})
    finding = {
        "file_path": "src/x.py", "start_line": 1,
        "metadata": {"name": "nonexistent"},
    }
    _enrich_finding_with_ast_view(finding, target)
    assert "ast_view" not in finding


def test_missing_file_skips_enrichment(tmp_path):
    target = _project(tmp_path, {})
    finding = {
        "file_path": "src/nope.py", "start_line": 1,
        "metadata": {"name": "f"},
    }
    _enrich_finding_with_ast_view(finding, target)
    assert "ast_view" not in finding


def test_unsupported_language_skips(tmp_path):
    target = _project(tmp_path, {"src/x.unknownext": "stuff"})
    finding = {
        "file_path": "src/x.unknownext", "start_line": 1,
        "metadata": {"name": "f"},
    }
    _enrich_finding_with_ast_view(finding, target)
    assert "ast_view" not in finding


def test_unreadable_file_does_not_raise(tmp_path):
    """A file the OS refuses to read (e.g. permission-denied,
    EISDIR) should leave the finding alone, not raise."""
    target = _project(tmp_path, {})
    # Give a path that exists as a directory — OSError on read.
    (target / "src").mkdir(exist_ok=True)
    finding = {
        "file_path": "src",  # is a directory, not a file
        "start_line": 1,
        "metadata": {"name": "f"},
    }
    _enrich_finding_with_ast_view(finding, target)
    assert "ast_view" not in finding
