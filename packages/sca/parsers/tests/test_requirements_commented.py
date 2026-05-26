"""Tests for ``--include-commented`` mode in the requirements parser."""

from __future__ import annotations

from pathlib import Path

import pytest

from packages.sca.parsers import requirements as req_parser
from packages.sca.parsers.requirements import parse


@pytest.fixture(autouse=True)
def _reset_toggle():
    """Default off after every test so other tests aren't poisoned."""
    yield
    req_parser.set_include_commented(False)


def _write(tmp_path: Path, body: str, name: str = "requirements.txt") -> Path:
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Default (off) — current behaviour
# ---------------------------------------------------------------------------

def test_commented_lines_skipped_by_default(tmp_path: Path) -> None:
    p = _write(tmp_path, """\
django==4.2.7
# z3-solver==4.16.0.0
# pip install foo
""")
    deps = parse(p)
    assert len(deps) == 1
    assert deps[0].name == "django"


# ---------------------------------------------------------------------------
# Toggle on
# ---------------------------------------------------------------------------

def test_commented_pinned_dep_yielded(tmp_path: Path) -> None:
    req_parser.set_include_commented(True)
    p = _write(tmp_path, """\
django==4.2.7
# z3-solver==4.16.0.0
""")
    deps = parse(p)
    by_name = {d.name: d for d in deps}
    assert "django" in by_name and "z3-solver" in by_name
    assert by_name["django"].commented_out is False
    assert by_name["z3-solver"].commented_out is True
    assert by_name["z3-solver"].version == "4.16.0.0"


def test_uncommented_lines_unaffected_when_toggle_on(tmp_path: Path) -> None:
    req_parser.set_include_commented(True)
    p = _write(tmp_path, "requests>=2.31.0\n")
    deps = parse(p)
    assert len(deps) == 1
    assert deps[0].commented_out is False


def test_unparseable_comment_silently_skipped(tmp_path: Path) -> None:
    """`# pip install openai` and free-form comments don't parse as
    PEP 508 requirements; they're dropped without error."""
    req_parser.set_include_commented(True)
    p = _write(tmp_path, """\
# pip install openai
# this is just a note
# Optional: For SMT (one-gadget feasibility, etc.)
""")
    assert parse(p) == []


def test_multiple_hashes_stripped(tmp_path: Path) -> None:
    """`### z3-solver==4.16.0` (multiple `#`) — strip them all."""
    req_parser.set_include_commented(True)
    p = _write(tmp_path, "### z3-solver==4.16.0\n")
    deps = parse(p)
    assert deps and deps[0].name == "z3-solver"
    assert deps[0].commented_out is True


def test_commented_caret_or_range_classified(tmp_path: Path) -> None:
    req_parser.set_include_commented(True)
    p = _write(tmp_path, "# requests>=2.31.0,<3.0\n")
    deps = parse(p)
    assert deps and deps[0].name == "requests"
    assert deps[0].commented_out is True


def test_set_include_commented_resets(tmp_path: Path) -> None:
    """Toggling back to False stops yielding commented deps mid-process."""
    p = _write(tmp_path, "# z3-solver==4.16.0\n")
    req_parser.set_include_commented(True)
    assert parse(p)                   # yields
    req_parser.set_include_commented(False)
    assert parse(p) == []             # silent again


def test_commented_section_header_skipped(tmp_path: Path) -> None:
    """`# Core`, `# Testing` etc. are section headers, not unpinned deps.

    Emitting them produces a flood of false-positive `unpinned_dependency`
    findings on real-world requirements.txt files.
    """
    req_parser.set_include_commented(True)
    p = _write(tmp_path, """\
# Core
django==4.2.7

# Testing
# pytest==8.1.1

# Linting
""")
    deps = parse(p)
    names = sorted(d.name for d in deps)
    # 'core', 'testing', 'linting' must NOT appear; pytest still does.
    assert names == ["django", "pytest"]


def test_commented_bare_url_skipped(tmp_path: Path) -> None:
    """`# https://ollama.ai` is documentation, not a dep — skip it.

    Without `#egg=name` the parser would synthesise a `<url:...>` placeholder
    that adds noise and may leak internal URLs into reports.
    """
    req_parser.set_include_commented(True)
    p = _write(tmp_path, """\
# https://ollama.ai
# git+https://github.com/example/repo.git
""")
    assert parse(p) == []
