"""Tests for the uv.lock parser."""

from __future__ import annotations

from pathlib import Path

from packages.sca.models import PinStyle
from packages.sca.parsers.uv_lock import parse


def _write(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "uv.lock"
    p.write_text(content)
    return p


# ---------------------------------------------------------------------------
# Basic parsing
# ---------------------------------------------------------------------------


def test_parses_pypi_packages(tmp_path):
    p = _write(tmp_path, """\
version = 1
revision = 1
requires-python = ">=3.11"

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "urllib3"
version = "2.0.7"
source = { registry = "https://pypi.org/simple" }
""")
    deps = parse(p)
    by_name = {d.name: d for d in deps}
    assert "requests" in by_name
    assert "urllib3" in by_name
    assert by_name["requests"].version == "2.31.0"
    assert by_name["requests"].ecosystem == "PyPI"
    assert by_name["requests"].is_lockfile is True
    assert by_name["requests"].pin_style == PinStyle.EXACT
    assert by_name["requests"].purl == "pkg:pypi/requests@2.31.0"


def test_skips_virtual_project(tmp_path):
    """The project's own row uses ``source = { virtual = "." }``
    — not a registry-published dep."""
    p = _write(tmp_path, """\
version = 1

[[package]]
name = "myproject"
version = "0.1.0"
source = { virtual = "." }

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
""")
    deps = parse(p)
    by_name = {d.name: d for d in deps}
    assert "requests" in by_name
    assert "myproject" not in by_name


def test_skips_editable_source(tmp_path):
    """``source = { editable = "..." }`` — local-path editable
    install, not a registry-published dep."""
    p = _write(tmp_path, """\
version = 1

[[package]]
name = "local-thing"
version = "0.0.0"
source = { editable = "../local-thing" }

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
""")
    deps = parse(p)
    by_name = {d.name: d for d in deps}
    assert "requests" in by_name
    assert "local-thing" not in by_name


def test_skips_directory_source(tmp_path):
    """``source = { directory = "..." }`` — local path, not a
    registry-published dep."""
    p = _write(tmp_path, """\
version = 1

[[package]]
name = "local-pkg"
version = "0.0.0"
source = { directory = "./vendor/foo" }
""")
    assert parse(p) == []


def test_git_source_marked_as_git_pin(tmp_path):
    """``source = { git = "..." }`` — git-pinned dep. Version
    typically a commit SHA or tag; record it but mark
    ``pin_style=GIT``."""
    p = _write(tmp_path, """\
version = 1

[[package]]
name = "github-pkg"
version = "abc12345"
source = { git = "https://github.com/x/y.git", rev = "abc12345" }
""")
    [d] = parse(p)
    assert d.pin_style == PinStyle.GIT
    assert d.version == "abc12345"


def test_lockfile_marks_direct_false(tmp_path):
    """uv.lock contains the full resolved tree without direct/
    transitive distinction; rows are marked ``direct=False`` so
    the joined view defers to pyproject.toml when both are
    present."""
    p = _write(tmp_path, """\
version = 1

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
""")
    [d] = parse(p)
    assert d.direct is False


# ---------------------------------------------------------------------------
# Resilience
# ---------------------------------------------------------------------------


def test_malformed_toml(tmp_path):
    p = _write(tmp_path, "not toml at all = [")
    assert parse(p) == []


def test_missing_package_array(tmp_path):
    p = _write(tmp_path, "version = 1\n")
    assert parse(p) == []


def test_package_with_missing_name_skipped(tmp_path):
    p = _write(tmp_path, """\
version = 1

[[package]]
version = "1.0.0"
source = { registry = "..." }

[[package]]
name = "ok"
version = "1.0.0"
source = { registry = "..." }
""")
    deps = parse(p)
    assert {d.name for d in deps} == {"ok"}


def test_package_with_missing_version_skipped(tmp_path):
    p = _write(tmp_path, """\
version = 1

[[package]]
name = "bad"
source = { registry = "..." }

[[package]]
name = "ok"
version = "1.0.0"
source = { registry = "..." }
""")
    deps = parse(p)
    assert {d.name for d in deps} == {"ok"}


# ---------------------------------------------------------------------------
# Discovery integration
# ---------------------------------------------------------------------------


def test_discovery_finds_uv_lock(tmp_path):
    from packages.sca.discovery import find_manifests
    _write(tmp_path, """\
version = 1

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "..." }
""")
    manifests = find_manifests(tmp_path)
    found = [m for m in manifests if m.path.name == "uv.lock"]
    assert len(found) == 1
    assert found[0].ecosystem == "PyPI"
    assert found[0].is_lockfile is True
