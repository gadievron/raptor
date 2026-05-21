"""Tests for the Conan parsers — conanfile.txt / conanfile.py /
conan.lock."""

from __future__ import annotations

import json

from packages.sca.models import PinStyle
from packages.sca.parsers.conan import parse_lock, parse_py, parse_txt


# ---------------------------------------------------------------------------
# conanfile.txt
# ---------------------------------------------------------------------------


def test_txt_simple_requires(tmp_path):
    p = tmp_path / "conanfile.txt"
    p.write_text(
        "[requires]\n"
        "boost/1.83.0\n"
        "fmt/9.1.0\n"
    )
    deps = parse_txt(p)
    by_name = {d.name: d for d in deps}
    assert by_name["boost"].version == "1.83.0"
    assert by_name["fmt"].version == "9.1.0"
    assert all(d.ecosystem == "ConanCenter" for d in deps)
    assert all(d.scope == "main" for d in deps)
    assert all(d.pin_style == PinStyle.EXACT for d in deps)


def test_txt_user_channel_qualifier(tmp_path):
    p = tmp_path / "conanfile.txt"
    p.write_text(
        "[requires]\n"
        "myproj/1.0.0@myorg/stable\n"
    )
    [d] = parse_txt(p)
    # user/channel qualifier dropped from name; version preserved.
    assert d.name == "myproj"
    assert d.version == "1.0.0"


def test_txt_revision_qualifier(tmp_path):
    """``name/version#revision`` — revision is metadata, not version."""
    p = tmp_path / "conanfile.txt"
    p.write_text(
        "[requires]\n"
        "fmt/9.1.0#abcd1234\n"
    )
    [d] = parse_txt(p)
    assert d.name == "fmt"
    assert d.version == "9.1.0"


def test_txt_scope_buckets(tmp_path):
    p = tmp_path / "conanfile.txt"
    p.write_text(
        "[requires]\n"
        "boost/1.83.0\n"
        "[tool_requires]\n"
        "cmake/3.27.0\n"
        "[test_requires]\n"
        "gtest/1.14.0\n"
    )
    deps = parse_txt(p)
    by_name = {d.name: d.scope for d in deps}
    assert by_name == {
        "boost": "main",
        "cmake": "build",
        "gtest": "test",
    }


def test_txt_build_requires_alias_for_tool_requires(tmp_path):
    """Conan 1's ``[build_requires]`` is the same scope as Conan 2's
    ``[tool_requires]``."""
    p = tmp_path / "conanfile.txt"
    p.write_text(
        "[build_requires]\n"
        "cmake/3.27.0\n"
    )
    [d] = parse_txt(p)
    assert d.scope == "build"


def test_txt_comments_and_blank_lines_ignored(tmp_path):
    p = tmp_path / "conanfile.txt"
    p.write_text(
        "# Project deps\n"
        "[requires]\n"
        "\n"
        "boost/1.83.0\n"
        "# fmt/9.1.0\n"   # commented — skipped
    )
    deps = parse_txt(p)
    assert {d.name for d in deps} == {"boost"}


def test_txt_options_section_not_treated_as_requires(tmp_path):
    """Lines under ``[options]`` are not deps — must not be parsed
    as refs."""
    p = tmp_path / "conanfile.txt"
    p.write_text(
        "[requires]\n"
        "boost/1.83.0\n"
        "[options]\n"
        "boost:shared=True\n"
    )
    deps = parse_txt(p)
    assert len(deps) == 1


def test_txt_version_range_recognised(tmp_path):
    p = tmp_path / "conanfile.txt"
    p.write_text(
        "[requires]\n"
        "fmt/[>=9.0 <10]\n"
    )
    [d] = parse_txt(p)
    assert d.pin_style == PinStyle.RANGE


# ---------------------------------------------------------------------------
# conanfile.py
# ---------------------------------------------------------------------------


def test_py_string_attribute(tmp_path):
    p = tmp_path / "conanfile.py"
    p.write_text(
        "from conan import ConanFile\n"
        "class MyProj(ConanFile):\n"
        "    requires = 'boost/1.83.0'\n"
    )
    [d] = parse_py(p)
    assert d.name == "boost"
    assert d.version == "1.83.0"


def test_py_tuple_attribute(tmp_path):
    p = tmp_path / "conanfile.py"
    p.write_text(
        "class MyProj(object):\n"
        "    requires = ('boost/1.83.0', 'fmt/9.1.0')\n"
    )
    deps = parse_py(p)
    assert {d.name for d in deps} == {"boost", "fmt"}


def test_py_list_attribute(tmp_path):
    p = tmp_path / "conanfile.py"
    p.write_text(
        "class MyProj(object):\n"
        "    requires = ['boost/1.83.0']\n"
        "    build_requires = ['cmake/3.27.0']\n"
    )
    deps = parse_py(p)
    by_name = {d.name: d.scope for d in deps}
    assert by_name == {"boost": "main", "cmake": "build"}


def test_py_dynamic_method_skipped(tmp_path):
    """``def requirements(self): self.requires(...)`` — Turing-complete,
    out of scope. Must not blow up; just emit nothing for this
    conanfile."""
    p = tmp_path / "conanfile.py"
    p.write_text(
        "class MyProj(object):\n"
        "    def requirements(self):\n"
        "        self.requires('boost/1.83.0')\n"
    )
    assert parse_py(p) == []


def test_py_syntax_error(tmp_path):
    p = tmp_path / "conanfile.py"
    p.write_text("class :")
    assert parse_py(p) == []


# ---------------------------------------------------------------------------
# conan.lock — Conan 2 JSON lockfile
# ---------------------------------------------------------------------------


def test_lock_basic(tmp_path):
    p = tmp_path / "conan.lock"
    p.write_text(json.dumps({
        "version": "0.5",
        "requires": [
            "boost/1.83.0#abcd1234",
            "fmt/9.1.0#1234abcd",
        ],
        "build_requires": [
            "cmake/3.27.0#5678",
        ],
    }))
    deps = parse_lock(p)
    by_name = {d.name: d for d in deps}
    assert by_name["boost"].version == "1.83.0"
    assert by_name["boost"].is_lockfile is True
    assert by_name["boost"].direct is False
    assert by_name["cmake"].scope == "build"


def test_lock_malformed_json(tmp_path):
    p = tmp_path / "conan.lock"
    p.write_text("not json")
    assert parse_lock(p) == []


def test_lock_missing_blocks(tmp_path):
    p = tmp_path / "conan.lock"
    p.write_text(json.dumps({"version": "0.5"}))
    assert parse_lock(p) == []


def test_lock_python_requires(tmp_path):
    p = tmp_path / "conan.lock"
    p.write_text(json.dumps({
        "python_requires": ["my-helper/1.0.0#abc"],
    }))
    [d] = parse_lock(p)
    assert d.name == "my-helper"
    assert d.scope == "build"
