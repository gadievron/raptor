"""Tests for the requirements*.txt parser."""

from __future__ import annotations

from pathlib import Path

from packages.sca.models import PinStyle
from packages.sca.parsers.requirements import parse


def _write(tmp_path: Path, body: str, name: str = "requirements.txt") -> Path:
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p


def test_basic_pinned_dep(tmp_path: Path) -> None:
    p = _write(tmp_path, "Django==4.2.7\n")
    deps = parse(p)
    assert len(deps) == 1
    d = deps[0]
    assert d.name == "django"
    assert d.version == "4.2.7"
    assert d.pin_style is PinStyle.EXACT
    assert d.scope == "main"
    assert d.purl == "pkg:pypi/django@4.2.7"
    assert d.parser_confidence.level == "high"


def test_extras_and_markers_drop_through(tmp_path: Path) -> None:
    body = "requests[security,socks]>=2.31 ; python_version >= '3.10'\n"
    deps = parse(_write(tmp_path, body))
    assert len(deps) == 1
    assert deps[0].name == "requests"
    assert deps[0].pin_style is PinStyle.RANGE


def test_compatible_release_is_tilde(tmp_path: Path) -> None:
    deps = parse(_write(tmp_path, "flask~=2.3.0\n"))
    assert deps[0].pin_style is PinStyle.TILDE
    assert deps[0].version == "2.3.0"


def test_inclusive_lower_bound_records_operand(tmp_path: Path) -> None:
    """``>=X`` keeps X as the conservative version guess."""
    deps = parse(_write(tmp_path, "requests>=2.31\n"))
    assert deps[0].pin_style is PinStyle.RANGE
    assert deps[0].version == "2.31"


def test_exclusion_bound_records_no_version(tmp_path: Path) -> None:
    """``!=X`` excludes X — recording it as the installed version
    produced findings for the one version guaranteed NOT installed."""
    deps = parse(_write(tmp_path, "requests!=2.31.0\n"))
    assert deps[0].pin_style is PinStyle.RANGE
    assert deps[0].version is None


def test_exclusive_bounds_record_no_version(tmp_path: Path) -> None:
    for body in ("requests<2.0\n", "requests>1.0\n"):
        deps = parse(_write(tmp_path, body))
        assert deps[0].pin_style is PinStyle.RANGE
        assert deps[0].version is None, body


def test_spec_bounds_drop_unparseable_versions() -> None:
    """An unparseable bound operand is dropped, not coerced to 0 —
    coercion let a garbage operand win min(uppers) as a bogus ceiling."""
    from types import SimpleNamespace

    from packages.sca.parsers.requirements import _spec_bounds
    spec = [
        SimpleNamespace(operator="<", version="not-a-version"),
        SimpleNamespace(operator="<", version="2.0"),
        SimpleNamespace(operator=">=", version="also-bad"),
    ]
    floor, ceiling = _spec_bounds(spec)
    assert ceiling == "2.0"
    assert floor is None


def test_unpinned_is_wildcard(tmp_path: Path) -> None:
    deps = parse(_write(tmp_path, "click\n"))
    assert deps[0].pin_style is PinStyle.WILDCARD
    assert deps[0].version is None


def test_recursive_include(tmp_path: Path) -> None:
    base = _write(tmp_path, "Django==4.2.7\n", name="base.txt")
    head = tmp_path / "requirements.txt"
    head.write_text(f"-r {base.name}\nrequests==2.31.0\n", encoding="utf-8")
    names = sorted(d.name for d in parse(head))
    assert names == ["django", "requests"]


def test_recursive_include_cycle_is_safe(tmp_path: Path) -> None:
    a = tmp_path / "a.txt"
    b = tmp_path / "b.txt"
    a.write_text("-r b.txt\nfoo==1.0\n", encoding="utf-8")
    b.write_text("-r a.txt\nbar==2.0\n", encoding="utf-8")
    names = sorted(d.name for d in parse(a))
    assert names == ["bar", "foo"]


def test_pip_options_are_skipped(tmp_path: Path) -> None:
    body = """\
--index-url https://pypi.org/simple
--extra-index-url https://example.com/simple
--no-deps
--require-hashes
django==4.2.7 --hash=sha256:abcdef
"""
    deps = parse(_write(tmp_path, body))
    assert len(deps) == 1
    assert deps[0].name == "django"
    assert deps[0].version == "4.2.7"


def test_inline_comment_stripped(tmp_path: Path) -> None:
    deps = parse(_write(tmp_path, "django==4.2.7  # pinned for security\n"))
    assert deps[0].version == "4.2.7"


def test_full_line_comment_skipped(tmp_path: Path) -> None:
    body = """\
# top comment
django==4.2.7
# another
"""
    deps = parse(_write(tmp_path, body))
    assert len(deps) == 1


def test_line_continuation_joined(tmp_path: Path) -> None:
    body = "django==\\\n4.2.7\n"
    deps = parse(_write(tmp_path, body))
    assert len(deps) == 1
    assert deps[0].version == "4.2.7"


def test_editable_with_path(tmp_path: Path) -> None:
    deps = parse(_write(tmp_path, "-e ./local_pkg#egg=local_pkg\n"))
    assert len(deps) == 1
    d = deps[0]
    assert d.pin_style is PinStyle.PATH
    assert d.name == "local-pkg"


def test_url_only_with_egg_fragment(tmp_path: Path) -> None:
    body = "git+https://github.com/u/r.git@v1.2.3#egg=r==1.2.3\n"
    deps = parse(_write(tmp_path, body))
    assert len(deps) == 1
    d = deps[0]
    assert d.pin_style is PinStyle.GIT
    assert d.name == "r"
    assert d.version == "1.2.3"


def test_pep508_with_url_form_is_git(tmp_path: Path) -> None:
    body = "django @ git+https://github.com/django/django.git@4.2.7\n"
    deps = parse(_write(tmp_path, body))
    assert len(deps) == 1
    d = deps[0]
    assert d.name == "django"
    assert d.pin_style is PinStyle.GIT


def test_pep503_normalisation(tmp_path: Path) -> None:
    deps = parse(_write(tmp_path, "Foo_Bar.Baz==1.0.0\n"))
    assert deps[0].name == "foo-bar-baz"


def test_unparseable_line_is_skipped(tmp_path: Path) -> None:
    body = "valid==1.0.0\nthis is not a requirement\n"
    deps = parse(_write(tmp_path, body))
    names = [d.name for d in deps]
    assert names == ["valid"]


def test_empty_requirement_value_no_crash(tmp_path: Path) -> None:
    body = "--requirement=\ndjango==4.2.7\n"
    deps = parse(_write(tmp_path, body))
    assert [d.name for d in deps] == ["django"]
