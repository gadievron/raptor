"""Tests for ``packages.sca.parsers.inline_installs._managers``.

Pins the runtime row shapes yielded by the registered package-manager
arg parsers — most yield ``(name, version, pin_style)`` 3-tuples while
``_parse_pip_args`` yields 5-tuples carrying range bounds (the
``_ParsedRow`` / ``_ParsedRowWithBounds`` annotations) — and the
defensive-unpack contract the consumer relies on.
"""

from __future__ import annotations

from packages.sca.models import PinStyle
from packages.sca.parsers.inline_installs._managers import (
    _MANAGERS,
    _parse_apt_args,
    _parse_pip_args,
)


def test_pip_rows_are_5_tuples_with_bounds() -> None:
    rows = list(_parse_pip_args("'foo>=1.0,<2.0' bar==1.5"))
    assert all(len(r) == 5 for r in rows)
    by_name = {r[0]: r for r in rows}
    name, version, pin, floor, ceiling = by_name["foo"]
    assert version is None and pin is PinStyle.RANGE
    assert (floor, ceiling) == ("1.0", "2.0")
    name, version, pin, floor, ceiling = by_name["bar"]
    assert version == "1.5" and pin is PinStyle.EXACT
    assert (floor, ceiling) == (None, None)


def test_apt_rows_are_3_tuples() -> None:
    rows = list(_parse_apt_args("nginx=1.18.0-6.1 curl"))
    assert all(len(r) == 3 for r in rows)
    assert ("nginx", "1.18.0-6.1", PinStyle.EXACT) in rows
    assert ("curl", None, PinStyle.WILDCARD) in rows


def test_every_manager_yields_defensively_unpackable_rows() -> None:
    """The consumer takes parsed[0..2] plus parsed[3]/[4] when
    present — every registered parser must produce rows of length 3
    or 5 with the (name, version, pin_style) prefix."""
    samples = {
        "PyPI": "foo==1.0",
        "Debian": "nginx=1.18.0-6.1",
        "Red Hat": "nginx-1.18.0-2.el8",
        "Alpine": "nginx=1.18.0-r0",
        "npm": "lodash@4.17.21",
        "Cargo": "ripgrep --version 14.1.0",
        "RubyGems": "rake -v 13.0.6",
        "Homebrew": "python@3.12",
        "Go": "github.com/foo/bar@v1.2.3",
    }
    seen = set()
    for mgr in _MANAGERS:
        args = samples[mgr.ecosystem]
        for parsed in mgr.parse_args(args):
            assert len(parsed) in (3, 5), (mgr.ecosystem, parsed)
            name, version, pin = parsed[0], parsed[1], parsed[2]
            assert isinstance(name, str) and name
            assert version is None or isinstance(version, str)
            assert isinstance(pin, PinStyle)
            floor = parsed[3] if len(parsed) > 3 else None
            ceiling = parsed[4] if len(parsed) > 4 else None
            assert floor is None or isinstance(floor, str)
            assert ceiling is None or isinstance(ceiling, str)
            seen.add(mgr.ecosystem)
    assert seen == set(samples), "every manager sample should parse"


# ---------------------------------------------------------------------------
# pip token classification
# ---------------------------------------------------------------------------

def test_pip_extras_token_records_base_package() -> None:
    # ``pkg[extra]==1.0`` selects optional features of the SAME PyPI
    # package; the token used to be dropped entirely because the
    # extras bracket failed the operator check.
    from packages.sca.parsers.inline_installs._managers import (
        _classify_pip_token,
    )
    row = _classify_pip_token("requests[security]==2.31.0")
    assert row is not None
    name, version, pin, _floor, _ceiling = row
    assert (name, version, pin) == ("requests", "2.31.0", PinStyle.EXACT)
    # Unpinned extras form too.
    row = _classify_pip_token("uvicorn[standard]")
    assert row is not None
    assert (row[0], row[1], row[2]) == ("uvicorn", None, PinStyle.WILDCARD)


def test_pip_exclusion_spec_records_no_version() -> None:
    # ``foo!=1.5`` EXCLUDES 1.5 — recording it as the installed
    # version flagged advisories for the one version guaranteed
    # absent. Classification is shared with the requirements.txt
    # parser so the two pip surfaces agree.
    from packages.sca.parsers.inline_installs._managers import (
        _classify_pip_token,
    )
    row = _classify_pip_token("foo!=1.5")
    assert row is not None
    assert row[1] is None
    assert row[2] is PinStyle.RANGE


def test_pip_exact_spec_still_records_version() -> None:
    from packages.sca.parsers.inline_installs._managers import (
        _classify_pip_token,
    )
    row = _classify_pip_token("foo==1.5")
    assert row is not None
    assert row[1] == "1.5"
    assert row[2] is PinStyle.EXACT


def test_pip_classifier_shared_with_requirements_parser() -> None:
    # Structural guard: the token classifier must delegate to the
    # requirements parser's specifier classifier rather than keep a
    # drift-prone local copy.
    import inspect
    from packages.sca.parsers.inline_installs import _managers
    from packages.sca.parsers.requirements import _classify_specifier
    assert _managers._classify_specifier is _classify_specifier
    assert "_classify_specifier(" in inspect.getsource(
        _managers._classify_pip_token,
    )


def test_pip_legacy_fallback_exclusion_records_no_version() -> None:
    from packages.sca.parsers.inline_installs._managers import (
        _legacy_single_spec,
    )
    row = _legacy_single_spec("foo", "!=1.5")
    assert row is not None
    assert row[1] is None and row[2] is PinStyle.RANGE
    row = _legacy_single_spec("foo", ">=1.5")
    assert row is not None
    assert row[1] == "1.5" and row[3] == "1.5"    # inclusive floor kept


def test_pip_value_taking_flag_value_not_a_package() -> None:
    # ``--progress-bar off`` — "off" is the flag's VALUE, not a
    # package; it used to be emitted as a phantom dep.
    rows = list(_parse_pip_args("--progress-bar off foo==1.0"))
    assert [r[0] for r in rows] == ["foo"]


def test_pip_boolean_flag_next_token_still_a_package() -> None:
    # Other direction: after a boolean flag the next token really is
    # a package.
    rows = list(_parse_pip_args("--upgrade foo==1.0"))
    assert [r[0] for r in rows] == ["foo"]


# ---------------------------------------------------------------------------
# yum/dnf name-version split
# ---------------------------------------------------------------------------

def test_yum_digit_bearing_name_not_split() -> None:
    # ``java-1.8.0-openjdk`` is a package NAME (the ``openjdk``
    # segment can't start a version-release); the first-dash-digit
    # split mangled it into name ``java`` + bogus version.
    from packages.sca.parsers.inline_installs._managers import (
        _parse_yum_args,
    )
    [(name, version, pin)] = list(_parse_yum_args("java-1.8.0-openjdk"))
    assert name == "java-1.8.0-openjdk"
    assert version is None
    assert pin is PinStyle.WILDCARD


def test_yum_real_version_release_still_split() -> None:
    from packages.sca.parsers.inline_installs._managers import (
        _parse_yum_args,
    )
    [(name, version, pin)] = list(_parse_yum_args("nginx-1.18.0-2.el8"))
    assert (name, version, pin) == ("nginx", "1.18.0-2.el8", PinStyle.EXACT)


def test_yum_digit_name_with_full_nevra_splits_at_version() -> None:
    from packages.sca.parsers.inline_installs._managers import (
        _parse_yum_args,
    )
    [(name, version, _pin)] = list(
        _parse_yum_args("java-1.8.0-openjdk-1.8.0.412-1.el8"))
    assert name == "java-1.8.0-openjdk"
    assert version == "1.8.0.412-1.el8"
