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
