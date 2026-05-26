"""Tests for ``packages.sca.purl`` (the ``raptor-sca purl`` utility)."""

from __future__ import annotations

import pytest

from packages.sca import purl


def test_npm(capsys) -> None:
    rc = purl.main(["npm", "lodash", "4.17.21"])
    assert rc == 0
    assert capsys.readouterr().out.strip() == "pkg:npm/lodash@4.17.21"


def test_pypi_lowercases_ecosystem(capsys) -> None:
    purl.main(["PyPI", "django", "4.2.10"])
    assert capsys.readouterr().out.strip() == "pkg:pypi/django@4.2.10"


def test_maven_with_colon_in_name(capsys) -> None:
    purl.main(["Maven", "org.apache.logging.log4j:log4j-core", "2.17.1"])
    out = capsys.readouterr().out.strip()
    assert out == "pkg:maven/org.apache.logging.log4j:log4j-core@2.17.1"


def test_scoped_npm_package(capsys) -> None:
    purl.main(["npm", "@types/node", "20.10.5"])
    assert capsys.readouterr().out.strip() == "pkg:npm/@types/node@20.10.5"


def test_missing_args_returns_2() -> None:
    with pytest.raises(SystemExit) as exc:
        purl.main(["npm"])
    assert exc.value.code == 2


def test_unknown_ecosystem_returns_2(capsys) -> None:
    rc = purl.main(["InvalidEcosystem", "foo", "1.0"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "unknown ecosystem" in err


def test_path_traversal_rejected(capsys) -> None:
    rc = purl.main(["PyPI", "../../etc/passwd", "1.0"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "invalid package name" in err


def test_whitespace_in_name_rejected(capsys) -> None:
    rc = purl.main(["PyPI", "foo bar", "1.0"])
    assert rc == 2


def test_ecosystem_canonicalisation(capsys) -> None:
    """Lowercase ecosystem name is normalised to canonical form."""
    purl.main(["pypi", "django", "4.2.10"])
    assert capsys.readouterr().out.strip() == "pkg:pypi/django@4.2.10"
