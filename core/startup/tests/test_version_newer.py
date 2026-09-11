"""Pin _version_newer's pre-release semantics.

Parsing stops at the first non-numeric segment: ``1.82.0rc1`` compares
as ``(1, 82)`` — strictly OLDER than the ``1.82.0`` release — so an
installed release candidate earns the update star and an installed
release never earns one for its own rc.
"""

from __future__ import annotations

from core.startup.init import _version_newer


def test_release_is_newer_than_its_rc() -> None:
    assert _version_newer("1.82.0", "1.82.0rc1") is True


def test_rc_is_not_newer_than_the_release() -> None:
    assert _version_newer("1.82.0rc1", "1.82.0") is False


def test_equal_versions_are_not_newer() -> None:
    assert _version_newer("1.99.0", "1.99.0") is False


def test_ordinary_ordering() -> None:
    assert _version_newer("1.100.0", "1.99.9") is True
    assert _version_newer("1.99.9", "1.100.0") is False
