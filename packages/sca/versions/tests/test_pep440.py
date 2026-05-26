"""Tests for the PEP 440 version comparator (Python).

The comparator has two code paths:

  1. ``packaging`` library (preferred) — pip's own reference
     implementation. Used when ``packaging`` is import-available.
  2. Fallback regex parser — covers the X.Y.Z[aN|bN|rcN][.postN]
     [.devN] subset for environments without ``packaging``.

Both paths get test coverage. The ``packaging`` path is the
production behaviour; the fallback path is exercised by
monkeypatching ``_HAS_PACKAGING`` to ``False``, which forces the
comparator into the fallback branch.

PEP 440's subtle bits that the tests pin:

  * Pre-release labels ``a`` / ``b`` / ``c`` / ``rc`` / ``alpha``
    / ``beta`` / ``pre`` normalise to canonical forms.
  * Pre-releases sort BELOW the bare release.
  * Post-releases sort ABOVE the bare release.
  * Dev-releases sort BELOW pre-releases of the same release.
  * Epoch prefix ``N!`` is a sort-domination signal.
  * Local versions ``+local`` are ordered against each other.
"""

from __future__ import annotations

import pytest

import packages.sca.versions.pep440 as pep440_mod
from packages.sca.versions import VersionError
from packages.sca.versions import compare as dispatch_compare
from packages.sca.versions import in_range
from packages.sca.versions.pep440 import compare as cmp


# ---------------------------------------------------------------------------
# Section 1: ``packaging``-backed path (production default).
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("a, b, expected", [
    ("1.0", "1.1", -1),
    ("1.1", "1.0", 1),
    ("1.0", "1.0", 0),
    ("1.0", "2.0", -1),
    ("1.0.0", "1.0.1", -1),
    ("0.9.9", "1.0.0", -1),
    ("10.0", "9.0", 1),         # numeric, not lex
])
def test_basic_ordering(a, b, expected) -> None:
    assert cmp(a, b) == expected


def test_trailing_zero_equality() -> None:
    """``1.0 == 1.0.0`` per PEP 440 — trailing zero release
    segments don't affect ordering."""
    assert cmp("1.0", "1.0.0") == 0
    assert cmp("1.0.0", "1.0.0.0") == 0


def test_pre_release_below_bare() -> None:
    """Pre-releases sort below the bare release: ``1.0a1 < 1.0``,
    ``1.0b1 < 1.0``, ``1.0rc1 < 1.0``."""
    assert cmp("1.0a1", "1.0") == -1
    assert cmp("1.0b1", "1.0") == -1
    assert cmp("1.0rc1", "1.0") == -1
    assert cmp("1.0", "1.0a1") == 1


def test_pre_release_label_ladder() -> None:
    """Within pre-releases of the same release:
    ``a < b < c == rc``. Note: ``c`` is an alias for ``rc``."""
    assert cmp("1.0a1", "1.0b1") == -1
    assert cmp("1.0b1", "1.0rc1") == -1
    assert cmp("1.0c1", "1.0rc1") == 0      # c alias for rc


def test_pre_label_aliases() -> None:
    """PEP 440 normalises long-form pre-release labels.
    ``1.0a1`` / ``1.0alpha1`` / ``1.0.alpha.1`` are all equal."""
    assert cmp("1.0a1", "1.0alpha1") == 0
    assert cmp("1.0b1", "1.0beta1") == 0
    assert cmp("1.0c1", "1.0rc1") == 0


def test_post_release_above_bare() -> None:
    """Post-releases sort ABOVE the bare release.
    ``1.0 < 1.0.post1``."""
    assert cmp("1.0", "1.0.post1") == -1
    assert cmp("1.0.post1", "1.0") == 1
    assert cmp("1.0.post1", "1.0.post2") == -1


def test_dev_below_pre() -> None:
    """Dev releases sort BELOW pre-releases of the same release.
    ``1.0a1.dev1 < 1.0a1``."""
    assert cmp("1.0a1.dev1", "1.0a1") == -1
    assert cmp("1.0a1", "1.0a1.dev1") == 1


def test_dev_below_bare() -> None:
    """Dev releases on a bare version sort below the bare
    version. ``1.0.dev1 < 1.0``."""
    assert cmp("1.0.dev1", "1.0") == -1


def test_epoch_dominates() -> None:
    """The ``N!`` epoch prefix dominates ordering. ``1!1.0`` is
    in a different epoch than ``999.0`` — and the epoch always
    wins regardless of the release part. This is rare in real
    packages but appears when a project renumbers (e.g., a
    ``1.x`` epoch followed by a ``2.x`` epoch with lower
    version components)."""
    assert cmp("1!1.0", "999.0") == 1
    assert cmp("999.0", "1!1.0") == -1
    assert cmp("1!1.0", "2!1.0") == -1


def test_local_versions_compare_against_each_other() -> None:
    """Local versions (``1.0+local``) compare lex against other
    local-version labels. A bare ``1.0`` is NOT equal to
    ``1.0+local``; the local label adds info."""
    # The bare version is ranked BELOW the same release with a
    # local label.
    assert cmp("1.0+a", "1.0+b") == -1
    assert cmp("1.0", "1.0+local") == -1
    assert cmp("1.0+local", "1.0") == 1


def test_invalid_raises_version_error() -> None:
    """Bad inputs surface as ``VersionError`` (a ``ValueError``
    subclass) — callers can catch the package-wide error."""
    with pytest.raises(VersionError):
        cmp("not-a-version", "1.0")
    with pytest.raises(VersionError):
        cmp("1.0", "@@@@")


def test_identical_short_circuit() -> None:
    """Identical strings short-circuit to 0."""
    assert cmp("1.0", "1.0") == 0
    assert cmp("1.0a1", "1.0a1") == 0


# ---------------------------------------------------------------------------
# Section 2: dispatcher integration.
# ---------------------------------------------------------------------------

def test_dispatch_routes_pypi() -> None:
    """``versions.compare("PyPI", ...)`` routes to the PEP 440
    comparator."""
    assert dispatch_compare("PyPI", "1.0", "1.0.1") == -1
    assert dispatch_compare("PyPI", "1.0a1", "1.0") == -1


def test_in_range_pypi_smoke() -> None:
    """End-to-end via the OSV-style range matcher."""
    events = [{"introduced": "1.0"}, {"fixed": "2.0"}]
    assert in_range("PyPI", "1.5", events) is True
    assert in_range("PyPI", "2.0", events) is False
    # Pre-release of 2.0 still in range (< 2.0).
    assert in_range("PyPI", "2.0a1", events) is True


# ---------------------------------------------------------------------------
# Section 3: fallback path (when ``packaging`` is not importable).
# ---------------------------------------------------------------------------
#
# Production environments ship ``packaging``, so the fallback path
# is mostly defensive — for stripped-down envs where the dep
# isn't available. Tests here exercise the regex-driven fallback
# by monkeypatching ``_HAS_PACKAGING`` to ``False``, forcing the
# comparator into ``_fallback_compare``.

def test_fallback_basic_ordering(monkeypatch) -> None:
    """Same as ``test_basic_ordering`` but routed through the
    fallback parser. Covers the X.Y.Z subset that real-world
    Python deps mostly stay within."""
    monkeypatch.setattr(pep440_mod, "_HAS_PACKAGING", False)
    assert cmp("1.0", "1.1") == -1
    assert cmp("1.0.0", "1.0.1") == -1
    assert cmp("2.0", "1.0") == 1


def test_fallback_pre_release_order(monkeypatch) -> None:
    """Fallback covers the pre-release subset."""
    monkeypatch.setattr(pep440_mod, "_HAS_PACKAGING", False)
    assert cmp("1.0a1", "1.0") == -1
    assert cmp("1.0b1", "1.0") == -1
    assert cmp("1.0rc1", "1.0") == -1
    assert cmp("1.0a1", "1.0b1") == -1
    assert cmp("1.0b1", "1.0rc1") == -1


def test_fallback_pre_label_aliases(monkeypatch) -> None:
    """Fallback's ``_PRE_NORMALISE`` dict equates short + long
    label forms — same as ``packaging`` behaviour."""
    monkeypatch.setattr(pep440_mod, "_HAS_PACKAGING", False)
    assert cmp("1.0a1", "1.0alpha1") == 0
    assert cmp("1.0b1", "1.0beta1") == 0
    assert cmp("1.0c1", "1.0rc1") == 0


def test_fallback_dev_below_pre(monkeypatch) -> None:
    """Dev-release ordering preserved in fallback path."""
    monkeypatch.setattr(pep440_mod, "_HAS_PACKAGING", False)
    assert cmp("1.0a1.dev1", "1.0a1") == -1


def test_fallback_post_above_release(monkeypatch) -> None:
    """Post-release ordering preserved in fallback path."""
    monkeypatch.setattr(pep440_mod, "_HAS_PACKAGING", False)
    assert cmp("1.0", "1.0.post1") == -1
    assert cmp("1.0.post1", "1.0.post2") == -1


def test_fallback_rejects_epoch(monkeypatch) -> None:
    """Fallback regex doesn't recognise the epoch ``N!`` form —
    inputs outside the documented subset raise cleanly via
    ``VersionError`` rather than silently returning a wrong
    result."""
    monkeypatch.setattr(pep440_mod, "_HAS_PACKAGING", False)
    with pytest.raises(VersionError):
        cmp("1!1.0", "1.0")


def test_fallback_rejects_local_version(monkeypatch) -> None:
    """Local versions (``1.0+local``) aren't covered by the
    fallback regex — raise cleanly rather than silently strip."""
    monkeypatch.setattr(pep440_mod, "_HAS_PACKAGING", False)
    with pytest.raises(VersionError):
        cmp("1.0+local", "1.0")


def test_fallback_invalid_raises(monkeypatch) -> None:
    """Garbage input in fallback path raises ``VersionError``."""
    monkeypatch.setattr(pep440_mod, "_HAS_PACKAGING", False)
    with pytest.raises(VersionError):
        cmp("not-a-version", "1.0")
