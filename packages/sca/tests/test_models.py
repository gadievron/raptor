"""Tests for ``packages.sca.models``.

``Dependency.__post_init__`` derives ``source_kind="lockfile"`` for
lockfile-parsed rows that don't set an explicit ``source_kind``, so
they don't inherit the ``"manifest"`` default and misreport their
provenance. Explicitly-set source_kind values are always preserved.
"""

from __future__ import annotations

import json
from pathlib import Path

from packages.sca.models import Confidence, Dependency, PinStyle


def _dep(**overrides) -> Dependency:
    kwargs = dict(
        ecosystem="PyPI", name="requests", version="2.31.0",
        declared_in=Path("/repo/Pipfile.lock"), scope="main",
        is_lockfile=True, pin_style=PinStyle.EXACT, direct=False,
        purl="pkg:pypi/requests@2.31.0",
        parser_confidence=Confidence("high", reason="t"),
    )
    kwargs.update(overrides)
    return Dependency(**kwargs)


def test_lockfile_row_defaults_to_lockfile_source_kind() -> None:
    assert _dep(is_lockfile=True).source_kind == "lockfile"


def test_manifest_row_keeps_manifest_default() -> None:
    assert _dep(is_lockfile=False).source_kind == "manifest"


def test_explicit_source_kind_preserved_on_lockfile_row() -> None:
    d = _dep(is_lockfile=True, source_kind="cascade_resolver")
    assert d.source_kind == "cascade_resolver"


def test_explicit_manifest_on_non_lockfile_row_preserved() -> None:
    d = _dep(is_lockfile=False, source_kind="manifest")
    assert d.source_kind == "manifest"


def test_lockfile_parser_emits_lockfile_source_kind(tmp_path: Path) -> None:
    """End-to-end through one of the lockfile parsers that omits
    source_kind (Pipfile.lock)."""
    from packages.sca.parsers import pipfile_lock

    lock = tmp_path / "Pipfile.lock"
    lock.write_text(json.dumps({
        "default": {"requests": {"version": "==2.31.0"}},
        "develop": {},
    }), encoding="utf-8")
    deps = pipfile_lock.parse(lock)
    assert deps, "fixture should parse"
    assert all(d.is_lockfile for d in deps)
    assert all(d.source_kind == "lockfile" for d in deps)


class TestClassifyPinStyle:
    """Contract for the shared OCI-tag pin-style classifier."""

    def test_none_and_empty_are_wildcard(self):
        from packages.sca.models import PinStyle, classify_pin_style
        assert classify_pin_style(None) is PinStyle.WILDCARD
        assert classify_pin_style("") is PinStyle.WILDCARD

    def test_digest_is_exact(self):
        from packages.sca.models import PinStyle, classify_pin_style
        assert classify_pin_style("sha256:" + "a" * 64) is PinStyle.EXACT

    def test_floating_tags_are_wildcard_case_insensitive(self):
        from packages.sca.models import (
            FLOATING_TAGS, PinStyle, classify_pin_style,
        )
        for tag in FLOATING_TAGS:
            assert classify_pin_style(tag) is PinStyle.WILDCARD, tag
            assert classify_pin_style(tag.upper()) is PinStyle.WILDCARD, tag

    def test_ordinary_tag_is_exact(self):
        from packages.sca.models import PinStyle, classify_pin_style
        assert classify_pin_style("16.3") is PinStyle.EXACT
        assert classify_pin_style("3.11-slim") is PinStyle.EXACT


class TestCveIds:
    """``cve_ids`` is THE owner of the CVE-list shape for every
    enrichment consumer (KEV / EPSS / SSVC joins, harden ranking).
    The enrichment maps are keyed UPPERCASE, so the owner must
    normalise spellings — admitting a lowercase id but appending it
    raw silently loses the join downstream."""

    @staticmethod
    def _adv(osv_id: str, aliases: list[str]):
        from packages.sca.models import Advisory
        return Advisory(
            osv_id=osv_id, aliases=aliases, summary="s", details="d",
            affected=[], severity=None, fixed_versions=[], references=[],
        )

    def test_lowercase_spellings_normalised_to_uppercase(self):
        from packages.sca.models import cve_ids
        adv = self._adv("GHSA-x", ["cve-2024-0001", "Cve-2024-0002"])
        assert cve_ids(adv) == ["CVE-2024-0001", "CVE-2024-0002"]

    def test_lowercase_primary_id_normalised(self):
        from packages.sca.models import cve_ids
        adv = self._adv("cve-2024-31337", [])
        assert cve_ids(adv) == ["CVE-2024-31337"]

    def test_case_variants_deduplicate(self):
        from packages.sca.models import cve_ids
        adv = self._adv(
            "CVE-2024-0001", ["cve-2024-0001", "CVE-2024-0001"],
        )
        assert cve_ids(adv) == ["CVE-2024-0001"]

    def test_uppercase_behaviour_unchanged(self):
        from packages.sca.models import cve_ids
        adv = self._adv("GHSA-x", ["CVE-2024-0001", "OSV-2024-1"])
        assert cve_ids(adv) == ["CVE-2024-0001"]

    def test_distro_primary_id_resolves_to_embedded_cve(self):
        """Debian / Ubuntu / Alpine secdb records ship
        ``<DISTRO>-CVE-*`` as the PRIMARY id with an EMPTY alias
        list — the embedded CVE must drive every enrichment join."""
        from packages.sca.models import cve_ids
        for primary in (
            "DEBIAN-CVE-2026-54369",
            "UBUNTU-CVE-2017-18018",
            "ALPINE-CVE-2024-0001",
        ):
            adv = self._adv(primary, [])
            expected = primary.split("-", 1)[1]
            assert cve_ids(adv) == [expected], primary

    def test_distro_primary_deduplicates_against_cve_alias(self):
        from packages.sca.models import cve_ids
        adv = self._adv("UBUNTU-CVE-2017-18018", ["CVE-2017-18018"])
        assert cve_ids(adv) == ["CVE-2017-18018"]


class TestCanonicalCveId:
    """``canonical_cve_id`` is the single owner of the CVE-join-key
    shape — corpus label joins (calibration validate / refit) and
    live enrichment joins both resolve through it."""

    def test_cve_passthrough_and_case_fold(self):
        from packages.sca.models import canonical_cve_id
        assert canonical_cve_id("CVE-2024-0001") == "CVE-2024-0001"
        assert canonical_cve_id("cve-2024-0001") == "CVE-2024-0001"

    def test_distro_prefix_resolves(self):
        from packages.sca.models import canonical_cve_id
        assert (
            canonical_cve_id("DEBIAN-CVE-2026-54369")
            == "CVE-2026-54369"
        )
        # Case-folded before matching, like every other spelling.
        assert (
            canonical_cve_id("debian-cve-2026-54369")
            == "CVE-2026-54369"
        )

    def test_non_cve_ids_yield_none(self):
        from packages.sca.models import canonical_cve_id
        for cand in (
            "GHSA-jfh8-c2jp-5v3q",
            "PYSEC-2024-1",
            "RUSTSEC-2024-0001",
            "OSV-2024-1",
            None,
            12345,
        ):
            assert canonical_cve_id(cand) is None, cand

    def test_distro_shape_is_anchored(self):
        """Trailing garbage, multi-segment prefixes, and short CVE
        numbers must NOT join — the prefix-strip only recognises the
        exact one-token distro-primary family."""
        from packages.sca.models import canonical_cve_id
        for cand in (
            "DEBIAN-CVE-2026-54369-1",       # trailing segment
            "BIT-APACHE-CVE-2024-1234",       # multi-segment prefix
            "DEBIAN-CVE-2026-123",            # sub-spec number
            "DEBIAN-CVE-26-1234",             # 2-digit year
            "-CVE-2024-0001",                 # empty prefix
            "DEBIAN-CVE-2026-5436\uff19",    # fullwidth digit (not [0-9])
        ):
            assert canonical_cve_id(cand) is None, cand
        # Whitespace PADDING normalises deliberately (strip-before-
        # fold — whitespace-padded feed spellings must not lose their
        # joins), so a trailing newline resolves. The \Z anchor still
        # matters: it blocks non-whitespace trailers (first case
        # above), which $ alone would only partially catch.
        assert (canonical_cve_id("DEBIAN-CVE-2026-54369\n")
                == "CVE-2026-54369")

    def test_hostile_prefix_gains_no_new_authority(self):
        """Any ``[A-Z]+`` prefix resolves — a hostile ``EVIL-CVE-*``
        primary joins its embedded CVE, which is exactly the power
        the (attacker-writable) alias list already grants. Pinned so
        a future tightening is a deliberate decision, not drift."""
        from packages.sca.models import canonical_cve_id
        assert (
            canonical_cve_id("EVIL-CVE-2021-44228") == "CVE-2021-44228"
        )


def test_cve_ids_strips_whitespace_bearing_spellings() -> None:
    """Whitespace-padded feed spellings must not survive into (or be
    dropped from) the uppercase-keyed joins: 'CVE-2021-9999\\t' was
    admitted verbatim (failing every KEV/EPSS join) while a
    leading-space spelling was dropped entirely."""
    from packages.sca.models import Advisory, cve_ids

    adv = Advisory(
        osv_id="GHSA-x",
        aliases=["CVE-2021-9999\t", "  cve-2021-0001", "CVE-2021-9999"],
        summary="", details="", affected=[], severity=None,
        fixed_versions=[], references=[],
    )
    assert cve_ids(adv) == ["CVE-2021-9999", "CVE-2021-0001"]
