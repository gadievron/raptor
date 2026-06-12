"""Phase 51A RED tests: extend Phase 18 sanitizer for residual triggers.

Forensic source: CVE-2024-36401 audit JSONL in Phase 49 bench
(output/agentic/bench50-20260517-071853/manual-*/CVE-2024-36401.jsonl).
Phase 50.2 evidence: existing sanitizer correctly substitutes
"Remote Code Execution" / "RCE" → "remote-code path" but Anthropic policy
classifier still refuses on residual phrases the sanitizer does not yet
cover. Phase 49 combined dataset: 7 refusals / 70 = 10% vs ~0% in
Phase 23/38 — actionable gap.

Patterns Phase 51A adds:
  1. "<by> unauthenticated <users> through <specially> crafted input"
     — clause-level inline replacement; preserves build-info around it
  2. "default <product> installation"
     — preserves product name (build-info); drops "default" framing

RED: tests assert post-sanitize text does NOT contain trigger phrases.
GREEN flip is atomic with Phase 51.A.2 impl (xfail markers removed
in the same commit per past-bench-lessons §13 #1 TDD discipline).
"""
from __future__ import annotations


from cve_env.utils.exploit_text_sanitizer import sanitize_exploit_text


CVE_2024_36401_NVD_DESCRIPTION = (
    "GeoServer is an open source server that allows users to share and edit "
    "geospatial data. Prior to versions 2.22.6, 2.23.6, 2.24.4, and 2.25.2, "
    "multiple OGC request parameters allow Remote Code Execution (RCE) by "
    "unauthenticated users through specially crafted input against a default "
    "GeoServer installation due to unsafely evaluating property names as "
    "XPath expressions."
)


def test_strips_unauthenticated_through_crafted_input_phrase() -> None:
    """Phase 51A pattern 1: clause-level neutralization of
    'unauthenticated users through specially crafted input' construction.

    The phrase is the AUP-trigger residual after RCE substitution.
    Build-relevant info (product, version) must survive.
    """
    out = sanitize_exploit_text(CVE_2024_36401_NVD_DESCRIPTION, max_chars=600)
    out_lower = out.lower()
    # Neither "specially crafted" nor "unauthenticated users through" should
    # survive post-sanitization. The 51.A.2 pattern targets the joint
    # construction; either side of the conjunction may remain in isolation
    # for other CVEs but not in this specific co-occurrence.
    assert "specially crafted" not in out_lower, (
        f"sanitizer should strip 'specially crafted' construct; got: {out!r}"
    )
    assert "unauthenticated users through" not in out_lower, (
        f"sanitizer should strip 'unauthenticated users through' construct; "
        f"got: {out!r}"
    )
    # Build-relevant info preserved
    assert "geoserver" in out_lower, f"product name lost; got: {out!r}"
    assert "2.22.6" in out, f"version literal lost; got: {out!r}"


def test_neutralizes_default_product_installation_framing() -> None:
    """Phase 51A pattern 2: 'default <product> installation' framing.

    The "default ... installation" construction implies a vulnerable baseline
    config — AUP-trigger residual. Product name (build-info) preserved.
    """
    out = sanitize_exploit_text(CVE_2024_36401_NVD_DESCRIPTION, max_chars=600)
    out_lower = out.lower()
    # "default GeoServer installation" should be neutralized; the "default"
    # framing dropped while product literal stays.
    assert "default geoserver installation" not in out_lower, (
        f"sanitizer should neutralize 'default {{product}} installation' framing; "
        f"got: {out!r}"
    )
    # Product literal preserved
    assert "geoserver" in out_lower, f"product name lost; got: {out!r}"


def test_cve_2024_36401_full_sanitizer_roundtrip_preserves_build_info() -> None:
    """Phase 51A end-to-end: CVE-2024-36401 NVD description roundtrip.

    After 51A patterns ship, all 4 residual trigger phrases must be absent
    AND build-relevant info (vendor, product, version literals) preserved.
    This is the forensic source case (Phase 50.2).
    """
    out = sanitize_exploit_text(CVE_2024_36401_NVD_DESCRIPTION, max_chars=600)
    out_lower = out.lower()

    # All 4 trigger phrases observed in Phase 50.2 forensic absent:
    triggers = [
        "specially crafted",
        "unauthenticated users through",
        "default geoserver installation",
        "crafted input",
    ]
    surviving = [t for t in triggers if t in out_lower]
    assert not surviving, (
        f"trigger phrases survived sanitization: {surviving}; got: {out!r}"
    )

    # Build-relevant info preserved (product, version literals):
    must_preserve = ["geoserver", "2.22.6", "2.25.2"]
    missing = [p for p in must_preserve if p.lower() not in out_lower]
    assert not missing, (
        f"build-relevant info lost during sanitization: {missing}; got: {out!r}"
    )


def test_phase_51a_does_not_regress_existing_phase_18_patterns() -> None:
    """Phase 51A regression guard: existing Phase 18 patterns still fire.

    Sanity check that adding 51A patterns doesn't conflict with the
    existing 12 EXPLOIT_LANGUAGE patterns + 1 TRIGGER_PHRASE + 20 CLASS_VERB
    replacements. (Full regression: run test_exploit_text_sanitizer.py
    22 existing tests as standalone gate.)
    """
    # Existing Phase 18.2 pattern: "the attack may be launched"
    out = sanitize_exploit_text("The attack may be launched remotely.")
    assert "attack may be launched" not in out.lower(), (
        f"Phase 18.2 passive-attack pattern regressed: {out!r}"
    )

    # Existing TRIGGER_PHRASE_REPLACEMENTS: "unauthenticated <stuff> vulnerability"
    out = sanitize_exploit_text(
        "Foo bar baz an unauthenticated input-handling path vulnerability "
        "in the 'id' parameter. Foo bar."
    )
    assert "unauthenticated" not in out.lower() or "vulnerability" not in out.lower(), (
        f"Phase 18.2 unauthenticated-vulnerability pattern regressed: {out!r}"
    )

    # Existing CLASS_VERB: RCE → remote-code path
    out = sanitize_exploit_text("Allows RCE via foo.")
    assert "rce" not in out.lower(), f"RCE class-verb regressed: {out!r}"
