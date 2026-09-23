"""Round-trip closure between the CWE and vuln_type maps.

Every vuln_type the forward map (``CWE_TO_VULN_TYPE``) can produce
must be reverse-mappable through ``VULN_TYPE_TO_CWE`` — with exactly
one deliberate exception: ``"other"`` is the forward catch-all and
has no representative CWE. Without a pinned closure, forward-only
categories drift in silently and downstream both-direction converters
lose findings.

Also pins the two mislabel fixes: information-disclosure aliases must
not land in the memory_leak/CWE-401 resource-lifetime family, and
CWE-601 (open redirect — the server sends the CLIENT elsewhere) must
not be labelled SSRF (CWE-918 — the server is made to fetch).
"""

from core.schema_constants import (
    CWE_TO_VULN_TYPE,
    VULN_TYPE_TO_CWE,
    VULN_TYPES,
    normalise_vuln_type,
)


def test_forward_values_close_except_other():
    forward_values = set(CWE_TO_VULN_TYPE.values())
    missing = forward_values - set(VULN_TYPE_TO_CWE) - {"other"}
    assert not missing, (
        f"forward-only vuln_types with no reverse CWE: {sorted(missing)}"
    )


def test_other_is_the_only_deliberate_exception():
    assert "other" not in VULN_TYPE_TO_CWE


def test_forward_values_are_canonical():
    assert set(CWE_TO_VULN_TYPE.values()) <= set(VULN_TYPES)


def test_info_leak_aliases_are_disclosure_not_memory_leak():
    for alias in ("info_leak", "information_leak"):
        assert normalise_vuln_type(alias) == "information_disclosure"
    assert VULN_TYPE_TO_CWE["information_disclosure"] == "CWE-200"
    assert CWE_TO_VULN_TYPE["CWE-200"] == "information_disclosure"


def test_cwe_601_is_open_redirect_not_ssrf():
    assert CWE_TO_VULN_TYPE["CWE-601"] == "open_redirect"
    assert VULN_TYPE_TO_CWE["open_redirect"] == "CWE-601"
    # SSRF keeps its own family.
    assert VULN_TYPE_TO_CWE["ssrf"] == "CWE-918"


def test_memory_leak_family_intact():
    # Keep-direction: genuine resource-lifetime leaks stay CWE-401.
    assert CWE_TO_VULN_TYPE["CWE-401"] == "memory_leak"
    assert VULN_TYPE_TO_CWE["memory_leak"] == "CWE-401"
