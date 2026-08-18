"""ITEM P10: verification channels for web-facing CWE families.

Path traversal (CWE-22/23), deserialization (CWE-502), SSRF (CWE-918),
XXE (CWE-611), open redirect (CWE-601), command injection (CWE-77) and
code injection (CWE-94/95) were hypothesis-formable but
verification-orphaned: no dispatch entry, no flow/guard chain entry, no
hypothesis-keyword regex, no per-hypothesis semgrep rule. These tests
pin the new channels end to end:

- ``CWE_TO_TOOL_DISPATCH`` entries with joern sinks per family
- ``_cwe_fallback_chain`` emits joern / joern_flow / joern_guard entries
- ``infer_cwe_from_hypothesis`` maps family prose to the new CWEs
- per-hypothesis semgrep rules bind unsafe shapes and each keyword has
  a guarded negative-control fixture the pattern does NOT match
- dark-verify eligibility extends to the new families with a status
  filter bounding witness-call cost
"""

from __future__ import annotations

import re

import pytest

from core.audit.cwe_dispatch import (
    dark_verify_applicable,
    dark_verify_statuses,
    infer_cwe_from_hypothesis,
    lookup,
)
from core.audit.hypothesis_mapping import _HYPOTHESIS_SEMGREP_PATTERNS
from core.audit.orchestrator import _cwe_fallback_chain
from core.audit.sweep import negative_control_fixture

_NEW_FAMILY_CWES = (
    "CWE-22", "CWE-23", "CWE-502", "CWE-918",
    "CWE-611", "CWE-601", "CWE-77",
)


def _types(chain):
    return [e["type"] for e in chain]


class TestDispatchEntries:
    @pytest.mark.parametrize("cwe", _NEW_FAMILY_CWES)
    def test_entry_exists_with_joern_sinks(self, cwe):
        entry = lookup(cwe)
        assert entry is not None, f"{cwe} has no dispatch entry"
        assert entry.get("joern") is True
        assert entry.get("sinks"), f"{cwe} entry has no sinks"

    def test_code_injection_families(self):
        # CWE-94 pre-existed; CWE-95 is new. Both need sinks for the
        # flow channel.
        for cwe in ("CWE-94", "CWE-95"):
            entry = lookup(cwe)
            assert entry is not None
            assert entry.get("sinks")

    def test_prototype_pollution_entry(self):
        entry = lookup("CWE-1321")
        assert entry is not None
        assert entry.get("joern") is True


class TestChainEmission:
    @pytest.mark.parametrize("cwe", _NEW_FAMILY_CWES)
    def test_flow_chain_entry(self, cwe):
        assert "joern_flow" in _types(_cwe_fallback_chain(cwe)), cwe

    @pytest.mark.parametrize(
        "cwe", ("CWE-22", "CWE-502", "CWE-918", "CWE-611", "CWE-601"),
    )
    def test_guard_chain_entry(self, cwe):
        # Missing-validation-before-sink shapes get the dominance
        # channel too.
        assert "joern_guard" in _types(_cwe_fallback_chain(cwe)), cwe

    def test_plain_joern_taint_entry(self):
        for cwe in _NEW_FAMILY_CWES:
            assert "joern" in _types(_cwe_fallback_chain(cwe)), cwe

    def test_existing_families_unchanged(self):
        # CWE-190 keeps its non-flow chain shape.
        types = _types(_cwe_fallback_chain("CWE-190"))
        assert "joern_flow" not in types
        assert "joern_guard" not in types


class TestCweInference:
    @pytest.mark.parametrize("text,expected", [
        ("path traversal via ../ in archive member names", "CWE-22"),
        ("attacker-controlled filename enables directory traversal", "CWE-22"),
        ("unsafe deserialization of user data via pickle.loads", "CWE-502"),
        ("attacker can unpickle arbitrary objects", "CWE-502"),
        ("SSRF: attacker-controlled URL reaches urlopen", "CWE-918"),
        ("server-side request forgery through the webhook fetcher", "CWE-918"),
        ("XXE: xml external entity expansion in the parser", "CWE-611"),
        ("open redirect via the next parameter", "CWE-601"),
        ("unvalidated redirect to attacker-supplied location", "CWE-601"),
        ("prototype pollution via __proto__ key in merge", "CWE-1321"),
    ])
    def test_family_prose_maps(self, text, expected):
        assert infer_cwe_from_hypothesis(text) == expected

    def test_existing_mappings_take_precedence(self):
        # Command injection prose still maps to the pre-existing CWE-78.
        assert infer_cwe_from_hypothesis(
            "command injection via unsanitised filename"
        ) == "CWE-78"


class TestSemgrepFamilyRules:
    """Unsafe-shape patterns with guarded-fixture negative controls."""

    @pytest.mark.parametrize("keyword", [
        "deserialization", "ssrf", "xxe", "open redirect",
    ])
    def test_keyword_pattern_exists(self, keyword):
        assert keyword in _HYPOTHESIS_SEMGREP_PATTERNS

    @pytest.mark.parametrize("keyword,ext", [
        ("deserialization", ".py"),
        ("ssrf", ".py"),
        ("ssrf", ".c"),
        ("xxe", ".py"),
        ("xxe", ".c"),
        ("open redirect", ".py"),
    ])
    def test_negative_control_fixture_exists(self, keyword, ext):
        fixture = negative_control_fixture(keyword, f"target/app{ext}")
        assert fixture is not None, f"missing {keyword} fixture for {ext}"
        assert fixture.suffix == ext

    @pytest.mark.parametrize("keyword,ext", [
        ("deserialization", ".py"),
        ("ssrf", ".py"),
        ("ssrf", ".c"),
        ("xxe", ".py"),
        ("xxe", ".c"),
        ("open redirect", ".py"),
    ])
    def test_pattern_does_not_match_guarded_fixture(self, keyword, ext):
        # A pattern matching its own safe-usage fixture is a presence
        # detector — the whole point of the unsafe-shape patterns is
        # that safe usage does not trip them.
        pattern = re.compile(_HYPOTHESIS_SEMGREP_PATTERNS[keyword])
        fixture = negative_control_fixture(keyword, f"target/app{ext}")
        text = fixture.read_text(encoding="utf-8")
        assert not pattern.search(text), (
            f"{keyword} pattern matches its guarded fixture {fixture.name}"
        )

    @pytest.mark.parametrize("keyword,snippet", [
        ("deserialization", 'obj = pickle.loads(payload)'),
        ("deserialization", 'cfg = yaml.load(stream)'),
        ("ssrf", 'resp = requests.get(f"http://{host}/x")'),
        ("ssrf", 'resp = urlopen(base + path)'),
        ("xxe", 'parser = etree.XMLParser(resolve_entities=True)'),
        ("xxe", 'doc = xmlReadFile(path, NULL, XML_PARSE_NOENT);'),
        ("open redirect", 'return redirect(request.args["next"])'),
    ])
    def test_pattern_matches_unsafe_shape(self, keyword, snippet):
        pattern = re.compile(_HYPOTHESIS_SEMGREP_PATTERNS[keyword])
        assert pattern.search(snippet), (
            f"{keyword} pattern misses unsafe shape: {snippet}"
        )


class TestDarkVerifyEligibility:
    @pytest.mark.parametrize(
        "cwe", ("CWE-22", "CWE-502", "CWE-918", "CWE-601", "CWE-94", "CWE-95"),
    )
    def test_new_families_dark_verify(self, cwe):
        assert dark_verify_applicable(cwe), cwe

    @pytest.mark.parametrize(
        "cwe", ("CWE-22", "CWE-502", "CWE-918", "CWE-601", "CWE-94", "CWE-95"),
    )
    def test_new_families_carry_status_filter(self, cwe):
        statuses = dark_verify_statuses(cwe)
        assert statuses is not None, f"{cwe} has no status filter"
        assert "clean" not in statuses
        assert "suspicious" in statuses

    def test_existing_families_have_no_filter(self):
        # Only the original auth trio keeps unfiltered behaviour —
        # dark verify is their primary grounding mechanism.
        for cwe in ("CWE-287", "CWE-862", "CWE-863"):
            assert dark_verify_applicable(cwe)
            assert dark_verify_statuses(cwe) is None, cwe
        # The expanded families bound witness-call cost the same way
        # the web families do: clean outcomes are not eligible.
        for cwe in ("CWE-134", "CWE-190", "CWE-416", "CWE-457"):
            assert dark_verify_applicable(cwe)
            assert dark_verify_statuses(cwe) == frozenset(
                {"dark", "suspicious", "finding"}
            ), cwe

    def test_status_filter_bounds_witness_calls(self, monkeypatch, tmp_path):
        """A clean-status CWE-918 outcome must not spend a witness call;
        a suspicious-status one must."""
        from core.audit.orchestrator import (
            OrchestratorResult,
            ReviewOutcome,
            _run_dark_verification,
        )

        calls = []

        def fake_llm(prompt, system):
            calls.append(prompt)
            return "{}"

        # Never let parsing/execution proceed — eligibility is the
        # unit under test.
        import core.audit.dark_verify as dv
        monkeypatch.setattr(
            dv, "parse_witness_response",
            lambda *a, **kw: None,
        )

        def _outcome(status):
            o = ReviewOutcome(
                file="app.py", function="fetch", status=status,
                body="def fetch(url): pass", hypothesis="ssrf via urlopen",
                line=1,
            )
            o.review_result = {"cwe": "CWE-918"}
            return o

        class _Cfg:
            target_path = tmp_path
            out_dir = tmp_path
            models = ()

        result = OrchestratorResult()
        result.outcomes = [_outcome("clean")]
        _run_dark_verification(result, _Cfg(), llm_client=fake_llm)
        assert calls == [], "clean-status outcome consumed a witness call"

        result2 = OrchestratorResult()
        result2.outcomes = [_outcome("suspicious")]
        _run_dark_verification(result2, _Cfg(), llm_client=fake_llm)
        assert len(calls) == 1
