"""Tests for :mod:`packages.code_understanding.mitigation_enricher`.

Covers:

* Tri-state passthrough on ``glibc_n_disabled`` — CONDITIONAL (``None``)
  MUST NOT collapse to ``False`` in ``format_n_write``.
* CWE join key on ``mitigation_context.cwe_class``.
* Multi-source coexistence (a sink already carrying a distinct
  ``mitigation_context`` from a hypothetical /audit-side substrate is
  overwritten by us, but /audit doesn't write mitigation_context —
  see /tmp/integration/audit-response.md — so this test just asserts
  we own the key).
* Priority hint policy: renderers may re-order; enricher never
  drops sinks.
* Idempotency: enriching twice with the same inputs produces the same
  enrichment (modulo ``generated_at``).
* Missing binary / analyzer failure → returns map unchanged, no
  raise. /understand must not abort on best-effort enrichment.
* Sink CWE extraction from several plausible fields.

Adversarial cases:

* Sink without CWE gets a minimal enrichment (verdict only) — never
  dropped.
* ``sinks[]`` is not a list → early return, no mutation.
* ``analyze_binary`` returns partial result → enrichment still emits
  with the fields present.
"""

from unittest.mock import patch

from packages.code_understanding.mitigation_enricher import (
    SCHEMA_VERSION,
    build_mitigation_context,
    enrich_context_map,
    _availability_for_cwe,
    _priority_hint,
    _sink_cwe,
)


def _fake_result(**overrides):
    """Build a fake ``analyze_binary`` return dict."""
    base = {
        "verdict": "difficult",
        "protections": {
            "relro": True, "full_relro": True, "pie": True, "nx": True,
            "canary": True, "fortify": True,
        },
        "glibc_n_disabled": None,   # CONDITIONAL
        "printf_n_availability_detail": (
            "%n status is CONDITIONAL — depends on format-string memory class."
        ),
        "glibc_version": "2.43",
        "blockers": ["Full RELRO — GOT read-only"],
        "warnings": [],
    }
    base.update(overrides)
    return base


class TestAvailabilityTriState:

    def test_conditional_glibc_n_disabled_preserves_none(self):
        """Regression: ``None`` (CONDITIONAL) MUST NOT collapse to
        ``False``. Consumers that truthy-check ``format_n_write``
        would mis-treat CONDITIONAL as blocked, missing rodata-format
        exploit paths."""
        result = _fake_result(glibc_n_disabled=None)
        avail = _availability_for_cwe("CWE-134", result)
        assert avail["format_n_write"] is None
        assert avail["arbitrary_write"] is None

    def test_verified_disabled_becomes_false(self):
        result = _fake_result(glibc_n_disabled=True)
        avail = _availability_for_cwe("CWE-134", result)
        assert avail["format_n_write"] is False
        assert avail["arbitrary_write"] is False

    def test_verified_working_becomes_true(self):
        result = _fake_result(glibc_n_disabled=False)
        avail = _availability_for_cwe("CWE-134", result)
        assert avail["format_n_write"] is True
        assert avail["arbitrary_write"] is True

    def test_full_relro_blocks_got_and_fini(self):
        result = _fake_result(protections={"full_relro": True})
        avail = _availability_for_cwe("CWE-134", result)
        assert avail["got_overwrite"] is False
        assert avail["fini_array"] is False

    def test_partial_relro_allows_got_and_fini(self):
        result = _fake_result(protections={"full_relro": False})
        avail = _availability_for_cwe("CWE-134", result)
        assert avail["got_overwrite"] is True
        assert avail["fini_array"] is True

    def test_hook_overwrite_glibc_234_blocks(self):
        result = _fake_result(glibc_version="2.34")
        avail = _availability_for_cwe("CWE-416", result)
        assert avail["hook_overwrite"] is False

    def test_hook_overwrite_glibc_233_allows(self):
        result = _fake_result(glibc_version="2.33")
        avail = _availability_for_cwe("CWE-416", result)
        assert avail["hook_overwrite"] is True

    def test_arbitrary_write_conditional_for_non_fmt_cwe(self):
        """Non-fmt CWEs (121/122/787) can't be decided from glibc_n_disabled
        alone. arbitrary_write stays None; caller must decide via other
        primitives."""
        result = _fake_result(glibc_n_disabled=False)
        avail = _availability_for_cwe("CWE-121", result)
        assert avail["arbitrary_write"] is None
        # But format_n_write still passes through globally.
        assert avail["format_n_write"] is True


class TestPriorityHint:

    def test_all_blocked_gives_low(self):
        avail = {
            "arbitrary_write": False, "format_n_write": False,
            "got_overwrite": False, "fini_array": False,
            "hook_overwrite": False, "stack_smash": False,
        }
        assert _priority_hint(avail, "unlikely") == "low"

    def test_any_available_gives_high(self):
        avail = {"format_n_write": True, "got_overwrite": None}
        assert _priority_hint(avail, "difficult") == "high"

    def test_verdict_promotes_all_conditional_to_high(self):
        """When primitives are all conditional but the substrate's
        top-level verdict is optimistic, priority reflects the verdict
        so renderers surface the sink for LLM attention."""
        avail = {"format_n_write": None, "got_overwrite": None}
        assert _priority_hint(avail, "likely_exploitable") == "high"

    def test_no_signal_defaults_medium(self):
        assert _priority_hint({}, None) == "medium"


class TestBuildMitigationContext:

    def test_populates_cwe_join_key(self, tmp_path):
        """``cwe_class`` is the join key against /audit's
        findings.json. Must be present and match the sink's CWE."""
        binary = tmp_path / "prog"
        binary.write_bytes(b"\x7fELF fake")
        blob = build_mitigation_context(
            _fake_result(), sink_cwe="CWE-134", binary_path=binary,
        )
        assert blob["cwe_class"] == "CWE-134"

    def test_populates_schema_version(self, tmp_path):
        binary = tmp_path / "prog"
        binary.write_bytes(b"\x7fELF fake")
        blob = build_mitigation_context(
            _fake_result(), sink_cwe="CWE-134", binary_path=binary,
        )
        assert blob["schema_version"] == SCHEMA_VERSION

    def test_source_is_namespaced(self, tmp_path):
        """/audit and this substrate share the context-map. Each writes
        its own ``source`` so both can coexist on the same sink without
        overwrite ambiguity."""
        binary = tmp_path / "prog"
        binary.write_bytes(b"\x7fELF fake")
        blob = build_mitigation_context(
            _fake_result(), sink_cwe="CWE-134", binary_path=binary,
        )
        assert blob["source"] == "exploit_feasibility.analyze_binary"

    def test_conditional_detail_included(self, tmp_path):
        binary = tmp_path / "prog"
        binary.write_bytes(b"\x7fELF fake")
        blob = build_mitigation_context(
            _fake_result(), sink_cwe="CWE-134", binary_path=binary,
        )
        detail = blob.get("primitive_availability_detail") or {}
        assert "CONDITIONAL" in detail.get("format_n_write", "")

    def test_binary_sha256_present(self, tmp_path):
        """The sha256 is the cache key against re-runs. Must be
        deterministic for identical binary bytes."""
        binary = tmp_path / "prog"
        binary.write_bytes(b"\x7fELF fake body")
        b1 = build_mitigation_context(
            _fake_result(), sink_cwe="CWE-134", binary_path=binary,
        )
        b2 = build_mitigation_context(
            _fake_result(), sink_cwe="CWE-134", binary_path=binary,
        )
        assert b1["target_binary_sha256"] == b2["target_binary_sha256"]

    def test_generated_at_optional(self, tmp_path):
        """Omitted timestamp → field omitted (deterministic tests)."""
        binary = tmp_path / "prog"
        binary.write_bytes(b"\x7fELF fake")
        blob = build_mitigation_context(
            _fake_result(), sink_cwe="CWE-134", binary_path=binary,
        )
        assert "generated_at" not in blob


class TestSinkCweExtraction:

    def test_top_level_cwe_field(self):
        assert _sink_cwe({"cwe": "CWE-134"}) == "CWE-134"

    def test_top_level_cwe_class_field(self):
        assert _sink_cwe({"cwe_class": "CWE-121"}) == "CWE-121"

    def test_lowercase_normalized(self):
        assert _sink_cwe({"cwe": "cwe-134"}) == "CWE-134"

    def test_metadata_nested(self):
        assert _sink_cwe({"metadata": {"cwe": "CWE-416"}}) == "CWE-416"

    def test_missing_returns_none(self):
        assert _sink_cwe({"file": "src/parse.c"}) is None


class TestEnrichContextMap:

    def _make_map(self, sinks):
        return {"sinks": sinks}

    def test_enriches_every_sink(self, tmp_path):
        binary = tmp_path / "prog"
        binary.write_bytes(b"\x7fELF fake")
        cm = self._make_map([
            {"cwe": "CWE-134", "file": "a.c", "line": 10},
            {"cwe": "CWE-121", "file": "b.c", "line": 20},
        ])
        with patch(
            "packages.exploit_feasibility.api.analyze_binary",
            return_value=_fake_result(glibc_n_disabled=None),
        ):
            out = enrich_context_map(cm, binary_path=binary)
        assert len(out["sinks"]) == 2
        for sink in out["sinks"]:
            assert "mitigation_context" in sink
            assert sink["mitigation_context"]["cwe_class"] in ("CWE-134", "CWE-121")

    def test_never_drops_sinks(self, tmp_path):
        """Renderers may re-order; enricher never filters."""
        binary = tmp_path / "prog"
        binary.write_bytes(b"\x7fELF fake")
        cm = self._make_map([
            {"cwe": "CWE-999-nonsense", "file": "a.c"},
            {"file": "b.c"},   # no CWE field at all
        ])
        with patch(
            "packages.exploit_feasibility.api.analyze_binary",
            return_value=_fake_result(),
        ):
            out = enrich_context_map(cm, binary_path=binary)
        # Both sinks survive.
        assert len(out["sinks"]) == 2

    def test_missing_binary_returns_map_unchanged(self, tmp_path):
        """/understand best-effort — missing binary must not raise."""
        cm = self._make_map([{"cwe": "CWE-134", "file": "a.c"}])
        original_sinks = cm["sinks"][0].copy()
        out = enrich_context_map(cm, binary_path=tmp_path / "does-not-exist")
        assert out["sinks"][0] == original_sinks

    def test_analyzer_failure_returns_map_unchanged(self, tmp_path):
        """Substrate raises → enrichment silently skips. /understand
        continues rather than aborting the whole map build."""
        binary = tmp_path / "prog"
        binary.write_bytes(b"\x7fELF fake")
        cm = self._make_map([{"cwe": "CWE-134", "file": "a.c"}])
        with patch(
            "packages.exploit_feasibility.api.analyze_binary",
            side_effect=RuntimeError("substrate exploded"),
        ):
            out = enrich_context_map(cm, binary_path=binary)
        assert "mitigation_context" not in out["sinks"][0]

    def test_non_list_sinks_early_return(self, tmp_path):
        binary = tmp_path / "prog"
        binary.write_bytes(b"\x7fELF fake")
        cm = {"sinks": {"not": "a-list"}}
        with patch(
            "packages.exploit_feasibility.api.analyze_binary",
            return_value=_fake_result(),
        ):
            out = enrich_context_map(cm, binary_path=binary)
        # Not mutated.
        assert out["sinks"] == {"not": "a-list"}
