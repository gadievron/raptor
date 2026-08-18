"""Cloned-block drift (§3.9): fix-anchored + generic winnowing legs.

Fixture pairs: the fix-anchored near-clone missing the fix's guard
must confirm promote-capable with ``contract_source: fix_commit``;
the low-similarity pair must form no group; identical clones must
produce no deviation.
"""

from __future__ import annotations

import json
import textwrap

from core.audit.clone_drift import (
    CLONE_SIMILARITY,
    detect_clone_drift,
    fix_anchored_drift,
    load_fix_anchors,
)
from core.audit.consistency_verify import clone_drift_verdict
from core.audit.evidence_grade import is_tool_evidence
from core.testing import requires_ts

_GUARDED = textwrap.dedent("""\
    int handle_packet(pkt_t *p, size_t n) {
        if (validate_len(p, n) != 0)
            return -1;
        for (size_t i = 0; i < n; i++) {
            acc += p->data[i] * scale_factor(p, i);
            emit_sample(acc, p->flags, i);
        }
        flush_output(p, acc);
        return finalize_packet(p, acc, n);
    }
""")

# Same body, renamed identifiers, guard missing.
_DRIFTED = textwrap.dedent("""\
    int handle_frame(frm_t *f, size_t count) {
        for (size_t j = 0; j < count; j++) {
            total += f->data[j] * scale_factor(f, j);
            emit_sample(total, f->flags, j);
        }
        flush_output(f, total);
        return finalize_packet(f, total, count);
    }
""")

_UNRELATED = textwrap.dedent("""\
    char *format_name(const char *a, const char *b) {
        char *out = malloc(64);
        snprintf(out, 64, "%s.%s", a, b);
        return out;
    }
""")


class TestGenericWinnowing:
    @requires_ts('c')
    def test_guard_divergence_between_near_clones(self):
        devs = detect_clone_drift({
            "src/pkt.c": _GUARDED,
            "src/frm.c": _DRIFTED,
        })
        guard = [d for d in devs if d.kind == "guard"]
        assert len(guard) == 1
        d = guard[0]
        assert d.token == "validate_len"
        assert d.enclosing_function == "handle_frame"
        assert d.peer_function == "handle_packet"
        assert d.similarity >= CLONE_SIMILARITY
        pe = d.peer_evidence
        assert pe.dimension == "clone-drift"
        assert pe.formation == "clone"
        assert pe.contract_source == "majority"
        assert pe.rule_id == "consistency:clone-drift-majority"

    def test_low_similarity_pair_forms_no_group(self):
        devs = detect_clone_drift({
            "src/pkt.c": _GUARDED,
            "src/name.c": _UNRELATED,
        })
        assert devs == []

    def test_identical_clones_no_divergence(self):
        devs = detect_clone_drift({
            "src/a.c": _GUARDED,
            "src/b.c": _GUARDED.replace("handle_packet", "handle_copy"),
        })
        assert devs == []

    def test_short_functions_below_token_floor_skipped(self):
        short_a = "int a(void) { if (chk()) return 1; return 0; }\n"
        short_b = "int b(void) { return 0; }\n"
        assert detect_clone_drift({
            "src/a.c": short_a, "src/b.c": short_b,
        }) == []

    def test_detection_variant_never_standalone_evidence(self):
        assert not is_tool_evidence("consistency:clone-drift-majority")
        assert is_tool_evidence("consistency:clone-drift")


def _anchor(*, guard: str = "validate_len") -> dict:
    return {
        "file": "src/frm.c",
        "name": "handle_frame",
        "sha": "a" * 40,
        "guard": guard,
        "sensitive": "finalize_packet",
        "fixed_file": "src/pkt.c",
        "fixed_line": 2,
        "fixed_region": _GUARDED,
    }


class TestFixAnchoredLeg:
    @requires_ts('c')
    def test_near_clone_missing_guard_promotes(self):
        devs = fix_anchored_drift([_anchor()], {"src/frm.c": _DRIFTED})
        assert len(devs) == 1
        d = devs[0]
        assert d.kind == "fix_anchor"
        assert d.registry_grade
        assert d.fix_sha == "a" * 40
        pe = d.peer_evidence
        assert pe.contract_source == "fix_commit"
        assert pe.registry_grade
        assert pe.rule_id == "consistency:clone-drift"
        assert pe.provenance == f"fix_commit:{'a' * 12}"

        res = clone_drift_verdict(d)
        assert res.outcome == "confirmed"
        assert res.rule_id == "consistency:clone-drift"
        assert res.contract["source"] == "fix_commit"
        assert res.contract["grade"] == "registry"

    def test_guard_present_refutes_the_anchor(self):
        devs = fix_anchored_drift(
            [_anchor()],
            {"src/frm.c": _DRIFTED.replace(
                "for (size_t j = 0;",
                "if (validate_len(f, count) != 0)\n"
                "        return -1;\n"
                "    for (size_t j = 0;",
            )},
        )
        assert devs == []

    def test_low_containment_no_finding(self):
        devs = fix_anchored_drift(
            [_anchor()],
            {"src/frm.c": _UNRELATED.replace(
                "format_name", "handle_frame",
            ).replace("src/name.c", "src/frm.c")},
        )
        assert devs == []

    def test_anchors_loaded_from_fix_history_artifact(self, tmp_path):
        (tmp_path / "fix-history.json").write_text(json.dumps({
            "fixes": [],
            "variant_gaps": [],
            "regression_gaps": [],
            "variant_sites": [_anchor()],
        }))
        anchors = load_fix_anchors(tmp_path)
        assert len(anchors) == 1
        assert anchors[0]["guard"] == "validate_len"
        assert load_fix_anchors(tmp_path / "missing") == []


class TestVariantSiteRecords:
    def test_apply_fix_history_persists_anchor_records(self, tmp_path):
        """The additive variant_sites field carries the clone anchor:
        sha + guard + the current-tree fixed region."""
        from core.audit.fix_history import (
            SecurityFix,
            _variant_site_records,
        )

        target = tmp_path / "repo"
        target.mkdir()
        (target / "pkt.c").write_text(_GUARDED)
        fix = SecurityFix(
            sha="b" * 40,
            subject="fix overflow: validate length",
            category="overflow",
            added={"pkt.c": [(2, "    if (validate_len(p, n) != 0)")]},
        )
        variant_gap = {
            "file": "frm.c",
            "name": "handle_frame",
            "fix_anchor": {
                "sha": "b" * 40,
                "guard": "validate_len",
                "sensitive": "finalize_packet",
            },
        }
        records = _variant_site_records([variant_gap], [fix], target)
        assert len(records) == 1
        r = records[0]
        assert r["sha"] == "b" * 40
        assert r["guard"] == "validate_len"
        assert r["fixed_file"] == "pkt.c"
        assert "validate_len" in r["fixed_region"]

    def test_no_anchor_no_record(self, tmp_path):
        from core.audit.fix_history import _variant_site_records

        assert _variant_site_records(
            [{"file": "a.c", "name": "f"}], [], tmp_path,
        ) == []


class TestPrepassWiring:
    @requires_ts('c')
    def test_fix_anchored_finding_and_generic_lead(self, tmp_path):
        from core.audit.consistency_prepass import run_consistency_prepass

        (tmp_path / "fix-history.json").write_text(json.dumps({
            "variant_sites": [_anchor()],
        }))
        res = run_consistency_prepass(
            {"src/pkt.c": _GUARDED, "src/frm.c": _DRIFTED},
            out_dir=tmp_path,
        )
        drift_findings = [
            f for f in res["findings"]
            if f["dimension"] == "clone-drift"
        ]
        assert len(drift_findings) == 1
        f = drift_findings[0]
        assert f["rule_id"] == "consistency:clone-drift"
        assert f["detection_grade"] is False
        assert res["telemetry"]["contract_sources"].get(
            "fix_commit") == 1
        # The generic leg sees the same pair and seeds a lead.
        generic_leads = [
            ld for ld in res["leads"]
            if ld["dimension"] == "clone-drift"
            and ld["rule_id"] == "consistency:clone-drift-majority"
        ]
        assert generic_leads


class TestGrammarAbsentDegradation:
    """Grammar-absent must be a LOUD degraded signal, not a silent
    zero-deviation result — the fix-anchored leg is promote-capable
    and used to drop every fix anchor unchecked."""

    @staticmethod
    def _block_grammar(monkeypatch):
        import core.audit.consistency_dimensions as cd
        monkeypatch.setattr(cd, "_TS_AVAILABLE", False)

    def test_fix_anchored_leg_signals_degraded(
        self, monkeypatch, caplog,
    ):
        from core.audit.clone_drift import fix_anchored_drift

        self._block_grammar(monkeypatch)
        telemetry: dict = {}
        with caplog.at_level("WARNING", logger="core.audit.clone_drift"):
            out = fix_anchored_drift(
                [_anchor()], {"src/frm.c": _DRIFTED},
                telemetry=telemetry,
            )
        assert out == []
        assert telemetry.get("degraded", 0) == 1
        assert any("fix-anchored" in r
                   for r in telemetry.get("degraded_reasons", []))
        assert any("dropped unchecked" in rec.getMessage()
                   for rec in caplog.records)

    def test_winnowing_leg_signals_degraded(self, monkeypatch, caplog):
        from core.audit.clone_drift import detect_clone_drift

        self._block_grammar(monkeypatch)
        telemetry: dict = {}
        with caplog.at_level("WARNING", logger="core.audit.clone_drift"):
            out = detect_clone_drift(
                {"src/frm.c": _DRIFTED}, telemetry=telemetry,
            )
        assert out == []
        assert telemetry.get("degraded", 0) == 1

    def test_no_signal_when_nothing_to_check(self, monkeypatch, caplog):
        from core.audit.clone_drift import (
            detect_clone_drift,
            fix_anchored_drift,
        )

        self._block_grammar(monkeypatch)
        telemetry: dict = {}
        assert fix_anchored_drift([], {}, telemetry=telemetry) == []
        assert detect_clone_drift({}, telemetry=telemetry) == []
        assert "degraded" not in telemetry
