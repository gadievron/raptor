"""Sanitize-before-sink consistency dimension (§3.3).

Fixture pairs per the design's test plan: raw-writer-among-escaped-
writers → detection-grade lead with sanitizing exhibits; the
operator-annotated-convention twin → promote-capable. Plus the two
policy proofs this dimension owes: the comparator carries no sink or
sanitizer vocabulary of its own, and the premise split with the
fail-open channel (presence premise here, failure-handling premise
there) holds.
"""

from __future__ import annotations

import textwrap

from core.audit.consistency_dimensions import (
    DIMENSION_SANITIZE_SINK,
    detect_sanitize_sink_deviations,
)
from core.audit.consistency_verify import (
    RULE_SANITIZE_SINK,
    sanitize_sink_verdict,
)
from core.testing import requires_ts

_SINKS = {
    "db_exec": {"source": "context_map", "cwe": "CWE-89",
                "registry": False},
}
_SANITIZERS = frozenset({"escape_sql"})


def _writer(i: int) -> str:
    return textwrap.dedent(f"""\
        int writer_{i}(const char *raw) {{
            char *q = escape_sql(raw);
            db_exec(q);
            return 0;
        }}
    """)


def _fixture(*, deviant: bool, conforming: int = 3) -> dict[str, str]:
    parts = [_writer(i) for i in range(conforming)]
    if deviant:
        parts.append(textwrap.dedent("""\
            int writer_dev(const char *raw) {
                db_exec(raw);
                return 0;
            }
        """))
    else:
        parts.append(_writer(99))
    return {"src/writers.c": "\n".join(parts)}


class TestSanitizeSinkComparator:
    @requires_ts('c')
    def test_raw_writer_among_escaped_writers_is_flagged(self):
        devs = detect_sanitize_sink_deviations(
            _fixture(deviant=True), _SINKS, _SANITIZERS,
        )
        assert len(devs) == 1
        d = devs[0]
        assert d.sink == "db_exec"
        assert d.enclosing_function == "writer_dev"
        assert (d.n, d.conforming) == (4, 3)
        assert d.cwe == "CWE-89"
        assert not d.annotated and not d.registry_grade

    @requires_ts('c')
    def test_receipt_carries_sanitizing_exhibits(self):
        d = detect_sanitize_sink_deviations(
            _fixture(deviant=True), _SINKS, _SANITIZERS,
        )[0]
        pe = d.peer_evidence
        assert pe.dimension == DIMENSION_SANITIZE_SINK
        assert pe.formation == "same_sink"
        assert pe.group_key == "db_exec"
        assert pe.contract_source == "majority"
        assert pe.rule_id == "consistency:sanitize-sink-majority"
        assert pe.deviant is not None
        assert "db_exec(raw)" in pe.deviant.snippet
        # The exhibits quote the sanitizing lines, not the sink lines.
        assert len(pe.exhibits) == 3
        assert all("escape_sql" in e.snippet for e in pe.exhibits)

    def test_conforming_twin_not_flagged(self):
        assert detect_sanitize_sink_deviations(
            _fixture(deviant=False), _SINKS, _SANITIZERS,
        ) == []

    def test_inline_sanitizer_application_conforms(self):
        texts = _fixture(deviant=True)
        texts["src/writers.c"] = texts["src/writers.c"].replace(
            "db_exec(raw);\n    return 0;",
            "db_exec(escape_sql(raw));\n    return 0;",
        )
        assert detect_sanitize_sink_deviations(
            texts, _SINKS, _SANITIZERS,
        ) == []

    def test_group_too_small_not_flagged(self):
        devs = detect_sanitize_sink_deviations(
            _fixture(deviant=True, conforming=1), _SINKS, _SANITIZERS,
        )
        assert devs == []

    def test_no_learned_vocabulary_no_deviations(self):
        """Vocab-policy proof: the comparator has no sink or sanitizer
        list of its own — either surface empty means silence."""
        texts = _fixture(deviant=True)
        assert detect_sanitize_sink_deviations(
            texts, {}, _SANITIZERS) == []
        assert detect_sanitize_sink_deviations(
            texts, _SINKS, frozenset()) == []


class TestPremiseSplit:
    """§5.1 composition: presence premise here, failure handling in
    fail_open / return-check."""

    def test_ignored_sanitizer_return_still_conforms(self):
        """A site that CALLS the sanitizer but discards its result
        satisfies this dimension's presence premise — the ignored
        return is the census / fail_open channel's claim, not ours."""
        texts = _fixture(deviant=True)
        texts["src/writers.c"] = texts["src/writers.c"].replace(
            "    db_exec(raw);",
            "    escape_sql(raw);\n    db_exec(raw);",
        )
        assert detect_sanitize_sink_deviations(
            texts, _SINKS, _SANITIZERS,
        ) == []

    def test_verdict_never_binds_a_role_or_hands_off(self):
        for dev in detect_sanitize_sink_deviations(
                _fixture(deviant=True), _SINKS, _SANITIZERS):
            res = sanitize_sink_verdict(dev)
            assert res.fail_open_handoff is False
            assert "fail_open" not in (res.to_dict().get("reason") or "")


@requires_ts('c')
class TestSanitizeSinkVerdict:
    def test_majority_only_is_detection_grade(self):
        dev = detect_sanitize_sink_deviations(
            _fixture(deviant=True), _SINKS, _SANITIZERS,
        )[0]
        res = sanitize_sink_verdict(dev)
        assert res.outcome == "confirmed"
        assert res.rule_id == "consistency:sanitize-sink-majority"
        assert res.dimension == DIMENSION_SANITIZE_SINK
        assert res.contract is None

    def test_annotated_convention_below_promote_floor_stays_detection(self):
        sinks = {"db_exec": {**_SINKS["db_exec"], "source": "annotation",
                             "registry": True}}
        dev = detect_sanitize_sink_deviations(
            _fixture(deviant=True), sinks, _SANITIZERS,
        )[0]
        # 3/4 = 0.75 < the 0.9 promote-adjacent floor.
        assert dev.annotated and not dev.registry_grade
        res = sanitize_sink_verdict(dev)
        assert res.rule_id == "consistency:sanitize-sink-majority"

    def test_annotated_convention_twin_promotes(self):
        sinks = {"db_exec": {**_SINKS["db_exec"], "source": "annotation",
                             "registry": True}}
        dev = detect_sanitize_sink_deviations(
            _fixture(deviant=True, conforming=9), sinks, _SANITIZERS,
        )[0]
        assert dev.registry_grade
        assert dev.peer_evidence.contract_source == "annotation"
        res = sanitize_sink_verdict(dev)
        assert res.outcome == "confirmed"
        assert res.rule_id == RULE_SANITIZE_SINK
        assert res.contract == {
            "source": "annotation",
            "provenance": "annotation:sink:db_exec",
            "grade": "registry",
        }


class TestPrepassIntegration:
    def _seed_vocab(self, tmp_path, out):
        from core.annotations.models import Annotation
        from core.annotations.storage import write_annotation
        from core.evidence import EvidenceTier
        from core.iris.specs import TaintSpec
        from core.iris.store import save_specs

        ann_dir = tmp_path / "annotations"
        ann_dir.mkdir()
        write_annotation(ann_dir, Annotation(
            file="src/writers.c",
            function="db_exec",
            body="Executes raw SQL — every caller must escape first.",
            metadata={"status": "sink", "source": "human",
                      "cwe": "CWE-89"},
        ))
        save_specs(out, [TaintSpec(
            function="escape_sql",
            file="src/writers.c",
            role="sanitiser",
            evidence_tier=EvidenceTier.XREF_BACKED,
        )])
        return ann_dir

    @requires_ts('c')
    def test_annotated_sink_yields_promote_capable_finding(self, tmp_path):
        from core.audit.consistency_prepass import run_consistency_prepass

        out = tmp_path / "out"
        out.mkdir()
        ann_dir = self._seed_vocab(tmp_path, out)
        prepass = run_consistency_prepass(
            _fixture(deviant=True, conforming=9),
            out_dir=out,
            annotations_dir=ann_dir,
        )
        found = [
            f for f in prepass["findings"]
            if f["dimension"] == DIMENSION_SANITIZE_SINK
        ]
        assert len(found) == 1
        f = found[0]
        assert f["function"] == "writer_dev"
        assert f["rule_id"] == RULE_SANITIZE_SINK
        assert f["cwe"] == "CWE-89"
        assert f["status"] == "suspicious"  # reachability unknown (G7)
        assert not f["detection_grade"]
        mech = [
            m for m in prepass["mechanical"]
            if m["detector"] == "sanitize_sink_deviation"
        ]
        assert mech and mech[0]["callee"] == "db_exec"
        dims = prepass["telemetry"]["dimensions"]
        assert dims[DIMENSION_SANITIZE_SINK]["confirmed"] == 1
        assert prepass["telemetry"]["contract_sources"].get(
            "annotation") == 1

    def test_without_learned_vocab_dimension_is_silent(self, tmp_path):
        from core.audit.consistency_prepass import run_consistency_prepass

        out = tmp_path / "out"
        out.mkdir()
        prepass = run_consistency_prepass(
            _fixture(deviant=True, conforming=9),
            out_dir=out,
        )
        assert DIMENSION_SANITIZE_SINK not in (
            prepass["telemetry"]["dimensions"]
        )
