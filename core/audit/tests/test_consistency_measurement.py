"""Ground-truth corpus seed for the consistency dimensions (§4.4).

Per-dimension precision is tracked run-over-run through the existing
``measurement.py`` machinery: a target ships ``ground-truth.json``,
the run's findings land in ``findings.json``, ``evaluate_run`` scores
them. These fixtures are the corpus entries for the phase-1
dimensions — the failopen phase-3 discipline (promotion rights for
any detection-grade variant expand only behind a measured precision
report) starts from here.
"""

from __future__ import annotations

import json

from core.audit.consistency_prepass import run_consistency_prepass
from core.audit.measurement import evaluate_run, load_ground_truth
from core.testing import requires_ts


def _callers(checked: int, deviant: bool) -> str:
    parts = []
    for i in range(checked):
        parts.append(
            f"int caller_{i}(void) {{\n"
            f"    if (do_auth() != 0)\n"
            f"        return -1;\n"
            f"    return 0;\n}}\n"
        )
    if deviant:
        parts.append(
            "int caller_dev(void) {\n    do_auth();\n    return 0;\n}\n"
        )
    else:
        parts.append(
            "int caller_dev(void) {\n"
            "    if (do_auth() != 0)\n        return -1;\n"
            "    return 0;\n}\n"
        )
    return "\n".join(parts)


_WUR = "__attribute__((warn_unused_result)) int do_auth(void);\n"

_GROUND_TRUTH = [{
    "id": "GT-CONSISTENCY-1",
    "file": "callers.c",
    "function": "caller_dev",
    "line": 0,
    "vuln_type": "CWE-252",
    "description": "return of do_auth() discarded; 9/10 sites check",
    "depth": "L1",
}]


def _run(tmp_path, *, deviant: bool):
    target = tmp_path / "target"
    target.mkdir()
    (target / "callers.c").write_text(_callers(9, deviant))
    (target / "api.h").write_text(_WUR)
    (target / "ground-truth.json").write_text(json.dumps(_GROUND_TRUTH))

    out = tmp_path / "out"
    out.mkdir()
    prepass = run_consistency_prepass(
        {"callers.c": (target / "callers.c").read_text()},
        target_path=target,
        out_dir=out,
    )
    (out / "findings.json").write_text(json.dumps([
        {
            "file": f["file"],
            "function": f["function"],
            "status": f["status"],
            "evidence_chain": [{"source": "mechanical:tree_sitter"}],
        }
        for f in prepass["findings"]
    ]))
    truth = load_ground_truth(target)
    return evaluate_run(out, truth), prepass


class TestReturnCheckGroundTruth:
    def test_deviant_fixture_scores_true_positive(self, tmp_path):
        result, prepass = _run(tmp_path, deviant=True)
        assert prepass["findings"], "prepass produced no finding"
        assert len(result.true_positives) == 1
        assert result.true_positives[0].id == "GT-CONSISTENCY-1"
        assert result.false_positives == []
        assert result.detection_rate == 1.0
        assert result.precision == 1.0

    def test_conforming_twin_scores_no_false_positive(self, tmp_path):
        result, prepass = _run(tmp_path, deviant=False)
        assert prepass["findings"] == []
        assert result.false_positives == []
        assert len(result.false_negatives) == 1


class TestArgumentShapeGroundTruth:
    @requires_ts('c')
    def test_type_witness_scores_true_positive(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        parts = []
        for i in range(4):
            parts.append(
                f"void copy_{i}(const char *s) {{\n"
                f"    char buf{i}[64];\n"
                f"    fill_buffer(buf{i}, sizeof(buf{i}), s);\n}}\n"
            )
        parts.append(
            "void copy_dev(const char *s, char *out) {\n"
            "    fill_buffer(out, sizeof(out), s);\n}\n"
        )
        (target / "copy.c").write_text("\n".join(parts))
        (target / "ground-truth.json").write_text(json.dumps([{
            "id": "GT-ARGSHAPE-1",
            "file": "copy.c",
            "function": "copy_dev",
            "vuln_type": "CWE-467",
            "depth": "L1",
        }]))
        out = tmp_path / "out"
        out.mkdir()
        prepass = run_consistency_prepass(
            {"copy.c": (target / "copy.c").read_text()},
            target_path=target,
            out_dir=out,
        )
        shape = [
            f for f in prepass["findings"]
            if f["dimension"] == "argument-shape"
        ]
        assert shape and shape[0]["function"] == "copy_dev"
        (out / "findings.json").write_text(json.dumps([
            {
                "file": f["file"],
                "function": f["function"],
                "status": f["status"],
            }
            for f in shape
        ]))
        result = evaluate_run(out, load_ground_truth(target))
        assert len(result.true_positives) == 1
        assert result.false_positives == []


class TestCloneDriftGroundTruth:
    @requires_ts('c')
    def test_fix_anchored_drift_scores_true_positive(self, tmp_path):
        guarded = (
            "int wire_a(pkt_t *p, size_t n) {\n"
            "    if (validate_len(p, n) != 0)\n"
            "        return -1;\n"
            "    for (size_t i = 0; i < n; i++) {\n"
            "        acc += p->data[i] * scale_factor(p, i);\n"
            "        emit_sample(acc, p->flags, i);\n"
            "    }\n"
            "    flush_output(p, acc);\n"
            "    return finalize_packet(p, acc, n);\n}\n"
        )
        drifted = guarded.replace("wire_a", "wire_b").replace(
            "    if (validate_len(p, n) != 0)\n        return -1;\n",
            "",
        )
        target = tmp_path / "target"
        target.mkdir()
        (target / "wb.c").write_text(drifted)
        (target / "ground-truth.json").write_text(json.dumps([{
            "id": "GT-CLONEDRIFT-1",
            "file": "wb.c",
            "function": "wire_b",
            "vuln_type": "CWE-120",
            "depth": "L1",
        }]))
        out = tmp_path / "out"
        out.mkdir()
        (out / "fix-history.json").write_text(json.dumps({
            "variant_sites": [{
                "file": "wb.c", "name": "wire_b", "sha": "d" * 40,
                "guard": "validate_len",
                "sensitive": "finalize_packet",
                "fixed_file": "wa.c", "fixed_line": 2,
                "fixed_region": guarded,
            }],
        }))
        prepass = run_consistency_prepass(
            {"wb.c": drifted},
            target_path=target,
            out_dir=out,
        )
        drift = [
            f for f in prepass["findings"]
            if f["dimension"] == "clone-drift"
        ]
        assert drift and drift[0]["function"] == "wire_b"
        (out / "findings.json").write_text(json.dumps([
            {
                "file": f["file"],
                "function": f["function"],
                "status": f["status"],
            }
            for f in drift
        ]))
        result = evaluate_run(out, load_ground_truth(target))
        assert len(result.true_positives) == 1
        assert result.false_positives == []


class TestCleanupGroundTruth:
    @requires_ts('c')
    def test_cleanup_dimension_scores_true_positive(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        parts = []
        for i in range(3):
            parts.append(
                f"int user_{i}(void) {{\n"
                f"    res_t *r{i} = grab_lock();\n"
                f"    use(r{i});\n"
                f"    drop_lock(r{i});\n"
                f"    return 0;\n}}\n"
            )
        parts.append(
            "int leaker(void) {\n"
            "    res_t *r = grab_lock();\n"
            "    use(r);\n"
            "    return 0;\n}\n"
        )
        (target / "users.c").write_text("\n".join(parts))
        (target / "ground-truth.json").write_text(json.dumps([{
            "id": "GT-CLEANUP-1",
            "file": "users.c",
            "function": "leaker",
            "vuln_type": "CWE-667",
            "depth": "L1",
        }]))
        out = tmp_path / "out"
        out.mkdir()
        prepass = run_consistency_prepass(
            {"users.c": (target / "users.c").read_text()},
            target_path=target,
            out_dir=out,
            domain_model={"paired_operations": [{
                "acquire": "grab_lock",
                "release": "drop_lock",
                "kind": "mutex",
            }]},
        )
        cleanup = [
            f for f in prepass["findings"]
            if f["dimension"] == "cleanup"
        ]
        assert cleanup and cleanup[0]["function"] == "leaker"
        (out / "findings.json").write_text(json.dumps([
            {
                "file": f["file"],
                "function": f["function"],
                "status": f["status"],
            }
            for f in cleanup
        ]))
        result = evaluate_run(out, load_ground_truth(target))
        assert len(result.true_positives) == 1
        assert result.false_positives == []


class TestSanitizeSinkGroundTruth:
    """§3.3 corpus entry: the operator-annotated-convention shape (the
    dimension's only promote-capable premise) measured end to end
    through the prepass + measurement machinery."""

    def _writer(self, i: int) -> str:
        return (
            f"int writer_{i}(const char *raw) {{\n"
            f"    char *q = escape_sql(raw);\n"
            f"    db_exec(q);\n"
            f"    return 0;\n}}\n"
        )

    def _run(self, tmp_path, *, deviant: bool):
        from core.annotations.models import Annotation
        from core.annotations.storage import write_annotation
        from core.evidence import EvidenceTier
        from core.iris.specs import TaintSpec
        from core.iris.store import save_specs

        target = tmp_path / "target"
        target.mkdir()
        parts = [self._writer(i) for i in range(9)]
        if deviant:
            parts.append(
                "int writer_dev(const char *raw) {\n"
                "    db_exec(raw);\n    return 0;\n}\n"
            )
        else:
            parts.append(self._writer(99))
        (target / "writers.c").write_text("\n".join(parts))
        (target / "ground-truth.json").write_text(json.dumps([{
            "id": "GT-SANITIZE-SINK-1",
            "file": "writers.c",
            "function": "writer_dev",
            "vuln_type": "CWE-89",
            "depth": "L1",
        }]))
        out = tmp_path / "out"
        out.mkdir()
        ann_dir = tmp_path / "annotations"
        ann_dir.mkdir()
        write_annotation(ann_dir, Annotation(
            file="writers.c",
            function="db_exec",
            body="Raw SQL executor — callers must escape first.",
            metadata={"status": "sink", "source": "human",
                      "cwe": "CWE-89"},
        ))
        save_specs(out, [TaintSpec(
            function="escape_sql",
            file="writers.c",
            role="sanitiser",
            evidence_tier=EvidenceTier.XREF_BACKED,
        )])
        prepass = run_consistency_prepass(
            {"writers.c": (target / "writers.c").read_text()},
            target_path=target,
            out_dir=out,
            annotations_dir=ann_dir,
        )
        found = [
            f for f in prepass["findings"]
            if f["dimension"] == "sanitize-sink"
        ]
        (out / "findings.json").write_text(json.dumps([
            {
                "file": f["file"],
                "function": f["function"],
                "status": f["status"],
            }
            for f in found
        ]))
        return evaluate_run(out, load_ground_truth(target)), found

    @requires_ts('c')
    def test_raw_writer_scores_true_positive(self, tmp_path):
        result, found = self._run(tmp_path, deviant=True)
        assert found and found[0]["rule_id"] == \
            "consistency:sanitize-sink"
        assert len(result.true_positives) == 1
        assert result.true_positives[0].id == "GT-SANITIZE-SINK-1"
        assert result.false_positives == []

    def test_conforming_twin_scores_no_false_positive(self, tmp_path):
        result, found = self._run(tmp_path, deviant=False)
        assert found == []
        assert result.false_positives == []
        assert len(result.false_negatives) == 1


class TestGuardPresenceGroundTruth:
    """§3.4 corpus entry: the SMT-witnessed upgrade shape, hermetic —
    the solver leg is stubbed feasible/absent exactly as the design's
    test plan prescribes (no z3 subprocess in the corpus), so the
    entry measures the comparator + verdict + measurement machinery,
    not solver availability."""

    def _guarded(self, i: int) -> str:
        return (
            f"int use_{i}(map_t *m) {{\n"
            f"    entry_t *e = lookup_entry(m);\n"
            f"    if (!e)\n        return -1;\n"
            f"    return e->value;\n}}\n"
        )

    def _run(self, tmp_path, *, deviant: bool):
        from types import SimpleNamespace

        from core.audit.consistency_dimensions import (
            detect_guard_presence_deviations,
        )
        from core.audit.consistency_verify import guard_presence_verdict

        target = tmp_path / "target"
        target.mkdir()
        parts = [self._guarded(i) for i in range(9)]
        if deviant:
            parts.append(
                "int use_dev(map_t *m) {\n"
                "    entry_t *e = lookup_entry(m);\n"
                "    return e->value;\n}\n"
            )
        else:
            parts.append(self._guarded(99))
        (target / "map.c").write_text("\n".join(parts))
        (target / "ground-truth.json").write_text(json.dumps([{
            "id": "GT-GUARD-PRESENCE-1",
            "file": "map.c",
            "function": "use_dev",
            "vuln_type": "CWE-476",
            "depth": "L1",
        }]))
        out = tmp_path / "out"
        out.mkdir()
        texts = {"map.c": (target / "map.c").read_text()}
        findings = []
        for dev in detect_guard_presence_deviations(texts):
            res = guard_presence_verdict(
                dev,
                source_texts=texts,
                smt_check=lambda d: SimpleNamespace(
                    feasible=True, reasoning="sat", witness={"e": 0},
                ),
            )
            if res.outcome == "confirmed" \
                    and not res.rule_id.endswith("-majority"):
                findings.append({
                    "file": dev.file,
                    "function": dev.enclosing_function,
                    "status": "suspicious",
                    "rule_id": res.rule_id,
                })
        (out / "findings.json").write_text(json.dumps(findings))
        return evaluate_run(out, load_ground_truth(target)), findings

    @requires_ts('c')
    def test_unguarded_deref_scores_true_positive(self, tmp_path):
        result, findings = self._run(tmp_path, deviant=True)
        assert findings and findings[0]["rule_id"] == \
            "consistency:guard-presence"
        assert len(result.true_positives) == 1
        assert result.true_positives[0].id == "GT-GUARD-PRESENCE-1"
        assert result.false_positives == []

    def test_conforming_twin_scores_no_false_positive(self, tmp_path):
        result, findings = self._run(tmp_path, deviant=False)
        assert findings == []
        assert result.false_positives == []
        assert len(result.false_negatives) == 1
