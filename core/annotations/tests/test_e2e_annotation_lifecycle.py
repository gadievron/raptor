"""Cross-package E2E for the annotation-emission lifecycle.

Scope is narrow on purpose: every helper that *writes annotations
to disk* is exercised against a single shared annotations directory.
The cross-cutting properties this pins are limited to:

  * ``respect-manual`` is honoured end-to-end across LLM emission
    sources, even when they target the same function the operator
    annotated.
  * Last-writer-wins between LLM sources behaves predictably as
    findings progress through the validate stages.
  * The chronological lifecycle (Stage A → IRIS Tier 1 refute) lands
    the IRIS verdict and Stage A → Stage B → Stage D promotes the
    finding ruling.
  * ``build_from_annotations`` produces a coverage record covering
    every annotated function, with status preserved per entry.

Sources exercised, in the order an operator would invoke them:

  1. ``/annotate add`` — manual operator note (``source=human``)
     via ``write_annotation`` directly.
  2. ``/understand --map`` post-processor —
     ``synthesise_from_understand_output`` walks ``context-map.json``
     and emits entry_point / sink / trust_boundary / unchecked_flow
     annotations.
  3. ``/understand --trace`` post-processor — same call walks
     ``flow-trace-*.json`` and emits per-step ``flow_step``
     annotations.
  4. ``/understand --hunt`` post-processor — walks ``variants.json``
     and emits per-variant annotations (``finding`` / ``suspicious``
     based on taint_status).
  5. ``/validate`` Stage A — ``emit_stage_annotations(workdir, "A")``.
  6. ``/validate`` IRIS Tier 1 gate — ``emit_iris_tier1_annotations``.
  7. ``/validate`` Stage B — ``emit_stage_annotations(workdir, "B")``.
  8. ``/validate`` Stage D — ``emit_stage_annotations(workdir, "D")``.

What this test does NOT cover (each warrants a focused test rather
than bundling here, and the per-package suites already exercise the
single-source paths in depth):

  * /agentic's ``emit_finding_annotation`` — exercised by
    ``packages/llm_analysis/tests/test_annotation_emit.py`` with
    realistic ``vuln`` objects against the LLM-analysis schema.
  * CLI subprocess paths — per-package ``TestShim`` classes cover
    each ``libexec`` shim end-to-end.
  * Strategy-block wiring (PRs ε / ζ / η) — those wire substrates
    into LLM dispatch user_messages, not annotations; their own
    test files exercise them.
  * Hash-staleness lifecycle (``/annotate stale`` after source edits).
  * Cross-process concurrent writes (substrate uses tempfile+rename
    for atomicity; sequential test driver here doesn't exercise the
    race).
  * Path-traversal in finding/variant ``file`` fields across sources
    (the per-source adversarial suites pin this individually).
  * Unicode function names across sources.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest

from core.annotations import (
    Annotation,
    iter_all_annotations,
    read_annotation,
    write_annotation,
)
from core.coverage.record import build_from_annotations


# ``packages.*`` cross-package imports happen lazily inside the
# ``emits`` fixture rather than at module level. Pytest's
# ``--import-mode=importlib`` (configured in pytest.ini) doesn't add
# the repo root to ``sys.path``, so module-level
# ``from packages.X import Y`` fails during collection on CI even
# though it works locally where dev shells happen to have the root
# on ``PYTHONPATH``. The fixture defers the lookup until pytest has
# finished setting up the test environment.


@pytest.fixture
def emits():
    """Bundle of cross-package emission helpers used by the lifecycle
    tests. Keys: ``synth_understand``, ``stage_annotations``,
    ``iris_tier1_annotations``."""
    from packages.code_understanding.annotation_synth import (
        synthesise_from_understand_output,
    )
    from packages.exploitability_validation.annotation_emit import (
        emit_iris_tier1_annotations,
        emit_stage_annotations,
    )

    class _Emits:
        synth_understand = staticmethod(synthesise_from_understand_output)
        stage_annotations = staticmethod(emit_stage_annotations)
        iris_tier1_annotations = staticmethod(emit_iris_tier1_annotations)

    return _Emits


# ---------------------------------------------------------------------------
# Shared fixture: a realistic repo + run dir with all the input artefacts
# the post-processors and stage emits expect.
# ---------------------------------------------------------------------------


@pytest.fixture
def project(tmp_path):
    """Build a small but realistic project state with one shared
    annotations directory used by every emit source.

    Layout:
      tmp_path/
        repo/
          src/api/upload.py     — has save_user_upload (path traversal target)
          src/db/query.py       — has run_query (sql injection target)
          src/auth/login.py     — has check_credentials (auth check)
          src/util/helpers.py   — has utility (operator-reviewed)
          src/cleanup/buf.c     — has release_buf (UAF candidate)
        run/
          checklist.json        — inventory used by post-processors
          context-map.json      — for /understand --map pass
          flow-trace-EP-001.json — for /understand --trace pass
          variants.json         — for /understand --hunt pass
          findings.json         — for /validate Stage A/B/D emits
          annotations/          — single shared dir all sources write to
    """
    repo = tmp_path / "repo"
    (repo / "src" / "api").mkdir(parents=True)
    (repo / "src" / "db").mkdir()
    (repo / "src" / "auth").mkdir()
    (repo / "src" / "util").mkdir()
    (repo / "src" / "cleanup").mkdir()

    # Place each function on a stable line so inventory line_start /
    # line_end can resolve them. Pad with newlines so hash computation
    # has real source content.
    (repo / "src" / "api" / "upload.py").write_text(
        "\n" * 9
        + "def save_user_upload(req):\n"
        + "    path = req.path\n"
        + "    return open(path, 'wb')\n"
    )
    (repo / "src" / "db" / "query.py").write_text(
        "\n" * 19
        + "def run_query(s):\n"
        + "    cursor.execute(f'SELECT * FROM t WHERE x = {s}')\n"
    )
    (repo / "src" / "auth" / "login.py").write_text(
        "\n" * 4
        + "def check_credentials(req):\n"
        + "    return req.token == 'admin'\n"
    )
    (repo / "src" / "util" / "helpers.py").write_text(
        "\n" * 2
        + "def utility():\n"
        + "    return 42\n"
    )
    (repo / "src" / "cleanup" / "buf.c").write_text(
        "\n" * 14
        + "void release_buf(buf *b) {\n"
        + "    free(b);\n"
        + "}\n"
    )

    run = tmp_path / "run"
    run.mkdir()

    checklist = {
        "target_path": str(repo),
        "files": [
            {
                "path": "src/api/upload.py",
                "items": [{"name": "save_user_upload",
                           "line_start": 10, "line_end": 12}],
            },
            {
                "path": "src/db/query.py",
                "items": [{"name": "run_query",
                           "line_start": 20, "line_end": 21}],
            },
            {
                "path": "src/auth/login.py",
                "items": [{"name": "check_credentials",
                           "line_start": 5, "line_end": 6}],
            },
            {
                "path": "src/util/helpers.py",
                "items": [{"name": "utility",
                           "line_start": 3, "line_end": 4}],
            },
            {
                "path": "src/cleanup/buf.c",
                "items": [{"name": "release_buf",
                           "line_start": 15, "line_end": 17}],
            },
        ],
    }
    (run / "checklist.json").write_text(json.dumps(checklist))

    return repo, run


# ---------------------------------------------------------------------------
# Helpers for layering the JSON inputs the various post-processors expect.
# ---------------------------------------------------------------------------


def _write_context_map(run: Path) -> None:
    cmap = {
        "entry_points": [
            {"id": "EP-001", "type": "http_route",
             "method": "POST", "path": "/api/upload",
             "file": "src/api/upload.py", "line": 10,
             "accepts": "multipart", "auth_required": True},
        ],
        "sink_details": [
            {"id": "SINK-001", "type": "filesystem",
             "operation": "open(path)",
             "file": "src/api/upload.py", "line": 12},
            {"id": "SINK-002", "type": "database",
             "operation": "cursor.execute",
             "file": "src/db/query.py", "line": 21},
        ],
        "boundary_details": [
            {"id": "BND-001", "type": "auth_check",
             "file": "src/auth/login.py", "line": 5},
        ],
        "unchecked_flows": [
            {"entry_point": "EP-001", "sink": "SINK-001",
             "description": "Path traversal — no canonicalisation"},
        ],
    }
    (run / "context-map.json").write_text(json.dumps(cmap))


def _write_flow_trace(run: Path) -> None:
    trace = {
        "trace_id": "EP-001",
        "steps": [
            {"step": 1, "type": "entry",
             "definition": "src/api/upload.py:10",
             "description": "request enters",
             "tainted_var": "req", "transform": "none",
             "confidence": "high"},
            {"step": 2, "type": "sink",
             "definition": "src/api/upload.py:12",
             "description": "path reaches open()",
             "tainted_var": "path", "transform": "none",
             "confidence": "high"},
        ],
    }
    (run / "flow-trace-EP-001.json").write_text(json.dumps(trace))


def _write_variants(run: Path, variants: List[Dict[str, Any]]) -> None:
    (run / "variants.json").write_text(
        json.dumps({"variants": variants}),
    )


def _write_findings(run: Path, findings: List[Dict[str, Any]]) -> None:
    (run / "findings.json").write_text(json.dumps({
        "stage": "A",
        "target_path": str(run.parent / "repo"),
        "findings": findings,
    }))


def _basic_finding(
    fid: str, file: str, function: str,
    cwe: str = "CWE-22", rule_id: str = "py/path-traversal",
    vuln_type: str = "path_traversal",
    stage_a_status: str = "not_disproven",
    description: str = "Untrusted path reaches open()",
) -> Dict[str, Any]:
    """Construct a finding shaped for both Stage A/B/D emit and the
    IRIS Tier 1 gate (which reads top-level ``status``)."""
    return {
        "id": fid,
        "file": file,
        "function": function,
        "line": 10,
        "cwe_id": cwe,
        "rule_id": rule_id,
        "vuln_type": vuln_type,
        "description": description,
        "candidate_reasoning": description,
        "status": stage_a_status,
        "stage_a_summary": {
            "status": stage_a_status,
            "confidence": "medium",
            "candidate_reasoning": description,
        },
    }


# ---------------------------------------------------------------------------
# Test 1: operator manual seed survives every LLM emission pass.
# ---------------------------------------------------------------------------


class TestOperatorSeedSurvival:
    def test_human_annotation_survives_all_llm_passes(self, project, emits):
        """Operator note on a HOT function — one targeted by every
        LLM pass. Tests ``respect-manual`` against actual contention,
        not a function nothing else touches."""
        repo, run = project
        ann_dir = run / "annotations"

        # Operator marks save_user_upload() as clean. This function
        # is targeted by --map (entry_point + sink), --hunt (variant
        # candidate), --trace (every step), and Stage A/B/D — every
        # LLM pass downstream will try to overwrite it.
        write_annotation(ann_dir, Annotation(
            file="src/api/upload.py", function="save_user_upload",
            body="Operator: reviewed 2026-05-09 — sanitiser at line 11 covers it.",
            metadata={"source": "human", "status": "clean"},
        ))
        manual_path = ann_dir / "src" / "api" / "upload.py.md"
        manual_body_before = read_annotation(
            ann_dir, "src/api/upload.py", "save_user_upload",
        ).body

        # /understand passes — explicitly target save_user_upload.
        _write_context_map(run)
        _write_flow_trace(run)
        _write_variants(run, [{
            "id": "VAR-PATH",
            "file": "src/api/upload.py",
            "function": "save_user_upload", "line": 10,
            "taint_status": "confirmed_tainted",
            "matched_code": "open(path, 'wb')",
        }])
        emits.synth_understand(run)

        # /validate emits — also targeting save_user_upload.
        _write_findings(run, [_basic_finding(
            fid="F-PATH", file="src/api/upload.py",
            function="save_user_upload",
        )])
        emits.stage_annotations(run, "A")
        emits.iris_tier1_annotations(run, [_basic_finding(
            fid="F-PATH", file="src/api/upload.py",
            function="save_user_upload",
        )])
        emits.stage_annotations(run, "B")
        emits.stage_annotations(run, "D")

        # Operator note preserved across every contended pass.
        ann_after = read_annotation(
            ann_dir, "src/api/upload.py", "save_user_upload",
        )
        assert ann_after.metadata["source"] == "human"
        assert ann_after.metadata["status"] == "clean"
        assert ann_after.body == manual_body_before
        # File still exists; substrate didn't quietly delete it
        # in some "respect-manual = skip" misinterpretation.
        assert manual_path.exists()


# ---------------------------------------------------------------------------
# Test 2: chronological lifecycle for a refuted finding.
# /understand --map sink → Stage A suspicious → IRIS clean.
# ---------------------------------------------------------------------------


class TestRefutedFindingLifecycle:
    def test_understand_map_then_stage_a_then_iris_clean(self, project, emits):
        repo, run = project

        # Step: --map identifies run_query as a sink.
        _write_context_map(run)
        emits.synth_understand(run)

        ann_after_map = read_annotation(
            run / "annotations", "src/db/query.py", "run_query",
        )
        assert ann_after_map.metadata["status"] == "sink"
        assert ann_after_map.metadata["sink_id"] == "SINK-002"

        # Step: Stage A surfaces a finding on run_query → suspicious.
        _write_findings(run, [_basic_finding(
            fid="F-SQL", file="src/db/query.py", function="run_query",
            cwe="CWE-89", rule_id="py/sql-injection",
            vuln_type="sql_injection",
        )])
        emits.stage_annotations(run, "A")

        ann_after_a = read_annotation(
            run / "annotations", "src/db/query.py", "run_query",
        )
        # Stage A overwrites the sink annotation (last LLM writer).
        assert ann_after_a.metadata["status"] == "suspicious"
        assert ann_after_a.metadata["stage"] == "A"
        # Sink-id metadata gone; finding metadata in.
        assert ann_after_a.metadata.get("finding_id") == "F-SQL"

        # Step: IRIS Tier 1 refutes it → clean.
        emits.iris_tier1_annotations(run, [_basic_finding(
            fid="F-SQL", file="src/db/query.py", function="run_query",
        )])

        ann_after_iris = read_annotation(
            run / "annotations", "src/db/query.py", "run_query",
        )
        assert ann_after_iris.metadata["status"] == "clean"
        assert ann_after_iris.metadata["stage"] == "IRIS_TIER1"
        assert ann_after_iris.metadata["iris_verdict"] == "refuted"
        assert "Refuted by IRIS Tier 1" in ann_after_iris.body


# ---------------------------------------------------------------------------
# Test 3: chronological lifecycle for a confirmed exploitable finding.
# Stage A suspicious → IRIS uncertain (no flip) → Stage B confirmed → Stage D ruling.
# ---------------------------------------------------------------------------


class TestConfirmedFindingLifecycle:
    def test_full_validate_lifecycle_lands_finding_with_ruling(self, project, emits):
        repo, run = project

        # Stage A surfaces the path-traversal finding.
        finding = _basic_finding(
            fid="F-PATH", file="src/api/upload.py",
            function="save_user_upload",
            cwe="CWE-22", rule_id="py/path-traversal",
            vuln_type="path_traversal",
        )
        _write_findings(run, [finding])
        emits.stage_annotations(run, "A")
        ann_a = read_annotation(
            run / "annotations",
            "src/api/upload.py", "save_user_upload",
        )
        assert ann_a.metadata["status"] == "suspicious"

        # IRIS Tier 1 doesn't refute (no emit happens; we model that
        # by simply not calling emit_iris_tier1_annotations). Stage B
        # progresses with hypothesis_status=confirmed.
        finding["stage_b_summary"] = {
            "hypothesis_status": "confirmed",
            "hypothesis_id": "H-1",
            "proximity": 8,
            "attack_path_id": "AP-1",
        }
        _write_findings(run, [finding])
        emits.stage_annotations(run, "B")

        ann_b = read_annotation(
            run / "annotations",
            "src/api/upload.py", "save_user_upload",
        )
        assert ann_b.metadata["status"] == "finding"
        assert ann_b.metadata["stage"] == "B"
        assert ann_b.metadata.get("proximity") == "8"
        assert "Hypothesis: confirmed" in ann_b.body

        # Stage D ruling locks it.
        finding["ruling"] = {
            "status": "exploitable",
            "reason": "User input reaches open() without sanitisation",
        }
        finding["cvss_vector"] = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        finding["stage_d_summary"] = {
            "ruling": "exploitable",
            "cvss_vector": finding["cvss_vector"],
        }
        _write_findings(run, [finding])
        emits.stage_annotations(run, "D")

        ann_d = read_annotation(
            run / "annotations",
            "src/api/upload.py", "save_user_upload",
        )
        assert ann_d.metadata["status"] == "finding"
        assert ann_d.metadata["stage"] == "D"
        assert ann_d.metadata["ruling"] == "exploitable"
        assert ann_d.metadata["cvss"] == finding["cvss_vector"]


# ---------------------------------------------------------------------------
# Test 4: hunt variants alongside validate findings on different functions.
# ---------------------------------------------------------------------------


class TestHuntVariantsAlongsideValidate:
    def test_hunt_and_validate_coexist_on_distinct_functions(self, project, emits):
        repo, run = project

        # /understand --hunt finds a variant in release_buf.
        _write_variants(run, [{
            "id": "VAR-UAF",
            "file": "src/cleanup/buf.c", "function": "release_buf",
            "line": 15, "vuln_type": "uaf",
            "taint_status": "confirmed_tainted",
            "matched_code": "free(b)",
            "notes": "Same shape as upstream CVE",
        }])
        emits.synth_understand(run)

        # /validate is processing the SQL injection finding.
        _write_findings(run, [_basic_finding(
            fid="F-SQL", file="src/db/query.py", function="run_query",
            cwe="CWE-89",
        )])
        emits.stage_annotations(run, "A")

        # Both annotations land independently; neither overwrites
        # the other (different (file, function) keys).
        ann_uaf = read_annotation(
            run / "annotations",
            "src/cleanup/buf.c", "release_buf",
        )
        assert ann_uaf is not None
        assert ann_uaf.metadata["status"] == "finding"
        assert ann_uaf.metadata.get("variant_id") == "VAR-UAF"

        ann_sql = read_annotation(
            run / "annotations", "src/db/query.py", "run_query",
        )
        assert ann_sql is not None
        assert ann_sql.metadata["status"] == "suspicious"
        assert ann_sql.metadata.get("finding_id") == "F-SQL"


# ---------------------------------------------------------------------------
# Test 5: full chronological run with all sources, then audit the union.
# ---------------------------------------------------------------------------


class TestFullChronologicalUnion:
    """Drive every source in chronological order; assert
    ``iter_all_annotations`` returns a stable, complete union and
    each function's final state matches its lifecycle."""

    def _drive_full_lifecycle(self, repo, run, emits):
        """Apply every source in order. Returns nothing — caller
        inspects the resulting annotations directory."""
        # 1. Operator note.
        write_annotation(run / "annotations", Annotation(
            file="src/util/helpers.py", function="utility",
            body="Manual: trivial constant.",
            metadata={"source": "human", "status": "clean"},
        ))

        # 2-3. /understand --map + --trace.
        _write_context_map(run)
        _write_flow_trace(run)

        # 4. /understand --hunt.
        _write_variants(run, [{
            "id": "VAR-UAF",
            "file": "src/cleanup/buf.c", "function": "release_buf",
            "line": 15, "vuln_type": "uaf",
            "taint_status": "confirmed_tainted",
        }])
        emits.synth_understand(run)

        # 5. /validate Stage A — two findings: one we'll refute via
        # IRIS, one we'll confirm via Stage B/D.
        f_refute = _basic_finding(
            fid="F-SQL", file="src/db/query.py", function="run_query",
            cwe="CWE-89", rule_id="py/sql-injection",
            vuln_type="sql_injection",
        )
        f_confirm = _basic_finding(
            fid="F-PATH", file="src/api/upload.py",
            function="save_user_upload",
            cwe="CWE-22", rule_id="py/path-traversal",
        )
        _write_findings(run, [f_refute, f_confirm])
        emits.stage_annotations(run, "A")

        # 6. IRIS Tier 1 refutes f_refute.
        emits.iris_tier1_annotations(run, [f_refute])

        # 7. Stage B confirms f_confirm. Mirrors the real orchestrator
        # behaviour: refuted findings have been moved to disproven.json
        # and are no longer part of the Stage B findings.json the LLM
        # skill processes. Stage B's annotation emit therefore only
        # walks live (not_disproven) findings — the IRIS clean
        # annotation for f_refute survives because nothing rewrites it.
        f_confirm["stage_b_summary"] = {
            "hypothesis_status": "confirmed",
            "hypothesis_id": "H-PATH",
            "proximity": 9,
        }
        _write_findings(run, [f_confirm])
        emits.stage_annotations(run, "B")

        # 8. Stage D rules f_confirm exploitable.
        f_confirm["ruling"] = {"status": "exploitable",
                                "reason": "Untrusted path reaches open"}
        f_confirm["cvss_vector"] = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        f_confirm["stage_d_summary"] = {
            "ruling": "exploitable",
            "cvss_vector": f_confirm["cvss_vector"],
        }
        _write_findings(run, [f_confirm])
        emits.stage_annotations(run, "D")

    def test_each_function_lands_in_expected_final_state(self, project, emits):
        repo, run = project
        self._drive_full_lifecycle(repo, run, emits)
        ann_dir = run / "annotations"

        # utility: operator clean (untouched by any LLM pass).
        ann = read_annotation(ann_dir, "src/util/helpers.py", "utility")
        assert ann.metadata["source"] == "human"
        assert ann.metadata["status"] == "clean"

        # save_user_upload: --map entry_point → flow_step → Stage A
        # → Stage B confirmed → Stage D exploitable. Final state:
        # finding + stage=D + ruling=exploitable.
        ann = read_annotation(
            ann_dir, "src/api/upload.py", "save_user_upload",
        )
        assert ann.metadata["status"] == "finding"
        assert ann.metadata["stage"] == "D"
        assert ann.metadata["ruling"] == "exploitable"
        assert ann.metadata["cvss"].startswith("CVSS:3.1/")

        # run_query: --map sink → Stage A suspicious → IRIS clean.
        # Survives Stage B / D because the orchestrator drops refuted
        # findings from findings.json before Stage B runs (mirrored
        # in the fixture).
        ann = read_annotation(ann_dir, "src/db/query.py", "run_query")
        assert ann.metadata["status"] == "clean"
        assert ann.metadata["stage"] == "IRIS_TIER1"

        # check_credentials: --map trust_boundary, no validate
        # findings → final state is trust_boundary.
        ann = read_annotation(
            ann_dir, "src/auth/login.py", "check_credentials",
        )
        assert ann.metadata["status"] == "trust_boundary"

        # release_buf: --hunt variant only → finding.
        ann = read_annotation(
            ann_dir, "src/cleanup/buf.c", "release_buf",
        )
        assert ann.metadata["status"] == "finding"
        assert ann.metadata.get("variant_id") == "VAR-UAF"

    def test_iter_all_annotations_returns_complete_union(self, project, emits):
        """``iter_all_annotations`` returns every annotation from the
        union; iteration order across two consecutive reads matches.

        We don't claim the order is stable across processes or across
        substrate revisions — just that within one process two reads
        see the same sequence. Consumers needing a specific order
        should sort explicitly."""
        repo, run = project
        self._drive_full_lifecycle(repo, run, emits)
        ann_dir = run / "annotations"

        # Same call twice — order should be deterministic within
        # one process's filesystem state (no concurrent writes).
        keys_first = [(a.file, a.function)
                      for a in iter_all_annotations(ann_dir)]
        keys_second = [(a.file, a.function)
                       for a in iter_all_annotations(ann_dir)]
        assert keys_first == keys_second

        # The union is complete — every annotated function appears
        # exactly once. We compare as a set here because ``complete``
        # is a set property; we already pinned ordering above.
        assert set(keys_first) == {
            ("src/api/upload.py", "save_user_upload"),
            ("src/auth/login.py", "check_credentials"),
            ("src/cleanup/buf.c", "release_buf"),
            ("src/db/query.py", "run_query"),
            ("src/util/helpers.py", "utility"),
        }
        # No duplicates.
        assert len(keys_first) == len(set(keys_first))

    def test_coverage_record_built_from_union(self, project, emits):
        repo, run = project
        self._drive_full_lifecycle(repo, run, emits)
        ann_dir = run / "annotations"

        record = build_from_annotations(ann_dir)
        assert record is not None
        assert record["tool"] == "annotations"

        funcs = record["functions_analysed"]
        # Every annotated function appears.
        keys = sorted((f.get("file"), f.get("function")) for f in funcs)
        assert keys == [
            ("src/api/upload.py", "save_user_upload"),
            ("src/auth/login.py", "check_credentials"),
            ("src/cleanup/buf.c", "release_buf"),
            ("src/db/query.py", "run_query"),
            ("src/util/helpers.py", "utility"),
        ]

        # Status is preserved per entry — the coverage record carries
        # what each annotation said, not just "function exists". Pin
        # the actual final status for each so a substrate change that
        # silently drops the field is caught.
        by_key = {
            (f.get("file"), f.get("function")): f for f in funcs
        }
        # save_user_upload — Stage D ruling=exploitable.
        assert by_key[
            ("src/api/upload.py", "save_user_upload")
        ].get("status") == "finding"
        # run_query — IRIS Tier 1 refutation.
        assert by_key[
            ("src/db/query.py", "run_query")
        ].get("status") == "clean"
        # release_buf — hunt variant confirmed_tainted.
        assert by_key[
            ("src/cleanup/buf.c", "release_buf")
        ].get("status") == "finding"
        # check_credentials — --map trust_boundary.
        assert by_key[
            ("src/auth/login.py", "check_credentials")
        ].get("status") == "trust_boundary"
        # utility — operator manual clean.
        assert by_key[
            ("src/util/helpers.py", "utility")
        ].get("status") == "clean"

    def test_source_attribution_split_human_vs_llm(self, project, emits):
        """Verifies what the docstring promised: every non-human
        annotation has ``source=llm`` exactly. The four emit helpers
        write the literal string ``"llm"`` independently — this test
        pins that they all agree, so a future helper using
        ``"raptor"`` / ``"understand"`` / similar would fail here.
        Operator visibility into "what did I write myself" relies on
        this attribution surviving multi-pass runs."""
        repo, run = project
        self._drive_full_lifecycle(repo, run, emits)
        ann_dir = run / "annotations"

        sources = {
            (a.file, a.function): a.metadata.get("source")
            for a in iter_all_annotations(ann_dir)
        }
        assert sources[("src/util/helpers.py", "utility")] == "human"
        for key, src in sources.items():
            if key == ("src/util/helpers.py", "utility"):
                continue
            assert src == "llm", f"{key} should be llm-sourced"


# ---------------------------------------------------------------------------
# Test 6: empty-artefact paths — every emit helper is a no-op when its
# input file exists but contains no work to do.
# ---------------------------------------------------------------------------


class TestEmptyArtefactNoOps:
    """Each emit helper should treat ``empty input list`` as a no-op
    rather than crash or emit garbage. Pin this so a regression that
    starts treating an empty findings.json as an error doesn't ship
    silently."""

    def test_empty_findings_emits_zero(self, project, emits):
        repo, run = project
        _write_findings(run, [])
        n_a = emits.stage_annotations(run, "A")
        n_b = emits.stage_annotations(run, "B")
        n_d = emits.stage_annotations(run, "D")
        assert n_a == n_b == n_d == 0
        assert not (run / "annotations").exists()

    def test_empty_iris_refuted_list_emits_zero(self, project, emits):
        repo, run = project
        n = emits.iris_tier1_annotations(run, [])
        assert n == 0
        assert not (run / "annotations").exists()

    def test_empty_variants_emits_zero(self, project, emits):
        repo, run = project
        _write_variants(run, [])
        counts = emits.synth_understand(run)
        assert counts.sources.get("variant", 0) == 0

    def test_empty_context_map_arrays_emits_zero(self, project, emits):
        repo, run = project
        (run / "context-map.json").write_text(json.dumps({
            "entry_points": [],
            "sink_details": [],
            "boundary_details": [],
            "unchecked_flows": [],
        }))
        counts = emits.synth_understand(run)
        assert counts.emitted == 0
        assert counts.errors == 0

    def test_only_checklist_present_no_inputs(self, project, emits):
        """No input artefacts at all — just the checklist. Synth
        produces nothing; no annotations dir created; no errors."""
        repo, run = project
        counts = emits.synth_understand(run)
        assert counts.emitted == 0
        assert counts.errors == 0


# ---------------------------------------------------------------------------
# Test 7: substrate quirk pin — Stage B emit walking a refuted finding.
# ---------------------------------------------------------------------------


class TestStageBOnRefutedFindingRegressionPin:
    """If Stage B's annotation emit walks a findings.json that still
    contains an IRIS-refuted finding (top-level ``status`` flipped to
    ``disproven`` but no ``stage_b_summary`` added), Stage B's status
    mapping regresses the IRIS clean annotation back to ``suspicious``
    because it falls through to ``stage_a_summary.status`` — which is
    still ``not_disproven`` because the IRIS gate only updates the
    top-level field.

    The realistic /validate orchestrator side-steps this by removing
    refuted findings from the list Stage B's pipeline processes — but
    that's an orchestrator-level invariant the substrate doesn't
    enforce.

    This test pins the current buggy substrate behaviour. If the fix
    lands (e.g., ``_emit_one`` Stage B branch skipping findings with
    ``status="disproven"``, or the IRIS gate also flipping
    ``stage_a_summary.status``), this test will fail and the docstring
    should be updated accordingly.

    TODO(follow-up): tighten Stage B's ``_emit_one`` to short-circuit
    on ``finding["status"] == "disproven"``, removing the orchestrator's
    responsibility here.
    """

    def test_stage_b_emit_regresses_iris_clean_for_refuted_finding(self, project, emits):
        repo, run = project

        finding = _basic_finding(
            fid="F-REG", file="src/db/query.py", function="run_query",
            cwe="CWE-89",
        )
        _write_findings(run, [finding])
        emits.stage_annotations(run, "A")

        # IRIS Tier 1 refutes — annotation flips to clean.
        emits.iris_tier1_annotations(run, [finding])
        ann_after_iris = read_annotation(
            run / "annotations", "src/db/query.py", "run_query",
        )
        assert ann_after_iris.metadata["status"] == "clean"
        assert ann_after_iris.metadata["stage"] == "IRIS_TIER1"

        # Findings.json still contains the refuted finding (top-level
        # status flipped to disproven, no stage_b_summary added) —
        # this is what the IRIS gate writes back in real flow.
        finding["status"] = "disproven"
        _write_findings(run, [finding])

        # Stage B emit walks all findings — REGRESSES the IRIS clean
        # to suspicious.
        emits.stage_annotations(run, "B")
        ann_after_b = read_annotation(
            run / "annotations", "src/db/query.py", "run_query",
        )
        # Pin current (buggy) behaviour. Update this when the fix
        # lands — see class docstring.
        assert ann_after_b.metadata["status"] == "suspicious"
        assert ann_after_b.metadata["stage"] == "B"
        assert "iris_verdict" not in ann_after_b.metadata
