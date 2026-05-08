"""Tests for ``packages.code_understanding.annotation_synth``.

Builds tiny ``context-map.json`` / ``flow-trace-*.json`` / ``checklist.json``
fixtures, runs the synth, and asserts annotations appear with the
right metadata. Also exercises the libexec shim end-to-end.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from core.annotations import (
    Annotation,
    iter_all_annotations,
    read_annotation,
    read_file_annotations,
    write_annotation,
)
from packages.code_understanding.annotation_synth import (
    SynthCounts,
    _parse_definition,
    synthesise_from_understand_output,
)


REPO_ROOT = Path(__file__).resolve().parents[3]
SHIM = REPO_ROOT / "libexec" / "raptor-understand-annotate"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def understand_run(tmp_path):
    """Build a realistic /understand output dir + repo with a few
    real source files so hash computation has data to chew on."""
    repo = tmp_path / "repo"
    (repo / "src" / "routes").mkdir(parents=True)
    (repo / "src" / "db").mkdir()
    (repo / "src" / "middleware").mkdir()

    (repo / "src" / "routes" / "query.py").write_text(
        "\n" * 33
        + "def query_handler(req):\n"
        + "    body = req.get_json()\n"
        + "    return run_query(body)\n"
        + "\n" * 4
        + "def admin_bulk(req):\n"
        + "    return run_query(req.json)\n"
    )
    (repo / "src" / "db" / "query.py").write_text(
        "\n" * 88
        + "def run_query(s):\n"
        + "    cursor.execute(f'SELECT * FROM t WHERE x = {s}')\n"
    )
    (repo / "src" / "middleware" / "auth.py").write_text(
        "\n" * 11
        + "def require_auth(req):\n"
        + "    if not req.token:\n"
        + "        raise Unauth()\n"
    )

    out = tmp_path / "out"
    out.mkdir()

    checklist = {
        "target_path": str(repo),
        "files": [
            {
                "path": "src/routes/query.py",
                "items": [
                    {"name": "query_handler",
                     "line_start": 34, "line_end": 38},
                    {"name": "admin_bulk",
                     "line_start": 42, "line_end": 44},
                ],
            },
            {
                "path": "src/db/query.py",
                "items": [
                    {"name": "run_query",
                     "line_start": 89, "line_end": 91},
                ],
            },
            {
                "path": "src/middleware/auth.py",
                "items": [
                    {"name": "require_auth",
                     "line_start": 12, "line_end": 14},
                ],
            },
        ],
    }
    (out / "checklist.json").write_text(json.dumps(checklist))

    return repo, out


def _make_context_map(out: Path) -> None:
    cmap = {
        "entry_points": [
            {
                "id": "EP-001", "type": "http_route", "method": "POST",
                "path": "/api/v2/query",
                "file": "src/routes/query.py", "line": 34,
                "accepts": "JSON body", "auth_required": True,
                "notes": "Auth at line 38",
            },
            {
                "id": "EP-003", "type": "http_route", "method": "POST",
                "path": "/api/v2/admin/bulk",
                "file": "src/routes/query.py", "line": 42,
                "auth_required": False,
            },
        ],
        "sink_details": [
            {
                "id": "SINK-001", "type": "db_query",
                "operation": "cursor.execute(raw_sql)",
                "file": "src/db/query.py", "line": 89,
                "reaches_from": ["EP-001", "EP-003"],
                "trust_boundaries_crossed": ["TB-001"],
                "parameterized": False,
                "notes": "f-string SQL",
            },
        ],
        "boundary_details": [
            {
                "id": "TB-001", "type": "auth_check",
                "file": "src/middleware/auth.py", "line": 12,
                "covers": ["EP-001"],
                "gaps": "EP-003 bypasses",
            },
        ],
        "unchecked_flows": [
            {
                "entry_point": "EP-003", "sink": "SINK-001",
                "missing_boundary": "no auth on admin bulk",
            },
        ],
    }
    (out / "context-map.json").write_text(json.dumps(cmap))


def _make_flow_trace(out: Path) -> None:
    trace = {
        "entry_id": "EP-001",
        "steps": [
            {
                "step": 1, "type": "entry",
                "definition": "src/routes/query.py:34",
                "description": "POST handler receives JSON",
                "tainted_var": "body", "transform": "none",
                "confidence": "high",
            },
            {
                "step": 2, "type": "call",
                "call_site": "src/routes/query.py:35",
                "definition": "src/db/query.py:89",
                "description": "Passes body to run_query",
                "tainted_var": "s", "transform": "none",
                "confidence": "high",
            },
            {
                "step": 3, "type": "sink",
                "definition": "psycopg2.cursor.execute()",
                "description": "External library symbol",
                "tainted_var": "s", "transform": "none",
                "confidence": "high",
            },
        ],
    }
    (out / "flow-trace-EP-001.json").write_text(json.dumps(trace))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class TestContextMap:
    def test_emits_entry_points(self, understand_run):
        repo, out = understand_run
        _make_context_map(out)
        counts = synthesise_from_understand_output(out)
        # Two entry-points + one sink + one trust-boundary + one
        # unchecked-flow = 5 distinct annotations.
        # But the unchecked flow targets the same function as EP-003,
        # so they collide on the same (file, function) → the unchecked
        # flow overwrites the EP-003 annotation (last writer wins
        # within the synth's own pass; respect-manual only protects
        # source=human).
        assert counts.emitted >= 4
        ann = read_annotation(
            out / "annotations", "src/routes/query.py", "query_handler"
        )
        assert ann is not None
        assert ann.metadata["status"] == "entry_point"
        assert ann.metadata["entry_point_id"] == "EP-001"
        assert "POST /api/v2/query" in ann.body
        assert "Auth at line 38" in ann.body
        assert ann.metadata.get("hash"), "hash should be stamped"

    def test_emits_sinks(self, understand_run):
        repo, out = understand_run
        _make_context_map(out)
        synthesise_from_understand_output(out)
        ann = read_annotation(
            out / "annotations", "src/db/query.py", "run_query"
        )
        assert ann is not None
        assert ann.metadata["status"] == "sink"
        assert ann.metadata["sink_id"] == "SINK-001"
        assert "cursor.execute" in ann.body
        assert "Reaches from: EP-001, EP-003" in ann.body

    def test_emits_trust_boundary(self, understand_run):
        repo, out = understand_run
        _make_context_map(out)
        synthesise_from_understand_output(out)
        ann = read_annotation(
            out / "annotations",
            "src/middleware/auth.py", "require_auth",
        )
        assert ann is not None
        assert ann.metadata["status"] == "trust_boundary"
        assert ann.metadata["boundary_id"] == "TB-001"
        assert "Covers: EP-001" in ann.body
        assert "EP-003 bypasses" in ann.body

    def test_emits_unchecked_flow_attached_to_entry_point(self, understand_run):
        repo, out = understand_run
        # No flow trace, just context map — so EP-003 only has the
        # unchecked-flow annotation. The status should be
        # ``unchecked_flow`` after the unchecked-flow pass overwrites
        # the entry-point annotation written earlier.
        _make_context_map(out)
        synthesise_from_understand_output(out)
        ann = read_annotation(
            out / "annotations",
            "src/routes/query.py", "admin_bulk",
        )
        assert ann is not None
        # Unchecked-flow pass runs LAST and overwrites the entry-point
        # status. Body mentions both. Pin only the metadata invariant.
        assert ann.metadata["status"] == "unchecked_flow"
        assert "EP-003" in ann.body
        assert "SINK-001" in ann.body


class TestFlowTrace:
    def test_emits_per_step_annotations(self, understand_run):
        repo, out = understand_run
        _make_context_map(out)
        _make_flow_trace(out)
        counts = synthesise_from_understand_output(out)
        # Step 1 → query_handler (already has entry_point); step 2 →
        # run_query (already has sink); step 3 is external library,
        # skipped.
        # Steps 1+2 overwrite (respect-manual doesn't apply, both
        # annotations are llm-source). The last writer for each
        # function is the flow-step pass. Pin: at least one
        # flow_step annotation present.
        assert any(
            a.metadata.get("status") == "flow_step"
            for a in iter_all_annotations(out / "annotations")
        )

    def test_skips_external_library_definitions(self, understand_run):
        """Step 3's ``psycopg2.cursor.execute()`` has no file:line —
        synth must skip without crashing."""
        repo, out = understand_run
        _make_flow_trace(out)
        # checklist exists; no context-map. Just trace.
        counts = synthesise_from_understand_output(out)
        # Step 3 should land in skipped_no_function.
        assert counts.skipped_no_function >= 1

    def test_trace_step_metadata_includes_trace_id_and_step(
        self, understand_run,
    ):
        repo, out = understand_run
        _make_flow_trace(out)
        synthesise_from_understand_output(out)
        # Find any flow_step annotation.
        for ann in iter_all_annotations(out / "annotations"):
            if ann.metadata.get("status") == "flow_step":
                assert ann.metadata.get("trace_id") == "EP-001"
                assert ann.metadata.get("step") in ("1", "2")
                return
        pytest.fail("no flow_step annotation found")


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_no_output_dir(self, tmp_path):
        counts = synthesise_from_understand_output(tmp_path / "nope")
        assert counts.emitted == 0
        assert counts.errors == 0

    def test_no_checklist(self, tmp_path):
        # Output dir exists but no checklist -> skip silently.
        tmp_path.mkdir(exist_ok=True)
        (tmp_path / "context-map.json").write_text(
            json.dumps({"entry_points": [
                {"id": "EP-1", "file": "src/foo.py", "line": 10}
            ]})
        )
        counts = synthesise_from_understand_output(tmp_path)
        assert counts.emitted == 0

    def test_no_json_inputs(self, understand_run):
        repo, out = understand_run
        # Just checklist, no context-map / no flow-trace.
        counts = synthesise_from_understand_output(out)
        assert counts.emitted == 0

    def test_corrupt_context_map_does_not_crash(self, understand_run):
        repo, out = understand_run
        (out / "context-map.json").write_text("{ not valid json")
        counts = synthesise_from_understand_output(out)
        # Bad JSON → load returns None → that file is silently skipped.
        assert counts.errors == 0

    def test_unknown_entry_point_in_unchecked_flow(self, understand_run):
        repo, out = understand_run
        cmap = {
            "entry_points": [],
            "unchecked_flows": [
                {"entry_point": "EP-DOES-NOT-EXIST", "sink": "SINK-1"},
            ],
        }
        (out / "context-map.json").write_text(json.dumps(cmap))
        counts = synthesise_from_understand_output(out)
        # EP not found → skipped_no_function bumps; no crash.
        assert counts.skipped_no_function >= 1

    def test_function_without_inventory_match_skipped(self, understand_run):
        repo, out = understand_run
        cmap = {
            "entry_points": [{
                "id": "EP-1", "type": "http_route", "method": "GET",
                "path": "/x",
                "file": "src/not_in_inventory.py", "line": 1,
            }],
        }
        (out / "context-map.json").write_text(json.dumps(cmap))
        counts = synthesise_from_understand_output(out)
        assert counts.skipped_no_function >= 1
        assert counts.emitted == 0


class TestCoverageRecordWireIn:
    """The synth writes a ``coverage-annotations.json`` record after
    emitting annotations, so ``raptor-coverage-summary`` can pick
    them up as reviewed functions."""

    def test_writes_coverage_record_when_emit_succeeds(self, understand_run):
        repo, out = understand_run
        _make_context_map(out)
        synthesise_from_understand_output(out)
        record_path = out / "coverage-annotations.json"
        assert record_path.exists(), (
            "synth must write coverage-annotations.json"
        )
        import json
        record = json.loads(record_path.read_text())
        assert record["tool"] == "annotations"
        assert len(record["functions_analysed"]) > 0

    def test_no_record_when_no_emits(self, understand_run):
        """Empty run (no JSON inputs) must not leave a stale record."""
        repo, out = understand_run
        synthesise_from_understand_output(out)
        assert not (out / "coverage-annotations.json").exists()


class TestRespectManual:
    def test_skips_manual_annotation(self, understand_run):
        repo, out = understand_run
        _make_context_map(out)
        # Operator wrote a manual note for query_handler first.
        write_annotation(out / "annotations", Annotation(
            file="src/routes/query.py", function="query_handler",
            body="Operator: reviewed clean",
            metadata={"source": "human", "status": "clean"},
        ))
        counts = synthesise_from_understand_output(out)
        # Synth tried to write entry_point + (maybe other), but the
        # query_handler write was blocked.
        assert counts.skipped_manual_blocked >= 1
        # Operator content still there.
        ann = read_annotation(
            out / "annotations",
            "src/routes/query.py", "query_handler",
        )
        assert ann.metadata["source"] == "human"
        assert "Operator" in ann.body


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


class TestParseDefinition:
    def test_file_line_form(self):
        assert _parse_definition("src/foo.py:42") == ("src/foo.py", 42)

    def test_external_library_returns_none(self):
        assert _parse_definition("psycopg2.cursor.execute()") is None

    def test_empty_returns_none(self):
        assert _parse_definition("") is None

    def test_no_colon_returns_none(self):
        assert _parse_definition("src/foo.py") is None

    def test_garbage_line_number_returns_none(self):
        assert _parse_definition("src/foo.py:abc") is None


# ---------------------------------------------------------------------------
# Libexec shim
# ---------------------------------------------------------------------------


class TestShim:
    def _run(self, *args, env_extra=None):
        env = dict(os.environ)
        env["_RAPTOR_TRUSTED"] = "1"
        if env_extra:
            env.update(env_extra)
        return subprocess.run(
            [sys.executable, str(SHIM), *args],
            env=env,
            capture_output=True,
            text=True,
        )

    def test_trust_marker_required(self, tmp_path):
        env = {k: v for k, v in os.environ.items()
               if k not in ("_RAPTOR_TRUSTED", "CLAUDECODE")}
        r = subprocess.run(
            [sys.executable, str(SHIM), str(tmp_path)],
            env=env, capture_output=True, text=True,
        )
        assert r.returncode == 2
        assert "internal dispatch" in r.stderr

    def test_no_args_prints_usage(self):
        r = self._run()
        assert r.returncode == 1
        assert "Usage" in r.stderr

    def test_missing_dir_errors(self, tmp_path):
        r = self._run(str(tmp_path / "nope"))
        assert r.returncode == 1
        assert "not found" in r.stderr

    def test_empty_dir_says_nothing_to_do(self, tmp_path):
        r = self._run(str(tmp_path))
        assert r.returncode == 0
        assert "nothing to synthesise" in r.stdout

    def test_full_run(self, understand_run):
        repo, out = understand_run
        _make_context_map(out)
        _make_flow_trace(out)
        r = self._run(str(out))
        assert r.returncode == 0, r.stderr
        assert "emitted=" in r.stdout
        assert "by_kind=" in r.stdout
