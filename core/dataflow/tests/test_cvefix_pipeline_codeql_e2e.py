"""Real-CodeQL end-to-end for the trust-corpus pipeline AND the sound tier.

Builds CodeQL databases from the committed before/after python fixtures (once,
module-scoped) and exercises two real-CodeQL paths:

  1. the pipeline: generate_corpus_for_pair labels the post-fix-still-flagged
     finding as a missing_sanitizer_model FP;
  2. the sound tier: a synthesized barrier (the host_is_allowed guard the LLM
     would emit) SUPPRESSES that FP while preserving the real pre-fix TP.

Both use the actual CodeQL CLI (no stub) — this is what keeps the QL the loop
assembles regression-guarded (the unit tests stub CodeQL and never compile it).
Skipped when CodeQL isn't installed (e.g. CI). Slow: two DB builds + CodeQL runs.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from core.dataflow.barrier_synth import BarrierProposal, run_synthesis_loop
from core.dataflow.cvefix_pipeline import generate_corpus_for_pair

_CODEQL = shutil.which("codeql")
_FIXTURES = Path(__file__).parent / "fixtures" / "cvefix_cmdi_py"
_QUERY = "codeql/python-queries:Security/CWE-078/CommandInjection.ql"

# The guard a proposer would emit for the fixture's project validator.
_HOST_ALLOWED_GUARD = (
    "predicate proposedGuard(DataFlow::GuardNode g, ControlFlowNode node, boolean branch) {\n"
    "  exists(DataFlow::CallCfgNode c |\n"
    '    c.getFunction().asExpr().(Name).getId() = "host_is_allowed" and\n'
    "    g = c.asCfgNode() and node = c.getArg(0).asCfgNode() and branch = true) }"
)

pytestmark = pytest.mark.skipif(_CODEQL is None, reason="codeql CLI not installed")


def _build_db(src: Path, db: Path) -> None:
    subprocess.run(
        [_CODEQL, "database", "create", str(db), "--language=python",
         f"--source-root={src}", "--overwrite"],
        check=True, capture_output=True, text=True,
    )


@pytest.fixture(scope="module")
def codeql_dbs(tmp_path_factory):
    """Build the before/after fixture DBs once for the module."""
    base = tmp_path_factory.mktemp("codeql-dbs")
    before_db, after_db = base / "before-db", base / "after-db"
    _build_db(_FIXTURES / "before", before_db)
    _build_db(_FIXTURES / "after", after_db)
    return before_db, after_db


def test_pipeline_labels_post_fix_finding_as_missing_sanitizer_fp(codeql_dbs, tmp_path):
    before_db, after_db = codeql_dbs
    pairs = generate_corpus_for_pair(
        before_db, after_db, [_QUERY],
        cve_id="DEMO-CVE-0001", cwe="CWE-78", labeled_at="2026-05-25",
        out_dir=tmp_path / "out", fix_touched_files={"app.py"},
    )
    by_verdict = {gt.verdict: (f, gt) for f, gt in pairs}
    assert "true_positive" in by_verdict, "CodeQL should flag the pre-fix vuln"
    assert "false_positive" in by_verdict, (
        "CodeQL should still flag the post-fix code (project allowlist unmodeled)"
    )
    assert by_verdict["false_positive"][1].fp_category == "missing_sanitizer_model"
    assert by_verdict["true_positive"][0].sink.file_path == "app.py"


def test_synthesized_barrier_suppresses_fp_and_preserves_tp(codeql_dbs, tmp_path):
    """The sound-tier capstone, regression-guarded: the assembled barrier query
    must compile under real CodeQL and suppress the FP (after=0) without
    suppressing the real TP (before=1)."""
    before_db, after_db = codeql_dbs
    res = run_synthesis_loop(
        BarrierProposal(sink_class="cmdi", finding_id="DEMO",
                        sink_snippet="os.system(host)", source_context="(fixture)"),
        after_db, before_db,
        proposer=lambda _proposal, _err: _HOST_ALLOWED_GUARD,
        work_dir=tmp_path / "synth",
        # search_path=None: `codeql database analyze` resolves codeql/python-all
    )
    assert res is not None, "the assembled barrier query must compile under CodeQL"
    assert res.after_count == 0, "the FP should be suppressed by the barrier"
    assert res.before_count == 1, "the real TP must be preserved"
    assert res.is_sound
