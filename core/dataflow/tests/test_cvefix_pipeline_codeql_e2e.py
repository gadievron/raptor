"""Real-CodeQL end-to-end for the trust-corpus pipeline.

Builds CodeQL databases from the committed before/after python fixtures and
drives the orchestrator with the actual CodeQL CLI (no stub) — proving the
pipeline handles real SARIF and reproduces the trust-axis target: a
project-specific sanitizer CodeQL does not model leaves the post-fix code
still flagged (a real ``missing_sanitizer_model`` false positive).

Skipped when CodeQL isn't installed (e.g. CI) — same posture as the
reachability program's fetched/local-only gates. Slow: builds two DBs.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from core.dataflow.cvefix_pipeline import generate_corpus_for_pair

_CODEQL = shutil.which("codeql")
_FIXTURES = Path(__file__).parent / "fixtures" / "cvefix_cmdi_py"
_QUERY = "codeql/python-queries:Security/CWE-078/CommandInjection.ql"

pytestmark = pytest.mark.skipif(_CODEQL is None, reason="codeql CLI not installed")


def _build_db(src: Path, db: Path) -> None:
    subprocess.run(
        [_CODEQL, "database", "create", str(db), "--language=python",
         f"--source-root={src}", "--overwrite"],
        check=True, capture_output=True, text=True,
    )


def test_real_codeql_reproduces_missing_sanitizer_fp(tmp_path: Path):
    before_db = tmp_path / "before-db"
    after_db = tmp_path / "after-db"
    _build_db(_FIXTURES / "before", before_db)
    _build_db(_FIXTURES / "after", after_db)

    pairs = generate_corpus_for_pair(
        before_db, after_db, [_QUERY],
        cve_id="DEMO-CVE-0001", cwe="CWE-78", labeled_at="2026-05-25",
        out_dir=tmp_path / "out", fix_touched_files={"app.py"},
    )

    by_verdict = {gt.verdict: (f, gt) for f, gt in pairs}
    # Pre-fix flags the real vuln (TP); post-fix is STILL flagged despite the
    # project allowlist -> the missing_sanitizer_model FP the trust tier targets.
    assert "true_positive" in by_verdict, "CodeQL should flag the pre-fix vuln"
    assert "false_positive" in by_verdict, (
        "CodeQL should still flag the post-fix code (project allowlist unmodeled)"
    )
    assert by_verdict["false_positive"][1].fp_category == "missing_sanitizer_model"
    assert by_verdict["true_positive"][0].sink.file_path == "app.py"
