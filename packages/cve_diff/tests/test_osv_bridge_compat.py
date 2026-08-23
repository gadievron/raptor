"""Writer↔reader contract: osv_schema.render → cvediff_bridge.

The /cve-env pre-fill bridge (core/orchestration/cvediff_bridge.py)
reads ``{CVE}.osv.json`` as plain JSON — no cve_diff import, so
nothing in the type system ties the two together. This test runs the
REAL production serializer over a DiffBundle and asserts the bridge
recovers every pointer field, so a schema change on either side fails
here instead of silently breaking pre-fill.
"""

from __future__ import annotations

import json

from cve_diff.core.models import CommitSha, DiffBundle, RepoRef
from cve_diff.report import osv_schema

from core.orchestration.cvediff_bridge import find_fix_pointer

CVE = "CVE-2021-41773"
REPO = "https://github.com/apache/httpd"
FIX = "f" * 40
BEFORE = "b" * 40


def _bundle(**over) -> DiffBundle:
    base = dict(
        cve_id=CVE,
        repo_ref=RepoRef(
            repository_url=REPO, fix_commit=CommitSha(FIX),
            introduced=None, canonical_score=100,
        ),
        commit_before=CommitSha(BEFORE),
        commit_after=CommitSha(FIX),
        diff_text="--- a/x\n+++ b/x\n",
        files_changed=2,
        bytes_size=512,
        shape="source",
        consensus={"verdict": "agree", "methods": ["clone", "api"]},
    )
    base.update(over)
    return DiffBundle(**base)


def test_bridge_reads_rendered_artifact(tmp_path):
    osv = osv_schema.render(_bundle())
    (tmp_path / f"{CVE}.osv.json").write_text(json.dumps(osv))

    ptr = find_fix_pointer(CVE, out_dir=tmp_path)
    assert ptr is not None
    assert ptr.cve_id == CVE
    assert ptr.repository_url == REPO
    assert ptr.fix_commit == FIX
    assert ptr.commit_before == BEFORE
    assert ptr.diff_shape == "source"
    assert ptr.consensus_verdict == "agree"
    assert ptr.files_changed == 2
    assert ptr.mirror_warning is False


def test_bridge_sees_mirror_shape_from_renderer(tmp_path):
    osv = osv_schema.render(_bundle(shape="packaging_only", consensus=None))
    (tmp_path / f"{CVE}.osv.json").write_text(json.dumps(osv))

    ptr = find_fix_pointer(CVE, out_dir=tmp_path)
    assert ptr is not None
    assert ptr.mirror_warning is True
    assert ptr.consensus_verdict == ""
