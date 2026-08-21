"""Tests for the consensus → verified-outcome writer
(``cve_diff/report/verified_outcomes.py``)."""

from __future__ import annotations

import json

from cve_diff.core.models import CommitSha, DiffBundle, RepoRef
from cve_diff.report.verified_outcomes import write_consensus_outcome

FIX = "a" * 40
PARENT = "b" * 40


def _bundle(consensus=None, **kw):
    ref = RepoRef(
        repository_url="https://github.com/example/proj",
        fix_commit=CommitSha(FIX),
        introduced=CommitSha(PARENT),
        canonical_score=100,
    )
    return DiffBundle(
        cve_id="CVE-2024-31337",
        repo_ref=ref,
        commit_before=CommitSha(PARENT),
        commit_after=CommitSha(FIX),
        diff_text="--- a\n+++ b\n",
        files_changed=2,
        bytes_size=64,
        consensus=consensus,
        **kw,
    )


def _consensus(agreement=2, slug="example/proj", sha=FIX[:12]):
    return {
        "cve_id": "CVE-2024-31337",
        "methods": [
            {"name": "osv_refs", "found": True, "slug": slug, "sha": sha},
            {"name": "nvd_patch_refs", "found": True, "slug": slug, "sha": sha},
        ],
        "consensus_slug": slug,
        "consensus_sha": sha,
        "agreement_count": agreement,
        "attempted_count": 2,
    }


def test_writes_consensus_record_that_round_trips(tmp_path):
    assert write_consensus_outcome(
        tmp_path, _bundle(consensus=_consensus()), cwe_id="CWE-787",
    )
    from core.labeled_attempts.view import (
        VERIFIED_OUTCOMES_FILENAME,
        Oracle,
        OutcomeStatus,
        VerifiedOutcome,
    )
    lines = (tmp_path / VERIFIED_OUTCOMES_FILENAME).read_text().splitlines()
    assert len(lines) == 1
    vo = VerifiedOutcome.from_dict(json.loads(lines[0]))
    assert vo.finding_id == "CVE-2024-31337"
    assert vo.oracle is Oracle.CONSENSUS
    assert vo.status is OutcomeStatus.VERIFIED
    assert vo.reproducible is False
    assert vo.cwe_id == "CWE-787"
    assert vo.produced_by == "cve-diff"
    assert vo.evidence["fix_commit"] == FIX
    assert vo.evidence["methods"] == ["osv_refs", "nvd_patch_refs"]


def test_single_vote_is_not_verified(tmp_path):
    assert not write_consensus_outcome(
        tmp_path, _bundle(consensus=_consensus(agreement=1)),
    )
    assert not list(tmp_path.iterdir())


def test_no_consensus_dict_skips(tmp_path):
    assert not write_consensus_outcome(tmp_path, _bundle(consensus=None))
    assert not list(tmp_path.iterdir())


def test_consensus_on_a_different_pointer_refutes_not_confirms(tmp_path):
    """Two sources agreeing on some OTHER commit must not mint a
    verified outcome for the pipeline's pick."""
    other = "c" * 12
    assert not write_consensus_outcome(
        tmp_path, _bundle(consensus=_consensus(sha=other)),
    )
    assert not write_consensus_outcome(
        tmp_path, _bundle(consensus=_consensus(slug="other/repo")),
    )
    assert not list(tmp_path.iterdir())


def test_io_trouble_never_raises(tmp_path):
    target = tmp_path / "not-a-dir"
    target.write_text("occupied")
    # output_dir is a FILE — the append will fail; must return False.
    assert not write_consensus_outcome(
        target / "sub", _bundle(consensus=_consensus()),
    )
