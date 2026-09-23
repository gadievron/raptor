"""run_sca persists parse failures to the analysis-gap trail."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from core.http import HttpError
from core.json import JsonCache
from core.run import gaps
from packages.sca.pipeline import RunOptions, run_sca


class _OfflineStub:
    """Minimal HttpClient: empty OSV results, empty KEV/EPSS."""

    def post_json(self, url: str, body: dict, timeout: int = 30) -> dict:
        return {"results": [{} for _ in body.get("queries", ())]}

    def get_json(self, url: str, timeout: int = 30) -> dict:
        if "cisa.gov" in url:
            return {"vulnerabilities": []}
        if "first.org" in url:
            return {"data": []}
        raise HttpError(f"unexpected GET {url}", status=404)

    def get_bytes(self, *a: Any, **k: Any):
        raise NotImplementedError


@pytest.fixture(autouse=True)
def _fresh_gap_state(monkeypatch):
    monkeypatch.setattr(gaps, "_gap_count", 0)
    monkeypatch.setattr(gaps, "_pending", [])


def test_hostile_manifest_lands_on_gap_trail(tmp_path: Path) -> None:
    target = tmp_path / "repo"
    target.mkdir()
    # Crafted manifest: deep TOML nesting degrades to warn + [].
    (target / "pyproject.toml").write_text("x = " + "[" * 5000)
    (target / "requirements.txt").write_text("requests==2.31.0\n")
    out = tmp_path / "out"

    result = run_sca(
        target=target, output_dir=out,
        options=RunOptions(enable_llm_review=False, enable_triage=False),
        http=_OfflineStub(), cache=JsonCache(root=tmp_path / "cache"),
    )

    # The honest sibling still analysed.
    assert result.deps_analysed >= 1
    # Structured failure surfaced on the run result...
    assert any(
        f.path.name == "pyproject.toml" for f in result.parse_failures
    )
    # ...and durably on the analysis-gap trail.
    records = gaps.load_gaps(out)
    assert any(
        r["file_path"].endswith("pyproject.toml")
        and r["reason"] == "parse_error"
        and r["tool"] == "sca"
        for r in records
    ), records


def test_clean_tree_writes_no_gap_trail(tmp_path: Path) -> None:
    target = tmp_path / "repo"
    target.mkdir()
    (target / "requirements.txt").write_text("requests==2.31.0\n")
    out = tmp_path / "out"
    run_sca(
        target=target, output_dir=out,
        options=RunOptions(enable_llm_review=False, enable_triage=False),
        http=_OfflineStub(), cache=JsonCache(root=tmp_path / "cache"),
    )
    assert not (out / gaps.GAPS_FILE).exists()


def test_gap_records_are_valid_jsonl(tmp_path: Path) -> None:
    target = tmp_path / "repo"
    target.mkdir()
    (target / "yarn.lock").write_text(
        "__metadata: {version: 8}\nx: " + "[" * 50_000 + "\n",
    )
    out = tmp_path / "out"
    run_sca(
        target=target, output_dir=out,
        options=RunOptions(enable_llm_review=False, enable_triage=False),
        http=_OfflineStub(), cache=JsonCache(root=tmp_path / "cache"),
    )
    trail = out / gaps.GAPS_FILE
    assert trail.exists()
    for line in trail.read_text().splitlines():
        record = json.loads(line)
        assert record["event"] == gaps.GAP_EVENT
