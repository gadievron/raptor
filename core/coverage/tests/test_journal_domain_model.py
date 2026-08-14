"""Tests for _find_domain_model_file path search."""

from pathlib import Path

from core.coverage.journal import _find_domain_model_file


def test_finds_colocated(tmp_path: Path):
    (tmp_path / "domain-model.json").write_text("{}")
    assert _find_domain_model_file(tmp_path) == tmp_path / "domain-model.json"


def test_finds_in_project_concepts(tmp_path: Path):
    run_dir = tmp_path / "project" / "run_001"
    run_dir.mkdir(parents=True)
    concepts = tmp_path / "project" / "concepts"
    concepts.mkdir()
    (concepts / "domain-model.json").write_text("{}")
    assert _find_domain_model_file(run_dir) == concepts / "domain-model.json"


def test_finds_in_parent(tmp_path: Path):
    run_dir = tmp_path / "project" / "run_001"
    run_dir.mkdir(parents=True)
    (tmp_path / "project" / "domain-model.json").write_text("{}")
    assert _find_domain_model_file(run_dir) == tmp_path / "project" / "domain-model.json"


def test_prefers_colocated_over_parent(tmp_path: Path):
    run_dir = tmp_path / "project" / "run_001"
    run_dir.mkdir(parents=True)
    (run_dir / "domain-model.json").write_text("{}")
    (tmp_path / "project" / "domain-model.json").write_text("{}")
    assert _find_domain_model_file(run_dir) == run_dir / "domain-model.json"


def test_returns_none_when_absent(tmp_path: Path):
    assert _find_domain_model_file(tmp_path) is None
