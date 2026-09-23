"""Tests for the domain-model path search (_find_domain_model_file /
domain_model_context)."""

import json
from pathlib import Path

from core.coverage.journal import _find_domain_model_file, domain_model_context


def _standalone_pin(run_dir: Path) -> None:
    """Stamp *run_dir* as a standalone run (authoritative pin-to-none)."""
    (run_dir / ".raptor-run.json").write_text(
        json.dumps({"project": None, "project_source": "none"})
    )


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


def test_standalone_run_ignores_foreign_sibling(tmp_path: Path):
    # A standalone run (pin-to-none) sitting in a shared out/ next to
    # ANOTHER target's domain model must not import it.
    run_dir = tmp_path / "out" / "run_001"
    run_dir.mkdir(parents=True)
    _standalone_pin(run_dir)
    concepts = tmp_path / "out" / "concepts"
    concepts.mkdir()
    (concepts / "domain-model.json").write_text('{"concepts": []}')
    (tmp_path / "out" / "domain-model.json").write_text('{"concepts": []}')
    assert _find_domain_model_file(run_dir) is None


def test_context_standalone_run_ignores_foreign_sibling(tmp_path: Path):
    # Same pin discipline for the staleness-gate view: a foreign
    # sibling model is neither canonical nor a comparison basis.
    run_dir = tmp_path / "out" / "run_001"
    run_dir.mkdir(parents=True)
    _standalone_pin(run_dir)
    concepts = tmp_path / "out" / "concepts"
    concepts.mkdir()
    (concepts / "domain-model.json").write_text(
        '{"concepts": [{"id": "foreign.concept"}]}'
    )
    assert domain_model_context(run_dir) is None


def test_context_standalone_run_uses_own_model_non_canonical(tmp_path: Path):
    run_dir = tmp_path / "out" / "run_001"
    run_dir.mkdir(parents=True)
    _standalone_pin(run_dir)
    (tmp_path / "out" / "domain-model.json").write_text(
        '{"concepts": [{"id": "foreign.concept"}]}'
    )
    (run_dir / "domain-model.json").write_text(
        '{"concepts": [{"id": "own.concept"}]}'
    )
    ctx = domain_model_context(run_dir)
    assert ctx is not None
    assert ctx["canonical"] is False
    assert list(ctx["concepts"]) == ["own.concept"]


def test_context_legacy_dir_keeps_parent_probe(tmp_path: Path):
    # Pin-less legacy run dirs keep the pre-series parent probe.
    run_dir = tmp_path / "project" / "run_001"
    run_dir.mkdir(parents=True)
    concepts = tmp_path / "project" / "concepts"
    concepts.mkdir()
    (concepts / "domain-model.json").write_text(
        '{"concepts": [{"id": "proj.concept"}]}'
    )
    ctx = domain_model_context(run_dir)
    assert ctx is not None
    assert ctx["canonical"] is True
    assert list(ctx["concepts"]) == ["proj.concept"]


def test_pin_resolution_error_fails_closed(tmp_path: Path, monkeypatch):
    # An internal ERROR in run-pin resolution must not re-open the
    # standalone-run foreign domain-model adoption the pin exists to
    # prevent — the parent probe is the LEGACY fallback, chosen by
    # the resolution itself, never by its failure.
    import json as _json

    from core.coverage.journal import _find_domain_model_file

    run = tmp_path / "run"
    run.mkdir()
    foreign = tmp_path / "domain-model.json"       # sibling plant
    foreign.write_text(_json.dumps({"concepts": []}))

    def _boom(_out_dir):
        raise RuntimeError("pin substrate broke")

    monkeypatch.setattr("core.run.pin.resolve_run_pin", _boom)
    assert _find_domain_model_file(run) is None
