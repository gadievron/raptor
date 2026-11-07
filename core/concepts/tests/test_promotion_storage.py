"""Promotion must preserve durable study data under bounded storage."""

import json
import os

import pytest

from core.concepts import study
from core.concepts.model import Concept, DomainModel


from core.testing.module_bindings import patch_module_attribute


def _model(path, name="one"):
    DomainModel(target="target", concepts=[Concept(id=name, description="description")]).save(path)


def test_corrupt_canonical_is_not_replaced(tmp_path):
    canonical = tmp_path / "domain-model.json"
    run = tmp_path / "run.json"
    canonical.write_bytes(b"{broken")
    _model(run)
    with pytest.raises(ValueError):
        study.merge_promote_domain_model(run, canonical)
    assert canonical.read_bytes() == b"{broken"


def test_first_promotion_refuses_invalid_json(tmp_path):
    canonical = tmp_path / "domain-model.json"
    run = tmp_path / "run.json"
    run.write_bytes(b"{broken")
    with pytest.raises(ValueError):
        study.merge_promote_domain_model(run, canonical)
    assert not canonical.exists()


def test_unchanged_promotion_preserves_inode(tmp_path):
    canonical = tmp_path / "domain-model.json"
    run = tmp_path / "run.json"
    _model(run)
    study.merge_promote_domain_model(run, canonical)
    study.merge_promote_domain_model(run, canonical)
    before = canonical.stat()
    study.merge_promote_domain_model(run, canonical)
    assert canonical.stat().st_ino == before.st_ino
    assert canonical.stat().st_mtime_ns == before.st_mtime_ns


def _promote(kind, source, canonical):
    if kind == "domain":
        return study.merge_promote_domain_model(source, canonical)
    return study.merge_promote_patterns(source, canonical)


def _document(kind, name):
    if kind == "domain":
        from dataclasses import asdict
        return asdict(DomainModel(target="target", concepts=[Concept(id=name, description="x" * 100)]))
    return {"patterns": {name: {"description": "x" * 100}}}


@pytest.mark.parametrize("kind", ["domain", "patterns"])
def test_oversize_source_is_not_published(tmp_path, monkeypatch, kind):
    source = tmp_path / "run.json"
    canonical = tmp_path / "canonical.json"
    source.write_text(json.dumps(_document(kind, "one"), indent=2))
    monkeypatch.setattr(study, "_PROMOTION_MAX_BYTES", source.stat().st_size - 1)
    with pytest.raises(ValueError):
        _promote(kind, source, canonical)
    assert not canonical.exists()
    assert not list(tmp_path.glob(".atomic-*"))


@pytest.mark.parametrize("kind", ["domain", "patterns"])
def test_oversize_canonical_is_preserved(tmp_path, monkeypatch, kind):
    source = tmp_path / "run.json"
    canonical = tmp_path / "canonical.json"
    source.write_text("{}")
    original = json.dumps({"retained": "x" * 100}).encode()
    canonical.write_bytes(original)
    monkeypatch.setattr(study, "_PROMOTION_MAX_BYTES", 32)
    with pytest.raises(ValueError):
        _promote(kind, source, canonical)
    assert canonical.read_bytes() == original


@pytest.mark.parametrize("kind", ["domain", "patterns"])
def test_merged_output_must_fit_reader_budget(tmp_path, monkeypatch, kind):
    source = tmp_path / "run.json"
    canonical = tmp_path / "canonical.json"
    source.write_text(json.dumps(_document(kind, "two"), indent=2))
    canonical.write_text(json.dumps(_document(kind, "one"), indent=2))
    original = canonical.read_bytes()
    budget = max(len(original), source.stat().st_size) + 1
    monkeypatch.setattr(study, "_PROMOTION_MAX_BYTES", budget)
    with pytest.raises(ValueError, match="artifact budget"):
        _promote(kind, source, canonical)
    assert canonical.read_bytes() == original
    assert not list(tmp_path.glob(".atomic-*"))


@pytest.mark.parametrize("kind", ["domain", "patterns"])
@pytest.mark.parametrize("payload", ["null", "[]"])
def test_nonobject_source_is_refused(tmp_path, kind, payload):
    source = tmp_path / "run.json"
    canonical = tmp_path / "canonical.json"
    source.write_text(payload)
    with pytest.raises(ValueError, match="JSON object"):
        _promote(kind, source, canonical)
    assert not canonical.exists()


@pytest.mark.parametrize("kind", ["domain", "patterns"])
@pytest.mark.parametrize("shape", ["fifo", "symlink"])
def test_nonregular_source_is_refused(tmp_path, kind, shape):
    source = tmp_path / "run.json"
    canonical = tmp_path / "canonical.json"
    target = tmp_path / "outside.json"
    target.write_text("{}")
    if shape == "fifo":
        os.mkfifo(source)
    else:
        source.symlink_to(target)
    with pytest.raises((ValueError, OSError)):
        _promote(kind, source, canonical)
    assert not canonical.exists()
    assert target.read_text() == "{}"


@pytest.mark.parametrize("kind", ["domain", "patterns"])
def test_missing_source_preserves_canonical(tmp_path, kind):
    source = tmp_path / "missing.json"
    canonical = tmp_path / "canonical.json"
    canonical.write_text("{}")
    with pytest.raises(FileNotFoundError):
        _promote(kind, source, canonical)
    assert canonical.read_text() == "{}"


@pytest.mark.parametrize("kind", ["domain", "patterns"])
@pytest.mark.parametrize("cancel", [False, True])
def test_failed_publication_preserves_canonical(tmp_path, monkeypatch, kind, cancel):
    from core import atomic_fs

    source = tmp_path / "run.json"
    canonical = tmp_path / "canonical.json"
    source.write_text(json.dumps(_document(kind, "two")))
    canonical.write_text(json.dumps(_document(kind, "one")))
    original = canonical.read_bytes()

    def fail_replace(*args, **kwargs):
        if cancel:
            raise KeyboardInterrupt("publication cancelled")
        raise OSError("publication failed")

    with monkeypatch.context() as fault:
        patch_module_attribute(fault, atomic_fs, 'os', "replace", fail_replace)
        with pytest.raises(KeyboardInterrupt if cancel else OSError):
            _promote(kind, source, canonical)
    assert canonical.read_bytes() == original
    assert not list(tmp_path.glob(".atomic-*"))


def test_repeated_patterns_promotion_does_not_rewrite(tmp_path):
    source = tmp_path / "run.json"
    canonical = tmp_path / "patterns.json"
    source.write_text(json.dumps(_document("patterns", "one")))
    study.merge_promote_patterns(source, canonical)
    before = canonical.stat()
    study.merge_promote_patterns(source, canonical)
    assert canonical.stat().st_ino == before.st_ino
    assert canonical.stat().st_mtime_ns == before.st_mtime_ns


def test_domain_extras_and_bom_survive_bounded_merge(tmp_path):
    source = tmp_path / "run.json"
    canonical = tmp_path / "canonical.json"
    first = _document("domain", "one")
    first["overview_summary"] = "canonical summary"
    first["architecture"] = {"name": "café"}
    canonical.write_bytes(b"\xef\xbb\xbf" + json.dumps(first).encode())
    second = _document("domain", "two")
    second["overview_summary"] = "new summary"
    source.write_text(json.dumps(second))
    study.merge_promote_domain_model(source, canonical)
    merged = json.loads(canonical.read_text())
    assert merged["overview_summary"] == "new summary"
    assert merged["architecture"] == {"name": "café"}
    assert {entry["id"] for entry in merged["concepts"]} == {"one", "two"}
