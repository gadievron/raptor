"""Tests for the studio-side project-extras sidecar."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from packages.studio.services.project_extras import (
    PROJECT_TYPES,
    ProjectExtras,
    infer_type_from_runs,
    load,
    save,
)


def test_load_returns_empty_when_no_sidecar(tmp_path: Path):
    extras = load("missing", studio_dir=tmp_path)
    assert extras.type is None
    assert extras.is_empty


def test_save_then_load_roundtrip(tmp_path: Path):
    extras = ProjectExtras(type="source", language="python", created_via="studio")
    save("myproj", extras, studio_dir=tmp_path)
    loaded = load("myproj", studio_dir=tmp_path)
    assert loaded.type == "source"
    assert loaded.language == "python"
    assert loaded.created_via == "studio"


def test_save_creates_parent_dir(tmp_path: Path):
    extras = ProjectExtras(type="binary")
    save("myproj", extras, studio_dir=tmp_path / "nested" / "deeper")
    assert (tmp_path / "nested" / "deeper" / "project-extras" / "myproj.json").is_file()


def test_project_types_constants():
    assert set(PROJECT_TYPES) == {"source", "binary", "forensics"}


def test_malformed_sidecar_returns_empty(tmp_path: Path):
    (tmp_path / "project-extras").mkdir()
    (tmp_path / "project-extras" / "bad.json").write_text("{not json")
    assert load("bad", studio_dir=tmp_path).is_empty


@dataclass
class _FakeRun:
    kind: str


def test_infer_type_from_runs():
    assert infer_type_from_runs([_FakeRun("agentic")]) == "source"
    assert infer_type_from_runs([_FakeRun("scan")]) == "source"
    assert infer_type_from_runs([_FakeRun("fuzz")]) == "binary"
    assert infer_type_from_runs([_FakeRun("crash-analysis")]) == "binary"
    assert infer_type_from_runs([_FakeRun("oss-forensics")]) == "forensics"
    assert infer_type_from_runs([]) is None
    assert infer_type_from_runs([_FakeRun("other")]) is None


def test_infer_uses_first_run_with_conclusive_kind():
    runs = [_FakeRun("other"), _FakeRun("fuzz")]
    assert infer_type_from_runs(runs) == "binary"


def test_project_extras_is_empty_property():
    assert ProjectExtras().is_empty
    assert not ProjectExtras(type="source").is_empty
    assert not ProjectExtras(focus="something").is_empty
    assert not ProjectExtras(language="python").is_empty


def test_to_dict_shape():
    extras = ProjectExtras(
        type="binary", source_repo="/tmp/src", corpus_dir="/tmp/corpus",
        focus="", language="", created_via="studio",
    )
    d = extras.to_dict()
    assert d["type"] == "binary"
    assert d["source_repo"] == "/tmp/src"
    assert d["corpus_dir"] == "/tmp/corpus"
    assert d["created_via"] == "studio"


def test_backcompat_reads_old_binary_field(tmp_path):
    """Old sidecars used 'binary' for what is really a secondary source repo."""
    from packages.studio.services.project_extras import load
    sidecar = tmp_path / "project-extras" / "legacy.json"
    sidecar.parent.mkdir()
    import json
    sidecar.write_text(json.dumps({
        "type": "binary", "binary": "/tmp/old-source-path",
    }))
    extras = load("legacy", studio_dir=tmp_path)
    assert extras.source_repo == "/tmp/old-source-path"
    # And the legacy .binary alias still works for any remaining callers
    assert extras.binary == "/tmp/old-source-path"


def test_new_fields_roundtrip(tmp_path):
    from packages.studio.services.project_extras import load, save
    save("full", ProjectExtras(
        type="forensics", vendor_report_url="https://vendor/report.html",
        focus="July incident", corpus_dir="",
    ), studio_dir=tmp_path)
    loaded = load("full", studio_dir=tmp_path)
    assert loaded.vendor_report_url == "https://vendor/report.html"
    assert loaded.focus == "July incident"
