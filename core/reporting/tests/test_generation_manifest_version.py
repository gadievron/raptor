"""Unsupported immutable formats stay refused even with consistent byte hashes."""
import json

import pytest

from core.reporting.builders import build_document
from core.reporting.document import ReportContext, digest, encode
from core.reporting.options import ReportOptions
from core.reporting.writer import load_committed_report, load_report_generation, publish_report


def _generation(tmp_path, version=1):
    context = ReportContext("scan", "captured")
    publication = publish_report(context, build_document(context), tmp_path,
                                 options=ReportOptions(formats=("json",)))
    original = tmp_path / ".reporting" / publication.generation
    inputs = {name: (original / name).read_bytes() for name in ("report-context.json", "report-document.json")}
    manifest = json.loads((original / "manifest.json").read_bytes())
    if version == "missing":
        manifest.pop("schema_version")
    else:
        manifest["schema_version"] = version
    # Deliberately construct unsupported, self-consistent wire metadata. This
    # is not publisher evidence of a future format or an authenticity claim.
    definition = {k: v for k, v in manifest.items() if k not in {"generation", "directory", "status"}}
    generation = digest(definition)
    directory = ".reporting/" + generation
    manifest.update(generation=generation, directory=directory)
    (original / "manifest.json").write_bytes(encode(manifest))
    target = tmp_path / directory
    if target != original:
        original.rename(target)
    current_path = tmp_path / "reporting-manifest.json"
    current = json.loads(current_path.read_bytes())
    assert type(current["schema_version"]) is int and current["schema_version"] == 1
    current.update(generation=generation, directory=directory)
    current_path.write_bytes(encode(current))
    assert all((target / name).read_bytes() == data for name, data in inputs.items())
    return context, generation, target


def _load(directory, reader, generation, snapshot_id):
    if reader == "current":
        return load_committed_report(directory)
    return load_report_generation(directory, generation, snapshot_id)


@pytest.mark.parametrize("reader,version", [
    pytest.param("current", 2, id="current-future"),
    pytest.param("current", True, id="current-boolean"),
    pytest.param("current", "missing", id="current-missing"),
    pytest.param("pinned", 2, id="pinned-future"),
    pytest.param("pinned", True, id="pinned-boolean"),
    pytest.param("pinned", "missing", id="pinned-missing"),
])
def test_unsupported_generation_version_is_refused(tmp_path, reader, version):
    context, generation, _ = _generation(tmp_path, version)
    before = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    with pytest.raises(ValueError, match="manifest schema version"):
        _load(tmp_path, reader, generation, context.snapshot_id)
    assert all(path.read_bytes() == data for path, data in before.items())


@pytest.mark.parametrize("reader", ["current", "pinned"])
def test_publisher_schema_one_keeps_roundtrip(tmp_path, reader):
    context, generation, _ = _generation(tmp_path)
    before = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    restored, document, _ = _load(tmp_path, reader, generation, context.snapshot_id)
    assert restored.to_dict() == context.to_dict()
    assert restored.snapshot_id == document.snapshot_id == context.snapshot_id
    assert all(path.read_bytes() == data for path, data in before.items())


def test_supported_version_does_not_bypass_manifest_digest(tmp_path):
    context, generation, target = _generation(tmp_path)
    manifest_path = target / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["stem"] = "changed-without-updating-digest"
    manifest_path.write_bytes(encode(manifest))
    before = manifest_path.read_bytes()
    with pytest.raises(ValueError, match="generation digest mismatch"):
        load_report_generation(tmp_path, generation, context.snapshot_id)
    assert manifest_path.read_bytes() == before
