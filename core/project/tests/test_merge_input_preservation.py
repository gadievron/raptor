"""Destructive merges must not turn unreadable source data into empty results."""

import json
from types import SimpleNamespace

import pytest

from core.json import load_json
from core.project import cli, findings_utils as utils, merge, readjudication
from core.testing.state_isolation import pin_user_state_dirs


ROW = {"id": "row", "file": "a.c", "function": "main", "line": 1}


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


VALID = [
    pytest.param([], [], id="empty-list"),
    pytest.param({}, [], id="legacy-empty-object"),
    pytest.param([ROW], [ROW], id="list"),
    pytest.param({"findings": [ROW]}, [ROW], id="findings"),
    pytest.param({"results": [ROW]}, [ROW], id="results"),
    pytest.param({"findings": []}, [], id="empty-findings"),
    pytest.param({"results": []}, [], id="empty-results"),
    pytest.param({"findings": [], "results": [ROW]}, [], id="empty-primary-wins"),
    pytest.param({"findings": [ROW], "results": []}, [ROW], id="primary-wins"),
]
BAD = [
    pytest.param(None, id="null"),
    pytest.param(False, id="false"),
    pytest.param(1, id="number"),
    pytest.param("rows", id="string"),
    pytest.param({"other": [ROW]}, id="unknown-envelope"),
    pytest.param({"findings": None}, id="null-collection"),
    pytest.param({"findings": False}, id="false-collection"),
    pytest.param({"findings": "rows"}, id="string-collection"),
    pytest.param({"findings": ROW}, id="object-collection"),
    pytest.param({"results": 1}, id="numeric-results"),
    pytest.param([None], id="null-row"),
    pytest.param(["row"], id="string-row"),
    pytest.param([1, ROW, False, []], id="mixed-rows"),
    pytest.param({"findings": [ROW, None]}, id="mixed-envelope"),
    pytest.param({"findings": "bad", "results": [ROW]}, id="malformed-primary"),
]


@pytest.mark.parametrize("data,expected", VALID)
@pytest.mark.parametrize("source", ["findings.json", "openant_findings.json", "sca/findings.json"])
def test_valid_collection_shapes(tmp_path, source, data, expected):
    write(tmp_path / source, data)
    if source.startswith("sca/"):
        assert utils.load_sca_findings_from_dir(tmp_path) == expected
    else:
        assert utils.load_findings_from_dir(tmp_path) == expected
        assert utils.load_findings_from_dir(tmp_path, strict=True) == expected


@pytest.mark.parametrize("data", BAD)
@pytest.mark.parametrize("source", ["findings.json", "openant_findings.json", "sca/findings.json"])
def test_readonly_views_keep_only_object_rows(tmp_path, source, data):
    write(tmp_path / source, data)
    collection = data.get("findings") if isinstance(data, dict) else data
    expected = [row for row in collection if isinstance(row, dict)] if isinstance(collection, list) else []
    loader = utils.load_sca_findings_from_dir if source.startswith("sca/") else utils.load_findings_from_dir
    assert loader(tmp_path) == expected


@pytest.mark.parametrize("data", BAD)
@pytest.mark.parametrize("source", ["findings.json", "openant_findings.json"])
def test_malformed_sources_cannot_publish_a_lossy_merge(tmp_path, source, data):
    run = tmp_path / "scan-old"
    path = run / source
    write(path, data)
    before = path.read_bytes()
    output = tmp_path / "merged"
    with pytest.raises(ValueError):
        merge.merge_runs([run], output)
    assert not output.exists()
    assert path.read_bytes() == before
    assert not list(tmp_path.glob(".merge-stage-*"))


@pytest.mark.parametrize("kind", ["syntax", "encoding", "oversized", "directory", "symlink", "dangling", "deep"])
@pytest.mark.parametrize("fallback", [False, True], ids=["no-fallback", "valid-fallback"])
def test_strict_reads_refuse_unrepresented_primary(tmp_path, monkeypatch, kind, fallback):
    path = tmp_path / "findings.json"
    if kind == "directory":
        path.mkdir()
    elif kind in {"symlink", "dangling"}:
        target = tmp_path / "target.json"
        if kind == "symlink":
            write(target, [ROW])
        path.symlink_to(target)
    elif kind == "encoding":
        path.write_bytes(b"\xff")
    elif kind == "oversized":
        write(path, [ROW])
        monkeypatch.setattr(utils, "MAX_FINDINGS_JSON_BYTES", 8)
    elif kind == "deep":
        path.write_text("[" * 3000 + "]" * 3000)
    else:
        path.write_text("{unfinished")
    if fallback:
        write(tmp_path / "openant_findings.json", [ROW])
    with pytest.raises((ValueError, OSError)):
        utils.load_findings_from_dir(tmp_path, strict=True)


@pytest.mark.parametrize("strict", [False, True])
def test_missing_artifacts_are_valid_empty_runs(tmp_path, strict):
    assert utils.load_findings_from_dir(tmp_path, strict=strict) == []
    # Keep all generated paths inside the owned fixture directory.
    run = tmp_path / "empty-run"
    run.mkdir()
    output = tmp_path / "merged"
    assert merge.merge_runs([run], output)["unique_findings"] == 0
    assert output.is_dir()


@pytest.mark.parametrize("kind", ["unreadable", "vanished", "grew"])
def test_strict_read_refuses_changes_after_advisory_stat(tmp_path, monkeypatch, kind):
    path = tmp_path / "findings.json"
    write(path, [ROW])
    original = utils.load_json

    def changing_read(p, **kwargs):
        if kind == "unreadable":
            raise PermissionError("test-owned read denied")
        if kind == "vanished":
            path.unlink()
        else:
            path.write_text(" " * 1024)
        return original(p, **kwargs)

    monkeypatch.setattr(utils, "MAX_FINDINGS_JSON_BYTES", 256)
    monkeypatch.setattr(utils, "load_json", changing_read)
    with pytest.raises((ValueError, OSError)):
        utils.load_findings_from_dir(tmp_path, strict=True)


@pytest.mark.parametrize("strict", [False, True])
def test_existing_bad_artifact_cannot_be_hidden_by_supplied_snapshot(tmp_path, strict):
    write(tmp_path / "findings.json", None)
    context = SimpleNamespace(findings=[{"native": ROW}], kind="scan")
    if strict:
        with pytest.raises(ValueError):
            utils.load_findings_from_dir(tmp_path, report_context=context, strict=True)
    else:
        assert utils.load_findings_from_dir(tmp_path, report_context=context) == []


@pytest.mark.parametrize("strict", [False, True])
def test_explicit_snapshot_remains_available_without_live_artifacts(tmp_path, strict):
    context = SimpleNamespace(findings=[{"native": ROW}], kind="scan")
    assert utils.load_findings_from_dir(tmp_path, report_context=context, strict=strict) == [ROW]


def test_unreadable_committed_snapshot_refuses_destructive_merge(tmp_path):
    run = tmp_path / "run"
    write(run / "reporting-manifest.json", {"broken": True})
    with pytest.raises((ValueError, OSError, TypeError)):
        merge.merge_runs([run], tmp_path / "merged")
    assert not (tmp_path / "merged").exists()
    assert (run / "reporting-manifest.json").exists()


@pytest.mark.parametrize("data", BAD)
def test_cli_preserves_both_sources_when_one_input_is_invalid(tmp_path, monkeypatch, capsys, data):
    pin_user_state_dirs(monkeypatch, tmp_path / "user")
    root = tmp_path / "output"
    runs = [root / "scan-new", root / "scan-old"]
    for run in runs:
        write(run / ".raptor-run.json", {"version": 2, "command": "scan", "status": "completed",
                                        "project": None, "project_source": "none"})
        write(run / "findings.json", [ROW])
    write(runs[1] / "findings.json", data)
    before = [(run / "findings.json").read_bytes() for run in runs]
    project = SimpleNamespace(name="demo", target=str(tmp_path / "source"), output_path=root,
                              get_run_dirs_by_type=lambda: {"scan": runs})
    cli._do_merge(project, "all", yes=True)
    assert "Source runs preserved" in capsys.readouterr().out
    assert [(run / "findings.json").read_bytes() for run in runs] == before
    assert {path.name for path in root.iterdir() if path.is_dir()} == {run.name for run in runs}
    assert not list(root.glob(".raptor-merge-*"))


def test_all_merge_consumers_share_one_capture(tmp_path, monkeypatch):
    run = tmp_path / "run"
    write(run / "findings.json", [ROW])
    write(run / ".raptor-imported.json", {"imported": True})
    write(run / ".raptor-run.json", {"status": "completed"})
    (run / ".reporting").mkdir()
    (run / ".reporting" / "history.txt").write_text("historical input")
    reads = []
    origins = []
    detections = []
    original_load = merge._load_findings_from_dir
    original_origin = merge._run_is_imported
    original_fold = merge.merge_findings
    original_detect = readjudication.detect_project_contradictions

    def read(path, **kwargs):
        reads.append((path, kwargs))
        return original_load(path, **kwargs)

    def origin(path):
        origins.append(path)
        value = original_origin(path)
        (path / ".raptor-imported.json").unlink()
        return value

    def fold(paths, **kwargs):
        write(run / "findings.json", [{**ROW, "id": "changed-after-capture"}])
        write(run / ".raptor-run.json", {"status": "running"})
        assert kwargs["records_by_run"][str(run)] == [ROW]
        assert kwargs["origins_by_run"][str(run)] is True
        return original_fold(paths, **kwargs)

    def detect(paths, **kwargs):
        assert kwargs["records_by_run"][str(run)] == [ROW]
        assert kwargs["origins_by_run"][str(run)] is True
        assert kwargs["metadata_by_run"][str(run)] == {"status": "completed"}
        result = original_detect(paths, **kwargs)
        detections.append(True)
        return result

    monkeypatch.setattr(merge, "_load_findings_from_dir", read)
    monkeypatch.setattr(merge, "_run_is_imported", origin)
    monkeypatch.setattr(merge, "merge_findings", fold)
    monkeypatch.setattr(readjudication, "detect_project_contradictions", detect)
    output = tmp_path / "merged"
    result = merge.merge_runs([run], output)
    assert reads == [(run, {"strict": True})]
    assert origins == [run]
    assert detections == [True]
    assert result["total_findings"] == result["unique_findings"] == 1
    assert load_json(output / "findings.json")["findings"] == [ROW]
    assert load_json(output / ".raptor-imported.json")["imported"] is True
    history_source, = (output / "report-histories").glob("*/source.json")
    assert load_json(history_source)["imported"] is True


@pytest.mark.parametrize("kind", ["directory", "symlink", "dangling"])
def test_nonregular_reporting_manifest_is_not_an_empty_run(tmp_path, kind):
    run = tmp_path / "run"
    run.mkdir()
    manifest = run / "reporting-manifest.json"
    if kind == "directory":
        manifest.mkdir()
    else:
        target = tmp_path / "target.json"
        if kind == "symlink":
            write(target, {"broken": True})
        manifest.symlink_to(target)
    with pytest.raises(ValueError):
        merge.merge_runs([run], tmp_path / "merged")
    assert not (tmp_path / "merged").exists()
    assert manifest.is_symlink() or manifest.is_dir()


@pytest.mark.parametrize("source", ["findings.json", "openant_findings.json"])
def test_diff_reads_valid_rows_from_malformed_collections(tmp_path, source):
    from core.project.diff import diff_runs

    old, new = tmp_path / "old", tmp_path / "new"
    write(old / source, [None, ROW, "not-a-row"])
    write(new / source, [ROW, False])
    diff = diff_runs(old, new)
    assert diff["unchanged"] == 1
    assert diff["new"] == diff["removed"] == diff["changed"] == []
    assert diff["summary"]["findings_a"] == diff["summary"]["findings_b"] == 1


def test_report_publication_and_reader_keep_valid_rows(tmp_path, monkeypatch):
    from core.project.project import Project
    from core.project.report import generate_project_report
    from core.reporting.writer import load_committed_report

    pin_user_state_dirs(monkeypatch, tmp_path / "user")
    root = tmp_path / "output"
    run = root / "scan-old"
    write(run / ".raptor-run.json", {"command": "scan", "status": "completed"})
    write(run / "findings.json", {"findings": [None, ROW, "broken"]})
    project = Project(name="demo", target=str(tmp_path / "source"), output_dir=str(root))
    result = generate_project_report(project)
    assert result["findings"] == 1
    context, document, manifest = load_committed_report(root / "_report")
    assert len(context.findings) == 1
    assert context.findings[0]["native"]["id"] == ROW["id"]
    assert document.snapshot_id == context.snapshot_id
    assert manifest["snapshot_id"] == context.snapshot_id
    assert load_json(run / "findings.json")["findings"] == [None, ROW, "broken"]
