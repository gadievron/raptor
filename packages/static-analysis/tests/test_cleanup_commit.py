"""Artifact cleanup must follow a committed merge and preserve unknown output."""

import importlib.util
import json
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location(
    "scanner_cleanup_commit", Path(__file__).parents[1] / "scanner.py"
)
scanner = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scanner)
EMPTY = {"version": "2.1.0", "runs": [{"results": []}]}
FINDINGS = {
    "version": "2.1.0",
    "runs": [{"results": [{"ruleId": "keep", "message": {"text": "finding"}}]}],
}


def pack(root, suffix="auth", exit_code="0", sarif=FINDINGS):
    paths = {
        ext: root / f"semgrep_{suffix}.{ext}"
        for ext in ("exit", "json", "sarif", "stderr.log")
    }
    paths["exit"].write_text(exit_code)
    paths["json"].write_text('{"results":[{"check_id":"keep"}]}')
    paths["sarif"].write_text(json.dumps(sarif))
    paths["stderr.log"].write_text("diagnostic\n")
    return paths


def combined(root, data=FINDINGS):
    target = root / "combined.sarif"
    target.write_text(json.dumps(data))
    return target


@pytest.mark.parametrize("exit_code", ["0", "1", "2"])
@pytest.mark.parametrize("state", ["missing", "invalid", "wrong_shape", "symlink"])
def test_no_cleanup_without_readable_canonical_report(tmp_path, exit_code, state):
    paths = pack(tmp_path, exit_code=exit_code)
    if state == "invalid":
        (tmp_path / "combined.sarif").write_text("truncated {")
    elif state == "wrong_shape":
        combined(tmp_path, {"runs": "unknown"})
    elif state == "symlink":
        real = tmp_path / "other.sarif"
        real.write_text(json.dumps(FINDINGS))
        (tmp_path / "combined.sarif").symlink_to(real)
    assert scanner.cleanup_per_pack_artifacts(tmp_path) == 0
    assert all(path.exists() for path in paths.values())


@pytest.mark.parametrize("exit_code", ["0", "1", "2", "invalid"])
@pytest.mark.parametrize(
    "data",
    [
        None,
        [],
        {},
        {"runs": []},
        {"version": "2.1.0", "runs": [None]},
        {"version": "2.1.0", "runs": [{"results": "unknown"}]},
    ],
)
def test_unknown_pack_report_preserves_raw_results_and_diagnostics(
    tmp_path, exit_code, data
):
    combined(tmp_path)
    paths = pack(tmp_path, exit_code=exit_code, sarif=data)
    scanner.cleanup_per_pack_artifacts(tmp_path)
    assert all(path.exists() for path in paths.values())


@pytest.mark.parametrize("exit_code", ["0", "2"])
def test_unparseable_pack_report_is_preserved(tmp_path, exit_code):
    combined(tmp_path)
    paths = pack(tmp_path, exit_code=exit_code)
    paths["sarif"].write_text("truncated {")
    scanner.cleanup_per_pack_artifacts(tmp_path)
    assert all(path.exists() for path in paths.values())


def test_cleanup_only_covers_actual_merge_inputs(tmp_path):
    combined(tmp_path)
    merged = pack(tmp_path, "merged")
    omitted = pack(tmp_path, "omitted")
    scanner.cleanup_per_pack_artifacts(tmp_path, merged_inputs=[merged["sarif"]])
    assert not merged["sarif"].exists()
    assert all(path.exists() for path in omitted.values())


def test_exit_read_is_bounded_and_does_not_follow_links(tmp_path):
    combined(tmp_path)
    paths = pack(tmp_path)
    paths["exit"].unlink()
    real = tmp_path / "other.exit"
    real.write_text("0")
    paths["exit"].symlink_to(real)
    scanner.cleanup_per_pack_artifacts(tmp_path)
    assert paths["exit"].is_symlink()
    assert paths["sarif"].exists()
    assert real.read_text() == "0"


def test_unreadable_pack_does_not_abort_other_cleanup(tmp_path, monkeypatch):
    combined(tmp_path)
    bad = pack(tmp_path, "a_bad", exit_code="2")
    good = pack(tmp_path, "b_good")
    original = Path.is_file

    def fail(path):
        if path == bad["sarif"]:
            raise PermissionError("unreadable report")
        return original(path)

    original_read = scanner.read_bytes_gated

    def read(path, *args, **kwargs):
        if path == bad["sarif"]:
            raise PermissionError("unreadable report")
        return original_read(path, *args, **kwargs)

    monkeypatch.setattr(Path, "is_file", fail)
    monkeypatch.setattr(scanner, "read_bytes_gated", read)
    scanner.cleanup_per_pack_artifacts(tmp_path)
    assert not good["sarif"].exists()
    assert bad["sarif"].exists()


@pytest.mark.parametrize("merge_completed", [False, True])
def test_finalize_saves_provenance_before_cleanup(
    tmp_path, monkeypatch, merge_completed
):
    paths = pack(tmp_path)
    merged = combined(tmp_path)
    original = scanner.cleanup_per_pack_artifacts
    calls = []

    def cleanup(root, **kwargs):
        receipt = json.loads((root / "verification.json").read_text())
        assert receipt["packs"][0]["sarif_sha256"]
        assert paths["sarif"].exists()
        calls.append(kwargs)
        return original(root, **kwargs)

    monkeypatch.setattr(scanner, "cleanup_per_pack_artifacts", cleanup)
    scanner._finalize_scan_artifacts(
        [paths["sarif"]], merged, tmp_path, merge_completed=merge_completed
    )
    assert bool(calls) is merge_completed
    assert paths["sarif"].exists() is (not merge_completed)
    assert (tmp_path / "verification.json").exists()


def test_failed_provenance_commit_keeps_original_artifacts(tmp_path, monkeypatch):
    paths = pack(tmp_path)
    merged = combined(tmp_path)

    def fail(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(scanner, "save_json", fail)
    with pytest.raises(OSError):
        scanner._finalize_scan_artifacts(
            [paths["sarif"]], merged, tmp_path, merge_completed=True
        )
    assert all(path.exists() for path in paths.values())


def test_failed_provenance_composition_keeps_original_artifacts(tmp_path, monkeypatch):
    paths = pack(tmp_path)
    merged = combined(tmp_path)

    def fail(*args, **kwargs):
        raise OSError("cannot hash")

    monkeypatch.setattr(scanner, "_compose_verification_manifest", fail)
    scanner._finalize_scan_artifacts(
        [paths["sarif"]], merged, tmp_path, merge_completed=True
    )
    assert all(path.exists() for path in paths.values())
    assert (tmp_path / "verification.json").exists()


@pytest.mark.parametrize("marker", [b"0" * 65, b"1" * 10000, b"\xff", b"not-an-exit"])
def test_bad_exit_markers_are_unknown_to_cleanup_and_provenance(tmp_path, marker):
    combined(tmp_path)
    paths = pack(tmp_path)
    paths["exit"].write_bytes(marker)
    scanner.cleanup_per_pack_artifacts(tmp_path)
    assert all(path.exists() for path in paths.values())
    provenance = scanner._pack_provenance_from_sarif(paths["sarif"], tmp_path)
    assert provenance["exit"] == -1


def test_stale_combined_report_is_not_recorded_as_current_after_merge_failure(tmp_path):
    paths = pack(tmp_path)
    merged = combined(tmp_path)
    scanner._finalize_scan_artifacts(
        [paths["sarif"]], merged, tmp_path, merge_completed=False
    )
    manifest = json.loads((tmp_path / "verification.json").read_text())
    assert manifest["combined_sarif"]["sha256"] == ""
    assert manifest["combined_sarif"]["size_bytes"] == 0
    assert manifest["packs"][0]["sarif_sha256"]
    assert all(path.exists() for path in paths.values())


def test_cleanup_failure_leaves_committed_provenance(tmp_path, monkeypatch):
    paths = pack(tmp_path)
    merged = combined(tmp_path)

    def fail(*args, **kwargs):
        raise OSError("cannot delete")

    monkeypatch.setattr(scanner, "cleanup_per_pack_artifacts", fail)
    scanner._finalize_scan_artifacts(
        [paths["sarif"]], merged, tmp_path, merge_completed=True
    )
    assert (tmp_path / "verification.json").exists()
    assert paths["sarif"].exists()


def test_over_budget_report_is_preserved_as_unknown(tmp_path, monkeypatch):
    combined(tmp_path, EMPTY)
    paths = pack(
        tmp_path,
        sarif={"version": "2.1.0", "runs": [{"results": [], "padding": "x" * 512}]},
    )
    monkeypatch.setattr(scanner, "_MAX_TOOL_JSON_BYTES", 128)
    scanner.cleanup_per_pack_artifacts(tmp_path)
    assert all(path.exists() for path in paths.values())


def test_failed_unlink_does_not_cancel_other_packs(tmp_path, monkeypatch):
    combined(tmp_path)
    bad = pack(tmp_path, "a_bad")
    good = pack(tmp_path, "b_good")
    unlink = Path.unlink

    def fail(path, *args, **kwargs):
        if path == bad["json"]:
            raise PermissionError("busy")
        return unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail)
    count = scanner.cleanup_per_pack_artifacts(tmp_path)
    assert count == 3
    assert bad["json"].exists()
    assert not good["sarif"].exists()


@pytest.mark.parametrize("blocked", ["json", "sarif"])
def test_partial_cleanup_retains_exit_marker_until_large_files_are_removed(
    tmp_path, monkeypatch, blocked
):
    combined(tmp_path)
    paths = pack(tmp_path)
    unlink = Path.unlink

    def fail(path, *args, **kwargs):
        if path == paths[blocked]:
            raise PermissionError("file is busy")
        return unlink(path, *args, **kwargs)

    with monkeypatch.context() as fault:
        fault.setattr(Path, "unlink", fail)
        scanner.cleanup_per_pack_artifacts(tmp_path)
    assert paths[blocked].exists()
    assert paths["exit"].exists()
    scanner.cleanup_per_pack_artifacts(tmp_path)
    assert not paths["json"].exists()
    assert not paths["sarif"].exists()
    assert not paths["exit"].exists()
