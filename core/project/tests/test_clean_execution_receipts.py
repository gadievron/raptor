"""Confirmed cleanup reports and cache references follow actual removals."""

import json
import os
import shutil
import time
from pathlib import Path
import pytest
from core.project import clean
from core.project import cli


class Project:
    def __init__(self, root, target=None):
        self.output_path = root
        self.output_dir = str(root)
        self.target = target

    def get_run_dirs(self, sweep=False):
        return sorted(
            [
                p
                for p in self.output_path.iterdir()
                if p.is_dir() and not p.name.startswith((".", "_"))
            ],
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )

    def get_run_dirs_by_type(self):
        groups = {}
        for path in self.get_run_dirs():
            command = json.loads((path / ".raptor-run.json").read_text()).get(
                "command", "scan"
            )
            groups.setdefault(command, []).append(path)
        return groups


def run(root, name, *, command="scan", age=0, sha=None, coverage=None):
    path = root / name
    path.mkdir()
    metadata = {"version": 2, "command": command, "status": "completed", "extra": {}}
    if sha:
        metadata["manifest"] = {"target": {"source": "archive", "archive_sha256": sha}}
    (path / ".raptor-run.json").write_text(json.dumps(metadata))
    (path / "payload").write_bytes(b"x" * 128)
    if coverage is not None:
        (path / "coverage-semgrep.json").write_text(
            json.dumps(
                {"tool": "semgrep", "files_examined": coverage, "timestamp": "t"}
            )
        )
        (path / "findings.json").write_text("[]")
    os.utime(path, (time.time() - age,) * 2)
    return path


def archive(root, sha):
    path = root / "_sources" / ("archive-" + sha)
    path.mkdir(parents=True)
    (path / "payload").write_text("source material")
    old = time.time() - 86400
    os.utime(path, (old, old))
    return path


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    return Project(root)


@pytest.mark.parametrize("change", ["resumed", "removed", "replaced"])
@pytest.mark.parametrize("command", ["scan", "audit", "validate"])
def test_execution_reports_only_actual_deletions(project, monkeypatch, change, command):
    root = project.output_path
    old = run(root, "scan-01-old", command=command, age=30)
    new = run(root, "scan-02-new", command=command)
    plan = clean.plan_clean(project)
    if change == "resumed":
        monkeypatch.setattr(clean, "run_is_live", lambda path: path == old)
    elif change == "removed":
        shutil.rmtree(old)
    else:
        old.rename(root / "_original")
        run(root, "scan-01-old", command=command, age=30)
    clean.execute_clean(plan, output_path=root)
    assert plan["deleted"] == []
    assert plan["delete_dirs"] == []
    assert plan["freed_bytes"] == 0
    assert plan["by_type"][command]["delete"] == 0
    assert plan["by_type"][command]["freed_bytes"] == 0
    assert new.exists()
    if change != "removed":
        assert old.exists()
        assert old.name in plan["kept"]


@pytest.mark.parametrize("mode", ["keep", "dedup"])
def test_replaced_victim_is_not_covered_by_old_confirmation(project, mode):
    root = project.output_path
    old = run(root, "scan-01-old", age=30, coverage=["a.c"])
    run(root, "scan-02-new", coverage=["a.c"])
    plan = clean.plan_dedup(project) if mode == "dedup" else clean.plan_clean(project)
    assert old in plan["delete_dirs"]
    old.rename(root / "_saved")
    run(root, "scan-01-old", age=30, coverage=["a.c"])
    clean.execute_clean(plan, output_path=root)
    assert old.exists()
    assert plan["deleted"] == []


def test_execution_remeasures_bytes_before_reporting(project):
    root = project.output_path
    old = run(root, "scan-01-old", age=30)
    run(root, "scan-02-new")
    plan = clean.plan_clean(project)
    (old / "new-payload").write_bytes(b"x" * 4096)
    expected = clean._run_dir_size(old)
    clean.execute_clean(plan, output_path=root)
    assert plan["deleted"] == ["scan-01-old"]
    assert plan["freed_bytes"] == expected
    assert plan["by_type"]["scan"]["freed_bytes"] == expected


def test_failed_removal_keeps_receipt_of_successful_prefix(project, monkeypatch):
    root = project.output_path
    first = run(root, "first", age=30)
    second = run(root, "second", age=20)
    run(root, "scan-02-new")
    plan = clean.plan_clean(project)
    plan["delete_dirs"] = [first, second]
    expected = clean._run_dir_size(first)
    remove = clean.rmtree_hardened
    monkeypatch.setattr(
        clean, "rmtree_hardened", lambda path: False if path == second else remove(path)
    )
    with pytest.raises(OSError):
        clean.execute_clean(plan, output_path=root)
    assert plan["deleted"] == ["first"]
    assert plan["freed_bytes"] == expected
    assert plan["by_type"]["scan"]["delete"] == 1
    assert second.exists()


def test_duplicate_plan_paths_are_not_counted_twice(project):
    root = project.output_path
    old = run(root, "scan-01-old", age=30)
    run(root, "scan-02-new")
    plan = clean.plan_clean(project)
    plan["delete_dirs"].append(old)
    clean.execute_clean(plan, output_path=root)
    assert plan["deleted"] == [old.name]
    assert plan["delete_dirs"] == [old]


def test_output_root_itself_is_never_a_deletion_candidate(project):
    root = project.output_path
    run(root, "keep")
    with pytest.raises(RuntimeError):
        clean.execute_clean({"delete_dirs": [root]}, output_path=root)
    assert root.exists()


def test_unresolvable_explicit_root_does_not_enable_legacy_fallback(
    project, tmp_path, monkeypatch
):
    root = project.output_path
    victim = run(root, "keep")
    broken = tmp_path / "unresolvable"
    resolve = Path.resolve

    def fail(path, *args, **kwargs):
        if path == broken:
            raise OSError("root unavailable")
        return resolve(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", fail)
    with pytest.raises(RuntimeError):
        clean.execute_clean({"delete_dirs": [victim]}, output_path=broken)
    assert victim.exists()


@pytest.mark.parametrize("dedup", [False, True])
def test_confirmation_race_preserves_last_or_only_covered_run(
    project, monkeypatch, capsys, dedup
):
    root = project.output_path
    old = run(root, "scan-01-old", age=30, coverage=["a.c"])
    newest = run(root, "scan-02-new", coverage=["a.c"])

    def confirm(prompt):
        shutil.rmtree(newest)
        return True

    monkeypatch.setattr(cli, "_confirm", confirm)
    cli._do_clean(project, keep=1, dry_run=False, yes=False, dedup=dedup)
    assert old.exists()
    output = capsys.readouterr().out
    assert "Deleted: scan-01-old" not in output
    assert "0 runs deleted" in output
    assert "0.0MB freed" in output


@pytest.mark.parametrize("dedup", [False, True])
def test_resumed_run_keeps_its_archive_cache_and_is_not_snapshotted(
    project, monkeypatch, capsys, dedup
):
    root = project.output_path
    sha = "a" * 64
    source = archive(root, sha)
    old = run(root, "scan-01-old", age=30, sha=sha, coverage=["a.c"])
    run(root, "scan-02-new", coverage=["a.c"])
    live = set()
    snapshots = []
    monkeypatch.setattr(clean, "run_is_live", lambda path: path in live)
    monkeypatch.setattr(
        cli,
        "_apply_clean_coverage",
        lambda p, plan, c: snapshots.extend(plan["delete_dirs"]),
    )

    def confirm(prompt):
        live.add(old)
        return True

    monkeypatch.setattr(cli, "_confirm", confirm)
    cli._do_clean(project, keep=1, dry_run=False, yes=False, dedup=dedup)
    assert old.exists()
    assert source.exists()
    assert snapshots == []
    assert "Deleted: scan-01-old" not in capsys.readouterr().out


def test_sources_executor_distrusts_claimed_but_still_existing_run_deletions(project):
    root = project.output_path
    sha = "b" * 64
    source = archive(root, sha)
    victim = run(root, "scan-01-old", age=30, sha=sha)
    plan = clean.plan_sources_sweep(project, [victim])
    assert source in plan["delete_dirs"]
    result = clean.execute_sources_sweep(project, plan, [victim])
    assert source.exists()
    assert result["deleted"] == []
    assert result["freed_bytes"] == 0


def test_sources_identity_replacement_survives_old_confirmation(project):
    root = project.output_path
    sha = "c" * 64
    source = archive(root, sha)
    plan = clean.plan_sources_sweep(project)
    source.rename(root / "_saved_source")
    archive(root, sha)
    result = clean.execute_sources_sweep(project, plan)
    assert source.exists()
    assert result["deleted"] == []
    assert result["freed_bytes"] == 0


@pytest.mark.parametrize("dedup", [False, True])
def test_new_candidates_are_not_added_after_confirmation(project, monkeypatch, dedup):
    root = project.output_path
    old = run(root, "scan-01-old", age=30, coverage=["a.c"])
    run(root, "scan-02-new", coverage=["a.c"])
    added = root / "scan-00-added"

    def confirm(prompt):
        run(root, "scan-00-added", age=60, coverage=["a.c"])
        return True

    monkeypatch.setattr(cli, "_confirm", confirm)
    cli._do_clean(project, keep=1, dry_run=False, yes=False, dedup=dedup)
    assert not old.exists()
    assert added.exists()


@pytest.mark.parametrize("dry_run", [True, False])
def test_dry_run_and_declined_confirmation_do_not_snapshot_or_delete(
    project, monkeypatch, dry_run
):
    root = project.output_path
    old = run(root, "scan-01-old", age=30)
    run(root, "scan-02-new")
    snapshots = []
    monkeypatch.setattr(cli, "_confirm", lambda prompt: False)
    monkeypatch.setattr(
        cli, "_apply_clean_coverage", lambda p, plan, c: snapshots.append(plan)
    )
    cli._do_clean(project, keep=1, dry_run=dry_run, yes=False)
    assert old.exists()
    assert snapshots == []


@pytest.mark.parametrize("change", ["resumed", "replaced"])
def test_callback_cannot_authorize_a_changed_run(project, monkeypatch, change):
    root = project.output_path
    victim = run(root, "scan-01-old", age=30)
    run(root, "scan-02-new")
    plan = clean.plan_clean(project)
    live = set()
    monkeypatch.setattr(clean, "run_is_live", lambda path: path in live)

    def callback(path):
        assert path == victim
        if change == "resumed":
            live.add(path)
        else:
            path.rename(root / "_saved")
            run(root, path.name)

    clean.execute_clean(plan, output_path=root, before_delete=callback)
    assert victim.exists()
    assert plan["deleted"] == []
    assert plan["freed_bytes"] == 0


@pytest.mark.parametrize("dedup", [False, True])
def test_failed_policy_census_retains_confirmed_runs(project, monkeypatch, dedup):
    root = project.output_path
    victim = run(root, "scan-01-old", age=30, coverage=["a.c"])
    run(root, "scan-02-new", coverage=["a.c"])

    def confirm(prompt):
        def fail():
            raise OSError("inventory unavailable")

        monkeypatch.setattr(project, "get_run_dirs_by_type", fail)
        return True

    monkeypatch.setattr(cli, "_confirm", confirm)
    cli._do_clean(project, keep=1, dry_run=False, yes=False, dedup=dedup)
    assert victim.exists()


def test_callback_failure_finalizes_empty_receipt(project):
    root = project.output_path
    victim = run(root, "scan-01-old", age=30)
    run(root, "scan-02-new")
    plan = clean.plan_clean(project)

    def callback(path):
        raise OSError("snapshot failed")

    with pytest.raises(OSError, match="snapshot failed"):
        clean.execute_clean(plan, output_path=root, before_delete=callback)
    assert victim.exists()
    assert plan["deleted"] == []
    assert plan["freed_bytes"] == 0
