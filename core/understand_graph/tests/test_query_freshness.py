"""Graph memory must describe the requested, unchanged source snapshot."""

import json

import pytest

from core.understand_graph import ingest_run, prompt_context_for_location, reachable_sinks
from core.understand_graph.store import graph_write_txn
from core.understand_graph.tests.test_understand_graph import _write_fixture_run


def _seed(tmp_path, name="one", *, graph=None):
    target = tmp_path / name
    run = tmp_path / f"run-{name}"
    _write_fixture_run(run, target)
    graph = ingest_run(run, str(target), graph_path=graph or tmp_path / "graph.sqlite")
    assert graph is not None
    return target, run, graph


def test_source_change_excludes_both_sink_and_prompt_evidence(tmp_path):
    target, _, graph = _seed(tmp_path)
    assert reachable_sinks(graph, str(target))
    assert prompt_context_for_location(graph, "app.py", target_path=str(target))
    (target / "app.py").write_text("# replaced since inventory\n")
    assert reachable_sinks(graph, str(target)) == []
    assert reachable_sinks(graph) == []
    assert prompt_context_for_location(graph, "app.py", target_path=str(target)) == ""
    assert prompt_context_for_location(graph, "app.py") == ""


def test_deleted_source_excludes_evidence(tmp_path):
    target, _, graph = _seed(tmp_path)
    (target / "app.py").unlink()
    assert reachable_sinks(graph, str(target)) == []
    assert prompt_context_for_location(graph, "app.py", target_path=str(target)) == ""


def test_prompt_context_requires_target_for_multi_target_history(tmp_path):
    target, _, graph = _seed(tmp_path)
    other, _, _ = _seed(tmp_path, "two", graph=graph)
    with graph_write_txn(graph) as conn:
        conn.execute("UPDATE nodes SET name='foreign', props_json=? WHERE kind='sink' "
                     "AND snapshot_id IN (SELECT id FROM snapshots WHERE target_path=?)",
                     (json.dumps({"id": "FOREIGN"}), str(other)))
    assert prompt_context_for_location(graph, "app.py") == ""
    block = prompt_context_for_location(graph, "app.py", target_path=str(target))
    assert "SINK-001" in block
    assert "FOREIGN" not in block
    assert prompt_context_for_location(graph, "app.py", target_path=str(tmp_path / "missing")) == ""


@pytest.mark.parametrize("path", ["missing/app.py", "../one/app.py", "elsewhere.py"])
def test_prompt_context_does_not_guess_by_basename(tmp_path, path):
    target, _, graph = _seed(tmp_path)
    assert prompt_context_for_location(graph, path, target_path=str(target)) == ""


def test_prompt_context_normalizes_absolute_source_path(tmp_path):
    target, _, graph = _seed(tmp_path)
    relative = prompt_context_for_location(graph, "app.py", target_path=str(target))
    assert relative
    assert prompt_context_for_location(graph, str(target / "app.py"),
                                       target_path=str(target)) == relative
    assert prompt_context_for_location(graph, str(tmp_path / "outside" / "app.py"),
                                       target_path=str(target)) == ""


def test_prompt_context_uses_latest_understand_snapshot(tmp_path):
    target, run, graph = _seed(tmp_path)
    later = tmp_path / "run-later"
    _write_fixture_run(later, target)
    context = json.loads((later / "context-map.json").read_text())
    context["sink_details"][0]["id"] = "CURRENT-SINK"
    (later / "context-map.json").write_text(json.dumps(context))
    ingest_run(later, str(target), graph_path=graph)
    with graph_write_txn(graph) as conn:
        conn.execute("UPDATE snapshots SET created_at=CASE WHEN producer_run=? "
                     "THEN '2030-01-01' ELSE '2020-01-01' END", (str(later),))
    block = prompt_context_for_location(graph, "app.py", target_path=str(target))
    assert "CURRENT-SINK" in block
    assert "SINK-001" not in block


def test_stale_sink_node_excludes_reachability(tmp_path):
    target, _, graph = _seed(tmp_path)
    with graph_write_txn(graph) as conn:
        conn.execute("UPDATE nodes SET stale=1 WHERE kind='sink'")
    assert reachable_sinks(graph, str(target)) == []


def test_prompt_lookup_hashes_only_the_requested_file(tmp_path, monkeypatch):
    target, run, graph = _seed(tmp_path)
    checklist = json.loads((run / "checklist.json").read_text())
    other = target / "unrelated.py"
    other.write_text("# unrelated source\n")
    checklist["files"].append({"path": "unrelated.py", "sha256": "0" * 64})
    (run / "checklist.json").write_text(json.dumps(checklist))
    ingest_run(run, str(target), graph_path=graph)
    from core import hash as hash_mod

    original = hash_mod.sha256_fileobj
    hashed = []

    def track(source, *args, **kwargs):
        hashed.append(source.name)
        return original(source, *args, **kwargs)

    monkeypatch.setattr(hash_mod, "sha256_fileobj", track)
    assert prompt_context_for_location(graph, "app.py", target_path=str(target))
    assert len(hashed) == 1


def test_source_symlink_outside_target_is_not_fresh(tmp_path):
    target, _, graph = _seed(tmp_path)
    source = target / "app.py"
    outside = tmp_path / "outside.py"
    outside.write_bytes(source.read_bytes())
    source.unlink()
    source.symlink_to(outside)
    assert reachable_sinks(graph, str(target)) == []
    assert prompt_context_for_location(graph, "app.py", target_path=str(target)) == ""


def test_source_symlink_within_target_remains_fresh(tmp_path):
    target, _, graph = _seed(tmp_path)
    source = target / "app.py"
    destination = target / "implementation.py"
    source.rename(destination)
    source.symlink_to(destination)
    assert reachable_sinks(graph, str(target))
    assert prompt_context_for_location(graph, "app.py", target_path=str(target))


def test_source_directory_swap_after_containment_refuses(tmp_path, monkeypatch):
    target, run, graph = _seed(tmp_path)
    sub = target / "sub"
    sub.mkdir()
    (target / "app.py").rename(sub / "app.py")
    for filename in ("checklist.json", "context-map.json"):
        text = (run / filename).read_text().replace('"app.py"', '"sub/app.py"')
        (run / filename).write_text(text)
    ingest_run(run, str(target), graph_path=graph)
    assert reachable_sinks(graph, str(target))
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "app.py").write_bytes((sub / "app.py").read_bytes())
    from core import paths

    original = paths.confine
    swapped = []

    def swap(root, candidate):
        resolved = original(root, candidate)
        if not swapped:
            sub.rename(target / "saved")
            sub.symlink_to(outside, target_is_directory=True)
            swapped.append(True)
        return resolved

    monkeypatch.setattr(paths, "confine", swap)
    assert reachable_sinks(graph, str(target)) == []
    assert swapped == [True]


def test_target_root_swap_during_containment_refuses(tmp_path, monkeypatch):
    target, _, graph = _seed(tmp_path)
    assert reachable_sinks(graph, str(target))
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "app.py").write_bytes((target / "app.py").read_bytes())
    from core import paths

    original = paths.confine
    swapped = []

    def swap(root, candidate):
        if not swapped:
            target.rename(tmp_path / "saved-root")
            target.symlink_to(outside, target_is_directory=True)
            swapped.append(True)
        return original(root, candidate)

    monkeypatch.setattr(paths, "confine", swap)
    assert reachable_sinks(graph, str(target)) == []
    assert swapped == [True]
