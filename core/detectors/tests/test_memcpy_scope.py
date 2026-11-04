"""Candidate inputs, containment and one shared wall budget across batches."""
from pathlib import Path
from types import SimpleNamespace
import os

import pytest

from core.detectors import memcpy_overlap as overlap


@pytest.fixture
def setup(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    root.mkdir()
    for name in ("a.c", "b.c", "c.c", "not-selected.c"):
        (root / name).write_text("void f(void) {}\n")
    calls = []
    monkeypatch.setattr("packages.semgrep.runner.is_available", lambda: True)

    def run(first, config, **kwargs):
        paths = (first, *kwargs.get("extra_targets", ()))
        calls.append((paths, kwargs))
        return SimpleNamespace(findings=[SimpleNamespace(file=str(p)) for p in paths], errors=[])

    monkeypatch.setattr("packages.semgrep.runner.run_rule", run)

    def state(files=("a.c", "b.c")):
        return overlap.OverlapAnalysis(root, files, lambda rel: None, lambda *a, **kw: None)

    return root, calls, state


def test_only_eligible_files_are_positional_inputs(setup):
    root, calls, make = setup
    state = make()
    assert overlap._candidates(state).status == "complete"
    assert calls[0][0] == (root / "a.c", root / "b.c")
    assert calls[0][1]["target_root"] == root
    assert root not in calls[0][0]
    assert state.candidates == {"a.c", "b.c"}


def test_literal_file_names_and_duplicate_inputs(setup):
    root, calls, make = setup
    names = ("space [*]?.c", "--option.c", "snow-雪.c")
    for name in names:
        (root / name).write_text("void f(void) {}\n")
    state = make((*names, names[0]))
    overlap._candidates(state)
    assert set(calls[0][0]) == {root / name for name in names}
    assert len(calls[0][0]) == len(names)
    assert state.candidates == set(names)


@pytest.mark.parametrize("invalid", ["../outside.c", "link.c", "missing.c", "directory.c"])
def test_invalid_inputs_never_grant_an_outside_read(setup, tmp_path, invalid):
    root, calls, make = setup
    outside = tmp_path / "outside.c"
    outside.write_text("secret\n")
    (root / "link.c").symlink_to(outside)
    (root / "directory.c").mkdir()
    state = make(("a.c", invalid))
    assert overlap._candidates(state).status == "partial"
    assert calls[0][0] == (root / "a.c",)
    assert state.candidates == {"a.c"}
    assert state.limitations


def test_all_unavailable_inputs_do_not_scan_the_root(setup):
    _, calls, make = setup
    state = make(("missing.c",))
    assert overlap._candidates(state).status == "error"
    assert not calls and not state.candidates


def test_deadline_is_shared_and_keeps_prior_candidates(setup, monkeypatch):
    root, calls, make = setup
    size = max(len(os.fsencode(root / f"{name}.c")) + 1 for name in "abc")
    monkeypatch.setattr(overlap, "_CANDIDATE_ARG_BYTES", size)
    now = [0.0]
    monkeypatch.setattr(overlap, "monotonic", lambda: now[0])

    def run(first, config, **kw):
        calls.append(((first, *kw.get("extra_targets", ())), kw))
        now[0] += 20
        return SimpleNamespace(findings=[SimpleNamespace(file=str(first))], errors=[])

    monkeypatch.setattr("packages.semgrep.runner.run_rule", run)
    state = make(("a.c", "b.c", "c.c"))
    assert overlap._candidates(state).status == "partial"
    assert [kw["timeout"] for _, kw in calls] == [30, 10]
    assert state.candidates == {"a.c", "b.c"}
    assert state.limitations


def test_failed_batch_does_not_hide_later_valid_candidates(setup, monkeypatch):
    root, calls, make = setup
    size = max(len(os.fsencode(root / f"{name}.c")) + 1 for name in "ab")
    monkeypatch.setattr(overlap, "_CANDIDATE_ARG_BYTES", size)

    def run(first, config, **kw):
        calls.append(((first,), kw))
        if first.name == "a.c":
            return SimpleNamespace(findings=[], errors=["parse error"])
        return SimpleNamespace(findings=[SimpleNamespace(file=str(first))], errors=[])

    monkeypatch.setattr("packages.semgrep.runner.run_rule", run)
    state = make()
    assert overlap._candidates(state).status == "partial"
    assert state.candidates == {"b.c"} and len(calls) == 2


def test_argument_budget_counts_encoded_bytes(monkeypatch):
    paths = [Path("/雪/first.c"), Path("/雪/second.c")]
    size = max(len(os.fsencode(p)) + 1 for p in paths)
    monkeypatch.setattr(overlap, "_CANDIDATE_ARG_BYTES", size)
    batches = list(overlap._target_batches(paths))
    assert batches == [(paths[0],), (paths[1],)]
    assert all(sum(len(os.fsencode(p)) + 1 for p in b) <= size for b in batches)
    with pytest.raises(ValueError, match="argument budget"):
        list(overlap._target_batches([Path("/" + "a" * size)]))
