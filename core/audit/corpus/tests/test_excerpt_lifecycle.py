"""Excerpt ownership spans preparation, consumers, and independent teardown."""

from contextlib import contextmanager
import logging
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace

import pytest

from core.atomic_fs import rmtree_hardened
from core.audit.corpus import excerpt, label as label_module, run_corpus, rule_eval
from core.audit.corpus.label import FunctionLabel, SourcePin
from core.run import scratch


def _label(repo="first"):
    return FunctionLabel(
        function_id="a.c:f", bug_class="clean", expected_status="clean",
        rationale="owned lifecycle fixture", labeler="test", labeled_at="2026-11-06",
        source=SourcePin(repo=repo, sha="a" * 40, file="a.c", line_start=1, line_end=1),
    )


@pytest.fixture
def owned(tmp_path, monkeypatch, caplog):
    stop = threading.Event()
    pins = set()
    monkeypatch.setattr(scratch, "_keepalive_paths", pins)
    monkeypatch.setattr(scratch, "_keepalive_thread", None)
    monkeypatch.setattr(scratch, "_keepalive_loop", lambda: stop.wait())
    logger = logging.getLogger("test.excerpt-lifecycle-owned")
    monkeypatch.setattr(logger, "handlers", [caplog.handler])
    monkeypatch.setattr(logger, "propagate", False)
    monkeypatch.setattr(run_corpus, "logger", logger)
    monkeypatch.setattr(run_corpus, "shutil", SimpleNamespace(**vars(run_corpus.shutil)))
    monkeypatch.setenv("RAPTOR_REGISTRY_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("RAPTOR_DIR", str(tmp_path / "inherited-root"))
    scratch_root = tmp_path / "scratch"
    scratch_root.mkdir()
    allocated = []
    def allocate(**kwargs):
        path = tempfile.mkdtemp(dir=scratch_root, **kwargs)
        allocated.append(Path(path))
        return path
    # Replace the consumer binding, never the shared tempfile module.
    monkeypatch.setattr(run_corpus, "tempfile", SimpleNamespace(mkdtemp=allocate))
    sources = {}
    try:
        for repo in ("first", "second"):
            source = tmp_path / repo
            source.mkdir()
            (source / "a.c").write_text("int f(void) { return 0; }\n")
            sources[repo] = source
        yield SimpleNamespace(
            root=scratch_root, paths=allocated, pins=pins, sources=sources,
            labels=[_label(repo) for repo in sources],
        )
    finally:
        stop.set()
        thread = scratch._keepalive_thread
        if thread is not None:
            thread.join(timeout=5)
            assert not thread.is_alive(), "owned keepalive did not stop"
        assert rmtree_hardened(scratch_root)


@pytest.mark.parametrize("phase", ["allocation", "registration", "copy", "owners", "perlasm", "headers", "announcement"])
@pytest.mark.parametrize("number", [1, 2])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_preparation_failure_releases_current_and_previous_trees(owned, monkeypatch, phase, number, error):
    calls = []
    bindings = {
        "allocation": (run_corpus.tempfile, "mkdtemp"),
        "registration": (run_corpus, "keepalive_register"),
        "copy": (run_corpus.shutil, "copy2"),
        "owners": (excerpt, "copy_c_translation_unit_owners"),
        "perlasm": (run_corpus, "_copy_perlasm_drivers"),
        "headers": (run_corpus, "_copy_c_include_closure"),
        "announcement": (run_corpus, "print"),
    }
    obj, name = bindings[phase]
    original = getattr(obj, name, print)
    failure = error("preparation stopped")
    def fail(*args, **kwargs):
        calls.append(None)
        if len(calls) == number:
            if phase == "registration":
                original(*args, **kwargs)
            raise failure
        return original(*args, **kwargs)
    monkeypatch.setattr(obj, name, fail, raising=False)
    with pytest.raises(error) as caught:
        run_corpus._build_excerpt_tree(owned.labels, owned.sources)
    assert caught.value is failure
    assert len(calls) == number
    assert not owned.pins
    assert not list(owned.root.iterdir())
    assert all((source / "a.c").is_file() for source in owned.sources.values())


@pytest.mark.parametrize("phase", ["unregister", "remove"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
@pytest.mark.parametrize("preserve", [False, True])
def test_release_attempts_every_resource_after_cleanup_failure(owned, monkeypatch, caplog, phase, error, preserve):
    directories = run_corpus._build_excerpt_tree(owned.labels, owned.sources)
    first, second = directories.values()
    unregister, remove = run_corpus.keepalive_unregister, run_corpus.rmtree_hardened
    attempts = []
    failure = error("cleanup stopped")
    def drop(path):
        attempts.append(("unregister", path))
        unregister(path)
        if path == first and phase == "unregister":
            raise failure
    def delete(path):
        attempts.append(("remove", path))
        if path == first and phase == "remove":
            raise failure
        return remove(path)
    monkeypatch.setattr(run_corpus, "keepalive_unregister", drop)
    monkeypatch.setattr(run_corpus, "rmtree_hardened", delete)
    if error is KeyboardInterrupt and not preserve:
        with pytest.raises(KeyboardInterrupt) as caught:
            run_corpus._release_excerpt_trees(directories, preserve_error=preserve)
        assert caught.value is failure
    else:
        run_corpus._release_excerpt_trees(directories, preserve_error=preserve)
    assert attempts == [("unregister", first), ("remove", first), ("unregister", second), ("remove", second)]
    assert not owned.pins
    assert not second.exists()
    assert first.exists() == (phase == "remove")
    assert "teardown failed" in caplog.text or "removal failed" in caplog.text


def test_release_recovers_restricted_trees_without_following_links(owned, tmp_path):
    directories = run_corpus._build_excerpt_tree(owned.labels, owned.sources)
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o750)
    keep = outside / "keep"
    keep.write_text("unrelated")
    permissions = outside.stat().st_mode
    for root in directories.values():
        locked = root / "locked"
        locked.mkdir()
        (locked / "data").write_text("partial tool output")
        (root / "external").symlink_to(outside, target_is_directory=True)
        locked.chmod(0)
    run_corpus._release_excerpt_trees(directories)
    assert not owned.pins
    assert all(not root.exists() for root in directories.values())
    assert keep.read_text() == "unrelated"
    assert outside.stat().st_mode == permissions


def test_failed_removal_is_reported_and_unpinned(owned, monkeypatch, caplog):
    directories = run_corpus._build_excerpt_tree(owned.labels, owned.sources)
    monkeypatch.setattr(run_corpus, "rmtree_hardened", lambda path: False)
    run_corpus._release_excerpt_trees(directories)
    assert not owned.pins
    assert all(path.exists() for path in directories.values())
    assert caplog.text.count("retained after failed removal") == 2


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_consumer_error_keeps_precedence_over_cleanup_cancellation(owned, monkeypatch, error):
    failure = error("consumer stopped")
    unregister = run_corpus.keepalive_unregister
    def drop(path):
        unregister(path)
        raise KeyboardInterrupt("cleanup interrupted")
    monkeypatch.setattr(run_corpus, "keepalive_unregister", drop)
    with pytest.raises(error) as caught:
        with run_corpus._excerpt_trees(owned.labels, owned.sources) as directories:
            assert owned.pins == {str(path) for path in directories.values()}
            raise failure
    assert caught.value is failure
    assert not owned.pins
    assert not list(owned.root.iterdir())


def test_scope_retains_ownership_until_exit_and_releases_once(owned, monkeypatch):
    unregister = run_corpus.keepalive_unregister
    dropped = []
    def drop(path):
        dropped.append(path)
        unregister(path)
    monkeypatch.setattr(run_corpus, "keepalive_unregister", drop)
    with run_corpus._excerpt_trees(owned.labels, owned.sources) as directories:
        assert all((path / "a.c").is_file() for path in directories.values())
        assert owned.pins == {str(path) for path in directories.values()}
    assert dropped == list(directories.values())
    assert not owned.pins
    assert not list(owned.root.iterdir())


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_rule_eval_releases_real_excerpt_trees_on_engine_failure(owned, monkeypatch, tmp_path, error):
    labels = owned.labels[:1]
    monkeypatch.setattr(label_module, "load_all_labels", lambda **kwargs: labels)
    monkeypatch.setattr(run_corpus, "_resolve_source_dirs", lambda *args, **kwargs: owned.sources)
    monkeypatch.setattr(rule_eval, "discover_rules", lambda engines: ([], []))
    failure = error("engine stopped")
    def run(*args, **kwargs):
        assert owned.paths and owned.pins
        raise failure
    monkeypatch.setattr(rule_eval, "run_semgrep_engine", run)
    with pytest.raises(error) as caught:
        rule_eval.main(["--engine", "semgrep", "--provenance", "shipped", "--out", str(tmp_path / "report")])
    assert caught.value is failure
    assert owned.paths
    assert not owned.pins
    assert not list(owned.root.iterdir())


@pytest.mark.parametrize("phase", ["mutation", "audit"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_audit_main_owns_excerpts_before_mutation_and_review(owned, monkeypatch, tmp_path, phase, error):
    from core.audit.corpus import history, lint, mutation
    label = owned.labels[0]
    monkeypatch.setattr(label_module, "load_all_labels", lambda **kwargs: [label])
    monkeypatch.setattr(run_corpus, "_resolve_source_dirs", lambda *args, **kwargs: owned.sources)
    monkeypatch.setattr(run_corpus, "_resolve_model_label", lambda model: "owned-model")
    monkeypatch.setattr(lint, "verify_pins", lambda pairs, **kwargs: [
        lint.PinCheck(label=lb, path=None, outcome="no-fixture", detail="") for _, lb in pairs
    ])
    monkeypatch.setenv(history.HISTORY_ENV, str(tmp_path / "history.jsonl"))
    @contextmanager
    def project(tag):
        yield "owned-project"
    monkeypatch.setattr(run_corpus, "_corpus_project_context", project)
    failure = error("consumer stopped")
    def fail(*args, **kwargs):
        assert owned.paths and owned.pins
        raise failure
    if phase == "mutation":
        # The label remains a production FunctionLabel; only the provenance
        # decision is supplied to reach incidental mutation-tool setup.
        monkeypatch.setattr(mutation, "label_kind", lambda label: mutation.PROVENANCE_SYNTHETIC_MUTANT)
        monkeypatch.setattr(mutation, "apply_labels_to_tree", fail)
    else:
        monkeypatch.setattr(run_corpus, "_run_audit", fail)
    with pytest.raises(error) as caught:
        run_corpus.main(["--output", str(tmp_path / "results.json")])
    assert caught.value is failure
    assert owned.paths
    assert not owned.pins
    assert not list(owned.root.iterdir())
