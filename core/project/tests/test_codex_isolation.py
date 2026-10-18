"""Codex root isolation and mixed-harness regressions for the shared registry."""
from contextlib import contextmanager
import io
import os
from pathlib import Path
import runpy
import sys

import pytest

from core.project import sessions, session_scope
from core.run import metadata
from core.json import save_json
from core.json import dumps_canonical, load_json

PID = 12345
ROOT_A = "root-a"
ROOT_B = "root-b"
STAMP = {"starttime": "12", "boot_id": "boot", "pidns": "99"}


@pytest.fixture
def registry(tmp_path, monkeypatch):
    monkeypatch.setenv("RAPTOR_REGISTRY_HOME", str(tmp_path / "registry"))
    monkeypatch.delitem(sessions.__dict__, "SESSIONS_DIR", raising=False)
    for name in ("CODEX_THREAD_ID", "RAPTOR_CODEX_CONTEXT_ID", "RAPTOR_SESSION_PID",
                 "RAPTOR_SESSION_TOKEN", "CLAUDECODE", "CODEX"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(sessions, "_identity_for", lambda pid: dict(STAMP))
    monkeypatch.setattr(sessions, "_identity_matches", lambda pid, fields: (
        fields.get("ended") != "1" and all(fields.get(k) == v for k, v in STAMP.items())))

    @contextmanager
    def owner(session_id=None, project=None):
        with monkeypatch.context() as context:
            if session_id:
                context.setenv("RAPTOR_CODEX_CONTEXT_ID", session_id)
            else:
                context.delenv("RAPTOR_CODEX_CONTEXT_ID", raising=False)
            credential = sessions.ensure_codex_session(PID)
            assert credential
            context.setenv("RAPTOR_SESSION_PID", str(PID))
            context.setenv("RAPTOR_SESSION_TOKEN", credential[1])
            if project:
                sessions.bind_session(project)
            yield credential[1]
    return owner


def test_same_pid_has_three_independent_bindings_tokens_and_ledgers(registry, tmp_path):
    tokens = []
    paths = []
    for sid, project in ((None, "claude-project"), (ROOT_A, "alpha"), (ROOT_B, "beta")):
        with registry(sid, project) as token:
            tokens.append(token)
            paths.append(sessions._sessions_dir())
            run = tmp_path / project
            run.mkdir()
            save_json(run / metadata.RUN_METADATA_FILE, {"status": "running"})
            sessions.ledger_record_start(run, record_pin=True, pin_project=project)
    assert len(set(tokens)) == 3
    assert len(set(paths)) == 3
    assert paths[0] == sessions._base_sessions_dir()
    for sid, project, token in zip((None, ROOT_A, ROOT_B), ("claude-project", "alpha", "beta"), tokens):
        with registry(sid) as restored:
            assert restored == token
            assert sessions.session_binding() == (project, "bound")
            assert [r["run_dir"] for r in sessions.ledger_runs()] == [str(tmp_path / project)]
    with registry(ROOT_A):
        sessions.bind_session(None)
    with registry(ROOT_B):
        assert sessions.session_binding() == ("beta", "bound")
    with registry():
        assert sessions.session_binding() == ("claude-project", "bound")


def test_global_project_operations_retain_all_namespaces(registry, tmp_path):
    for sid in (None, ROOT_A, ROOT_B):
        with registry(sid, "shared"):
            run = tmp_path / (sid or "claude")
            run.mkdir()
            save_json(run / metadata.RUN_METADATA_FILE, {"status": "running"})
            sessions.ledger_record_start(run, record_pin=True, pin_project="shared")
    assert len(sessions.all_sessions()) == 3
    assert len(sessions.ledger_runs_pinned_to("shared")) == 3
    assert len(sessions.ledger_running_runs_all_sessions()) == 3
    sessions.ledger_rewrite_pin_project("shared", "renamed")
    sessions.rebind_project_sessions("shared", "renamed")
    assert len(sessions.ledger_pinned_dirs("renamed")) == 3
    for sid in (None, ROOT_A, ROOT_B):
        with registry(sid):
            assert sessions.session_binding() == ("renamed", "bound")
    sessions.rebind_project_sessions("renamed", None)
    for sid in (None, ROOT_A, ROOT_B):
        with registry(sid):
            assert sessions.session_binding() == (None, "none")


def test_cross_namespace_pin_and_drain_use_the_correct_ledger(registry, tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    save_json(run / metadata.RUN_METADATA_FILE, {"status": "running"})
    with registry(ROOT_A, "alpha"):
        sessions.ledger_record_start(run, record_pin=True, pin_project="alpha")
        owner_directory = sessions._sessions_dir()
    with registry(ROOT_B, "beta"):
        assert sessions.ledger_pin_witness(run, pid=PID)[:2] == (True, "alpha")
        assert sessions.ledger_record_drain_request(run)
        assert sessions.ledger_drain_requests(run)
        assert not (sessions._sessions_dir() / f"{PID}.run").exists()
        assert "drain " in (owner_directory / f"{PID}.run").read_text()
        assert sessions.ledger_clear_drain_requests(run) == 1
        assert not sessions.ledger_drain_requests(run)


def test_end_retires_one_root_while_process_and_other_roots_live(registry):
    owners = []
    for sid in (ROOT_A, ROOT_B):
        with registry(sid) as token:
            owners.append(dict(sessions.logical_owner_stamp(), session_pid=PID))
            if sid == ROOT_A:
                old_token = token
    with registry(ROOT_A):
        assert sessions.logical_owner_liveness(owners[0], PID) == "alive"
        assert not sessions.end_codex_session(PID, "foreign-token")
        assert sessions.end_codex_session(PID, old_token)
    assert sessions.logical_owner_liveness(owners[0], PID) == "dead"
    assert sessions.logical_owner_liveness(owners[1], PID) == "alive"
    with registry(ROOT_A) as new_token:
        assert new_token != old_token
        assert not sessions.same_logical_owner(owners[0], PID)
    assert sessions.logical_owner_liveness(owners[0], PID) == "dead"


def test_contention_distinguishes_roots_sharing_pid(registry, tmp_path, monkeypatch):
    run = tmp_path / "other"
    run.mkdir()
    with registry(ROOT_A):
        owner = dict(sessions.logical_owner_stamp(), session_pid=PID,
                     status="running", command="scan")
        save_json(run / metadata.RUN_METADATA_FILE, owner)
    monkeypatch.setattr(metadata, "_gate_session_alive", lambda pid: True)
    with registry(ROOT_B):
        assert metadata._live_conflicting_run(tmp_path, tmp_path / "self", PID)["pid"] == PID
    with registry(ROOT_A):
        assert metadata._live_conflicting_run(tmp_path, tmp_path / "self", PID) is None


def test_plain_claude_identity_and_metadata_contract_are_unchanged(registry):
    with registry():
        assert sessions.logical_owner_stamp() == {}
        assert sessions.same_logical_owner({"session_pid": PID}, PID)
        assert sessions._sessions_dir() == sessions._base_sessions_dir()
        assert "ended" not in sessions._parse_entry(sessions._sessions_dir() / str(PID))


@pytest.mark.parametrize("sid", ["../escape", "a/b", "a\nb", "", "a" * 129, None])
def test_invalid_session_id_cannot_select_registry(sid, tmp_path):
    with pytest.raises(ValueError):
        session_scope.validate_id(sid)


def test_namespace_enumeration_never_follows_symlink(tmp_path):
    base = tmp_path / "sessions.d"
    target = tmp_path / "elsewhere"
    target.mkdir(mode=0o700)
    (base / "codex").mkdir(parents=True, mode=0o700)
    (base / "codex" / ("a" * 64)).symlink_to(target, target_is_directory=True)
    assert list(session_scope.directories(base)) == [base]


@pytest.mark.parametrize("event", ["codex-stop", "codex-end"])
def test_hook_only_finalizes_its_logical_owner(registry, tmp_path, monkeypatch, event):
    from core.startup import codex_environment
    hook = runpy.run_path(str(Path(__file__).resolve().parents[3] / "libexec/raptor-lifecycle-hook"))
    monkeypatch.setitem(hook["main"].__globals__, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(metadata, "_get_session_pid", lambda: PID)
    runs = []
    owners = []
    for sid in (None, ROOT_A, ROOT_B):
        with registry(sid):
            run = tmp_path / "out" / (sid or "claude")
            run.mkdir(parents=True)
            owner = dict(sessions.logical_owner_stamp(), session_pid=PID)
            meta = dict(owner, version=2, command="understand" if event == "codex-end" else "scan",
                        status="running", timestamp="2020-01-01T00:00:00+00:00", extra={},
                        session_start=STAMP["starttime"], session_boot_id=STAMP["boot_id"])
            save_json(run / metadata.RUN_METADATA_FILE, meta)
            (run / ".raptor-tool-failure").touch()
            sessions.ledger_record_start(run)
            runs.append(run)
            owners.append(owner)
    with registry(ROOT_A):
        def restore(sid):
            assert sid == ROOT_A
        monkeypatch.setattr(codex_environment, "restore", restore)
        monkeypatch.setattr(sys, "argv", ["hook", event])
        monkeypatch.setattr(sys, "stdin", io.StringIO(dumps_canonical({
            "hook_event_name": "SessionEnd" if event == "codex-end" else "Stop",
            "session_id": ROOT_A, "reason": "other"})))
        hook["main"]()
    assert load_json(runs[0] / metadata.RUN_METADATA_FILE)["status"] == "running"
    assert load_json(runs[1] / metadata.RUN_METADATA_FILE)["status"] == "failed"
    assert load_json(runs[2] / metadata.RUN_METADATA_FILE)["status"] == "running"
    if event == "codex-end":
        assert sessions.logical_owner_liveness(owners[1], PID) == "dead"
        assert sessions.logical_owner_liveness(owners[2], PID) == "alive"


def test_resume_moves_ledger_between_roots_with_the_same_pid(registry, tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    save_json(run / metadata.RUN_METADATA_FILE, {"status": "running"})
    with registry(ROOT_A):
        sessions.ledger_record_start(run)
    with registry(ROOT_B):
        sessions.ledger_record_resume(run, prior_session_pid=PID, pid=PID,
                                      prior_session_id=ROOT_A, prior_codex=True)
        assert sessions.ledger_runs()[0]["status"] == "running"
    with registry(ROOT_A):
        assert sessions.ledger_runs()[0]["status"] == "interrupted"


@pytest.mark.parametrize("comm,expected", [("claude", True), ("claude-code", True),
    ("wrapper-claude", True), ("codex", True), ("codex-app-serve", True),
    ("notcodex", False), ("python", False), ("codex-linux-san", False),
    ("codex-exec-serv", False)])
def test_legacy_liveness_preserves_claude_matching_and_adds_codex(monkeypatch, comm, expected):
    comm_path = Path(f"/proc/{PID}/comm")
    original_exists = Path.exists
    original_read = Path.read_text
    monkeypatch.setattr(os, "kill", lambda pid, signal: None)
    monkeypatch.setattr(Path, "exists", lambda path: True if path == comm_path else original_exists(path))
    monkeypatch.setattr(Path, "read_text", lambda path, *args, **kwargs:
                        comm if path == comm_path else original_read(path, *args, **kwargs))
    assert metadata._pid_alive(PID) is expected
    assert metadata._gate_session_alive(PID) is expected


def test_legacy_liveness_keeps_distinct_eperm_policies(monkeypatch):
    def denied(*args, **kwargs):
        raise PermissionError
    monkeypatch.setattr(os, "kill", denied)
    monkeypatch.setattr(Path, "read_text", denied)
    assert metadata._pid_alive(PID) is True
    assert metadata._gate_session_alive(PID) is False
    assert metadata._pid_alive(1) is False


def test_codex_cannot_fall_back_to_shared_pid_with_wrong_credential(registry, monkeypatch):
    monkeypatch.setattr(sessions, "_walk_session_pid", lambda: PID)
    with registry(ROOT_A):
        monkeypatch.setenv("RAPTOR_SESSION_TOKEN", "wrong-generation")
        assert sessions.resolve_session_pid() is None
        assert metadata._get_session_pid() is None
    with registry():
        monkeypatch.setenv("RAPTOR_SESSION_TOKEN", "wrong-generation")
        # The original Claude ancestry fallback remains available.
        assert sessions.resolve_session_pid() == PID


def test_session_end_does_not_wait_for_the_ledger_lock(registry):
    from concurrent.futures import ThreadPoolExecutor
    with registry(ROOT_A) as token:
        with ThreadPoolExecutor(max_workers=1) as executor:
            with sessions._ledger_lock(PID):
                result = executor.submit(sessions.end_codex_session, PID, token)
                assert result.result(timeout=1) is True


def test_retirement_marker_never_follows_a_symlink(registry, tmp_path):
    with registry(ROOT_A) as token:
        target = tmp_path / "untouched"
        target.write_text("untouched")
        marker = sessions._retirement_path(PID, token, sessions._sessions_dir())
        marker.symlink_to(target)
        assert sessions.end_codex_session(PID, token)
        assert sessions.codex_session_ended(PID, {"token": token})
        assert target.read_text() == "untouched"


def test_reentrant_start_and_cross_root_completion_use_recorded_owner_ledger(registry, tmp_path, monkeypatch):
    monkeypatch.setattr(metadata, "_get_session_pid", lambda: PID)
    monkeypatch.setattr(metadata, "_session_stamp", lambda pid: {
        "session_start": STAMP["starttime"], "session_boot_id": STAMP["boot_id"],
        "session_pidns": STAMP["pidns"]})
    monkeypatch.setattr(metadata, "_worker_stamp", lambda **kwargs: {})
    monkeypatch.setattr(metadata, "_apply_standard_provenance", lambda *args: None)
    run = tmp_path / "run"
    with registry(ROOT_A):
        metadata.start_run(run, "scan")
        first = load_json(run / metadata.RUN_METADATA_FILE)
    with registry(ROOT_B):
        metadata.start_run(run, "scan")
        current = load_json(run / metadata.RUN_METADATA_FILE)
        assert current["session_id"] == first["session_id"] == ROOT_A
        assert current["session_generation"] == first["session_generation"]
        assert sessions.ledger_runs() == []
        metadata.complete_run(run)
        assert sessions.ledger_runs() == []
    with registry(ROOT_A):
        assert sessions.ledger_runs()[0]["status"] == "completed"


def test_publication_keeps_generation_locked_until_broker_is_ready(registry, tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    from core.startup import codex_environment, codex_broker
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(sessions, "resolve_codex_owner_pid", lambda: PID)
    started, release = Event(), Event()
    def start(*args):
        started.set()
        assert release.wait(timeout=5)
    monkeypatch.setattr(codex_broker, "start", start)
    with registry(ROOT_A) as token:
        with ThreadPoolExecutor(max_workers=2) as executor:
            publishing = executor.submit(codex_environment.publish, ROOT_A, PID)
            assert started.wait(timeout=3)
            seeding = executor.submit(sessions.ensure_codex_session, PID)
            try:
                with pytest.raises(TimeoutError):
                    seeding.result(timeout=0.1)
            finally:
                release.set()
            publishing.result(timeout=3)
            assert seeding.result(timeout=3) == (str(PID), token)


@pytest.mark.parametrize("sid", [None, ROOT_A], ids=["claude", "codex"])
@pytest.mark.parametrize("first,second", [
    ("start", "interrupt"), ("interrupt", "resume"), ("resume", "interrupt"),
])
def test_metadata_and_ledger_transitions_serialize(registry, tmp_path, monkeypatch, sid, first, second):
    """A blocked mirror must retain the metadata lock in BOTH harness paths.

    Force a competing transition to reach that lock before releasing the first
    mirror. This reproduces the old terminal/resume race and its reverse.
    """
    from concurrent.futures import ThreadPoolExecutor
    from contextlib import contextmanager
    from threading import Event, current_thread
    from core.run import provenance

    monkeypatch.setattr(metadata, "_get_session_pid", lambda: PID)
    monkeypatch.setattr(metadata, "_worker_stamp", lambda **kwargs: {})
    monkeypatch.setattr(metadata, "_session_stamp", lambda pid: {})
    monkeypatch.setattr(metadata, "_cleanup_abandoned", lambda *args: None)
    monkeypatch.setattr(provenance, "build_start_manifest", lambda **kwargs: {"provenance": "unavailable"})
    run = tmp_path / "serialized-run"
    with registry(sid):
        if first != "start":
            metadata.start_run(run, "scan")
        if first == "resume":
            metadata.interrupt_run(run)
        reached, release, contender, done = Event(), Event(), Event(), Event()
        mirror_name = {"start": "ledger_record_start", "interrupt": "ledger_record_finish",
                       "resume": "ledger_record_resume"}[first]
        mirror = getattr(sessions, mirror_name)
        lock = metadata._metadata_lock

        def delayed_mirror(*args, **kwargs):
            if current_thread().name == "first-transition":
                reached.set()
                assert release.wait(5), "test failed to release first mirror"
            return mirror(*args, **kwargs)

        @contextmanager
        def observed_lock(*args, **kwargs):
            if current_thread().name == "second-transition":
                contender.set()
            with lock(*args, **kwargs):
                yield

        monkeypatch.setattr(sessions, mirror_name, delayed_mirror)
        monkeypatch.setattr(metadata, "_metadata_lock", observed_lock)
        operations = {"start": lambda: metadata.start_run(run, "scan"),
                      "interrupt": lambda: metadata.interrupt_run(run),
                      "resume": lambda: metadata.resume_run(run)}

        def invoke(which, name):
            current_thread().name = name
            try:
                return operations[which]()
            finally:
                if name == "second-transition":
                    done.set()

        with ThreadPoolExecutor(max_workers=2) as executor:
            one = executor.submit(invoke, first, "first-transition")
            try:
                assert reached.wait(3)
                two = executor.submit(invoke, second, "second-transition")
                assert contender.wait(3)
                assert not done.wait(0.1), "competing transition escaped metadata serialization"
            finally:
                release.set()
            one.result(timeout=5)
            two.result(timeout=5)
        expected = "running" if second == "resume" else "interrupted"
        assert load_json(run / metadata.RUN_METADATA_FILE)["status"] == expected
        assert sessions.ledger_runs()[0]["status"] == expected
