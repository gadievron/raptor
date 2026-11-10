"""Own SQLite report/ack caller cleanup, without analysis or external delivery."""
from contextlib import closing
import json
import sqlite3
import sys
from types import SimpleNamespace

import pytest

from core.audit.cross_entry import progress as module


@pytest.fixture
def queue_io(tmp_path, monkeypatch):
    with closing(module.WorkQueue(tmp_path, "main")) as queue:
        queue.add_views(["owned.c"])
        view = queue.db.execute("SELECT id FROM views").fetchone()[0]
        queue.add_jobs(view, [("owned-consumer", "")])
        job = queue.db.execute("SELECT id FROM jobs").fetchone()[0]
        queue.finish(view, job, "complete", {"key": "owned-evidence"})
    manifest = tmp_path / "cross-entry-progress.json"
    manifest.write_text(json.dumps({"namespace": "main", "report_keys": ["owned.c:f", 7, None],
                                    "selection_key": "selected", "target": str(tmp_path.resolve())}))
    state = {"path": tmp_path, "manifest": manifest, "dbpath": tmp_path / "cross-entry-work.sqlite",
             "connections": [], "closes": 0, "cleanup": None, "primary": None,
             "receipt": {"namespace": "main", "view": view, "job": job, "evidence": "owned-evidence"}}

    class OwnedConnection(sqlite3.Connection):
        def close(self):
            state["primary"] = sys.exc_info()[1]
            super().close()
            state["closes"] += 1
            if state["cleanup"] is not None:
                raise state["cleanup"]

    def connect(*args, **kwargs):
        connection = sqlite3.connect(*args, **kwargs, factory=OwnedConnection)
        state["connections"].append(connection)
        return connection

    monkeypatch.setattr(module, "sqlite3", SimpleNamespace(**{**vars(sqlite3), "connect": connect}))
    try:
        yield state
    finally:
        for connection in state["connections"]:
            sqlite3.Connection.close(connection)


def _invoke(state, operation):
    if operation == "reports":
        return module.pending_report_keys(state["path"])
    return module.acknowledge_delivery(state["path"], state["receipt"])


def _malformed(state):
    with closing(sqlite3.connect(state["dbpath"])) as db:
        db.execute("UPDATE jobs SET result=?", ("{",))
        db.commit()


def _assert_retired(state):
    assert state["closes"] == len(state["connections"]) == 1
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        state["connections"][0].execute("SELECT 1")


def _assert_ack(state, operation):
    with closing(sqlite3.connect(state["dbpath"])) as db:
        rows = db.execute("SELECT namespace,view_id,job_id,evidence FROM acknowledgements").fetchall()
    receipt = state["receipt"]
    assert rows == ([tuple(receipt[k] for k in ("namespace", "view", "job", "evidence"))] if operation == "ack" else [])


@pytest.mark.parametrize("operation", ["reports", "ack"])
def test_native_json_refusal_survives_secondary_close_error(queue_io, operation):
    _malformed(queue_io)
    queue_io["cleanup"] = OSError("after native SQLite close")
    with pytest.raises(json.JSONDecodeError) as raised:
        _invoke(queue_io, operation)
    assert raised.value is queue_io["primary"]
    _assert_retired(queue_io)
    _assert_ack(queue_io, operation)


@pytest.mark.parametrize("operation", ["reports", "ack"])
@pytest.mark.parametrize("close_type", [None, RuntimeError, KeyboardInterrupt])
def test_native_json_refusal_keeps_identity(queue_io, operation, close_type):
    _malformed(queue_io)
    queue_io["cleanup"] = close_type("after native SQLite close") if close_type else None
    with pytest.raises(json.JSONDecodeError) as raised:
        _invoke(queue_io, operation)
    assert raised.value is queue_io["primary"]
    _assert_retired(queue_io)
    _assert_ack(queue_io, operation)


@pytest.mark.parametrize("operation", ["reports", "ack"])
@pytest.mark.parametrize("close_type", [None, OSError, SystemExit])
def test_success_retains_returns_commits_and_fresh_close_errors(queue_io, operation, close_type):
    cleanup = close_type("after native SQLite close") if close_type else None
    queue_io["cleanup"] = cleanup
    if cleanup is None:
        assert _invoke(queue_io, operation) == ({"owned.c:f"} if operation == "reports" else None)
    else:
        with pytest.raises(close_type) as raised:
            _invoke(queue_io, operation)
        assert raised.value is cleanup
    assert queue_io["primary"] is None
    _assert_retired(queue_io)
    _assert_ack(queue_io, operation)


@pytest.mark.parametrize("guard", ["missing-progress", "missing-namespace", "selection", "target", "receipt"])
def test_preopen_guards_never_allocate_queue(queue_io, guard):
    if guard == "missing-progress":
        queue_io["manifest"].unlink()
        result = module.pending_report_keys(queue_io["path"])
    elif guard == "missing-namespace":
        queue_io["manifest"].write_text("{}")
        result = module.pending_report_keys(queue_io["path"])
    elif guard == "selection":
        result = module.pending_report_keys(queue_io["path"], selection_key="other")
    elif guard == "target":
        result = module.pending_report_keys(queue_io["path"], target=queue_io["path"] / "other")
    else:
        result = module.acknowledge_delivery(queue_io["path"], {"namespace": "main"})
    assert result == (None if guard == "receipt" else set())
    assert queue_io["connections"] == []
    assert queue_io["closes"] == 0
