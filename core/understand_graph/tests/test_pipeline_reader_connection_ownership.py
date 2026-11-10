"""Pipeline fixture readers own native SQLite across errors and rebuilds."""

import os
import sqlite3
from pathlib import Path
from types import FunctionType

import pytest

from core.project.project import ProjectManager
from core.testing.state_isolation import pin_user_state_dirs
from core.understand_graph.tests import test_adversarial_regressions as adversarial
from core.understand_graph.tests import test_pipeline_integration as pipeline

pytestmark = pytest.mark.skipif(
    not Path("/proc/self/fd").is_dir(), reason="native descriptor observation requires procfs",
)


@pytest.fixture(autouse=True)
def _user_state_in_tmp(tmp_path):
    with pytest.MonkeyPatch.context() as patch:
        pin_user_state_dirs(patch, tmp_path / "user")
        patch.setenv("HOME", str(tmp_path / "home"))
        patch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-data"))
        patch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg-config"))
        patch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg-cache"))
        yield


CASES = ["lane", "agentic", "empty-before", "empty-after", "pipeline-agentic", "pipeline-fuzz", "pipeline-rebuild"]


def _owned_fds(path):
    resolved = str(Path(path).resolve())
    count = 0
    for name in os.listdir("/proc/self/fd"):
        try:
            target = os.readlink("/proc/self/fd/" + name)
        except FileNotFoundError:
            continue
        count += target in (resolved, resolved + " (deleted)")
    return count


def _exercise(tmp_path, consumer, error=None, after=True, deny=False):
    records, closed, paths = [], [], []
    failure = error("owned pipeline reader fault") if error else None
    fault_index = int(consumer == "empty-after")
    original_list = ProjectManager.list_projects
    original_find = ProjectManager.find_project_for_target

    class Connection:
        def __init__(self, connection, index):
            self.connection = connection
            self.index = index
            self.calls = 0

        def __enter__(self):
            self.connection.__enter__()
            return self

        def __exit__(self, *args):
            return self.connection.__exit__(*args)

        def execute(self, *args):
            self.calls += 1
            selected = error and self.index == fault_index and self.calls == 1
            if selected and not after:
                raise failure
            result = self.connection.execute(*args)
            if selected:
                result.close()
                raise failure
            return result

        def close(self):
            self.connection.close()
            closed.append(self.connection)

    def opened(path):
        connection = pipeline.open_graph(path)
        index = len(records)
        records.append(connection)
        paths.append(Path(path))
        if deny and index == fault_index:
            connection.set_authorizer(
                lambda action, *rest: sqlite3.SQLITE_DENY
                if action == sqlite3.SQLITE_SELECT else sqlite3.SQLITE_OK,
            )
        return Connection(connection, index)

    try:
        with pytest.MonkeyPatch.context() as patch:
            project = pipeline.project.__wrapped__(tmp_path, patch)
            root, target, graph = project
            if consumer == "lane":
                run = root / "web"
                adversarial._web(run, [{"id": "W", "url": "https://example.test/"}], [{"finding_id": "W", "status": "verified"}])
                adversarial.ingest_web_evidence(run, str(target))
                function, arguments = adversarial._lane_state, (graph, run, "web")
            elif consumer == "agentic":
                function, arguments = adversarial.test_agentic_groups_only_the_requested_snapshot_with_reused_ids, (project,)
            elif consumer.startswith("empty"):
                function, arguments = adversarial.test_empty_generic_scan_does_not_manufacture_an_sca_rebuild, (project,)
            elif consumer == "pipeline-agentic":
                function, arguments = pipeline.test_agentic_envelope_and_production_grouping, (project,)
            elif consumer == "pipeline-fuzz":
                function, arguments = pipeline.test_fuzz_execution_writes_persistent_evidence, (project, patch)
            else:
                function, arguments = pipeline.test_producers_idempotent_imported_and_rebuildable, (project,)
            body = FunctionType(function.__code__, {**function.__globals__, "open_graph": opened}, function.__name__, function.__defaults__, function.__closure__)
            expected = error or (sqlite3.DatabaseError if deny else None)
            if expected:
                with pytest.raises(expected, match="not authorized" if deny else "owned pipeline reader fault") as caught:
                    body(*arguments)
                if failure is not None:
                    assert caught.value is failure
            else:
                result = body(*arguments)
                if consumer == "lane":
                    assert len(result["nodes"]) == 3 and len(result["edges"]) == 2
            assert len(records) == (2 if consumer.startswith("empty") and not expected else fault_index + 1)
            assert closed == records
            for connection in records:
                with pytest.raises(sqlite3.ProgrammingError, match="closed"):
                    connection.execute("SELECT 1")
            assert all(_owned_fds(path) == 0 for path in paths)
    finally:
        for connection in records:
            sqlite3.Connection.close(connection)
        assert all(_owned_fds(path) == 0 for path in paths)
        assert ProjectManager.list_projects is original_list
        assert ProjectManager.find_project_for_target is original_find


@pytest.mark.parametrize("consumer", CASES)
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True])
def test_pipeline_query_faults_retire_connections(tmp_path, consumer, error, after):
    _exercise(tmp_path, consumer, error, after)


@pytest.mark.parametrize("consumer", CASES)
def test_native_pipeline_select_refusal_retires_connection(tmp_path, consumer):
    _exercise(tmp_path, consumer, deny=True)


@pytest.mark.parametrize("consumer", CASES)
def test_native_pipeline_assertions_and_reader_retirement(tmp_path, consumer):
    _exercise(tmp_path, consumer)
