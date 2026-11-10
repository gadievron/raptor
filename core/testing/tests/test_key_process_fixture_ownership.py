"""Real key-creator processes and parent queue handles retire on every exit."""

import ast
import importlib
import multiprocessing
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest


_METHODS = multiprocessing.get_all_start_methods()
_PREFERRED = "fork" if "fork" in _METHODS else "spawn"
_ALTERNATES = [method for method in ("fork", "spawn")
               if method in _METHODS and method != _PREFERRED]
_FAULTS = [(method, operation, after, index, error)
           for method in [_PREFERRED]
           for operation in ("start", "get", "join")
           for after in (False, True)
           for index in ((0, 1, 7) if operation == "start" else (0,))
           for error in (OSError, KeyboardInterrupt, SystemExit)]
_FAULTS += [(method, operation, after, 1 if operation == "start" else 0, KeyboardInterrupt)
            for method in _ALTERNATES for operation in ("start", "get", "join")
            for after in (False, True)]


@pytest.mark.parametrize("method,operation,after,index,error", _FAULTS)
def test_process_and_queue_ownership(method, operation, after, index, error, tmp_path):
    _exercise(method, operation, after, index, error, tmp_path)


@pytest.mark.parametrize("method", _ALTERNATES or [_PREFERRED])
def test_alternate_context_keeps_real_key_race_assertions(method, tmp_path):
    _exercise(method, None, False, 0, None, tmp_path)


def _exercise(method, operation, after, index, error, tmp_path):
    owner = importlib.import_module("core.security.tests.test_mac_key")
    source = Path(owner.__file__)
    cls = next(n for n in ast.parse(source.read_text()).body
               if isinstance(n, ast.ClassDef) and n.name == "TestParallelCreators")
    body = next(n for n in cls.body if isinstance(n, ast.FunctionDef)
                and n.name == "test_parallel_creators_converge_on_one_key_without_warnings")
    processes, queues, barriers, closed = [], [], [], []
    failure = error("owned key-creator fault") if error else None
    fired = False
    actual_context = multiprocessing.get_context(method)

    class Process:
        def __init__(self, real):
            self.real = real

        def __getattr__(self, name):
            return getattr(self.real, name)

        def start(self):
            nonlocal fired
            if operation == "start" and processes.index(self) == index and not fired:
                fired = True
                if after:
                    self.real.start()
                raise failure
            result = self.real.start()
            if operation == "get" and processes.index(self) == 7:
                # Install only in the parent's owned queue, after every
                # spawn has serialized the original native queue object.
                for queue in queues:
                    real_get = queue.get

                    def get(*args, _get=real_get, **kwargs):
                        nonlocal fired
                        if not fired:
                            fired = True
                            if after:
                                _get(*args, **kwargs)
                            raise failure
                        return _get(*args, **kwargs)

                    queue.get = get
            return result

        def join(self, *args, **kwargs):
            nonlocal fired
            if operation == "join" and processes.index(self) == index and not fired:
                fired = True
                if after:
                    self.real.join(*args, **kwargs)
                raise failure
            return self.real.join(*args, **kwargs)

        def close(self):
            closed.append((self.real.pid, self.real.exitcode, self.real.is_alive()))
            self.real.close()

    def process(*args, **kwargs):
        value = Process(actual_context.Process(*args, **kwargs))
        processes.append(value)
        return value

    def queue():
        value = actual_context.Queue()
        queues.append(value)
        return value

    def barrier(*args, **kwargs):
        value = actual_context.Barrier(*args, **kwargs)
        barriers.append(value)
        return value

    context = SimpleNamespace(Process=process, Queue=queue, Barrier=barrier)
    private = ModuleType("multiprocessing")
    vars(private).update(vars(multiprocessing))
    private.get_all_start_methods = lambda: [method]
    private.get_context = lambda chosen: context if chosen == method else None
    namespace = dict(vars(owner), multiprocessing=private)
    module = ast.fix_missing_locations(ast.Module(body=[body], type_ignores=[]))
    exec(compile(module, str(source), "exec"), namespace)
    key_path = owner.key_path.__wrapped__(tmp_path)
    try:
        if failure is None:
            namespace[body.name](owner.TestParallelCreators(), key_path)
        else:
            with pytest.raises(error) as caught:
                namespace[body.name](owner.TestParallelCreators(), key_path)
            assert caught.value is failure
            assert fired
        assert len(closed) == len(processes) == 8
        assert not any(alive for _, _, alive in closed)
        assert all(pid is None or exitcode is not None for pid, exitcode, _ in closed)
        assert all(process.real._closed for process in processes)
        assert all(queue._closed and queue._reader.closed and queue._writer.closed for queue in queues)
    finally:
        # Recovery uses raw native objects so a regressed owner cannot leak
        # children or pipe endpoints through the injected boundary wrappers.
        # Never reacquire barrier state after a creator may have been killed.
        for process in processes:
            real = process.real
            if real._closed:
                continue
            if real.pid is not None:
                if real.is_alive():
                    real.kill()
                real.join(5)
                assert not real.is_alive()
            real.close()
        for queue in queues:
            queue.close()
            queue.join_thread()
            queue._reader.close()
            queue._writer.close()
