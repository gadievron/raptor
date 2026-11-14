from pathlib import Path
import ast, __future__, hashlib, json, os, shutil, socket, subprocess, sys, time, uuid
from contextlib import ExitStack
from types import SimpleNamespace

root, scratch = map(Path, sys.argv[1:3])
helper, phase, outcome, expectation = sys.argv[3:7]
scratch.mkdir(parents=True, exist_ok=True)
attempts = []


def denied(*args, **kwargs):
    attempts.append("secondary execution or transport")
    raise AssertionError(attempts[-1])


subprocess.Popen = denied
for name in (
    "fork",
    "forkpty",
    "system",
    "posix_spawn",
    "posix_spawnp",
    "execl",
    "execle",
    "execv",
    "execve",
    "execvp",
    "execvpe",
):
    if hasattr(os, name):
        setattr(os, name, denied)
socket.socket.connect = denied
socket.socket.connect_ex = denied
source = root / "core/llm/dispatcher/tests/test_inproc_scratch_cleanup.py"
raw = source.read_bytes()
tree = ast.parse(raw)
nodes = [
    node
    for node in tree.body
    if isinstance(node, ast.FunctionDef) and node.name in {"_owned_dir", "_inproc_dir"}
]
assert len(nodes) == 2
producer = root / "core/run/tmp_ownership.py"
t = ast.parse(producer.read_bytes())
value = next(
    node.value
    for node in t.body
    if isinstance(node, ast.Assign)
    and any(
        isinstance(target, ast.Name) and target.id == "OWNER_MARKER_NAME"
        for target in node.targets
    )
)
marker = ast.literal_eval(value)
assert isinstance(marker, str)
paths = []


class OwnedPath(type(Path())):
    def mkdir(self, *args, **kwargs):
        assert self.parent == scratch
        result = super().mkdir(*args, **kwargs)
        paths.append(Path(self))
        return result


namespace = dict(
    Path=OwnedPath,
    tempfile=SimpleNamespace(gettempdir=lambda: str(scratch)),
    json=json,
    time=time,
    uuid=uuid,
    shutil=shutil,
    OWNER_MARKER_NAME=marker,
)
exec(
    compile(
        ast.Module(body=nodes, type_ignores=[]),
        str(source),
        "exec",
        flags=__future__.annotations.compiler_flag,
    ),
    namespace,
)
failure = {"error": RuntimeError, "interrupt": KeyboardInterrupt}[outcome](
    "owned finalizer registration failure"
)
stack = ExitStack()
events = []


def register(callback):
    events.append("called")
    if phase == "before":
        raise failure
    stack.callback(callback)
    events.append("registered")
    if phase == "after":
        raise failure


request = SimpleNamespace(addfinalizer=register)
caught = None
try:
    try:
        if helper == "_owned_dir":
            result = namespace[helper]("raptor-llm-owned-", os.getpid(), request)
        else:
            assert helper == "_inproc_dir"
            result = namespace[helper](os.getpid(), request)
    except BaseException as error:
        caught = error
    assert len(paths) == 1 and events.count("called") == 1
    path = paths[0]
    if phase == "normal":
        assert caught is None and result == path and path.is_dir()
        record = json.loads((path / marker).read_text())
        assert record["pid"] == os.getpid() and isinstance(record["created"], float)
        stack.close()
        assert not path.exists()
    else:
        assert caught is failure and not (path / marker).exists()
        if expectation == "baseline":
            assert phase == "before" and path.is_dir()
        else:
            assert expectation == "candidate" and not path.exists()
            path.mkdir()
            (path / "new-owner").write_bytes(b"caller-owned replacement")
            stack.close()
            assert (path / "new-owner").read_bytes() == b"caller-owned replacement"
    assert not attempts
    report = {
        "result": "DISPATCHER_FINALIZER_BASELINE_CONFIRMED"
        if expectation == "baseline"
        else "DISPATCHER_FINALIZER_OK",
        "helper": helper,
        "phase": phase,
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "marker_producer_sha256": hashlib.sha256(producer.read_bytes()).hexdigest(),
        "forbidden_attempts": attempts,
    }
finally:
    stack.close()
    for path in paths:
        shutil.rmtree(path, ignore_errors=True)
assert all(not path.exists() for path in paths)
print(json.dumps(report, sort_keys=True))
