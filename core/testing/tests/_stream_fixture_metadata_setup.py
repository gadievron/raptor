import ast, hashlib, json, os, socket, subprocess, sys
from pathlib import Path
from types import SimpleNamespace

root, scratch = map(Path, sys.argv[1:3])
phase, kind = sys.argv[3:5]
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
    "execv",
    "execve",
    "execvp",
    "execvpe",
):
    if hasattr(os, name):
        setattr(os, name, denied)
socket.socket.connect = denied
socket.socket.connect_ex = denied
source = root / "core/testing/tests/test_fixture_stream_adoption.py"
raw = source.read_bytes()
node = next(
    n
    for n in ast.parse(raw).body
    if isinstance(n, ast.FunctionDef)
    and n.name == "test_fdopen_default_text_mode_owns_descriptor"
)
real_open, real_stat, real_close = os.open, os.fstat, os.close
opened = []
failure = {"interrupt": KeyboardInterrupt, "error": RuntimeError}[kind](
    "owned pretransfer metadata fault"
)
closed = []
sentinels = []


def closing(fd):
    assert fd in opened and fd not in closed
    real_close(fd)
    closed.append(fd)
    replacement = real_open(scratch / "sentinel", os.O_CREAT | os.O_RDWR, 0o600)
    assert replacement == fd
    sentinels.append(replacement)


def opening(path, *args, **kwargs):
    assert path == scratch / "input"
    fd = real_open(path, *args, **kwargs)
    opened.append(fd)
    return fd


def stat(fd):
    assert fd in opened
    if phase == "after":
        real_stat(fd)
    raise failure


namespace = {
    "os": SimpleNamespace(
        open=opening, fstat=stat, close=closing, O_RDONLY=os.O_RDONLY
    ),
    "streams": SimpleNamespace(fdopen_owned=denied),
    "_close_if_owned": denied,
}
from contextlib import suppress

namespace["suppress"] = suppress
helper = next(
    n
    for n in ast.parse(raw).body
    if isinstance(n, ast.FunctionDef) and n.name == "_open_recorded"
)
exec(
    compile(ast.Module(body=[helper, node], type_ignores=[]), str(source), "exec"),
    namespace,
)
try:
    try:
        namespace[node.name](scratch)
    except type(failure) as caught:
        assert caught is failure
    else:
        raise AssertionError("metadata boundary not reached")
    assert len(opened) == 1
    assert closed == opened and sentinels == opened
    os.write(sentinels[0], b"caller-owned")
    assert real_stat(sentinels[0]).st_size == len(b"caller-owned")
    assert not attempts
    result = {
        "result": "STREAM_FIXTURE_METADATA_OK",
        "function": node.name,
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "fault": f"{type(failure).__name__} {phase} real fstat, before owning try/adoption",
        "sentinel_preserved": True,
        "adopter_called": False,
        "forbidden_attempts": attempts,
        "scope": "one actual AST-selected test body; not product stream adoption failure",
    }
finally:
    for fd in opened:
        real_close(fd)
result["raw_rescue_closed"] = True
print(json.dumps(result, sort_keys=True))
