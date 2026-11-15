from pathlib import Path
import ast, errno, hashlib, json, os, sys
from types import ModuleType
root = Path(sys.argv[1]).resolve()
mode = sys.argv[2]
assert mode in {"dup_error", "duplicate", "same"}
output = Path(sys.argv[3]).resolve()
assert output.parent.is_dir() and not output.exists()
source = root / "core/testing/tests/test_pipe_setup_cleanup.py"
data = source.read_bytes()
assert hashlib.sha256(data).hexdigest() == "9cd18b9d00b22d96715f4ae969ca015187b75dea23d7819e9d5a2efc97a922a3"
tree = ast.parse(data)
owner = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "test_tier_reader_preserves_reused_writer_descriptor")
node = next(n for n in ast.walk(owner) if isinstance(n, ast.FunctionDef) and n.name == "read")
assert node.decorator_list == []
private_os = ModuleType("os")
vars(private_os).update(vars(os))
opened = []
closes = []
duplicates = []
sentinel = OSError("private dup2 before-effect refusal")
def allocate(*args, **kwargs):
    fd = os.open(*args, **kwargs)
    st = os.fstat(fd)
    opened.append((fd, (st.st_dev, st.st_ino)))
    return fd
def duplicate(fd, target):
    assert len(opened) == 1 and fd == opened[0][0] and target == old_writer and fd != target
    duplicates.append((fd, target))
    if mode == "dup_error":
        raise sentinel
    return os.dup2(fd, target)
def close(fd):
    closes.append(fd)
    return os.close(fd)
private_os.open, private_os.dup2, private_os.close = allocate, duplicate, close
forbidden = []
def audit(event, args):
    if event.startswith(("subprocess.", "socket.", "ctypes.")) or event in {"os.system", "os.fork", "os.forkpty", "os.posix_spawn", "os.exec", "os.kill", "os.killpg"}:
        forbidden.append(event)
        raise AssertionError("forbidden action: " + event)
sys.addaudithook(audit)
work = output.parent / "callback-root"
work.mkdir(mode=0o700)
staged = []
borrowed = []
try:
    for name in ["hole", "guard", "old-writer"]:
        fd = os.open(work / name, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        st = os.fstat(fd)
        staged.append([fd, (st.st_dev, st.st_ino), True])
    assert staged[0][0] < staged[2][0]
    old_writer = staged[0][0] if mode == "same" else staged[2][0]
    os.close(staged[0][0]); staged[0][2] = False
    os.close(staged[2][0]); staged[2][2] = False
    namespace = {"os": private_os, "tmp_path": work, "pairs": [(None, old_writer)], "borrowed": borrowed}
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(source), "exec"), namespace)
    observed = None
    try:
        namespace["read"]()
    except BaseException as error:
        observed = error
    assert len(opened) == 1 and not forbidden
    fd, identity = opened[0]
    expected_identity = observed is sentinel if mode == "dup_error" else isinstance(observed, OSError) and str(observed) == "injected pipe setup failure"
    assert expected_identity
    distinct = mode != "same"
    assert duplicates == ([(fd, old_writer)] if distinct else [])
    assert closes == ([fd] if distinct else [])
    if distinct:
        try:
            os.fstat(fd)
        except OSError as error:
            assert error.errno == errno.EBADF
        else:
            raise AssertionError("source descriptor remained open")
    target_live = mode != "dup_error"
    if target_live:
        assert borrowed == [old_writer]
        st = os.fstat(old_writer)
        assert (st.st_dev, st.st_ino) == identity
        os.write(old_writer, b"still owned")
        assert (work / "other-owner").read_bytes() == b"still owned"
    else:
        assert not borrowed
        try:
            os.fstat(old_writer)
        except OSError as error:
            assert error.errno == errno.EBADF
        else:
            raise AssertionError("failed duplication consumed target")
    payload = {"mode": mode, "expected_exception": expected_identity, "distinct_source_closed_before_rescue": distinct, "target_live_before_rescue": target_live, "borrowed_handoff_count": len(borrowed), "source_close_calls": len(closes), "duplicate_calls": len(duplicates), "target_write_verified": target_live, "exact_callback_body": True, "pipe_process_body_excluded": True, "forbidden_attempts": forbidden}
finally:
    for fd, identity in opened:
        try:
            stat = os.fstat(fd)
        except OSError as error:
            assert error.errno == errno.EBADF
        else:
            assert (stat.st_dev, stat.st_ino) == identity
            os.close(fd)
    for fd in borrowed:
        try:
            stat = os.fstat(fd)
        except OSError as error:
            assert error.errno == errno.EBADF
        else:
            assert (stat.st_dev, stat.st_ino) == opened[0][1]
            os.close(fd)
    for fd, identity, active in staged:
        if active:
            stat = os.fstat(fd)
            assert (stat.st_dev, stat.st_ino) == identity
            os.close(fd)
    for file in work.iterdir():
        assert file.name in {"hole", "guard", "old-writer", "other-owner"} and file.is_file()
        file.unlink()
    work.rmdir()
payload["independent_verified_rescue_complete"] = True
with output.open("x") as stream:
    json.dump(payload, stream)
