"""Evidence closure owns its descriptor and preserves its final verdict."""

import errno
import os
import subprocess
import sys
import threading
from types import SimpleNamespace

import pytest

from core.sandbox import evidence


def test_close_during_encoding_cannot_write_to_reused_descriptor(tmp_path, monkeypatch):
    handle = evidence.EvidenceFile.open(tmp_path, "events.jsonl")
    entered, release = threading.Event(), threading.Event()
    results, errors, writes = [], [], []
    real_write = os.write
    victim_fd = None

    class PausedLine(str):
        def encode(self, *args, **kwargs):
            entered.set()
            assert release.wait(5)
            return super().encode(*args, **kwargs)

    def write():
        try:
            results.append(handle.write_line(PausedLine("late record\n")))
        except BaseException as exc:
            errors.append(exc)

    worker = threading.Thread(target=write, daemon=True)
    worker.start()
    try:
        assert entered.wait(5)
        assert handle.close() is True
        victim = tmp_path / "other-file"
        victim_fd = os.open(victim, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        real_write(victim_fd, b"unchanged")

        def reused_write(fd, data):
            # Model this descriptor number now belonging to another
            # file without overwriting any unrelated process fd.
            assert fd == handle.fd
            writes.append(bytes(data))
            return real_write(victim_fd, data)

        with monkeypatch.context() as patch:
            patch.setattr(evidence, "os", SimpleNamespace(write=reused_write))
            release.set()
            worker.join(5)
        assert not worker.is_alive()
        assert results == [False]
        assert not errors
        assert writes == []
        assert victim.read_bytes() == b"unchanged"
    finally:
        release.set()
        worker.join(5)
        handle.close(verify=False)
        if victim_fd is not None:
            os.close(victim_fd)


def test_failed_verification_survives_repeated_close(tmp_path):
    handle = evidence.EvidenceFile.open(tmp_path, "events.jsonl")
    handle.path.rename(handle.path.with_name("original.jsonl"))
    handle.path.touch()
    try:
        assert handle.close() is False
        assert handle.close() is False
        assert handle.close(verify=False) is False
        assert handle.write_line("after close\n") is False
    finally:
        handle.close(verify=False)


@pytest.mark.parametrize("failure", [RuntimeError("verify failed"), KeyboardInterrupt()])
def test_verification_exception_still_releases_descriptor(tmp_path, monkeypatch, failure):
    handle = evidence.EvidenceFile.open(tmp_path, "events.jsonl")
    calls = []

    def fail():
        calls.append(True)
        raise failure

    monkeypatch.setattr(handle, "verify", fail)
    try:
        with pytest.raises(type(failure)) as raised:
            handle.close()
        assert raised.value is failure
        with pytest.raises(OSError) as closed:
            os.fstat(handle.fd)
        assert closed.value.errno == errno.EBADF
        assert handle.close(verify=False) is False
        assert handle.close() is False
        assert calls == [True]
    finally:
        handle.close(verify=False)


@pytest.mark.parametrize("verdict", [True, False])
def test_concurrent_closers_share_one_verification_and_release(tmp_path, monkeypatch, verdict):
    handle = evidence.EvidenceFile.open(tmp_path, "events.jsonl")
    entered, release, second_started = threading.Event(), threading.Event(), threading.Event()
    verifications, closes, results, errors = [], [], [], []
    real_close = os.close

    def verify():
        verifications.append(True)
        entered.set()
        assert release.wait(5)
        return verdict

    def close_fd(fd):
        if fd == handle.fd:
            closes.append(fd)
            if len(closes) > 1:
                raise OSError(errno.EBADF, "duplicate close intercepted")
        return real_close(fd)

    def close(second=False):
        if second:
            second_started.set()
        try:
            results.append(handle.close())
        except BaseException as exc:
            errors.append(exc)

    monkeypatch.setattr(handle, "verify", verify)
    monkeypatch.setattr(evidence.os, "close", close_fd)
    first = threading.Thread(target=close, daemon=True)
    second = threading.Thread(target=close, args=(True,), daemon=True)
    first.start()
    try:
        assert entered.wait(5)
        second.start()
        assert second_started.wait(5)
        release.set()
        first.join(5)
        second.join(5)
        assert not first.is_alive() and not second.is_alive()
        assert not errors
        assert results == [verdict, verdict]
        assert verifications == [True]
        assert closes == [handle.fd]
    finally:
        release.set()
        first.join(5)
        if second.ident is not None:
            second.join(5)
        handle.close(verify=False)


def test_raw_descriptor_inheritor_does_not_need_parent_lock(tmp_path):
    handle = evidence.EvidenceFile.open(tmp_path, "events.jsonl")
    try:
        with handle._io_lock:
            result = subprocess.run(
                [sys.executable, "-c",
                 "import os, sys; os.write(int(sys.argv[1]), b'child\\n')",
                 str(handle.fd)],
                pass_fds=(handle.fd,), capture_output=True, timeout=10,
            )
            assert result.returncode == 0, result.stderr
            assert os.get_inheritable(handle.fd) is False
        assert handle.close() is True
        assert handle.path.read_bytes() == b"child\n"
    finally:
        handle.close(verify=False)
