"""Inspection-output ownership, with failures on owned files and duplicates."""

import errno
import os
import tempfile

import pytest

from core.analysis import binary_oracle as oracle
from core.testing.module_bindings import patch_module_attribute


@pytest.fixture
def output_faults(monkeypatch):
    raw_streams, copies, close_calls = [], {}, []
    real_temp, real_dup, real_close = tempfile.NamedTemporaryFile, os.dup, os.close

    def install(*, dup_error=None, dup_fail_at=1, file_close_error=None,
                descriptor_close_error=None, low_slots=False):
        class Stream:
            def __init__(self, raw):
                self.raw = raw
                raw_streams.append(raw)

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.close()

            def fileno(self):
                return self.raw.fileno()

            def close(self):
                self.raw.close()
                if file_close_error is not None:
                    raise file_close_error

        attempts = 0

        def duplicate(fd):
            nonlocal attempts
            attempts += 1
            if dup_error is not None and attempts == dup_fail_at:
                raise dup_error
            actual = real_dup(copies.get(fd, fd))
            # Model vacant stdio slots without ever closing the test runner's
            # real descriptors 0/1/2. Each virtual slot owns a real duplicate.
            visible = attempts - 1 if low_slots and attempts < 3 else actual
            copies[visible] = actual
            return visible

        def close(fd):
            close_calls.append(fd)
            real_close(copies.pop(fd))
            if descriptor_close_error is not None:
                raise descriptor_close_error

        patch_module_attribute(monkeypatch, oracle, "tempfile", "NamedTemporaryFile",
                               lambda **kwargs: Stream(real_temp(**kwargs)))
        patch_module_attribute(monkeypatch, oracle, "os", "dup", duplicate)
        patch_module_attribute(monkeypatch, oracle, "os", "close", close)
        return raw_streams, copies, close_calls

    yield install
    for raw in raw_streams:
        raw.close()
    for fd in copies.values():
        real_close(fd)


@pytest.mark.parametrize("error_type", [OSError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_body_error_survives_descriptor_cleanup(tmp_path, output_faults, error_type):
    primary = error_type("inspection interrupted")
    streams, copies, closed = output_faults(descriptor_close_error=OSError("close failed"))
    with pytest.raises(error_type) as caught:
        with oracle._owned_output(str(tmp_path)) as descriptor:
            assert descriptor >= 3
            os.write(descriptor, b"owned output")
            raise primary
    assert caught.value is primary
    assert streams and all(raw.closed for raw in streams)
    assert copies == {}
    assert len(closed) == 1


@pytest.mark.parametrize("error_type", [OSError, RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("dup_fail_at", [1, 3])
def test_duplication_error_survives_file_and_descriptor_cleanup(
    tmp_path, output_faults, error_type, dup_fail_at,
):
    primary = error_type("duplicate failed")
    streams, copies, _ = output_faults(
        dup_error=primary, dup_fail_at=dup_fail_at, low_slots=True,
        file_close_error=OSError("file close failed"),
        descriptor_close_error=OSError("duplicate close failed"),
    )
    with pytest.raises(error_type) as caught:
        with oracle._owned_output(str(tmp_path)):
            pytest.fail("failed setup must not yield an output descriptor")
    assert caught.value is primary
    assert streams and all(raw.closed for raw in streams)
    assert copies == {}


def test_intermediate_cleanup_attempts_all_owned_duplicates(tmp_path, output_faults):
    error = OSError("retirement failed")
    streams, copies, closed = output_faults(
        low_slots=True, descriptor_close_error=error,
    )
    with pytest.raises(OSError) as caught:
        with oracle._owned_output(str(tmp_path)):
            pytest.fail("failed setup must not yield an output descriptor")
    assert caught.value is error
    assert streams and all(raw.closed for raw in streams)
    assert copies == {}
    assert len(closed) == 3
    assert len(set(closed)) == 3  # Never retry a close with uncertain status.


def test_success_keeps_only_delegated_descriptor_until_exit(tmp_path, output_faults):
    streams, copies, closed = output_faults(low_slots=True)
    with oracle._owned_output(str(tmp_path)) as descriptor:
        assert descriptor >= 3
        assert all(raw.closed for raw in streams)
        assert list(copies) == [descriptor]
        assert not os.get_inheritable(descriptor)
        os.write(descriptor, b"inspection output")
        assert os.pread(descriptor, 17, 0) == b"inspection output"
    assert copies == {}
    assert len(closed) == 3
    with pytest.raises(OSError) as caught:
        os.fstat(descriptor)
    assert caught.value.errno == errno.EBADF


def test_success_does_not_hide_final_cleanup_failure(tmp_path, output_faults):
    error = OSError("final close failed")
    _, copies, closed = output_faults(descriptor_close_error=error)
    reached = False
    with pytest.raises(OSError) as caught:
        with oracle._owned_output(str(tmp_path)):
            reached = True
    assert reached
    assert caught.value is error
    assert copies == {} and len(closed) == 1
