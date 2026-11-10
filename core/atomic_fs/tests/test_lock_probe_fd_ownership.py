"""Native contention probes own every descriptor before another open."""

import os

import pytest

from core.atomic_fs.tests import test_fs_lock_bounded as native
from core.testing.module_bindings import patch_module_attribute

CASES = [
    pytest.param("TestHintContainment", "test_stuffed_lock_file_is_not_slurped",
                 marks=pytest.mark.skipif(not os.path.exists("/proc/self/io"), reason="native procfs counters unavailable")),
    pytest.param("TestHintContainment", "test_data_file_flock_never_reads_a_hint",
                 marks=pytest.mark.skipif(not os.path.exists("/proc/self/io"), reason="native procfs counters unavailable")),
    ("TestExpiryWarning", "test_expiry_warning_comes_from_the_helper"),
    ("TestExpiryWarning", "test_expiry_note_states_the_consequence"),
]


@pytest.mark.parametrize("cls,name", CASES)
@pytest.mark.parametrize("operation,error", [(operation, error)
    for operation in ("second_open", "first_close")
    for error in (OSError, KeyboardInterrupt, SystemExit)] + [(None, None)])
def test_native_probe_closes_each_owned_fd(
    tmp_path, monkeypatch, caplog, cls, name, operation, error,
):
    opened, closed = [], []
    opens = 0
    failure = error("owned probe descriptor failure") if error else None
    fired = False
    borrowed = native.os

    def opening(*a, **k):
        nonlocal opens, fired
        opens += 1
        if operation == "second_open" and opens == 2:
            fired = True
            raise failure
        fd = os.open(*a, **k)
        opened.append(fd)
        return fd

    def closing(fd):
        nonlocal fired
        assert fd in opened and fd not in closed
        os.close(fd)
        closed.append(fd)
        if operation == "first_close" and not fired:
            fired = True
            raise failure

    kwargs = dict(tmp_path=tmp_path)
    if cls == "TestExpiryWarning":
        kwargs["caplog"] = caplog
    with monkeypatch.context() as patch:
        kwargs["monkeypatch"] = patch
        patch_module_attribute(patch, native, "os", "open", opening)
        patch_module_attribute(patch, native, "os", "close", closing)
        try:
            invoke = getattr(getattr(native, cls)(), name)
            if error:
                with pytest.raises(error) as caught:
                    invoke(**kwargs)
                assert caught.value is failure
                assert fired
            else:
                invoke(**kwargs)
            assert opens == 2
            assert len(opened) == (1 if operation == "second_open" else 2)
            assert closed == list(reversed(opened))
        finally:
            # Every successful native close is recorded before fault injection.
            # Never close those consumed numbers again after possible reuse.
            for fd in opened:
                if fd not in closed:
                    os.close(fd)
    assert native.os is borrowed
