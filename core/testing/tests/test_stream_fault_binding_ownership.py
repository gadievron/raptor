"""Descriptor fault hooks belong to the selected consumer import."""
from contextlib import contextmanager
import os

import pytest

from core.testing.tests import test_stream_handoff_cleanup as native


@pytest.mark.parametrize("fault", ["constructor", "label", "open"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
@pytest.mark.parametrize("outcome", [None, RuntimeError, KeyboardInterrupt])
def test_descriptor_fault_binding_restores_after_exit(
    fault, error, outcome, tmp_path, monkeypatch
):
    from core.binary.tests import test_elf_worker as module

    name = "test_descriptor_input_reads_pinned_inode_without_reopening_alias"
    original = getattr(module, name)
    borrowed = os.dup
    entries = []
    reached = []

    class Patch:
        @contextmanager
        def context(self):
            with monkeypatch.context() as actual:
                class Scope:
                    def __getattr__(self, key):
                        return getattr(actual, key)

                    def setattr(self, target, key, value, *args, **kwargs):
                        actual.setattr(target, key, value, *args, **kwargs)
                        assert os.dup is borrowed
                        if key == "dup":
                            assert target is not os and target.dup is value
                            cells = dict(zip(value.__code__.co_freevars,
                                             (c.cell_contents for c in value.__closure__)))
                            record = cells["record"]
                            recorded = dict(zip(record.__code__.co_freevars,
                                                (c.cell_contents for c in record.__closure__)))
                            entries.append(recorded["entries"])
                            reached.append(True)
                yield Scope()
                assert reached and os.dup is borrowed
                if outcome is not None:
                    raise outcome("outer scope exit")

    def invoke():
        native.test_descriptor_argument_failure_closes_duplicate(
            fault, error, tmp_path, Patch()
        )

    if outcome is None:
        invoke()
    else:
        with pytest.raises(outcome, match="outer scope exit"):
            invoke()
    assert len(entries) == 1 and len(entries[0]) == 1
    assert all(not native._owned(fd, identity) for fd, identity in entries[0])
    assert getattr(module, name) is original
    assert os.dup is borrowed


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
@pytest.mark.parametrize("borrowed_open", [False, True])
def test_late_open_fault_restores_borrowed_binding(
    error, borrowed_open, tmp_path, monkeypatch
):
    from core.binary.tests import test_elf_worker as module

    def untouched(*args, **kwargs):
        pytest.fail("borrowed open binding was called")

    with monkeypatch.context() as outer:
        outer.delattr(module, "open", raising=False)
        if borrowed_open:
            outer.setattr(module, "open", untouched, raising=False)
        native.test_descriptor_argument_failure_closes_duplicate(
            "open", error, tmp_path, monkeypatch
        )
        if borrowed_open:
            assert module.open is untouched
        else:
            assert "open" not in vars(module)
