"""Line snapshots defer pure native work and release unused inputs."""

import gc
import sys
import weakref

import pytest

from core.source import lines


@pytest.mark.parametrize("size,eager", [(20, True), (2000, False)], ids=["small-eager", "large-lazy"])
def test_native_rows_are_prepared_once(size, eager):
    if sys.getprofile() is not None:
        pytest.skip("profiling hook already owned")
    source = "padding\r\n" * size
    calls = []

    def observe(frame, event, arg):
        if event == "call" and frame.f_code is lines.split_lines.__code__ and frame.f_locals.get("text") is source:
            calls.append(source)

    try:
        sys.setprofile(observe)
        snapshot = lines.SourceLineSnapshot(source)
        assert len(calls) == int(eager)
        first = snapshot.get()
        assert snapshot.get() is first
        assert len(calls) == 1
    finally:
        sys.setprofile(None)
    assert first == ["padding"] * size
    assert not any(value is source for value in gc.get_referents(snapshot))


@pytest.mark.parametrize("result", [None, [], ["adapter"], ("tuple",)], ids=["none", "empty", "list", "tuple"])
def test_custom_splitter_is_eager_and_its_exact_value_is_cached(result):
    calls = []

    def split(source):
        calls.append(source)
        return result

    source = "padding\n" * 3000
    snapshot = lines.SourceLineSnapshot(source, split)
    assert calls == [source]
    assert snapshot.get() is result
    assert snapshot.get() is result
    assert calls == [source]


def test_foreign_source_is_eager_and_not_retained():
    calls = []

    class Source(str):
        def split(self, separator):
            calls.append(separator)
            return ["adapter"]

    source = Source("padding\n" * 3000)
    reference = weakref.ref(source)
    snapshot = lines.SourceLineSnapshot(source)
    assert calls == ["\n"]
    del source
    if reference() is not None:
        gc.collect()
    assert reference() is None
    assert snapshot.get() == ["adapter"]


def test_eager_snapshot_does_not_keep_provider_alive():
    class Provider:
        def __call__(self, source):
            return ["adapter"]

    provider = Provider()
    reference = weakref.ref(provider)
    snapshot = lines.SourceLineSnapshot("source", provider)
    del provider
    if reference() is not None:
        gc.collect()
    assert reference() is None
    assert snapshot.get() == ["adapter"]


def test_failed_native_materialization_can_retry_without_losing_source():
    calls = []

    def split(source):
        calls.append(source)
        if len(calls) == 1:
            raise MemoryError("owned allocation failure")
        return ["rows"]

    source = "padding\n" * 3000
    snapshot = lines.SourceLineSnapshot(source)
    snapshot._splitter = split  # Fault injection belongs to this owned instance.
    with pytest.raises(MemoryError):
        snapshot.get()
    assert snapshot.get() == ["rows"]
    assert calls == [source, source]
    assert not any(value is source for value in gc.get_referents(snapshot))
