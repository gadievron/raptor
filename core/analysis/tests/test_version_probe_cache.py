"""A shared positive cache is bounded, retryable and safe under concurrency."""

import gc
import threading
import weakref
from concurrent.futures import Future, ThreadPoolExecutor
from unittest.mock import Mock

import pytest

from core.analysis import rule_versions
from core.analysis.rule_versions import VersionProbeCache


@pytest.fixture
def binary(tmp_path):
    path = tmp_path / 'tool'
    path.write_text('initial')
    path.chmod(0o755)
    return path


@pytest.mark.parametrize('outcome', ['success', 'unknown', 'exception'])
def test_parallel_checks_share_one_flight_and_failures_can_recover(binary, monkeypatch, outcome):
    workers = 6
    ready = threading.Event()
    release = threading.Event()
    waiting_lock = threading.Lock()
    waiting = 0
    class WaitingFuture(Future):
        def result(self, *args, **kwargs):
            nonlocal waiting
            with waiting_lock:
                waiting += 1
                if waiting == workers - 1:
                    ready.set()
            return super().result(*args, **kwargs)
    monkeypatch.setattr(rule_versions, 'Future', WaitingFuture)
    cache = VersionProbeCache()
    calls = []
    def probe():
        calls.append(1)
        assert release.wait(5)
        if outcome == 'exception':
            raise OSError('probe interrupted')
        return '1.3.0' if outcome == 'success' else None
    with ThreadPoolExecutor(max_workers=workers) as pool:
        pending = [pool.submit(cache.get, probe, lambda: str(binary)) for _ in range(workers)]
        try:
            assert ready.wait(5), 'concurrent callers did not reach the in-flight probe'
        finally:
            release.set()
        if outcome == 'exception':
            for future in pending:
                with pytest.raises(OSError, match='interrupted'):
                    future.result(timeout=5)
        else:
            assert [future.result(timeout=5) for future in pending] == [
                '1.3.0' if outcome == 'success' else None,
            ] * workers
    assert len(calls) == 1
    recovered = Mock(return_value='1.3.0')
    assert cache.get(recovered, lambda: str(binary)) == '1.3.0'
    assert recovered.call_count == (0 if outcome == 'success' else 1)


def test_cache_does_not_retain_callbacks_or_their_owner(binary):
    class Owner:
        def installed(self):
            return '1.3.0'
        def executable(self):
            return str(binary)
    owner = Owner()
    reference = weakref.ref(owner)
    cache = VersionProbeCache()
    assert cache.get(owner.installed, owner.executable) == '1.3.0'
    del owner
    gc.collect()
    assert reference() is None


def test_selected_executable_change_during_probe_cannot_reuse_the_old_answer(binary, tmp_path):
    other = tmp_path / 'other'
    other.write_text('other')
    selected = [str(binary)]
    def changed():
        selected[0] = str(other)
        return '1.3.0'
    cache = VersionProbeCache()
    assert cache.get(changed, lambda: selected[0]) is None
    assert cache.get(lambda: '1.1.1', lambda: selected[0]) == '1.1.1'


def test_forked_owner_discards_parent_lock_and_cached_answer(binary, monkeypatch):
    cache = VersionProbeCache()
    assert cache.get(lambda: '1.3.0', lambda: str(binary)) == '1.3.0'
    parent_lock = cache._lock
    child_pid = cache._pid + 1
    parent_lock.acquire()
    with monkeypatch.context() as context:
        context.setattr(rule_versions, '_process_id', lambda: child_pid)
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(cache.get, lambda: '2.0.0', lambda: str(binary))
            try:
                assert pending.result(timeout=2) == '2.0.0'
            finally:
                parent_lock.release()
