"""Every exit after acquiring the proxy persistence lock releases it."""
import threading

import pytest

from core.sandbox import context


class Cancelled(BaseException):
    pass


@pytest.mark.parametrize('failure', [Cancelled, RuntimeError])
@pytest.mark.parametrize('stage', ['state', 'canonicalize', 'open', 'open-report'])
def test_early_failures_release_lock(tmp_path, monkeypatch, failure, stage):
    lock = threading.Lock()
    monkeypatch.setattr(context, '_PROXY_PERSIST_LOCK', lock)
    monkeypatch.setattr(context, '_PROXY_STREAM_STATE', {})

    def fail(*args, **kwargs):
        raise failure('injected early exit')

    with monkeypatch.context() as scoped:
        if stage == 'state':
            class BrokenState(dict):
                setdefault = staticmethod(fail)
            scoped.setattr(context, '_PROXY_STREAM_STATE', BrokenState())
        elif stage == 'canonicalize':
            realpath = context.os.path.realpath

            def canonicalize(path, *args, **kwargs):
                if lock.locked():
                    return fail()
                return realpath(path, *args, **kwargs)

            scoped.setattr(context.os.path, 'realpath', canonicalize)
        elif stage == 'open':
            scoped.setattr(context.os, 'open', fail)
        else:
            def refused(*args, **kwargs):
                raise OSError('open refused')
            scoped.setattr(context.os, 'open', refused)
            scoped.setattr(context, '_read_proxy_count_sidecar', fail)
        with pytest.raises(failure, match='injected early exit'):
            context._persist_proxy_events([{'host': 'example.test'}], output=tmp_path)

    # Check without blocking: a regression must fail rather than hang pytest.
    assert lock.acquire(blocking=False)
    lock.release()


def test_open_failure_releases_lock_on_normal_return(tmp_path, monkeypatch):
    lock = threading.Lock()
    monkeypatch.setattr(context, '_PROXY_PERSIST_LOCK', lock)
    monkeypatch.setattr(context, '_PROXY_STREAM_STATE', {})

    def refused(*args, **kwargs):
        raise OSError('open refused')

    monkeypatch.setattr(context.os, 'open', refused)
    monkeypatch.setattr(context, '_read_proxy_count_sidecar', lambda *a: (0, set(), False))
    seen = []
    monkeypatch.setattr(context, '_write_proxy_count_sidecar', lambda *a: seen.append(a))
    context._persist_proxy_events([{'host': 'example.test'}], output=tmp_path)
    assert len(seen) == 1
    assert 'persist_open_failure' in seen[0][2]
    assert lock.acquire(blocking=False)
    lock.release()
