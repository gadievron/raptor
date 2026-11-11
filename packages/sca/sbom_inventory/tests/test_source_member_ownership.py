"""Member streams retire without replacing read or projection errors."""
import ctypes
import hashlib
import io
from types import SimpleNamespace
import zipfile

import pytest

from core.source import beneath
from core.testing.module_state import isolated_module_state
from packages.sca.sbom_inventory import source as module


@pytest.fixture
def members(tmp_path, monkeypatch):
    state = SimpleNamespace(native=[], wrapped=[], closed=[], primary=None, cleanup=None,
                            held_error=None, native_error=None)
    native_gated, native_beneath = module.open_regular_gated, module.open_regular_beneath
    native_zip, native_project = zipfile.ZipFile, module.project_object

    class Reader(io.BufferedReader):
        def __init__(self, raw, role):
            super().__init__(raw)
            self.role = role
            state.native.append((role, raw))
            state.wrapped.append(self)

        def read(self, *args):
            result = super().read(*args)
            if self.role == 'member' and state.primary is not None:
                raise state.primary
            return result

        def close(self):
            if self.closed:
                return super().close()
            super().close()
            state.closed.append(self.role)
            error = state.cleanup if self.role == 'member' else state.held_error
            if error is not None:
                raise error

    def gated(path, **kwargs):
        return Reader(native_gated(path, **kwargs), 'held' if path.suffix == '.zip' else 'member')

    def anchored(*args, **kwargs):
        stream = native_beneath(*args, **kwargs)
        return Reader(stream, 'member') if stream is not None else None

    class Archive(native_zip):
        def open(self, *args, **kwargs):
            return Reader(super().open(*args, **kwargs), 'member')

    def project(*args, **kwargs):
        try:
            return native_project(*args, **kwargs)
        except BaseException as error:
            state.native_error = error
            raise

    def create(profile, payload=b'{"owned":1}'):
        if profile == 'zip':
            path = tmp_path / 'input.zip'
            with native_zip(path, 'w') as archive:
                archive.writestr('owned.json', payload)
            name = 'owned.json'
        elif profile == 'directory':
            path = tmp_path / 'input'
            path.mkdir()
            (path / 'owned.json').write_bytes(payload)
            name = 'owned.json'
        else:
            path = tmp_path / 'snapshot.json'
            path.write_bytes(payload)
            name = ''
        return module.Source(path), name

    monkeypatch.setattr(module, 'open_regular_gated', gated)
    monkeypatch.setattr(module, 'open_regular_beneath', anchored)
    monkeypatch.setattr(module, 'zipfile', SimpleNamespace(**{**vars(zipfile), 'ZipFile': Archive}))
    monkeypatch.setattr(module, 'project_object', project)
    state.create = create
    saved_errno = ctypes.get_errno()
    # Use the process libc handle, avoiding find_library subprocess lookup.
    libc = beneath._libc if beneath._libc is not None else ctypes.CDLL(None, use_errno=True)
    try:
        with isolated_module_state(beneath, {'_libc': libc, '_openat2_usable': beneath._openat2_usable}):
            yield state
    finally:
        for stream in state.wrapped:
            if not stream.closed:
                io.BufferedReader.close(stream)
        ctypes.set_errno(saved_errno)


def assert_members_closed(state, count=1):
    selected = [raw for role, raw in state.native if role == 'member']
    assert len(selected) == state.closed.count('member') == count
    assert all(raw.closed for raw in selected)


def assert_all_closed(state):
    assert all(raw.closed for _, raw in state.native)
    assert all(stream.closed for stream in state.wrapped)


@pytest.mark.parametrize('profile', ['standalone', 'directory'])
def test_native_size_refusal_survives_member_close(members, profile):
    source, name = members.create(profile)
    members.cleanup = OSError('after native member close')
    with source:
        with pytest.raises(ValueError, match='evidence member exceeds read budget'):
            source.read(name, max_bytes=1)
        assert_members_closed(members)
    assert_all_closed(members)


@pytest.mark.parametrize('profile', ['standalone', 'directory', 'zip'])
def test_native_json_refusal_survives_member_close(members, profile):
    source, name = members.create(profile, b'{')
    members.cleanup = OSError('after native member close')
    with source:
        with pytest.raises(ValueError) as caught:
            source.read_json(name)
        assert caught.value is members.native_error
        assert_members_closed(members)
    assert_all_closed(members)


@pytest.mark.parametrize('profile', ['standalone', 'directory', 'zip'])
@pytest.mark.parametrize('primary', [OSError, ValueError, KeyboardInterrupt, SystemExit])
def test_read_error_keeps_identity(members, profile, primary):
    source, name = members.create(profile)
    members.primary = primary('after native member read')
    members.cleanup = OSError('after native member close')
    with source:
        with pytest.raises(primary) as caught:
            source.read(name)
        assert caught.value is members.primary
        assert_members_closed(members)
        if profile == 'zip':
            assert source.contains(name)
    assert_all_closed(members)


@pytest.mark.parametrize('profile', ['standalone', 'directory', 'zip'])
@pytest.mark.parametrize('cleanup', [OSError, KeyboardInterrupt])
def test_fresh_member_close_failure_still_visible(members, profile, cleanup):
    source, name = members.create(profile)
    members.cleanup = cleanup('fresh member close failure')
    with source:
        with pytest.raises(cleanup) as caught:
            source.read(name)
        assert caught.value is members.cleanup
        assert_members_closed(members)
    assert_all_closed(members)


def test_other_read_exception_keeps_valueerror_cause(members):
    source, name = members.create('zip')
    members.primary = RuntimeError('after native member read')
    members.cleanup = OSError('after native member close')
    with source:
        with pytest.raises(ValueError, match='unreadable evidence member') as caught:
            source.read(name)
        assert caught.value.__cause__ is members.primary
    assert_all_closed(members)


@pytest.mark.parametrize('profile', ['standalone', 'directory', 'zip'])
def test_healthy_read_and_projection_keep_result_contract(members, profile):
    payload = b'{"owned":1}'
    source, name = members.create(profile, payload)
    with source:
        assert source.read(name) == payload
        assert source.read_json(name) == ({'owned': 1}, hashlib.sha256(payload).hexdigest())
        assert_members_closed(members, 2)
        if profile == 'zip':
            assert source.archive.fp is not None
    assert_all_closed(members)


def test_member_and_held_owner_failures_keep_original_interrupt(members):
    source, name = members.create('zip')
    members.primary = KeyboardInterrupt('after native member read')
    members.cleanup = OSError('after native member close')
    members.held_error = MemoryError('after native held input close')
    with pytest.raises(KeyboardInterrupt) as caught:
        with source:
            source.read(name)
    assert caught.value is members.primary
    assert_members_closed(members)
    assert members.closed[-1] == 'held'
    assert_all_closed(members)
