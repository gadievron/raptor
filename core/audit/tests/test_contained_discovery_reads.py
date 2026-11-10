"""Discovery source acquisition retains the audit target boundary."""

import pytest

from core.audit import context, discovery


def test_function_reader_carries_root(tmp_path, monkeypatch):
    path = tmp_path / 'source.c'
    path.write_text('void f(void) {\n  handle();\n}\n')
    actual = context._read_target_text
    calls = []

    def read(candidate, *, target_root=None):
        assert target_root == tmp_path
        calls.append(candidate)
        return actual(candidate, target_root=target_root)

    monkeypatch.setattr(context, '_read_target_text', read)
    info = {'file': 'source.c', 'name': 'f', 'line_start': 1, 'line_end': 3}
    assert 'handle' in discovery._read_function_source(tmp_path, info, 1000)
    assert calls == [path]


def _read(kind, root, path):
    info = {'file': str(path), 'name': 'f', 'line_start': 1, 'line_end': 3}
    if kind == 'function':
        return discovery._read_function_source(root, info, 1000)
    if kind == 'call-site':
        return discovery._extract_call_site_snippet(path, 'commit', 1, 3, target_root=root)
    if kind == 'handler':
        return discovery._read_handler_context(path, 2, target_root=root)
    if kind == 'effect':
        return discovery._detect_side_effects('source.py:f', info, root)
    raise AssertionError(kind)


# Real fixture paths exercise the existing rooted opener, rather than a
# permissive checker double that can accidentally bypass source admission.
@pytest.mark.parametrize('kind', ['function', 'call-site', 'handler', 'effect'])
@pytest.mark.parametrize('admitted', [True, False], ids=['in-root', 'outside-root'])
def test_discovery_readers_honor_target_root(tmp_path, kind, admitted):
    root = tmp_path / 'root'
    root.mkdir()
    path = (root if admitted else tmp_path) / 'source.py'
    path.write_text('def f():\n    db.session.commit()\n    return True\n')
    result = _read(kind, root, path)
    if admitted:
        assert result
        if kind != 'effect':
            assert 'commit' in result
    else:
        assert result in (None, '', [])


@pytest.mark.parametrize('kind', ['function', 'call-site', 'handler', 'effect'])
def test_discovery_preserves_whole_file_cap(tmp_path, monkeypatch, kind):
    path = tmp_path / 'source.py'
    path.write_text('def f():\n    db.session.commit()\n    return True\n' + '# tail\n' * 100)
    monkeypatch.setattr(context, '_MAX_SOURCE_FILE_BYTES', 48)
    assert _read(kind, tmp_path, path) in (None, '', [])
