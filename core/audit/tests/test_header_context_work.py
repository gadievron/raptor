"""Header lookup bounds work and carries the analysed root into reads."""

import pytest

from core.audit import context


@pytest.fixture(autouse=True)
def owned_caches(monkeypatch):
    monkeypatch.setattr(context, '_header_cache', context.BoundedMemo(16))
    monkeypatch.setattr(context, '_type_definition_cache', context.BoundedMemo(64))


@pytest.mark.parametrize('cap', [0, -1])
def test_zero_type_budget_does_not_discover_headers(tmp_path, monkeypatch, cap):
    def unexpected(*args):
        raise AssertionError('header discovery ran with no type budget')

    monkeypatch.setattr(context, '_find_headers', unexpected)
    assert context._resolve_types(tmp_path, 'f.c', {}, 'struct Widget *w;', cap) == []


def test_type_header_read_receives_its_analysed_root(tmp_path, monkeypatch):
    (tmp_path / 'f.c').write_text('struct Widget *w;\n')
    (tmp_path / 'types.h').write_text('struct Widget { int field; };\n')
    read = context._read_target_text
    roots = []

    def checked(path, *, target_root=None):
        roots.append(target_root)
        assert target_root == tmp_path
        return read(path, target_root=target_root)

    monkeypatch.setattr(context, '_read_target_text', checked)
    result = context._resolve_types(tmp_path, 'f.c', {}, 'struct Widget *w;')
    assert [r['name'] for r in result] == ['Widget']
    assert roots and all(root == tmp_path for root in roots)


def test_rooted_read_refuses_paths_outside_the_analysed_root(tmp_path):
    root = tmp_path / 'repo'
    root.mkdir()
    outside = tmp_path / 'outside.h'
    outside.write_text('owned fixture outside the analysed root\n')
    assert context._read_target_text(outside, target_root=root) is None


def test_rooted_read_preserves_decoding_and_byte_cap(tmp_path, monkeypatch, caplog):
    file = tmp_path / 'types.h'
    file.write_bytes(b'header \xff\n')
    assert context._read_target_text(file, target_root=tmp_path) == 'header \ufffd\n'
    monkeypatch.setattr(context, '_MAX_SOURCE_FILE_BYTES', 8)
    file.write_bytes(b'x' * 9)
    assert context._read_target_text(file, target_root=tmp_path) is None
    assert 'cap, skipping' in caplog.text


def test_rooted_read_accepts_contained_links(tmp_path):
    real = tmp_path / 'real.h'
    real.write_text('struct Widget { int field; };\n')
    link = tmp_path / 'alias.h'
    link.symlink_to(real)
    assert context._read_target_text(link, target_root=tmp_path) == real.read_text()


def test_local_header_selection_keeps_lexical_order_and_total_cap(tmp_path):
    (tmp_path / 'f.c').write_text('struct Widget *w;\n')
    for i in reversed(range(120)):
        (tmp_path / f'{i:03d}.h').write_text('')
    headers = context._find_headers(tmp_path, 'f.c')
    assert [p.name for p in headers] == [f'{i:03d}.h' for i in range(50)]
    assert len(set(headers)) == len(headers)


def test_local_twenty_name_prefix_is_selected_before_admission(tmp_path, monkeypatch):
    (tmp_path / 'f.c').write_text('')
    for i in range(40):
        (tmp_path / f'{i:03d}.h').write_text('')
    context._header_cache.get_or_compute(str(tmp_path), lambda: [])
    monkeypatch.setattr(context, '_admissible_header', lambda root, path: path.name >= '010.h')
    headers = context._find_headers(tmp_path, 'f.c')
    assert [p.name for p in headers] == [f'{i:03d}.h' for i in range(10, 20)]
