"""Native source-order reuse retains resolution and foreign comparisons."""

from pathlib import Path

from core.concepts import lang_resolve as mod


def run(tmp_path, monkeypatch, *, foreign=False):
    text = 'first = 1\nsecond = 2\nthird = 3\n'
    paths = [tmp_path / 'b.py', tmp_path / 'a.py']
    for path in paths:
        path.write_text(text, encoding='utf-8')
    if foreign:
        class ForeignPath(type(Path())):
            pass
        paths = [ForeignPath(path) for path in paths]
    counts = []

    def observed(iterable, *args, **kwargs):
        counts.append(None)
        return sorted(iterable, *args, **kwargs)

    monkeypatch.setattr(mod, 'sorted', observed, raising=False)
    monkeypatch.setattr(mod, '_SORT_CONTENTS_IMPL', observed)
    result = mod.resolve_identifiers(tmp_path, ['first', 'second', 'third'], files=paths)
    return result, len(counts)


def test_native_resolution_reuses_one_ordered_snapshot(tmp_path, monkeypatch):
    result, sorts = run(tmp_path, monkeypatch)
    assert sorts == 1
    assert [(item.name, item.file) for item in result.items] == [
        ('first', 'a.py'), ('second', 'a.py'), ('third', 'a.py'),
    ]
    assert result.unresolved == []


def test_foreign_paths_keep_repeated_sorting(tmp_path, monkeypatch):
    result, sorts = run(tmp_path, monkeypatch, foreign=True)
    assert sorts > 1
    assert [(item.name, item.file) for item in result.items] == [
        ('first', 'a.py'), ('second', 'a.py'), ('third', 'a.py'),
    ]
    assert result.unresolved == []


def test_replaced_sorter_retains_each_fallback_order(tmp_path, monkeypatch):
    paths = [tmp_path / 'a.py', tmp_path / 'b.py']
    for path in paths:
        path.write_text('first = 1\nsecond = 2\nthird = 3\n', encoding='utf-8')
    calls = []

    def changing_order(items):
        calls.append(None)
        return sorted(items, reverse=len(calls) > 1)

    monkeypatch.setattr(mod, 'sorted', changing_order, raising=False)
    result = mod.resolve_identifiers(tmp_path, ['first', 'second', 'third'], files=paths)
    assert len(calls) > 1
    assert [(item.name, item.file) for item in result.items] == [
        ('first', 'b.py'), ('second', 'b.py'), ('third', 'b.py'),
    ]
