"""Fixed owned sourceless modules qualify visible import-origin refusals."""
import importlib.machinery
import importlib.util
import py_compile
import sys
from pathlib import Path

import pytest

from core.dataflow.sanitizer_catalog import repo_shadows_module_root
from core.dataflow.source_identity import known_python_origin_conflict


@pytest.mark.parametrize('shadow', [
    'html.pyc', 'html/__init__.pyc', 'app/html.pyc', 'app/html/__init__.pyc',
], ids=['root-module', 'root-package', 'script-module', 'script-package'])
def test_selected_owned_sourceless_origin_requires_refusal(tmp_path: Path, shadow):
    subject = tmp_path / 'app/handler.py'
    subject.parent.mkdir()
    subject.write_text('import html\n')
    bytecode = tmp_path / shadow
    bytecode.parent.mkdir(parents=True, exist_ok=True)
    source = bytecode.with_suffix('.py')
    source.write_text('def escape(value):\n    return value\n')
    py_compile.compile(str(source), cfile=str(bytecode), doraise=True)
    source.unlink()
    search_directory = bytecode.parent if bytecode.name != '__init__.pyc' else bytecode.parent.parent
    try:
        spec = importlib.machinery.PathFinder.find_spec('html', [str(search_directory)])
        assert spec is not None
        assert isinstance(spec.loader, importlib.machinery.SourcelessFileLoader)
        assert Path(spec.origin).resolve() == bytecode.resolve()
        owned_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(owned_module)
        assert owned_module.escape('<owned>') == '<owned>'
    finally:
        sys.path_importer_cache.pop(str(search_directory), None)
    assert repo_shadows_module_root(str(search_directory), 'html')
    assert known_python_origin_conflict(tmp_path, subject, 'html')


@pytest.mark.parametrize('shadow', ['html.py', 'html/__init__.py'])
def test_source_module_shadow_refusal_remains(tmp_path: Path, shadow):
    path = tmp_path / shadow
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('def escape(value):\n    return value\n')
    assert repo_shadows_module_root(str(tmp_path), 'html')
    assert known_python_origin_conflict(tmp_path, tmp_path / 'app.py', 'html')


def test_cache_only_bytecode_does_not_become_a_legacy_module(tmp_path: Path):
    source = tmp_path / 'html.py'
    source.write_text('def escape(value):\n    return value\n')
    cached = Path(py_compile.compile(str(source), doraise=True))
    source.unlink()
    assert cached.is_file() and cached.parent.name == '__pycache__'
    try:
        assert importlib.machinery.PathFinder.find_spec('html', [str(tmp_path)]) is None
    finally:
        sys.path_importer_cache.pop(str(tmp_path), None)
    assert not repo_shadows_module_root(str(tmp_path), 'html')
    assert known_python_origin_conflict(tmp_path, tmp_path / 'app.py', 'html') is None


@pytest.mark.parametrize('shadow', ['html.pyc', 'html/__init__.pyc'])
def test_bytecode_named_directories_are_not_module_files(tmp_path: Path, shadow):
    (tmp_path / shadow).mkdir(parents=True)
    assert not repo_shadows_module_root(str(tmp_path), 'html')
    assert known_python_origin_conflict(tmp_path, tmp_path / 'app.py', 'html') is None


def test_unrelated_sourceless_names_and_directories_do_not_shadow(tmp_path: Path):
    (tmp_path / 'other.pyc').write_bytes(b'owned-non-module-control')
    sibling = tmp_path / 'unrelated/html.pyc'
    sibling.parent.mkdir()
    sibling.write_bytes(b'owned-outside-search-control')
    assert not repo_shadows_module_root(str(tmp_path), 'html')
    assert known_python_origin_conflict(tmp_path, tmp_path / 'app/handler.py', 'html') is None


@pytest.mark.parametrize('root', ['', '../html', 'html.escape'])
def test_malformed_root_refusal_remains(tmp_path: Path, root):
    assert repo_shadows_module_root(str(tmp_path), root)
