"""Resource dispatch reuses one file's AST without caching the source forest."""

import ast
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

with patch.object(sys, "path", sys.path.copy()):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
    import codeql_scope as graph
    import test_scope as scope


def _write(repo, name, source):
    path = repo / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source)
    return Path(name)


def test_graph_observer_shares_exact_tree_and_preserves_failure_counts(tmp_path, monkeypatch):
    files = [
        _write(tmp_path, "core/value.py", "VALUE = 1\n"),
        _write(tmp_path, "core/tests/test_value.py",
               'import core.value\nSCRIPT = "libexec/raptor-demo"\n'),
        _write(tmp_path, "core/broken.py", "def broken(:\n"),
        Path("core/missing.py"),
    ]
    expected = graph.build_graph(files, tmp_path)
    observed = {}
    extracted = {}
    original = graph.extract_imports

    def observer(path, source, tree):
        assert path not in observed
        assert source == (tmp_path / path).read_text()
        observed[path] = (tree, ast.dump(tree, include_attributes=True))

    def record_extract(path, *args, **kwargs):
        extracted[path] = kwargs["source_tree"]
        return original(path, *args, **kwargs)

    monkeypatch.setattr(graph, "extract_imports", record_extract)
    borrowed = set()
    references = {"libexec/raptor-demo": borrowed}
    assert graph.build_graph(files, tmp_path, on_parsed=observer,
                             literal_references=references) == expected
    assert expected[1] == 2
    assert set(observed) == set(files[:2]) == set(extracted)
    for path, (tree, before) in observed.items():
        assert extracted[path] is tree
        assert ast.dump(tree, include_attributes=True) == before
    assert references == {"libexec/raptor-demo": {files[1]}}
    assert references["libexec/raptor-demo"] is borrowed


@pytest.mark.parametrize("error_type", [RuntimeError, KeyboardInterrupt, OSError, SyntaxError, ValueError])
def test_observer_failures_propagate_without_poisoning_next_graph(tmp_path, error_type):
    files = [_write(tmp_path, "core/value.py", "VALUE = 1\n")]
    calls = []

    def fail(path, source, tree):
        calls.append(path)
        raise error_type("observer failed")

    with pytest.raises(error_type, match="observer failed"):
        graph.build_graph(files, tmp_path, on_parsed=fail)
    assert calls == files
    assert graph.build_graph(files, tmp_path) == ({}, 0)


@pytest.mark.parametrize("source", [
    'DATA = Path(__file__).parent / "fixtures" / "nested"\n',
    'FIXTURE = Path(__file__).parent / "fixt\\x75res" / "nested"\n',
    'def read():\n    return consume(Path(__file__).parent / "data")\n',
    'description = "fixtures and data without a division chain"\n',
], ids=["nested", "escaped-name", "nested-scope", "sibling-fallback"])
def test_fixture_extraction_reuses_source_and_read_only_tree(tmp_path, source, monkeypatch):
    path = _write(tmp_path, "core/pkg/tests/test_data.py", source)
    for directory in ["fixtures/nested", "data"]:
        (tmp_path / path.parent / directory).mkdir(parents=True)
    expected = scope._extract_fixture_dirs(path, tmp_path)
    tree = ast.parse(source)
    before = ast.dump(tree, include_attributes=True)

    def unexpected_parse(*args, **kwargs):
        pytest.fail("supplied fixture tree must not be parsed again")

    monkeypatch.setattr(scope, "ast", SimpleNamespace(**(vars(ast) | {"parse": unexpected_parse})))
    # Removing the source also proves that the supplied source/tree need no read.
    (tmp_path / path).unlink()
    assert set(scope._extract_fixture_dirs(path, tmp_path, source=source,
                                          source_tree=tree)) == set(expected)
    assert ast.dump(tree, include_attributes=True) == before


@pytest.mark.parametrize("extra", [None, "core/pkg/value.py", "libexec/raptor-demo"])
def test_resource_dispatch_preserves_results_and_bounded_parses(tmp_path, monkeypatch, extra):
    value = _write(tmp_path, "core/pkg/value.py", "VALUE = 1\n")
    first = _write(tmp_path, "core/pkg/tests/test_first.py",
                   'import core.pkg.value\nDATA = Path(__file__).parent / "fixtures"\n'
                   'SCRIPT = "libexec/raptor-demo"\n')
    second = _write(tmp_path, "core/pkg/tests/test_second.py",
                    'import core.pkg.tests.test_first\nDATA = "fixtures"\n')
    broken = _write(tmp_path, "core/pkg/tests/test_broken.py", 'DATA = "fixtures"\ndef broken(:\n')
    resource = _write(tmp_path, "core/pkg/tests/fixtures/input.json", "{}")
    changed = [str(resource), *([extra] if extra else [])]
    counts = {}
    parse = ast.parse

    def record_parse(source, *args, **kwargs):
        filename = kwargs.get("filename", "<unknown>")
        counts[filename] = counts.get(filename, 0) + 1
        return parse(source, *args, **kwargs)

    view = SimpleNamespace(**(vars(ast) | {"parse": record_parse}))
    monkeypatch.setattr(graph, "ast", view)
    monkeypatch.setattr(scope, "ast", view)
    result = scope.compute_tier_dispatch(changed, tmp_path)
    assert not result.get("_scope", {}).get("full", False)
    assert set(result["python"]["files"]) == {first, second}
    # The scripted mixed lane retains its separate reference/census path.
    expected = {str(value): 1, str(first): 1, str(second): 1, str(broken): 1}
    if extra and extra.startswith("libexec/"):
        expected.update({str(first): 2, str(second): 2, str(broken): 2})
    assert counts == expected
    assert not any(row["run"] for name, row in result.items()
                   if not name.startswith("_") and name not in {"python", "redos_census", "ci_lint"})


def test_fixture_directory_results_are_optional_partial_and_refreshed(tmp_path):
    first = _write(tmp_path, "core/pkg/tests/test_first.py", 'DATA = "fixtures"\n')
    second = _write(tmp_path, "core/pkg/tests/test_second.py", 'DATA = "fixtures"\n')
    resource = _write(tmp_path, "core/pkg/tests/fixtures/input.json", "{}")
    directory = tmp_path / resource.parent
    borrowed = [directory]
    cached = {first: borrowed}
    assert scope.build_data_file_map([first, second], tmp_path, fixture_dirs_by_test=cached) == {
        resource: {first, second},
    }
    assert cached == {first: [directory]}
    assert cached[first] is borrowed
    (tmp_path / resource).unlink()
    replacement = _write(tmp_path, "core/pkg/tests/fixtures/new.json", "{}")
    assert scope.build_data_file_map([first, second], tmp_path, fixture_dirs_by_test=cached) == {
        replacement: {first, second},
    }
