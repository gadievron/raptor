"""Detector-correctness tests for the optional-dep import lint."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_SCRIPT = (
    Path(__file__).resolve().parents[1] / "check_optional_dep_imports.py"
)

_PYPROJECT_TOML = """\
[project]
name = "test-project"
version = "0.1.0"
dependencies = [
    "requests==2.34.2",
]

[project.optional-dependencies]
llm = [
    "anthropic==0.103.1",
    "botocore==1.43.16",
    "openai==2.30.0",
]
grammars = [
    "tree-sitter==0.25.2",
    "tree-sitter-go==0.25.0",
]

[dependency-groups]
test = [
    "pytest==9.1.1",
    "beautifulsoup4==4.15.0",
    "z3-solver==4.15.4.0",
]
dev = [
    {include-group = "test"},
]
"""


@pytest.fixture(scope="module")
def det():
    spec = importlib.util.spec_from_file_location(
        "check_optional_dep_imports", _SCRIPT,
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _tree(tmp_path: Path, files: dict[str, str]) -> Path:
    (tmp_path / "pyproject.toml").write_text(_PYPROJECT_TOML)
    for rel, body in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    return tmp_path


def test_module_list_derivation(det, tmp_path):
    root = _tree(tmp_path, {})
    mods = det.optional_modules(root)
    # Commented pins, dash mapped to underscore.
    assert "anthropic" in mods
    assert "botocore" in mods
    assert "tree_sitter" in mods
    assert "tree_sitter_go" in mods
    # Actively installed by the dev dependency group: not optional.
    assert "z3" not in mods
    assert "bs4" not in mods
    # Transitively guaranteed on bare CI (instructor -> openai).
    assert "openai" not in mods
    # Actively pinned in pyproject.toml.
    assert "requests" not in mods


def test_unguarded_module_import_flagged(det, tmp_path):
    root = _tree(tmp_path, {
        "core/llm/tests/test_x.py": "import botocore.session\n",
    })
    findings, _ = det.scan(root)
    assert "core/llm/tests/test_x.py::botocore" in findings


def test_unguarded_function_level_import_flagged(det, tmp_path):
    root = _tree(tmp_path, {
        "core/llm/tests/test_x.py": (
            "def test_y(monkeypatch):\n"
            "    import botocore.session\n"
            "    assert botocore.session\n"
        ),
    })
    findings, _ = det.scan(root)
    assert "core/llm/tests/test_x.py::botocore" in findings


def test_try_except_import_error_is_guard(det, tmp_path):
    root = _tree(tmp_path, {
        "core/llm/tests/test_x.py": (
            "try:\n"
            "    import botocore  # noqa: F401\n"
            "    _HAS = True\n"
            "except ImportError:\n"
            "    _HAS = False\n"
            "\n"
            "def test_y():\n"
            "    import botocore.session\n"
            "    assert botocore.session\n"
        ),
    })
    findings, _ = det.scan(root)
    assert findings == {}


def test_importorskip_is_guard(det, tmp_path):
    root = _tree(tmp_path, {
        "core/llm/tests/test_x.py": (
            "import pytest\n"
            'pytest.importorskip("anthropic")\n'
            "import anthropic\n"
        ),
    })
    findings, _ = det.scan(root)
    assert findings == {}


def test_sys_modules_stub_is_guard(det, tmp_path):
    root = _tree(tmp_path, {
        "core/llm/tests/test_x.py": (
            "import sys\n"
            "import types\n"
            "\n"
            "def test_y(monkeypatch):\n"
            '    stub = types.ModuleType("botocore")\n'
            '    monkeypatch.setitem(sys.modules, "botocore", stub)\n'
            "    import botocore  # the stub\n"
            "    assert botocore is stub\n"
        ),
    })
    findings, _ = det.scan(root)
    assert findings == {}


def test_skipif_naming_module_is_guard(det, tmp_path):
    root = _tree(tmp_path, {
        "core/llm/tests/test_x.py": (
            "import importlib.util\n"
            "import pytest\n"
            "\n"
            "@pytest.mark.skipif(\n"
            '    importlib.util.find_spec("tree_sitter") is None,\n'
            '    reason="tree_sitter not installed",\n'
            ")\n"
            "def test_y():\n"
            "    import tree_sitter\n"
            "    assert tree_sitter\n"
        ),
    })
    findings, _ = det.scan(root)
    assert findings == {}


def test_submodule_import_maps_to_top_level(det, tmp_path):
    root = _tree(tmp_path, {
        "core/llm/tests/test_x.py": (
            "from tree_sitter_go import language\n"
            "assert language\n"
        ),
    })
    findings, _ = det.scan(root)
    assert "core/llm/tests/test_x.py::tree_sitter_go" in findings


def test_non_test_files_ignored(det, tmp_path):
    root = _tree(tmp_path, {
        "core/llm/providers.py": "import anthropic\n",
    })
    findings, _ = det.scan(root)
    assert findings == {}


def test_non_optional_import_ignored(det, tmp_path):
    root = _tree(tmp_path, {
        "core/llm/tests/test_x.py": "import requests\nimport z3\n",
    })
    findings, _ = det.scan(root)
    assert findings == {}


@pytest.mark.parametrize("statement", [
    "import ａｎｔｈｒｏｐｉｃ",
    "from ａｎｔｈｒｏｐｉｃ import Client",
    "def test_nested():\n    import anthropic",
    "class Suite:\n    import anthropic",
    "try:\n    pass\nfinally:\n    import anthropic",
    "try:\n    pass\nexcept ImportError:\n    import anthropic",
    "try:\n    pass\nexcept ImportError:\n    pass\nelse:\n    import anthropic",
])
def test_import_prescreen_retains_nested_and_unicode_imports(det, tmp_path, statement):
    root = _tree(tmp_path, {"core/tests/test_reader.py": statement + "\n"})
    findings, _ = det.scan(root)
    assert set(findings) == {"core/tests/test_reader.py::anthropic"}


def test_dotted_optional_module_with_continued_import(det, tmp_path):
    root = _tree(tmp_path, {
        "core/tests/test_reader.py": 'from google \\\n    . genai import Client\n',
    })
    project = root / "pyproject.toml"
    project.write_text(project.read_text().replace('"anthropic==0.103.1",', '"google-genai==1.0.0",'))
    findings, mods = det.scan(root)
    assert "google.genai" in mods
    assert findings == {"core/tests/test_reader.py::google.genai": 1}


def test_prescreen_reloads_optional_groups_between_scans(det, tmp_path):
    root = _tree(tmp_path, {"core/tests/test_reader.py": "import new_capability\n"})
    assert det.scan(root)[0] == {}
    project = root / "pyproject.toml"
    project.write_text(project.read_text().replace('"anthropic==0.103.1",', '"new-capability==1.0.0",'))
    findings, mods = det.scan(root)
    assert "new_capability" in mods
    assert findings == {"core/tests/test_reader.py::new_capability": 1}


def test_empty_optional_set_retains_empty_result(det, tmp_path):
    root = _tree(tmp_path, {"core/tests/test_reader.py": "import anthropic\n"})
    (root / "pyproject.toml").write_text('[project]\nname = "empty"\nversion = "0.1.0"\n')
    assert det.scan(root) == ({}, set())


@pytest.mark.parametrize("ancestor", [".out", "build", "data", "fixtures", "tests"])
def test_checkout_ancestors_do_not_change_scan_scope(det, tmp_path, ancestor):
    checkout = tmp_path / ancestor / "checkout"
    checkout.mkdir(parents=True)
    root = _tree(checkout, {
        "core/tests/test_reader.py": "import anthropic\n",
        "core/runtime_reader.py": "import botocore\n",
        "core/tests/fixtures/test_example.py": "import botocore\n",
    })
    findings, _ = det.scan(root)
    assert findings == {"core/tests/test_reader.py::anthropic": 1}


def test_discovery_keeps_root_and_lexical_order(det, tmp_path):
    files = {
        "core/z/tests/test_z.py": "import anthropic\n",
        "core/a/tests/test_a.py": "import anthropic\n",
        "packages/tests/test_pkg.py": "import anthropic\n",
        "engine/tests/test_rule.py": "import anthropic\n",
        "core/tests/build/test_generated.py": "import anthropic\n",
        "core/tests/data/test_sample.py": "import anthropic\n",
    }
    root = _tree(tmp_path, files)
    assert [p.relative_to(root).as_posix() for p in det.iter_test_files(root)] == [
        "core/a/tests/test_a.py", "core/z/tests/test_z.py",
        "packages/tests/test_pkg.py", "engine/tests/test_rule.py",
    ]


def test_discovery_preserves_file_links_without_following_directory_links(det, tmp_path):
    root = _tree(tmp_path, {
        "core/runtime_reader.py": "import anthropic\n",
        "outside/test_hidden.py": "import botocore\n",
    })
    (root / "core/test_link.py").symlink_to(root / "core/runtime_reader.py")
    (root / "core/linked_tests").symlink_to(root / "outside", target_is_directory=True)
    findings, _ = det.scan(root)
    assert findings == {"core/test_link.py::anthropic": 1}
