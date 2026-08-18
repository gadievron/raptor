"""Detector-correctness tests for the optional-dep import lint."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_SCRIPT = (
    Path(__file__).resolve().parents[1] / "check_optional_dep_imports.py"
)

_REQUIREMENTS = """\
requests==2.34.2
# anthropic==0.103.1
# botocore==1.43.16
# tree-sitter==0.25.2
# tree-sitter-go==0.25.0
# z3-solver==4.15.4.0
# openai==2.30.0
# beautifulsoup4==4.15.0
"""

_REQUIREMENTS_DEV = """\
-r requirements.txt
pytest==9.1.1
beautifulsoup4==4.15.0
z3-solver==4.15.4.0
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
    (tmp_path / "requirements.txt").write_text(_REQUIREMENTS)
    (tmp_path / "requirements-dev.txt").write_text(_REQUIREMENTS_DEV)
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
    # Actively installed by requirements-dev.txt: not optional.
    assert "z3" not in mods
    assert "bs4" not in mods
    # Transitively guaranteed on bare CI (instructor -> openai).
    assert "openai" not in mods
    # Actively pinned in requirements.txt itself.
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
