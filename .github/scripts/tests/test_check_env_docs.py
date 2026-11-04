"""Detector-correctness tests for the env-var documentation guard."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "check_env_docs.py"


@pytest.fixture(scope="module")
def det():
    spec = importlib.util.spec_from_file_location("check_env_docs", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _tree(tmp_path: Path, files: dict[str, str]) -> Path:
    for rel, body in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
        if not p.suffix:
            p.chmod(0o755)
    return tmp_path


def _kinds(inv, name):
    return sorted({o.kind for o in inv.vars.get(name, [])})


def test_broker_json_credentials_are_inventoried(det, tmp_path):
    root = _tree(tmp_path, {"core/llm/model_brokers/registry.json": (
        '// self-documenting registry\n'
        '{"version":1,"brokers":[{"name":"examplebroker"}]} # inline comment\n'
    )})
    inv = det.scan_tree(root)
    name = "EXAMPLEBROKER_API_KEY"
    assert _kinds(inv, name) == ["declared:LLM_API_KEY_VARS", "read"]
    assert det.classify(name, inv.vars[name]) == "external-standard"


def test_broker_cannot_claim_python_env_variable(det, tmp_path):
    root = _tree(tmp_path, {
        "core/llm/model_brokers/registry.json": '{"version":1,"brokers":[{"name":"example"}]}',
        "core/other.py": 'import os\nx = os.environ.get("EXAMPLE_API_KEY")\n',
    })
    with pytest.raises(ValueError, match="conflicts with Python-owned environment variable"):
        det.scan_tree(root)


def test_api_token_broker_is_inventoried(det, tmp_path):
    root = _tree(tmp_path, {"core/llm/model_brokers/registry.json": (
        '{"version":1,"brokers":[{"name":"example","auth_scheme":"Bearer",'
        '"credential_suffix":"API_TOKEN"}]}'
    )})
    inv = det.scan_tree(root)
    assert _kinds(inv, "EXAMPLE_API_TOKEN") == ["declared:LLM_API_KEY_VARS", "read"]
    assert "EXAMPLE_API_KEY" not in inv.vars


@pytest.mark.parametrize("suffix", ["API_KEY", "API_TOKEN"])
@pytest.mark.parametrize("has_convention", [True, False])
def test_broker_docs_convention_covers_only_registry_credentials(
    det, tmp_path, capsys, monkeypatch, suffix, has_convention,
):
    convention = "`<UPPERCASE_NAME>_<credential_suffix>`" if has_convention else "No naming convention."
    root = _tree(tmp_path, {
        "docs/environment.md": f"# Environment variables\n\nModel brokers use {convention}.\n",
        "core/llm/model_brokers/registry.json": (
            '{"version":1,"brokers":[{"name":"examplebroker",'
            f'"credential_suffix":"{suffix}"' + '}]}'
        ),
        "core/plumbing.py": 'child_env = {}\nchild_env["UNRELATED_API_KEY"] = "value"\n',
    })
    monkeypatch.setattr(sys, "argv", ["check_env_docs.py", "--root", str(root),
                                     "--baseline", str(tmp_path / "missing-baseline.json")])
    assert det.main() == 0
    output = capsys.readouterr().out
    broker_warning = f"undocumented external-standard variable: EXAMPLEBROKER_{suffix}"
    assert (broker_warning in output) is not has_convention
    assert "undocumented internal variable: UNRELATED_API_KEY" in output


class TestPythonExtraction:
    def test_direct_environ_forms(self, det, tmp_path):
        root = _tree(tmp_path, {"core/a.py": (
            "import os\n"
            "a = os.environ['RAPTOR_A']\n"
            "b = os.environ.get('RAPTOR_B', '1')\n"
            "os.environ['RAPTOR_C'] = 'x'\n"
            "os.environ.setdefault('RAPTOR_D', 'y')\n"
            "os.environ.pop('RAPTOR_E', None)\n"
            "del os.environ['RAPTOR_F']\n"
            "g = os.getenv('RAPTOR_G')\n"
        )})
        inv = det.scan_tree(root)
        assert _kinds(inv, "RAPTOR_A") == ["read"]
        assert _kinds(inv, "RAPTOR_B") == ["read"]
        assert _kinds(inv, "RAPTOR_C") == ["write"]
        assert _kinds(inv, "RAPTOR_D") == ["write"]
        assert _kinds(inv, "RAPTOR_E") == ["delete"]
        assert _kinds(inv, "RAPTOR_F") == ["delete"]
        assert _kinds(inv, "RAPTOR_G") == ["read"]

    def test_aliased_os_import(self, det, tmp_path):
        root = _tree(tmp_path, {"core/a.py": (
            "import os as _os\n"
            "flag = _os.environ.get('RAPTOR_ALIASED')\n"
        )})
        inv = det.scan_tree(root)
        assert _kinds(inv, "RAPTOR_ALIASED") == ["read"]

    def test_constant_key_resolution(self, det, tmp_path):
        root = _tree(tmp_path, {"core/a.py": (
            "import os\n"
            "MODE_ENV = 'RAPTOR_VIA_CONST'\n"
            "on = os.environ.get(MODE_ENV) == '1'\n"
        )})
        inv = det.scan_tree(root)
        assert _kinds(inv, "RAPTOR_VIA_CONST") == ["read"]

    def test_cross_module_env_constant(self, det, tmp_path):
        root = _tree(tmp_path, {
            "core/defs.py": "_ENV_MODE = 'RAPTOR_XMOD'\n",
            "core/use.py": (
                "import os\nfrom core.defs import _ENV_MODE\n"
                "on = os.environ.get(_ENV_MODE)\n"
            ),
        })
        inv = det.scan_tree(root)
        assert _kinds(inv, "RAPTOR_XMOD") == ["read"]

    def test_child_env_dict_write(self, det, tmp_path):
        root = _tree(tmp_path, {"core/a.py": (
            "import os\n"
            "env = dict(os.environ)\n"
            "env['RAPTOR_CHILD'] = 'x'\n"
            "other = {}\n"
            "other['NOT_ENV_KEY'] = 'x'\n"
        )})
        inv = det.scan_tree(root)
        assert _kinds(inv, "RAPTOR_CHILD") == ["child-write"]
        assert "NOT_ENV_KEY" not in inv.vars

    def test_env_flag_call_is_a_read(self, det, tmp_path):
        """``core.config.env_flag(name, default)`` wraps
        os.environ.get — the call site is the read (bare and
        attribute forms, and NAME-constant keys)."""
        root = _tree(tmp_path, {"core/a.py": (
            "from core.config import env_flag\n"
            "import core.config\n"
            "_C_ENV = 'RAPTOR_EF_CONST'\n"
            "a = env_flag('RAPTOR_EF_BARE', default=False)\n"
            "b = core.config.env_flag('RAPTOR_EF_ATTR', default=True)\n"
            "c = env_flag(_C_ENV, default=True)\n"
        )})
        inv = det.scan_tree(root)
        assert _kinds(inv, "RAPTOR_EF_BARE") == ["read"]
        assert _kinds(inv, "RAPTOR_EF_ATTR") == ["read"]
        assert "read" in _kinds(inv, "RAPTOR_EF_CONST")

    def test_monkeypatch_recorded_separately(self, det, tmp_path):
        root = _tree(tmp_path, {"core/tests/test_a.py": (
            "def test_x(monkeypatch):\n"
            "    monkeypatch.setenv('RAPTOR_MP_ONLY', '1')\n"
        )})
        inv = det.scan_tree(root)
        assert _kinds(inv, "RAPTOR_MP_ONLY") == ["monkeypatch"]

    def test_env_helper_call_is_a_read(self, det, tmp_path):
        """``_env_int('VAR', default)``-convention wrappers hide the
        os.environ.get key behind an opaque parameter — the call
        site is the read. Only ALL-CAPS first arguments register, so
        a helper matching the name shape over a non-env string stays
        invisible."""
        root = _tree(tmp_path, {"core/a.py": (
            "import os\n"
            "def _env_int(name, default):\n"
            "    return int(os.environ.get(name) or default)\n"
            "def _env_prefix(s):\n"
            "    return s + '_'\n"
            "_CONST_KEY = 'RAPTOR_HELPER_CONST'\n"
            "cap = _env_int('RAPTOR_HELPER_CAP', 10)\n"
            "srv = server._env_float('RAPTOR_HELPER_USD', 0.25)\n"
            "cst = _env_int(_CONST_KEY, 7)\n"
            "noise = _env_prefix('lowercase_key')\n"
        )})
        inv = det.scan_tree(root)
        assert _kinds(inv, "RAPTOR_HELPER_CAP") == ["read"]
        assert _kinds(inv, "RAPTOR_HELPER_USD") == ["read"]
        assert "read" in _kinds(inv, "RAPTOR_HELPER_CONST")
        assert "lowercase_key" not in inv.vars


class TestBashExtraction:
    def test_read_export_and_locals(self, det, tmp_path):
        root = _tree(tmp_path, {"libexec/raptor-x": (
            "#!/usr/bin/env bash\n"
            "export RAPTOR_EXPORTED=1\n"
            'LOCAL_ONLY="$(pwd)"\n'
            'echo "$LOCAL_ONLY" "$RAPTOR_READ_ONLY"\n'
            'KNOB="${KNOB:-default}"\n'
            'echo "$KNOB"\n'
        )})
        inv = det.scan_tree(root)
        assert "export" in _kinds(inv, "RAPTOR_EXPORTED")
        assert _kinds(inv, "RAPTOR_READ_ONLY") == ["bash-read"]
        assert _kinds(inv, "KNOB") == ["bash-read"]
        assert "LOCAL_ONLY" not in inv.vars

    def test_plain_local_with_brace_use_not_env(self, det, tmp_path):
        # ``${NAME##*.}`` on a local var is string surgery, not an
        # environment read (the FILE_PATH-in-hook false positive).
        root = _tree(tmp_path, {"libexec/raptor-y": (
            "#!/bin/bash\n"
            "FILE_LOCAL=$(cat)\n"
            'ext="${FILE_LOCAL##*.}"\n'
            '[ -n "${FILE_LOCAL:-}" ] && echo ok\n'
        )})
        inv = det.scan_tree(root)
        assert "FILE_LOCAL" not in inv.vars

    def test_chained_env_prefix_assignments(self, det, tmp_path):
        """``A=1 B=1 cmd`` records a child-write for EVERY prefix
        assignment — the first match's trailing context must not
        consume the second assignment's leading whitespace (which
        left B read-only in the inventory and misclassified pure
        child plumbing as an operator knob)."""
        root = _tree(tmp_path, {
            "libexec/raptor-setup": (
                "#!/bin/bash\n"
                'cat payload | RAPTOR_FIRST=1 RAPTOR_SECOND=1 '
                '$timeout_cmd "$W"\n'
            ),
            "libexec/raptor-consumer": (
                "#!/bin/bash\n"
                'if [ "${RAPTOR_SECOND:-}" = "1" ]; then exit 0; fi\n'
            ),
        })
        inv = det.scan_tree(root)
        assert "child-write" in _kinds(inv, "RAPTOR_FIRST")
        assert "child-write" in _kinds(inv, "RAPTOR_SECOND")
        # Set by one script, read by another → internal plumbing.
        assert det.classify(
            "RAPTOR_SECOND", inv.vars["RAPTOR_SECOND"],
        ) == "internal"

    def test_python_shebang_not_scanned_as_bash(self, det, tmp_path):
        root = _tree(tmp_path, {"libexec/raptor-z": (
            "#!/usr/bin/env python3\n"
            "import os\n"
            "x = os.environ.get('RAPTOR_PY_SHIM')\n"
        )})
        inv = det.scan_tree(root)
        assert _kinds(inv, "RAPTOR_PY_SHIM") == ["read"]


class TestClassification:
    def _classify(self, det, root, name):
        inv = det.scan_tree(root)
        return det.classify(name, inv.vars[name])

    def test_prod_read_only_is_operator(self, det, tmp_path):
        root = _tree(tmp_path, {"core/a.py": (
            "import os\nx = os.environ.get('RAPTOR_NEW_KNOB')\n"
        )})
        assert self._classify(det, root, "RAPTOR_NEW_KNOB") == "operator"

    def test_test_only_paths(self, det, tmp_path):
        root = _tree(tmp_path, {"core/tests/test_a.py": (
            "import os\nx = os.environ.get('RAPTOR_TEST_KNOB')\n"
        )})
        assert self._classify(det, root, "RAPTOR_TEST_KNOB") == "test-only"

    def test_written_and_read_is_internal(self, det, tmp_path):
        root = _tree(tmp_path, {"core/a.py": (
            "import os\n"
            "os.environ['RAPTOR_PLUMB'] = 'x'\n"
            "y = os.environ.get('RAPTOR_PLUMB')\n"
        )})
        assert self._classify(det, root, "RAPTOR_PLUMB") == "internal"

    def test_monkeypatch_only_is_test_only(self, det, tmp_path):
        """A name whose only occurrences are monkeypatch calls is
        test scaffolding, not a declared policy entry."""
        root = _tree(tmp_path, {"core/tests/test_a.py": (
            "def test_x(monkeypatch):\n"
            "    monkeypatch.setenv('RAPTOR_MP_CLASS', '1')\n"
        )})
        assert self._classify(det, root, "RAPTOR_MP_CLASS") == "test-only"

    def test_source_package_named_build_is_scanned(self, det, tmp_path):
        """``core/build`` is a tracked source package (it carries
        ``__init__.py``) — the artifact-dir skip must not prune it.
        A plain ``build/`` output tree without the package marker
        stays skipped."""
        root = _tree(tmp_path, {
            "core/build/__init__.py": "",
            "core/build/probe.py": (
                "import os\n"
                "t = os.environ.get('RAPTOR_BUILD_PKG_KNOB')\n"
            ),
            "core/x/build/gen.py": (
                "import os\n"
                "t = os.environ.get('RAPTOR_BUILD_ARTIFACT')\n"
            ),
        })
        inv = det.scan_tree(root)
        assert _kinds(inv, "RAPTOR_BUILD_PKG_KNOB") == ["read"]
        assert "RAPTOR_BUILD_ARTIFACT" not in inv.vars

    def test_external_standard_names(self, det, tmp_path):
        root = _tree(tmp_path, {"core/a.py": (
            "import os\n"
            "p = os.environ.get('HTTP_PROXY')\n"
            "r = os.environ.get('AWS_REGION')\n"
        )})
        assert self._classify(det, root, "HTTP_PROXY") == \
            "external-standard"
        assert self._classify(det, root, "AWS_REGION") == \
            "external-standard"


class TestDocsComparison:
    def _run(self, det, root, argv):
        import sys
        from unittest import mock
        with mock.patch.object(sys, "argv", ["check_env_docs.py"] + argv):
            return det.main()

    def test_undocumented_operator_var_fails(self, det, tmp_path,
                                             capsys):
        root = _tree(tmp_path, {
            "core/a.py": (
                "import os\nx = os.environ.get('RAPTOR_UNDOC')\n"
            ),
            "docs/environment.md": "# Environment\n",
        })
        baseline = tmp_path / "bl.json"
        baseline.write_text("{}")
        rc = self._run(det, root, ["--root", str(root),
                                   "--baseline", str(baseline)])
        assert rc == 1
        assert "RAPTOR_UNDOC" in capsys.readouterr().out

    def test_documented_var_passes(self, det, tmp_path):
        root = _tree(tmp_path, {
            "core/a.py": (
                "import os\nx = os.environ.get('RAPTOR_DOC')\n"
            ),
            "docs/environment.md": (
                "| Variable | Purpose |\n|---|---|\n"
                "| `RAPTOR_DOC` | a knob |\n"
            ),
        })
        baseline = tmp_path / "bl.json"
        baseline.write_text("{}")
        rc = self._run(det, root, ["--root", str(root),
                                   "--baseline", str(baseline)])
        assert rc == 0

    def test_stale_doc_entry_fails(self, det, tmp_path, capsys):
        root = _tree(tmp_path, {
            "core/a.py": "import os\n",
            "docs/environment.md": (
                "| Variable | Purpose |\n|---|---|\n"
                "| `RAPTOR_GONE` | vanished knob |\n"
            ),
        })
        baseline = tmp_path / "bl.json"
        baseline.write_text("{}")
        rc = self._run(det, root, ["--root", str(root),
                                   "--baseline", str(baseline)])
        assert rc == 1
        assert "RAPTOR_GONE" in capsys.readouterr().out

    def test_baselined_var_warns_not_fails(self, det, tmp_path, capsys):
        root = _tree(tmp_path, {
            "core/a.py": (
                "import os\nx = os.environ.get('RAPTOR_BASE')\n"
            ),
            "docs/environment.md": "# Environment\n",
        })
        baseline = tmp_path / "bl.json"
        baseline.write_text(
            '{"RAPTOR_BASE": {"note": "documented next sprint"}}'
        )
        rc = self._run(det, root, ["--root", str(root),
                                   "--baseline", str(baseline)])
        assert rc == 0
        assert "RAPTOR_BASE" in capsys.readouterr().out

    def test_heading_style_doc_counts(self, det, tmp_path):
        root = _tree(tmp_path, {
            "core/a.py": (
                "import os\nx = os.environ.get('RAPTOR_HEAD')\n"
            ),
            "docs/environment.md": "### `RAPTOR_HEAD`\n\nA knob.\n",
        })
        baseline = tmp_path / "bl.json"
        baseline.write_text("{}")
        rc = self._run(det, root, ["--root", str(root),
                                   "--baseline", str(baseline)])
        assert rc == 0

    @pytest.mark.slow
    def test_repo_tree_is_clean(self, det):
        """The checked-in tree itself must pass (docs complete).

        Full-tree scan (~30s) — genuine I/O over the whole checkout, so
        it rides the nightly tier. The default-tier signal is the
        detector script itself, which the miswiring-scan workflow runs
        directly against the repo.
        """
        rc = self._run(det, None, [])
        assert rc == 0


def test_container_runtime_environment_consumer_is_inventoried(det, tmp_path):
    root = _tree(tmp_path, {
        ".devcontainer/use-system-node.py": (
            "import os\n"
            "node = os.environ.get('PLAYWRIGHT_NODEJS_PATH')\n"
        ),
        "docs/environment.md": "### `PLAYWRIGHT_NODEJS_PATH`\n",
    })
    inventory = det.scan_tree(root)
    assert _kinds(inventory, "PLAYWRIGHT_NODEJS_PATH") == ["read"]
    assert inventory.vars["PLAYWRIGHT_NODEJS_PATH"][0].file == ".devcontainer/use-system-node.py"
    documented, _, _ = det.documented_vars(root)
    assert "PLAYWRIGHT_NODEJS_PATH" in documented
    assert "PLAYWRIGHT_NODEJS_PATH" in inventory.vars


def test_module_facts_are_collected_once_and_declaration_order_is_preserved(
    det, tmp_path, monkeypatch,
):
    root = _tree(tmp_path, {
        'core/a.py': (
            'def nested():\n'
            '    SHARED_ENV = "RAPTOR_SHARED"\n'
            '\n'
            'SHARED_ENV = "RAPTOR_SHARED"\n'
        ),
        'core/b.py': 'import os\nx = os.environ.get("RAPTOR_OTHER")\n',
    })
    calls = []
    original = det._collect_module_facts

    def collect_once(tree):
        calls.append(tree)
        return original(tree)

    monkeypatch.setattr(det, '_collect_module_facts', collect_once)
    inventory = det.scan_tree(root)
    assert len(calls) == 2
    assert [(o.file, o.line, o.kind) for o in inventory.vars['RAPTOR_SHARED']] == [
        ('core/a.py', 4, 'read'),
    ]
    assert 'RAPTOR_OTHER' in inventory.vars
