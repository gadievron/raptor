"""Unit tests for the preflight stub-module writer (hide_modules.py)."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "hide_modules.py"
_REPO_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(scope="module")
def hm():
    spec = importlib.util.spec_from_file_location("hide_modules", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _run_py(code: str, pythonpath: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONPATH": pythonpath}
    return subprocess.run(
        [sys.executable, "-c", code],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )


class TestWriteStubs:
    def test_writes_one_stub_per_unique_name(self, hm, tmp_path):
        dest = hm.write_stubs(tmp_path / "stubs", ["bbb", "aaa", "bbb"])
        assert dest == tmp_path / "stubs"
        assert sorted(p.name for p in dest.iterdir()) == ["aaa.py", "bbb.py"]

    def test_stub_body_raises_module_not_found(self, hm, tmp_path):
        dest = hm.write_stubs(tmp_path / "stubs", ["aaa"])
        body = (dest / "aaa.py").read_text(encoding="utf-8")
        with pytest.raises(ModuleNotFoundError) as exc_info:
            exec(compile(body, "aaa.py", "exec"))
        assert "No module named 'aaa'" in str(exc_info.value)
        assert exc_info.value.name == "aaa"

    @pytest.mark.parametrize(
        "bad", ["google.genai", "tree-sitter", "", "1abc", "a b"]
    )
    def test_rejects_non_importable_names(self, hm, tmp_path, bad):
        with pytest.raises(ValueError, match="not importable"):
            hm.write_stubs(tmp_path / "stubs", [bad])
        assert not (tmp_path / "stubs").exists()


class TestShadowing:
    """The stub must win over a really-installed package on sys.path."""

    def test_stub_shadows_installed_package(self, hm, tmp_path):
        # pytest is installed in every environment that runs this test,
        # so hiding it proves PYTHONPATH-stub-over-site-packages.
        dest = hm.write_stubs(tmp_path / "stubs", ["pytest"])
        proc = _run_py("import pytest", str(dest))
        assert proc.returncode != 0
        assert "ModuleNotFoundError" in proc.stderr
        assert "hidden by the CI preflight" in proc.stderr

    def test_importorskip_turns_stub_into_skip(self, hm, tmp_path):
        # A real module later on PYTHONPATH imports fine; once the stub
        # dir is prepended, pytest.importorskip must SKIP, not error.
        real = tmp_path / "real"
        real.mkdir()
        (real / "preflight_demo_mod.py").write_text(
            "VALUE = 1\n", encoding="utf-8"
        )
        dest = hm.write_stubs(tmp_path / "stubs", ["preflight_demo_mod"])
        code = textwrap.dedent(
            """
            import pytest
            from _pytest.outcomes import Skipped
            try:
                pytest.importorskip("preflight_demo_mod")
            except Skipped:
                print("SKIPPED_OK")
            else:
                print("IMPORTED")
            """
        )
        without_stub = _run_py(code, str(real))
        assert without_stub.returncode == 0, without_stub.stderr
        assert "IMPORTED" in without_stub.stdout
        with_stub = _run_py(code, f"{dest}{os.pathsep}{real}")
        assert with_stub.returncode == 0, with_stub.stderr
        assert "SKIPPED_OK" in with_stub.stdout

    def test_submodule_import_also_raises(self, hm, tmp_path):
        dest = hm.write_stubs(tmp_path / "stubs", ["preflight_demo_mod"])
        proc = _run_py("import preflight_demo_mod.sub", str(dest))
        assert proc.returncode != 0
        assert "ModuleNotFoundError" in proc.stderr


class TestNamedSets:
    def test_optional_deps_set(self, hm):
        assert hm.OPTIONAL_DEP_MODULES == (
            "anthropic", "botocore", "instructor", "h2", "sage_sdk",
        )

    def test_tree_sitter_set_derived_from_grammar_pins(self, hm):
        names = hm.tree_sitter_modules(_REPO_ROOT)
        assert "tree_sitter" in names
        assert "tree_sitter_python" in names
        assert all(n.startswith("tree_sitter") for n in names)
        # Core + one wheel per pinned grammar; every name is a valid
        # stub target (write_stubs would reject anything else).
        pin_lines = [
            line
            for line in (_REPO_ROOT / "requirements-grammars.txt")
            .read_text(encoding="utf-8")
            .splitlines()
            if "==" in line and not line.lstrip().startswith("#")
        ]
        assert len(names) == len(pin_lines)
        assert all(hm._NAME_RE.match(n) for n in names)

    def test_tree_sitter_set_requires_pins(self, hm, tmp_path):
        (tmp_path / "requirements-grammars.txt").write_text(
            "# only comments\n", encoding="utf-8"
        )
        with pytest.raises(ValueError, match="no ==-pinned"):
            hm.tree_sitter_modules(tmp_path)


class TestCli:
    def test_set_plus_extra_names(self, hm, tmp_path, capsys):
        dest = tmp_path / "stubs"
        rc = hm.main(["--dest", str(dest), "--set", "optional-deps", "extra"])
        assert rc == 0
        written = {p.stem for p in dest.iterdir()}
        assert written == set(hm.OPTIONAL_DEP_MODULES) | {"extra"}
        assert capsys.readouterr().out.strip() == str(dest.resolve())

    def test_nothing_to_hide_is_a_usage_error(self, hm, tmp_path):
        with pytest.raises(SystemExit) as exc_info:
            hm.main(["--dest", str(tmp_path / "stubs")])
        assert exc_info.value.code == 2

    def test_invalid_name_is_a_usage_error(self, hm, tmp_path):
        with pytest.raises(SystemExit) as exc_info:
            hm.main(["--dest", str(tmp_path / "stubs"), "not-a-module"])
        assert exc_info.value.code == 2
