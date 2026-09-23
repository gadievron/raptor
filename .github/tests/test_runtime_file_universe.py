"""Two-direction pins for the shared runtime-source universe.

The helper (`.github/scripts/runtime_universe.py`) is the single
derivation every tree-walking oracle consumes; a defect here would
silently narrow or widen ALL of them at once, so both directions are
pinned on a planted synthetic tree AND on the real checkout:

* inclusion — a new runtime file (package module, libexec python
  launcher, plugin hook, repo-root entry module) joins the universe
  with no registration step;
* exclusion — test files, fixtures, conftest.py, dev ``scripts/``
  harnesses, bash launchers, and dot-dirs stay out.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from runtime_universe import (  # noqa: E402
    RUNTIME_ROOTS,
    is_runtime_python_file,
    repo_root,
    runtime_file_universe,
)

REPO = repo_root()


def _plant(root: Path, rel: str, text: str = "x = 1\n") -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


class TestSyntheticTree:
    def test_planted_runtime_files_appear(self, tmp_path):
        expected = {
            _plant(tmp_path, "core/newpkg/mod.py"),
            _plant(tmp_path, "packages/newpkg/deep/mod.py"),
            _plant(tmp_path, "engine/rules/render.py"),
            _plant(tmp_path, "libexec/raptor-new-tool",
                   "#!/usr/bin/env python3\nx = 1\n"),
            _plant(tmp_path, "plugins/newplug/hooks/hook.py"),
            _plant(tmp_path, "raptor_newentry.py"),
        }
        got = set(runtime_file_universe(tmp_path))
        assert expected <= got, sorted(expected - got)

    def test_planted_non_runtime_files_stay_out(self, tmp_path):
        _plant(tmp_path, "core/pkg/mod.py")  # keep the walk non-empty
        planted = [
            _plant(tmp_path, "core/pkg/tests/test_mod.py"),
            _plant(tmp_path, "core/pkg/test/probe.py"),
            _plant(tmp_path, "core/pkg/fixtures/sample.py"),
            _plant(tmp_path, "core/pkg/conftest.py"),
            _plant(tmp_path, "conftest.py"),
            _plant(tmp_path, "core/pkg/scripts/harness.py"),
            _plant(tmp_path, "core/pkg/__pycache__/mod.py"),
            _plant(tmp_path, "core/.venv/lib/site.py"),
            _plant(tmp_path, "libexec/raptor-bash-tool",
                   "#!/usr/bin/env bash\necho hi\n"),
            _plant(tmp_path, "docs/example.py"),
            _plant(tmp_path, "out/run/artifact.py"),
        ]
        got = set(runtime_file_universe(tmp_path))
        offenders = [p for p in planted if p in got]
        assert not offenders, offenders

    def test_dev_scripts_opt_in(self, tmp_path):
        harness = _plant(tmp_path, "core/pkg/scripts/harness.py")
        assert harness not in set(runtime_file_universe(tmp_path))
        assert harness in set(
            runtime_file_universe(tmp_path, include_dev_scripts=True)
        )
        # The opt-in widens only the scripts/ dimension.
        test_file = _plant(tmp_path, "core/pkg/tests/test_mod.py")
        assert test_file not in set(
            runtime_file_universe(tmp_path, include_dev_scripts=True)
        )

    def test_extra_excluded_parts_are_gate_local(self, tmp_path):
        data = _plant(tmp_path, "packages/pkg/data/gen.py")
        assert data in set(runtime_file_universe(tmp_path))
        assert data not in set(
            runtime_file_universe(tmp_path, extra_excluded_parts=("data",))
        )


class TestRealTree:
    def test_core_build_is_in_the_universe(self):
        """Regression pin: the guardrails' bare ``build`` skip-name
        dropped the runtime package core/build from four gates."""
        uni = set(runtime_file_universe())
        assert REPO / "core/build/build_detector.py" in uni

    def test_entry_modules_and_launchers_present(self):
        uni = set(runtime_file_universe())
        assert REPO / "raptor.py" in uni
        assert REPO / "raptor_agentic.py" in uni
        assert REPO / "libexec/raptor-validation-helper" in uni

    def test_known_non_members_absent(self):
        uni = set(runtime_file_universe())
        assert REPO / "conftest.py" not in uni
        assert REPO / "core/json/tests/test_utils.py" not in uni
        # bash launcher, not python source
        assert REPO / "libexec/raptor-agentic" not in uni

    def test_roots_exist(self):
        for root in RUNTIME_ROOTS:
            assert (REPO / root).is_dir(), root

    def test_shebang_probe(self, tmp_path):
        py = tmp_path / "t"
        py.write_bytes(b"#!/usr/bin/env python3\n")
        assert is_runtime_python_file(py)
        sh = tmp_path / "s"
        sh.write_bytes(b"#!/usr/bin/env bash\n")
        assert not is_runtime_python_file(sh)
        # no shebang at all: data file, not runtime source
        raw = tmp_path / "r"
        raw.write_bytes(b"python\n")
        assert not is_runtime_python_file(raw)
