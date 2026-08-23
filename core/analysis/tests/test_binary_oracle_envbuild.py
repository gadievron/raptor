"""Binary-oracle env build-on-demand (S5.4).

Ratified rules: fires only when NOTHING else resolved and the project
``build`` trust marker authorises; suppression authority follows who
chose the build configuration (operator setting → full; detector
guess → ``earns_suppression`` downgrades, mirroring symbol_only);
artifacts are run-local with a persist hint, never auto-trusted.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from core.analysis.binary_oracle_cli import (
    _env_build_debug_binaries,
    apply_to_config,
    resolve_binary_paths,
)


def _args(**over):
    base = dict(binary=None, binary_auto=False, no_binary_oracle=False,
                binary_edges=False, target_kind="auto")
    base.update(over)
    return SimpleNamespace(**base)


def _product(ok=True, rels=("app",), tmp_path=None):
    artifacts = {}
    for rel in rels:
        p = tmp_path / rel.replace("/", "__")
        p.write_bytes(b"\x7fELF" + b"\x00" * 12)
        artifacts[rel] = p
    return SimpleNamespace(ok=ok, artifacts=artifacts if ok else {},
                           reason="" if ok else "build_failed",
                           detail="", checksums={})


class TestEnvBuildHook:
    def test_gate_denied_prints_hint(self, tmp_path, capsys):
        with patch("core.project.trust.resolve_build_execution",
                   return_value=False):
            paths, guessed = _env_build_debug_binaries(tmp_path)
        assert paths == [] and guessed is False
        out = capsys.readouterr().out
        assert "'build' trust marker" in out

    def test_operator_command_not_guessed(self, tmp_path, capsys):
        with patch("core.project.trust.resolve_build_execution",
                   return_value=True), \
             patch("core.build.resolve.resolve_build_command",
                   return_value=("make", "project-setting:default")), \
             patch("core.env.build.containerized_build",
                   return_value=_product(tmp_path=tmp_path)):
            paths, guessed = _env_build_debug_binaries(tmp_path)
        assert len(paths) == 1
        assert guessed is False
        out = capsys.readouterr().out
        assert "/project binary add" in out
        assert "GUESSED" not in out

    def test_detected_command_is_guessed(self, tmp_path, capsys):
        with patch("core.project.trust.resolve_build_execution",
                   return_value=True), \
             patch("core.build.resolve.resolve_build_command",
                   return_value=("make", "detected:make")), \
             patch("core.env.build.containerized_build",
                   return_value=_product(tmp_path=tmp_path)):
            paths, guessed = _env_build_debug_binaries(tmp_path)
        assert len(paths) == 1
        assert guessed is True
        assert "GUESSED build command" in capsys.readouterr().out

    def test_build_failure_degrades(self, tmp_path, capsys):
        with patch("core.project.trust.resolve_build_execution",
                   return_value=True), \
             patch("core.build.resolve.resolve_build_command",
                   return_value=("make", "detected:make")), \
             patch("core.env.build.containerized_build",
                   return_value=_product(ok=False, tmp_path=tmp_path)):
            paths, guessed = _env_build_debug_binaries(tmp_path)
        assert paths == []
        assert "env build failed" in capsys.readouterr().out


class TestResolveWiring:
    def test_fires_only_on_total_miss(self, tmp_path):
        with patch("core.analysis.binary_oracle_cli"
                   "._autodetect_binaries", return_value=[]), \
             patch("core.analysis.binary_oracle_cli._project_binaries",
                   return_value=([], None)), \
             patch("core.analysis.binary_oracle_cli"
                   "._env_build_debug_binaries",
                   return_value=(["/x/app"], True)) as hook:
            out: list = []
            paths = resolve_binary_paths(
                _args(), tmp_path, "auto", no_suppress_out=out)
        hook.assert_called_once()
        assert paths == ("/x/app",)
        assert out == ["/x/app"]

    def test_suppressed_by_project_binaries(self, tmp_path):
        proj_bin = tmp_path / "proj-bin"
        proj_bin.write_bytes(b"\x7fELF")
        with patch("core.analysis.binary_oracle_cli"
                   "._autodetect_binaries", return_value=[]), \
             patch("core.analysis.binary_oracle_cli._project_binaries",
                   return_value=([proj_bin], "p")), \
             patch("core.analysis.binary_oracle_cli"
                   "._env_build_debug_binaries") as hook:
            resolve_binary_paths(_args(), tmp_path, "auto")
        hook.assert_not_called()

    def test_dangling_project_binary_does_not_block_env_build(
            self, tmp_path):
        """Adversarial-review F3: a store entry whose file was deleted
        (e.g. by /project clean) must be ignored — it previously
        satisfied 'we have binaries', suppressing the env-build
        fallback while leaving the oracle binary-less."""
        with patch("core.analysis.binary_oracle_cli"
                   "._autodetect_binaries", return_value=[]), \
             patch("core.analysis.binary_oracle_cli._project_binaries",
                   return_value=([Path("/gone/away")], "p")), \
             patch("core.analysis.binary_oracle_cli"
                   "._env_build_debug_binaries",
                   return_value=(["/x/app"], False)) as hook:
            paths = resolve_binary_paths(_args(), tmp_path, "auto")
        hook.assert_called_once()
        assert paths == ("/x/app",)

    def test_operator_command_paths_not_in_no_suppress(self, tmp_path):
        with patch("core.analysis.binary_oracle_cli"
                   "._autodetect_binaries", return_value=[]), \
             patch("core.analysis.binary_oracle_cli._project_binaries",
                   return_value=([], None)), \
             patch("core.analysis.binary_oracle_cli"
                   "._env_build_debug_binaries",
                   return_value=(["/x/app"], False)):
            out: list = []
            paths = resolve_binary_paths(
                _args(), tmp_path, "auto", no_suppress_out=out)
        assert paths == ("/x/app",)
        assert out == []

    def test_apply_to_config_assigns_both(self, tmp_path):
        from core.config import RaptorConfig
        with patch("core.analysis.binary_oracle_cli"
                   "._autodetect_binaries", return_value=[]), \
             patch("core.analysis.binary_oracle_cli._project_binaries",
                   return_value=([], None)), \
             patch("core.analysis.binary_oracle_cli"
                   "._env_build_debug_binaries",
                   return_value=(["/x/app"], True)):
            apply_to_config(_args(), tmp_path)
        try:
            assert RaptorConfig.BINARY_ORACLE_PATHS == ("/x/app",)
            assert RaptorConfig.BINARY_ORACLE_NO_SUPPRESS == ("/x/app",)
        finally:
            RaptorConfig.BINARY_ORACLE_PATHS = ()
            RaptorConfig.BINARY_ORACLE_NO_SUPPRESS = ()

    def test_apply_to_config_clears_stale_no_suppress(self, tmp_path):
        """Always-assign: a prior run's no-suppress set must not leak."""
        from core.config import RaptorConfig
        RaptorConfig.BINARY_ORACLE_NO_SUPPRESS = ("/stale",)
        with patch("core.analysis.binary_oracle_cli"
                   "._autodetect_binaries", return_value=[]), \
             patch("core.analysis.binary_oracle_cli._project_binaries",
                   return_value=([], None)), \
             patch("core.analysis.binary_oracle_cli"
                   "._env_build_debug_binaries",
                   return_value=([], False)):
            apply_to_config(_args(), tmp_path)
        try:
            assert RaptorConfig.BINARY_ORACLE_NO_SUPPRESS == ()
        finally:
            RaptorConfig.BINARY_ORACLE_PATHS = ()
            RaptorConfig.BINARY_ORACLE_NO_SUPPRESS = ()
