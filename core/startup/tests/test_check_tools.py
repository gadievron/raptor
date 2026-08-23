"""Tests for ``core.startup.init.check_tools`` and the tool-version
probes behind the TOOL_DEPS version-display convention.

Convention under test (stated at ``RaptorConfig.TOOL_DEPS``): the
banner shows a tool's version IF AND ONLY IF RAPTOR gates behaviour
on that version — semgrep and joern here; python/z3/gcc are covered
by ``test_check_env_session.py`` / ``test_analyzer_probe.py``.

All probes are stubbed — no real subprocesses, no PATH dependence.
"""

from __future__ import annotations

import json
from unittest import mock

from core.startup import init as startup_init
from core.startup.init import check_tools

_FAKE_DEPS = {
    "afl++":      {"binary": "afl-fuzz", "severity": "required", "affects": "/fuzz"},
    "codeql":     {"binary": "codeql", "group": "scanner", "affects": "/codeql, /agentic"},
    "coccinelle": {"binary": "spatch", "severity": "degrades", "affects": "/codeql, /agentic (C/C++ semantic-patch verification)"},
    "semgrep":    {"binary": "semgrep", "group": "scanner", "affects": "/scan, /agentic"},
    "z3":         {"module": "z3", "pip": "z3-solver", "severity": "degrades", "affects": "/audit (SMT)"},
}
_FAKE_GROUPS = {"scanner": {"min_required": 1, "affects": "/scan, /agentic"}}


def _patched_deps():
    from core.config import RaptorConfig
    return (
        mock.patch.object(RaptorConfig, "TOOL_DEPS", _FAKE_DEPS),
        mock.patch.object(RaptorConfig, "TOOL_GROUPS", _FAKE_GROUPS),
    )


def _run_check_tools(*, on_path, versions=None, module_present=False):
    """Run check_tools with which()/find_spec/_tool_version stubbed."""
    versions = versions or {}
    deps_patch, groups_patch = _patched_deps()
    with deps_patch, groups_patch, mock.patch(
        "core.startup.init.shutil.which",
        side_effect=lambda b: f"/usr/bin/{b}" if b in on_path else None,
    ), mock.patch(
        "core.startup.init.importlib.util.find_spec",
        return_value=object() if module_present else None,
    ), mock.patch(
        "core.startup.init._tool_version",
        side_effect=lambda name: versions.get(name),
    ):
        return check_tools()


class TestVersionDecoration:
    def test_version_gated_tool_shows_version_when_found(self):
        results, _, _ = _run_check_tools(
            on_path={"semgrep"}, versions={"semgrep": "1.172.0"},
        )
        assert ("semgrep 1.172.0", True) in results

    def test_missing_tool_never_decorated(self):
        # Doctor's install-hint lookup keys on the bare TOOL_DEPS
        # name for MISSING tools — a version suffix would break it
        # (and is impossible anyway: nothing to probe).
        results, _, _ = _run_check_tools(on_path=set())
        names = [name for name, ok in results if not ok]
        assert "semgrep" in names
        assert all(" " not in n for n in names)

    def test_presence_only_tool_not_decorated(self):
        # spatch found, but coccinelle is NOT version-gated.
        results, _, _ = _run_check_tools(on_path={"spatch", "semgrep"})
        assert ("coccinelle", True) in results


class TestWarningsNameTheBinary:
    def test_warning_names_binary_not_dep_key(self):
        # coccinelle's binary is spatch — the operator installs
        # spatch, and doctor's install hints match on binary names.
        _, warnings, _ = _run_check_tools(on_path={"semgrep"})
        cocci = [w for w in warnings if "semantic-patch" in w]
        assert cocci and "spatch not found" in cocci[0]
        assert "coccinelle not found" not in cocci[0]

    def test_required_tool_warning_names_binary(self):
        _, warnings, unavailable = _run_check_tools(on_path={"semgrep"})
        fuzz = [w for w in warnings if "/fuzz" in w]
        assert fuzz and "afl-fuzz not found" in fuzz[0]
        assert "unavailable" in fuzz[0]
        assert "/fuzz" in unavailable

    def test_module_dep_warning_uses_dep_name(self):
        # Module deps have no binary — fall back to the dep key.
        _, warnings, _ = _run_check_tools(on_path={"semgrep"})
        assert any("z3 not found" in w for w in warnings)


class TestGroupMemberWarnings:
    def test_missing_member_of_satisfied_group_warns(self):
        # semgrep present satisfies the scanner group, but /codeql
        # specifically is still dead without codeql — pre-fix this
        # was completely silent.
        _, warnings, _ = _run_check_tools(on_path={"semgrep"})
        codeql = [w for w in warnings if "codeql not found" in w]
        assert codeql, warnings
        assert "limited" in codeql[0]
        assert "/codeql" in codeql[0]

    def test_unsatisfied_group_emits_only_group_warning(self):
        # No scanner at all → one group-level warning; no redundant
        # per-member warnings on top.
        _, warnings, unavailable = _run_check_tools(on_path=set())
        group = [w for w in warnings if "no scanner" in w]
        assert len(group) == 1
        assert not any("codeql not found" in w for w in warnings)
        assert not any("semgrep not found" in w for w in warnings)
        assert {"/scan", "/agentic"} <= unavailable

    def test_fully_satisfied_group_is_silent(self):
        _, warnings, _ = _run_check_tools(on_path={"semgrep", "codeql"})
        assert not any("scanner" in w for w in warnings)
        assert not any("codeql not found" in w for w in warnings)
        assert not any("semgrep not found" in w for w in warnings)


class TestSemgrepVersion:
    def test_prefers_importlib_metadata(self):
        with mock.patch(
            "importlib.metadata.version", return_value="1.172.0",
        ), mock.patch(
            "core.startup.init._cached_cli_version",
        ) as cli:
            assert startup_init._semgrep_version() == "1.172.0"
        cli.assert_not_called()

    def test_falls_back_to_cli_probe_when_not_pip_installed(self):
        from importlib.metadata import PackageNotFoundError

        with mock.patch(
            "importlib.metadata.version",
            side_effect=PackageNotFoundError("semgrep"),
        ), mock.patch(
            "core.startup.init._cached_cli_version",
            return_value="1.160.0",
        ) as cli:
            assert startup_init._semgrep_version() == "1.160.0"
        cli.assert_called_once_with("semgrep")


class TestJoernVersion:
    def test_reads_dist_version_without_subprocess(self):
        with mock.patch(
            "packages.joern.prereqs._joern_path",
            return_value="/opt/joern/joern",
        ), mock.patch(
            "packages.joern.prereqs._version_from_dist",
            return_value="4.0.470",
        ) as dist, mock.patch("subprocess.run") as sub:
            assert startup_init._joern_version() == "4.0.470"
        dist.assert_called_once_with("/opt/joern/joern")
        # No JVM boot at startup — dist-file read only.
        sub.assert_not_called()

    def test_none_when_joern_absent(self):
        with mock.patch(
            "packages.joern.prereqs._joern_path", return_value=None,
        ):
            assert startup_init._joern_version() is None

    def test_tool_version_never_raises(self):
        with mock.patch(
            "core.startup.init._joern_version",
            side_effect=RuntimeError("probe blew up"),
        ):
            assert startup_init._tool_version("joern") is None


class TestCachedCliVersion:
    def _env(self, tmp_path, monkeypatch, fake_bin):
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
        monkeypatch.setattr(
            startup_init.shutil, "which",
            lambda b: str(fake_bin) if b == fake_bin.name else None,
        )

    def test_probe_parses_and_caches(self, tmp_path, monkeypatch):
        fake_bin = tmp_path / "sometool"
        fake_bin.write_text("#!/bin/sh\n")
        self._env(tmp_path, monkeypatch, fake_bin)

        proc = mock.Mock(returncode=0, stdout="sometool 9.8.7\n", stderr="")
        with mock.patch("subprocess.run", return_value=proc) as sub:
            assert startup_init._cached_cli_version("sometool") == "9.8.7"
        sub.assert_called_once()

        cache_file = tmp_path / "cache" / "raptor" / "tool-versions.json"
        cached = json.loads(cache_file.read_text())
        assert cached["sometool"]["version"] == "9.8.7"

        # Second call: served from the cache — no subprocess.
        with mock.patch("subprocess.run") as sub2:
            assert startup_init._cached_cli_version("sometool") == "9.8.7"
        sub2.assert_not_called()

    def test_cache_invalidated_when_binary_changes(self, tmp_path, monkeypatch):
        fake_bin = tmp_path / "sometool"
        fake_bin.write_text("#!/bin/sh\n")
        self._env(tmp_path, monkeypatch, fake_bin)

        proc = mock.Mock(returncode=0, stdout="sometool 1.0.0\n", stderr="")
        with mock.patch("subprocess.run", return_value=proc):
            assert startup_init._cached_cli_version("sometool") == "1.0.0"

        # Simulate an upgrade: content (size) changes → key changes.
        fake_bin.write_text("#!/bin/sh\n# upgraded to 2\n")
        proc2 = mock.Mock(returncode=0, stdout="sometool 2.0.0\n", stderr="")
        with mock.patch("subprocess.run", return_value=proc2) as sub:
            assert startup_init._cached_cli_version("sometool") == "2.0.0"
        sub.assert_called_once()

    def test_probe_failure_returns_none_and_not_cached(
        self, tmp_path, monkeypatch,
    ):
        fake_bin = tmp_path / "sometool"
        fake_bin.write_text("#!/bin/sh\n")
        self._env(tmp_path, monkeypatch, fake_bin)

        with mock.patch("subprocess.run", side_effect=OSError("boom")):
            assert startup_init._cached_cli_version("sometool") is None
        cache_file = tmp_path / "cache" / "raptor" / "tool-versions.json"
        assert not cache_file.exists()

    def test_unparseable_output_returns_none(self, tmp_path, monkeypatch):
        fake_bin = tmp_path / "sometool"
        fake_bin.write_text("#!/bin/sh\n")
        self._env(tmp_path, monkeypatch, fake_bin)

        proc = mock.Mock(returncode=0, stdout="no digits here\n", stderr="")
        with mock.patch("subprocess.run", return_value=proc):
            assert startup_init._cached_cli_version("sometool") is None

    def test_binary_not_on_path_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
        monkeypatch.setattr(startup_init.shutil, "which", lambda b: None)
        assert startup_init._cached_cli_version("sometool") is None

    def test_corrupt_cache_file_is_tolerated(self, tmp_path, monkeypatch):
        fake_bin = tmp_path / "sometool"
        fake_bin.write_text("#!/bin/sh\n")
        self._env(tmp_path, monkeypatch, fake_bin)
        cache_dir = tmp_path / "cache" / "raptor"
        cache_dir.mkdir(parents=True)
        (cache_dir / "tool-versions.json").write_text("{not json")

        proc = mock.Mock(returncode=0, stdout="sometool 3.1.4\n", stderr="")
        with mock.patch("subprocess.run", return_value=proc):
            assert startup_init._cached_cli_version("sometool") == "3.1.4"
