"""Tests for ``core.startup.init.check_tools`` and the tool-version
probes behind the TOOL_DEPS version-display convention.

Convention under test (stated at ``RaptorConfig.TOOL_DEPS``): the
banner shows a tool's version IF AND ONLY IF RAPTOR gates behaviour
on that version — semgrep, joern, coccinelle and codeql here; python/z3/gcc are covered
by ``test_check_env_session.py`` / ``test_analyzer_probe.py``.

All probes are stubbed — no real subprocesses, no PATH dependence.
"""

from __future__ import annotations


import json
from unittest import mock

from core.startup import init as startup_init
from core.startup.init import check_tools

from core.testing.module_bindings import patch_module_attribute

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

    def test_unknown_version_keeps_presence_display(self):
        # A present tool remains visible when its version is unavailable.
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
            "shutil.which", return_value=None,
        ), mock.patch(
            "importlib.metadata.version", return_value="1.172.0",
        ), mock.patch(
            "core.startup.init._cached_cli_version",
        ) as cli:
            assert startup_init._semgrep_version() == "1.172.0"
        cli.assert_not_called()

    def test_falls_back_to_cli_probe_when_not_pip_installed(self):
        from importlib.metadata import PackageNotFoundError

        with mock.patch(
            "shutil.which", return_value=None,
        ), mock.patch(
            "importlib.metadata.version",
            side_effect=PackageNotFoundError("semgrep"),
        ), mock.patch(
            "core.startup.init._cached_cli_version",
            return_value="1.160.0",
        ) as cli:
            assert startup_init._semgrep_version() == "1.160.0"
        cli.assert_called_once_with("semgrep")

    def test_external_path_binary_uses_its_own_version(self, tmp_path):
        with mock.patch(
            "shutil.which", return_value=str(tmp_path / "semgrep"),
        ), mock.patch(
            "importlib.metadata.version",
        ) as metadata, mock.patch(
            "core.startup.init._cached_cli_version", return_value="1.177.0",
        ) as cli:
            assert startup_init._semgrep_version() == "1.177.0"
        metadata.assert_not_called()
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
        patch_module_attribute(monkeypatch, startup_init, "shutil", "which", lambda b: str(fake_bin) if b == fake_bin.name else None)

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
        patch_module_attribute(monkeypatch, startup_init, "shutil", "which", lambda b: None)
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


class TestVersionNewer:
    def test_newer(self):
        assert startup_init._version_newer("1.82.0", "1.79.0") is True

    def test_same(self):
        assert startup_init._version_newer("1.79.0", "1.79.0") is False

    def test_older(self):
        assert startup_init._version_newer("1.78.0", "1.79.0") is False

    def test_major_bump(self):
        assert startup_init._version_newer("2.0.0", "1.99.9") is True

    def test_trailing_rc_stripped(self):
        assert startup_init._version_newer("1.80.0rc1", "1.79.0") is True

    def test_both_have_two_segments(self):
        assert startup_init._version_newer("1.80", "1.79") is True


class TestCheckPypiUpdate:
    def test_returns_true_when_newer(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
        resp = mock.Mock(status_code=200)
        resp.json.return_value = {"info": {"version": "1.82.0"}}
        with mock.patch("requests.get", return_value=resp):
            assert startup_init._check_pypi_update("semgrep", "1.79.0") is True

    def test_returns_false_when_same(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
        resp = mock.Mock(status_code=200)
        resp.json.return_value = {"info": {"version": "1.79.0"}}
        with mock.patch("requests.get", return_value=resp):
            assert startup_init._check_pypi_update("semgrep", "1.79.0") is False

    def test_returns_false_on_network_error(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
        import requests as _req
        with mock.patch("requests.get", side_effect=_req.ConnectionError):
            assert startup_init._check_pypi_update("semgrep", "1.79.0") is False

    def test_returns_false_when_requests_missing(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
        import builtins
        real_import = builtins.__import__

        def _block_requests(name, *a, **kw):
            if name == "requests":
                raise ImportError("no requests")
            return real_import(name, *a, **kw)

        with mock.patch("builtins.__import__", side_effect=_block_requests):
            assert startup_init._check_pypi_update("semgrep", "1.79.0") is False

    def test_cached_result_avoids_network(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
        import json
        import time
        cache_dir = tmp_path / "cache" / "raptor"
        cache_dir.mkdir(parents=True)
        (cache_dir / "tool-versions.json").write_text(
            json.dumps({"updates": {"semgrep": {
                "latest": "1.82.0", "ts": time.time(),
            }}})
        )
        with mock.patch("requests.get") as get:
            assert startup_init._check_pypi_update("semgrep", "1.79.0") is True
        get.assert_not_called()

    def test_stale_cache_triggers_fetch(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
        import json
        import time
        cache_dir = tmp_path / "cache" / "raptor"
        cache_dir.mkdir(parents=True)
        (cache_dir / "tool-versions.json").write_text(
            json.dumps({"updates": {"semgrep": {
                "latest": "1.82.0", "ts": time.time() - 90000,
            }}})
        )
        resp = mock.Mock(status_code=200)
        resp.json.return_value = {"info": {"version": "1.83.0"}}
        with mock.patch("requests.get", return_value=resp) as get:
            assert startup_init._check_pypi_update("semgrep", "1.79.0") is True
        get.assert_called_once()


class TestCheckToolUpdates:
    def test_returns_name_when_update_available(self):
        with mock.patch(
            "core.startup.init._semgrep_version", return_value="1.79.0",
        ), mock.patch(
            "core.startup.init._check_pypi_update", return_value=True,
        ):
            assert "semgrep" in startup_init.check_tool_updates()

    def test_returns_empty_when_current(self):
        with mock.patch(
            "core.startup.init._semgrep_version", return_value="1.79.0",
        ), mock.patch(
            "core.startup.init._check_pypi_update", return_value=False,
        ):
            assert startup_init.check_tool_updates() == set()

    def test_returns_empty_when_version_unknown(self):
        with mock.patch(
            "core.startup.init._semgrep_version", return_value=None,
        ):
            assert startup_init.check_tool_updates() == set()


class TestRuleCompatibilityDisplay:
    def test_old_versions_warn_without_disabling_tools(self):
        results, warnings, unavailable = _run_check_tools(
            on_path={"spatch", "semgrep", "codeql", "afl-fuzz"},
            versions={"coccinelle": "1.1.1", "semgrep": "1.37.0", "codeql": "2.23.8"},
            module_present=True,
        )
        assert ("coccinelle 1.1.1", True) in results
        assert ("semgrep 1.37.0", True) in results
        assert ("codeql 2.23.8", True) in results
        assert any("1.38.0" in warning for warning in warnings)
        assert any("skipped individually" in warning for warning in warnings)
        assert not unavailable

    def test_compatible_versions_have_no_version_limit_warning(self):
        _, warnings, _ = _run_check_tools(
            on_path={"spatch", "semgrep", "codeql", "afl-fuzz"},
            versions={"coccinelle": "1.3", "semgrep": "1.177.0", "codeql": "2.23.8"},
            module_present=True,
        )
        assert not warnings

    def test_codeql_bootstrap_never_probed(self, tmp_path, monkeypatch):
        bootstrap = tmp_path / "raptor-codeql-bootstrap"
        bootstrap.write_text("#!/bin/sh\nexit 99\n")
        link = tmp_path / "codeql"
        link.symlink_to(bootstrap)
        patch_module_attribute(monkeypatch, startup_init, "shutil", "which", lambda name: str(link))
        with mock.patch.object(startup_init, "_cached_cli_version") as probe:
            assert startup_init._tool_version("codeql") is None
        probe.assert_not_called()

    def test_new_version_displays_use_existing_probe_cache(self):
        with mock.patch.object(startup_init, "_cached_cli_version", return_value="1.3.0") as probe:
            assert startup_init._tool_version("coccinelle") == "1.3.0"
        probe.assert_called_once_with("spatch")
        with mock.patch.object(startup_init.shutil, "which", return_value="/tools/codeql"), \
             mock.patch.object(startup_init, "_cached_cli_version", return_value="2.23.8") as probe:
            assert startup_init._tool_version("codeql") == "2.23.8"
        probe.assert_called_once_with("codeql")
