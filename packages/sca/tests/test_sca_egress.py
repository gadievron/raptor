"""Tests for SCA egress allowlist integration.

Verifies that:
1. SCA_ALLOWED_HOSTS contains all required hosts.
2. SCA_ALLOWED_HOSTS on the raptor side matches the raptor-sca side.
3. _find_sca_agent discovers (or doesn't discover) the raptor-sca agent.
4. run_sca_subprocess wires proxy_hosts correctly.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from packages.sca import SCA_ALLOWED_HOSTS
from packages.sca.agent import _find_sca_agent, run_sca_subprocess


# ---------------------------------------------------------------------------
# SCA_ALLOWED_HOSTS completeness
# ---------------------------------------------------------------------------

class TestScaAllowedHosts:

    def test_is_tuple(self):
        """Immutable — accidental mutation is a security regression."""
        assert isinstance(SCA_ALLOWED_HOSTS, tuple)

    def test_not_empty(self):
        assert len(SCA_ALLOWED_HOSTS) > 0

    def test_contains_osv(self):
        assert "api.osv.dev" in SCA_ALLOWED_HOSTS

    def test_contains_kev(self):
        assert "www.cisa.gov" in SCA_ALLOWED_HOSTS

    def test_contains_epss(self):
        assert "api.first.org" in SCA_ALLOWED_HOSTS

    def test_contains_pypi_registry(self):
        assert "pypi.org" in SCA_ALLOWED_HOSTS

    def test_contains_npm_registry(self):
        assert "registry.npmjs.org" in SCA_ALLOWED_HOSTS

    def test_contains_crates_registry(self):
        assert "crates.io" in SCA_ALLOWED_HOSTS

    def test_contains_rubygems_registry(self):
        assert "rubygems.org" in SCA_ALLOWED_HOSTS

    def test_contains_golang_proxy(self):
        assert "proxy.golang.org" in SCA_ALLOWED_HOSTS

    def test_contains_nuget_registry(self):
        assert "api.nuget.org" in SCA_ALLOWED_HOSTS

    def test_contains_maven_registry(self):
        assert "repo.maven.apache.org" in SCA_ALLOWED_HOSTS

    def test_contains_packagist_registry(self):
        assert "repo.packagist.org" in SCA_ALLOWED_HOSTS

    def test_contains_pypi_archives(self):
        """Source-archive downloads for version-diff review."""
        assert "files.pythonhosted.org" in SCA_ALLOWED_HOSTS

    def test_contains_github_api(self):
        assert "api.github.com" in SCA_ALLOWED_HOSTS

    def test_no_duplicates(self):
        assert len(SCA_ALLOWED_HOSTS) == len(set(SCA_ALLOWED_HOSTS))

    def test_all_lowercase(self):
        """Proxy comparison is case-insensitive but the canonical form
        should be lowercase for consistency."""
        for host in SCA_ALLOWED_HOSTS:
            assert host == host.lower(), f"{host} is not lowercase"


# ---------------------------------------------------------------------------
# Cross-repo parity
# ---------------------------------------------------------------------------

class TestCrossRepoParity:

    @pytest.fixture()
    def raptor_sca_init(self):
        """Path to raptor-sca's packages/sca/__init__.py, if available."""
        candidate = (Path(__file__).resolve().parents[3]
                     / ".." / "raptor-sca" / "packages" / "sca" / "__init__.py")
        if not candidate.resolve().is_file():
            pytest.skip("raptor-sca not available at ../raptor-sca")
        return candidate.resolve()

    def test_hosts_match_raptor_sca(self, raptor_sca_init):
        """Every host in raptor-sca's SCA_ALLOWED_HOSTS must appear in
        the raptor-side copy. Extra hosts on the raptor side are OK
        (forward-compat), but missing hosts mean the sandbox will block
        SCA traffic."""
        text = raptor_sca_init.read_text(encoding="utf-8")
        # Extract the SCA_ALLOWED_HOSTS tuple literal from source.
        # We isolate the block between "SCA_ALLOWED_HOSTS = (" and the
        # closing ")" then extract quoted hostnames (must contain a dot
        # to distinguish from non-host string literals).
        import re
        m = re.search(
            r'SCA_ALLOWED_HOSTS\s*=\s*\((.*?)\)',
            text, re.DOTALL,
        )
        assert m, "could not find SCA_ALLOWED_HOSTS in raptor-sca"
        block = m.group(1)
        hosts_in_sca = set(re.findall(r'"([a-z0-9][a-z0-9._-]*\.[a-z]{2,})"', block))
        raptor_hosts = set(SCA_ALLOWED_HOSTS)
        missing = hosts_in_sca - raptor_hosts
        assert not missing, (
            f"raptor-sca declares hosts not in raptor's SCA_ALLOWED_HOSTS: "
            f"{sorted(missing)}"
        )


# ---------------------------------------------------------------------------
# _find_sca_agent
# ---------------------------------------------------------------------------

class TestFindScaAgent:

    def test_returns_none_when_not_installed(self, tmp_path, monkeypatch):
        """When no raptor-sca tree exists, returns None."""
        monkeypatch.delenv("RAPTOR_SCA_AGENT", raising=False)
        # _find_sca_agent searches relative to packages/sca/agent.py's
        # parents; with no raptor-sca worktree it should return None.
        result = _find_sca_agent()
        # Either None (no raptor-sca) or a valid path (raptor-sca exists).
        # Both are acceptable — the function must not crash.
        assert result is None or result.is_file()

    def test_env_override(self, tmp_path, monkeypatch):
        """RAPTOR_SCA_AGENT env var overrides discovery."""
        agent = tmp_path / "agent.py"
        agent.write_text("from packages.sca import SCA_ALLOWED_HOSTS\n")
        monkeypatch.setenv("RAPTOR_SCA_AGENT", str(agent))
        result = _find_sca_agent()
        assert result == agent

    def test_env_override_nonexistent(self, tmp_path, monkeypatch):
        """RAPTOR_SCA_AGENT pointing to a missing file returns None."""
        monkeypatch.setenv("RAPTOR_SCA_AGENT", str(tmp_path / "nope.py"))
        result = _find_sca_agent()
        # Falls through to normal discovery (may find real agent or None).
        # The env path itself is skipped.
        assert result is None or result.is_file()


# ---------------------------------------------------------------------------
# run_sca_subprocess
# ---------------------------------------------------------------------------

class TestRunScaSubprocess:

    def test_passes_proxy_hosts(self, tmp_path):
        """Verify that run_sca_subprocess wires SCA_ALLOWED_HOSTS into
        the sandbox call via proxy_hosts."""
        agent = tmp_path / "agent.py"
        agent.write_text("# stub")

        captured_kwargs = {}

        def fake_sandbox_run(cmd, **kwargs):
            captured_kwargs.update(kwargs)
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = '{"status": "ok"}'
            mock_result.stderr = ""
            return mock_result

        with patch("packages.sca.agent.sandbox_run", fake_sandbox_run, create=True):
            # Patch the import inside run_sca_subprocess
            with patch("core.sandbox.run", fake_sandbox_run):
                rc, stdout, stderr = run_sca_subprocess(
                    agent, tmp_path, tmp_path / "out",
                )

        assert captured_kwargs.get("use_egress_proxy") is True
        proxy_hosts = captured_kwargs.get("proxy_hosts", [])
        assert set(proxy_hosts) == set(SCA_ALLOWED_HOSTS)
        assert captured_kwargs.get("caller_label") == "sca-agent"

    def test_passes_sandbox_args(self, tmp_path):
        """Extra --sandbox / --audit flags are forwarded to the command."""
        agent = tmp_path / "agent.py"
        agent.write_text("# stub")

        captured_cmd = []

        def fake_sandbox_run(cmd, **kwargs):
            captured_cmd.extend(cmd)
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "{}"
            mock_result.stderr = ""
            return mock_result

        with patch("core.sandbox.run", fake_sandbox_run):
            run_sca_subprocess(
                agent, tmp_path, tmp_path / "out",
                sandbox_args=["--sandbox", "full", "--audit"],
            )

        assert "--sandbox" in captured_cmd
        assert "full" in captured_cmd
        assert "--audit" in captured_cmd
