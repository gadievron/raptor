"""Tests for SCA egress allowlist integration.

Verifies that:
1. SCA_ALLOWED_HOSTS contains all required hosts.
2. SCA_ALLOWED_HOSTS on the raptor side matches the raptor-sca side.
3. _find_sca_agent discovers (or doesn't discover) the raptor-sca agent.
4. run_sca_subprocess wires proxy_hosts correctly.
"""

from __future__ import annotations

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

# Required hosts kept as a parameter list rather than asserted inline
# so that CodeQL's `py/incomplete-url-substring-sanitization` query
# doesn't flag every assertion. The query pattern-matches
# ``<literal-with-dot> in <var>`` even when ``<var>`` is a tuple of
# hostnames (membership-by-equality, not substring); binding the host
# to a parameter sidesteps the false positive without changing what is
# checked.
_REQUIRED_HOSTS = (
    "api.osv.dev",                    # OSV advisory database
    "www.cisa.gov",                   # CISA KEV
    "api.first.org",                  # FIRST.org EPSS
    "pypi.org",                       # PyPI registry
    "registry.npmjs.org",             # npm registry
    "crates.io",                      # Cargo registry
    "rubygems.org",                   # RubyGems registry
    "proxy.golang.org",               # Go proxy
    "api.nuget.org",                  # NuGet registry
    "repo.maven.apache.org",          # Maven Central
    "repo.packagist.org",             # Packagist (PHP)
    "files.pythonhosted.org",         # source-archive downloads (version-diff)
    "api.github.com",                 # GitHub API (rate-limited public refs)
)


class TestScaAllowedHosts:

    def test_is_tuple(self):
        """Immutable — accidental mutation is a security regression."""
        assert isinstance(SCA_ALLOWED_HOSTS, tuple)

    def test_not_empty(self):
        assert len(SCA_ALLOWED_HOSTS) > 0

    @pytest.mark.parametrize("host", _REQUIRED_HOSTS)
    def test_required_host_present(self, host):
        """Every host the SCA pipeline relies on must be in the allowlist."""
        assert host in SCA_ALLOWED_HOSTS

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

        # Patch both the module alias and the import inside
        # run_sca_subprocess.
        with patch("packages.sca.agent.sandbox_run", fake_sandbox_run,
                   create=True), \
             patch("core.sandbox.run", fake_sandbox_run):
            _rc, _stdout, _stderr = run_sca_subprocess(
                agent, tmp_path, tmp_path / "out",
            )

        assert captured_kwargs.get("use_egress_proxy") is True
        proxy_hosts = captured_kwargs.get("proxy_hosts", [])
        assert set(SCA_ALLOWED_HOSTS) <= set(proxy_hosts)
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


# ---------------------------------------------------------------------------
# compose_proxy_hosts — repo-derived host validation + logging
# ---------------------------------------------------------------------------

class TestComposeProxyHostsRepoDerived:
    """Repo manifests are untrusted input: every image-ref / chart-dep
    host must pass hostname-shape validation before landing on the
    egress allowlist, and the additions must be logged once per run."""

    @pytest.fixture()
    def _stub_sources(self, monkeypatch):
        """Route both repo-derived sources through test-controlled
        lists; the LLM / private-registry sections stay live (they
        are operator-level, not repo-derived)."""
        import packages.sca.dockerfile_from as dfrom
        import packages.sca.parsers.helm_chart as helm

        def set_hosts(image_hosts=(), chart_hosts=()):
            monkeypatch.setattr(
                dfrom, "image_source_registry_hosts",
                lambda target: list(image_hosts),
            )
            monkeypatch.setattr(
                helm, "chart_repository_hosts",
                lambda target: list(chart_hosts),
            )
        return set_hosts

    def test_valid_hosts_added_and_logged(
        self, tmp_path, caplog, _stub_sources,
    ):
        from packages.sca import compose_proxy_hosts
        _stub_sources(image_hosts=["ghcr.io", "quay.io"],
                      chart_hosts=["charts.bitnami.com"])
        with caplog.at_level("WARNING", logger="packages.sca"):
            hosts = compose_proxy_hosts(tmp_path)
        assert "ghcr.io" in hosts
        assert "quay.io" in hosts
        assert "charts.bitnami.com" in hosts
        added_lines = [r.getMessage() for r in caplog.records
                       if "repo-derived hosts added" in r.getMessage()]
        assert len(added_lines) == 1        # one line per run
        assert "image refs: ghcr.io, quay.io" in added_lines[0]
        assert "chart deps: charts.bitnami.com" in added_lines[0]

    def test_malformed_hosts_rejected_and_logged(
        self, tmp_path, caplog, _stub_sources,
    ):
        from packages.sca import compose_proxy_hosts
        bad = [
            "evil.example.com/path",         # path-carrying
            "http://evil.example.com",       # scheme-carrying
            "evil host.example.com",         # whitespace
            " evil.example.com",             # padded
            "evil.example.com:5000",         # non-standard port
            "a@evil.example.com",            # userinfo
            "evil.example.com,other.io",     # separator smuggling
            "",                              # empty
        ]
        _stub_sources(image_hosts=bad + ["good.example.com"])
        with caplog.at_level("WARNING", logger="packages.sca"):
            hosts = compose_proxy_hosts(tmp_path)
        assert "good.example.com" in hosts
        for raw in bad:
            assert raw not in hosts
        rejected_lines = [r.getMessage() for r in caplog.records
                          if "rejected malformed" in r.getMessage()]
        assert len(rejected_lines) == 1
        assert "evil.example.com/path" in rejected_lines[0]

    def test_standard_port_stripped_to_hostname(
        self, tmp_path, caplog, _stub_sources,
    ):
        """The proxy allowlist is hostname-keyed — a :443 / :80
        suffix is tolerated and stripped; other ports are rejected
        (see test above)."""
        from packages.sca import compose_proxy_hosts
        _stub_sources(image_hosts=["reg.example.com:443",
                                    "alt.example.com:80"])
        with caplog.at_level("WARNING", logger="packages.sca"):
            hosts = compose_proxy_hosts(tmp_path)
        assert "reg.example.com" in hosts
        assert "alt.example.com" in hosts
        assert "reg.example.com:443" not in hosts

    def test_operator_registry_port_env_admits_host(
        self, tmp_path, monkeypatch, _stub_sources,
    ):
        """RAPTOR_SCA_REGISTRY_PORTS (operator config, never repo-
        derived) widens the tolerated port set so self-hosted
        registries like reg.corp:5000 keep their base-image SBOM
        fetches. The port is still stripped for the hostname-keyed
        allowlist."""
        from packages.sca import compose_proxy_hosts
        monkeypatch.setenv("RAPTOR_SCA_REGISTRY_PORTS", "5000, 8081")
        _stub_sources(image_hosts=["reg.corp:5000",
                                    "mirror.corp:8081",
                                    "evil.example.com:9999"])
        hosts = compose_proxy_hosts(tmp_path)
        assert "reg.corp" in hosts
        assert "mirror.corp" in hosts
        assert "evil.example.com" not in hosts   # port not declared

    def test_operator_registry_port_env_rejects_garbage(
        self, tmp_path, monkeypatch, _stub_sources, caplog,
    ):
        """Invalid env entries are ignored (warned), never widen."""
        from packages.sca import compose_proxy_hosts
        monkeypatch.setenv("RAPTOR_SCA_REGISTRY_PORTS",
                           "0, 70000, abc, -1")
        _stub_sources(image_hosts=["reg.corp:5000"])
        with caplog.at_level("WARNING", logger="packages.sca"):
            hosts = compose_proxy_hosts(tmp_path)
        assert "reg.corp" not in hosts

    def test_no_target_no_repo_derived_section(self, caplog):
        """``target=None`` short-circuits before the repo-derived
        section — no added/rejected log lines."""
        from packages.sca import compose_proxy_hosts
        with caplog.at_level("WARNING", logger="packages.sca"):
            compose_proxy_hosts(None)
        assert not [r for r in caplog.records
                    if "repo-derived hosts added" in r.getMessage()]
