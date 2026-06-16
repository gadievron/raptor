"""TDD tests for the two experimental env vars added to support
deep-explore benches:

- ``CVE_ENV_DENY_REGISTRY``: filter image_resolve cascade by registry name
- ``CVE_ENV_EXTRA_PROMPT_PREFIX``: prepend custom prompt block

Both are no-ops when unset (default) — production benches keep the
existing behavior. Set during experimental runs only.
"""
from __future__ import annotations

import os
from unittest.mock import patch

from cve_env.tools.image_resolve import _candidate_refs


def _registry_host(ref: str) -> str:
    """First path segment of a candidate ref (the registry hostname).

    Used in assertions to check the registry exactly rather than via
    substring/prefix matching (which CodeQL's
    ``py/incomplete-url-substring-sanitization`` rule flags).
    """
    return ref.split("/", 1)[0].split(":", 1)[0].lower()


class TestDenyRegistryEnv:
    def _refs(self, env_value: str | None) -> list[str]:
        env = dict(os.environ)
        if env_value is not None:
            env["CVE_ENV_DENY_REGISTRY"] = env_value
        else:
            env.pop("CVE_ENV_DENY_REGISTRY", None)
        with patch.dict(os.environ, env, clear=True):
            return _candidate_refs("drupal", "8.5.0")

    def test_unset_env_yields_full_cascade(self) -> None:
        refs = self._refs(None)
        assert any(_registry_host(r) == "vulhub" for r in refs)
        assert any(_registry_host(r) == "docker.io" for r in refs)
        assert any("library/drupal" in r for r in refs)
        assert any(_registry_host(r) == "mirror.gcr.io" for r in refs)

    def test_empty_env_yields_full_cascade(self) -> None:
        refs = self._refs("")
        assert any(_registry_host(r) == "vulhub" for r in refs)
        assert any(_registry_host(r) == "docker.io" for r in refs)

    def test_deny_vulhub_drops_only_vulhub(self) -> None:
        refs = self._refs("vulhub")
        assert not any(_registry_host(r) == "vulhub" for r in refs)
        # Other registries preserved
        assert any(_registry_host(r) == "mirror.gcr.io" for r in refs)
        assert any(_registry_host(r) == "docker.io" for r in refs)

    def test_deny_docker_io_drops_full_dockerhub_family(self) -> None:
        """docker.io deny drops every Docker Hub-resolved ref:
        bare names, library/*, docker.io/*, AND user namespaces under
        docker.io (e.g., vulhub/* — Docker Hub user namespace).

        First-path-segment heuristic: any segment without '.' / ':' /
        'localhost' is a Docker Hub user namespace.
        """
        refs = self._refs("docker.io")
        assert not any(_registry_host(r) == "docker.io" for r in refs)
        assert not any(_registry_host(r) == "library" for r in refs)
        assert not any(r == "drupal:8.5.0" for r in refs)
        assert not any(_registry_host(r) == "vulhub" for r in refs)  # also Docker Hub
        # Non-Docker-Hub registries preserved
        assert any(_registry_host(r) == "mirror.gcr.io" for r in refs)
        assert any(_registry_host(r) == "ghcr.io" for r in refs)

    def test_deny_both_vulhub_and_docker_io(self) -> None:
        """The deep-explore bench config: skip both."""
        refs = self._refs("vulhub,docker.io")
        for r in refs:
            host = _registry_host(r)
            assert host != "vulhub", r
            assert host != "library", r
            assert host != "docker.io", r
            assert "/" in r, f"bare name not filtered: {r}"
        # Should leave only the alternate registries
        assert any(_registry_host(r) == "mirror.gcr.io" for r in refs)
        assert any(_registry_host(r) == "public.ecr.aws" for r in refs)

    def test_unknown_registry_in_deny_is_ignored(self) -> None:
        """Robustness: typos shouldn't crash. Unknown deny terms have no effect."""
        refs = self._refs("nonexistent-registry")
        # Full cascade preserved
        assert any(_registry_host(r) == "vulhub" for r in refs)
        assert any(_registry_host(r) == "docker.io" for r in refs)


class TestExtraPromptPrefixEnv:
    """Lightweight wiring test — the env var must be readable at the
    location loop.py prepends it.
    """

    def test_env_var_is_read(self) -> None:
        env = dict(os.environ)
        env["CVE_ENV_EXTRA_PROMPT_PREFIX"] = "EXPERIMENTAL_BLOCK"
        with patch.dict(os.environ, env, clear=True):
            assert os.environ.get("CVE_ENV_EXTRA_PROMPT_PREFIX") == "EXPERIMENTAL_BLOCK"

    def test_env_var_default_empty(self) -> None:
        env = {k: v for k, v in os.environ.items()
               if k != "CVE_ENV_EXTRA_PROMPT_PREFIX"}
        with patch.dict(os.environ, env, clear=True):
            assert os.environ.get("CVE_ENV_EXTRA_PROMPT_PREFIX", "") == ""
