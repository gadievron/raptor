"""Tests for ``packages.sca.bump.gha_action_image``.

The resolver fetches ``action.yml`` from raw.githubusercontent.com
and identifies Docker-container actions that point at a pre-built
image (the only shape we can capability-diff). Tests use a stub
HttpClient so we don't hit the network.
"""

from __future__ import annotations

from typing import Dict, List, Optional


from packages.sca.bump.gha_action_image import (
    _parse_docker_action_image,
    resolve_gha_action_image,
)


# ---------------------------------------------------------------------------
# Stub HTTP client
# ---------------------------------------------------------------------------


class _StubHttp:
    """Minimal HttpClient stand-in.

    ``responses`` maps URL → bytes (200 response) or exception
    (raised by ``get_bytes``). Missing URLs → KeyError surfaced as
    exception (caller's ``except`` handles it).
    """

    def __init__(self, responses: Optional[Dict[str, object]] = None):
        self.responses = responses or {}
        self.urls_fetched: List[str] = []

    def get_bytes(self, url, *, max_bytes=None, **kwargs):
        self.urls_fetched.append(url)
        if url not in self.responses:
            raise RuntimeError(f"no stub for {url}")
        v = self.responses[url]
        if isinstance(v, BaseException):
            raise v
        return v


# ---------------------------------------------------------------------------
# _parse_docker_action_image — unit coverage of the YAML parser
# ---------------------------------------------------------------------------


class TestParseDockerActionImage:
    def test_docker_uri_image_stripped(self):
        text = """name: My Action
runs:
  using: docker
  image: docker://ghcr.io/owner/img:1.2.3
"""
        assert _parse_docker_action_image(text) == (
            "ghcr.io/owner/img:1.2.3"
        )

    def test_plain_image_returned_as_is(self):
        """``image: alpine:3.18`` (no ``docker://`` URI) is also
        valid GHA syntax."""
        text = """runs:
  using: docker
  image: ghcr.io/owner/img:v2
"""
        assert _parse_docker_action_image(text) == "ghcr.io/owner/img:v2"

    def test_using_node20_returns_none(self):
        """JS action — no image to extract."""
        text = """runs:
  using: node20
  main: index.js
"""
        assert _parse_docker_action_image(text) is None

    def test_using_composite_returns_none(self):
        text = """runs:
  using: composite
  steps: []
"""
        assert _parse_docker_action_image(text) is None

    def test_docker_with_dockerfile_returns_none(self):
        """Dockerfile-referenced image needs a build step we don't
        run. Skip."""
        text = """runs:
  using: docker
  image: Dockerfile
"""
        assert _parse_docker_action_image(text) is None

    def test_relative_path_dockerfile_returns_none(self):
        text = """runs:
  using: docker
  image: ./Dockerfile
"""
        assert _parse_docker_action_image(text) is None

    def test_subdir_dockerfile_returns_none(self):
        text = """runs:
  using: docker
  image: build/Dockerfile
"""
        assert _parse_docker_action_image(text) is None

    def test_dockerfile_extension_returns_none(self):
        """Files ending in ``.dockerfile`` are also build-time."""
        text = """runs:
  using: docker
  image: app.dockerfile
"""
        assert _parse_docker_action_image(text) is None

    def test_using_case_insensitive(self):
        text = """runs:
  using: Docker
  image: img:1
"""
        assert _parse_docker_action_image(text) == "img:1"

    def test_no_runs_block_returns_none(self):
        assert _parse_docker_action_image("name: Solo\n") is None

    def test_missing_image_returns_none(self):
        text = """runs:
  using: docker
"""
        assert _parse_docker_action_image(text) is None

    def test_empty_image_returns_none(self):
        text = """runs:
  using: docker
  image: ""
"""
        assert _parse_docker_action_image(text) is None

    def test_malformed_yaml_returns_none(self):
        # Unclosed bracket — yaml.SafeLoader raises.
        assert _parse_docker_action_image(
            "runs: {using: docker, image:[\n",
        ) is None

    def test_non_mapping_top_level_returns_none(self):
        assert _parse_docker_action_image("- just\n- a\n- list\n") is None


# ---------------------------------------------------------------------------
# resolve_gha_action_image — full fetch + parse path
# ---------------------------------------------------------------------------


class TestResolveGhaActionImage:
    def test_resolves_yml_extension(self):
        """``action.yml`` is tried first."""
        http = _StubHttp({
            "https://raw.githubusercontent.com/owner/repo/v1/action.yml":
                b"runs:\n  using: docker\n  image: img:v1\n",
        })
        out = resolve_gha_action_image("owner/repo", "v1", http=http)
        assert out is not None
        assert out.repo == "owner/repo"
        assert out.ref == "v1"
        assert out.image_ref == "img:v1"

    def test_falls_back_to_yaml_extension(self):
        """``.yml`` fetch fails → try ``.yaml``."""
        http = _StubHttp({
            "https://raw.githubusercontent.com/owner/repo/v1/action.yml":
                RuntimeError("404"),
            "https://raw.githubusercontent.com/owner/repo/v1/action.yaml":
                b"runs:\n  using: docker\n  image: img:v1\n",
        })
        out = resolve_gha_action_image("owner/repo", "v1", http=http)
        assert out is not None
        assert out.image_ref == "img:v1"
        # Both URLs were tried
        assert any(
            "action.yml" in u for u in http.urls_fetched
        )
        assert any(
            "action.yaml" in u for u in http.urls_fetched
        )

    def test_both_extensions_fail_returns_none(self):
        http = _StubHttp({
            "https://raw.githubusercontent.com/owner/repo/v1/action.yml":
                RuntimeError("404"),
            "https://raw.githubusercontent.com/owner/repo/v1/action.yaml":
                RuntimeError("404"),
        })
        assert resolve_gha_action_image(
            "owner/repo", "v1", http=http,
        ) is None

    def test_js_action_returns_none(self):
        http = _StubHttp({
            "https://raw.githubusercontent.com/owner/repo/v1/action.yml":
                b"runs:\n  using: node20\n  main: index.js\n",
        })
        out = resolve_gha_action_image("owner/repo", "v1", http=http)
        assert out is None

    def test_dockerfile_action_returns_none(self):
        http = _StubHttp({
            "https://raw.githubusercontent.com/owner/repo/v1/action.yml":
                b"runs:\n  using: docker\n  image: Dockerfile\n",
        })
        out = resolve_gha_action_image("owner/repo", "v1", http=http)
        assert out is None

    def test_unicode_decode_failure_returns_none(self):
        http = _StubHttp({
            "https://raw.githubusercontent.com/owner/repo/v1/action.yml":
                # invalid utf-8
                b"\xff\xfe\x00\x00binary",
            "https://raw.githubusercontent.com/owner/repo/v1/action.yaml":
                b"\xff\xfe",
        })
        out = resolve_gha_action_image("owner/repo", "v1", http=http)
        assert out is None
