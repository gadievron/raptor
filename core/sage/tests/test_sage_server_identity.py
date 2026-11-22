"""Server-identity gate for the SAGE sidecar's loopback endpoints.

The SAGE transport authenticates the caller (Ed25519 request signing)
but nothing authenticates the SERVER: /health is spoofable, and with
the container down any same-host process can bind the published
loopback port and serve forged recall rows. The gate
(``core.sage.server_identity``) refuses to construct a client unless
docker reports the compose-pinned image publishing the target port —
dockerd holds that binding, so an unprivileged local process cannot
squat it, and an adversary with docker control is already over the
privilege boundary.

All tests are hermetic: ``run_cli`` is mocked at the gate's import
binding, so no docker CLI, containers, or network are touched. The
package conftest neutralises the gate at the ``core.sage.client``
binding for the REST of the suite; the wiring tests here re-patch
that binding in-test (the later patch wins).
"""

from __future__ import annotations

import types
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import core.sage.client as client_mod
import core.sage.server_identity as si
from core.container.proc import RunOutcome
from core.sage.config import SageConfig

SAGE_URL = "http://localhost:8090"


def _outcome(stdout: str = "", *, returncode: int | None = 0,
             stderr: str = "", timed_out: bool = False,
             truncated: bool = False) -> RunOutcome:
    return RunOutcome(returncode=returncode, stdout=stdout, stderr=stderr,
                      timed_out=timed_out, truncated=truncated)


@pytest.fixture(autouse=True)
def _fresh_gate():
    si._cache.clear()
    si._warned.clear()
    yield
    si._cache.clear()
    si._warned.clear()


@pytest.fixture
def docker(monkeypatch):
    """Scriptable `docker ps`: set ``docker.outcome``; ``docker.calls``
    counts invocations and ``docker.cmds`` records them."""
    state = SimpleNamespace(outcome=_outcome(), calls=0, cmds=[])

    def fake_run_cli(cmd, *, timeout, **kwargs):
        state.calls += 1
        state.cmds.append(cmd)
        return state.outcome

    monkeypatch.setattr(si, "run_cli", fake_run_cli)
    return state


class TestComposePin:
    def test_sage_pin_is_the_digest_reference(self):
        ref = si.compose_pinned_image("sage")
        assert ref is not None
        assert ref.startswith("ghcr.io/l33tdawg/sage:")
        assert "@sha256:" in ref

    def test_ollama_pin_is_the_digest_reference(self):
        ref = si.compose_pinned_image("ollama")
        assert ref is not None
        assert ref.startswith("ollama/ollama:")
        assert "@sha256:" in ref

    def test_unknown_service_has_no_pin(self):
        assert si.compose_pinned_image("impostor") is None


class TestGateVerdicts:
    def test_pinned_image_publishing_the_port_serves(self, docker):
        docker.outcome = _outcome(si.compose_pinned_image("sage") + "\n")
        assert si.server_identity_ok(SAGE_URL, "sage") is True
        # The probe filtered on the URL's port.
        assert any("publish=8090" in part for part in docker.cmds[0])

    def test_digest_normalised_reference_still_vouches(self, docker):
        pinned = si.compose_pinned_image("sage")
        digest = pinned.partition("@")[2]
        docker.outcome = _outcome(f"ghcr.io/l33tdawg/sage@{digest}\n")
        assert si.server_identity_ok(SAGE_URL, "sage") is True

    def test_repo_tag_form_of_the_pin_still_vouches(self, docker):
        pinned = si.compose_pinned_image("sage")
        docker.outcome = _outcome(pinned.partition("@")[0] + "\n")
        assert si.server_identity_ok(SAGE_URL, "sage") is True

    def test_other_image_on_the_port_refuses(self, docker):
        docker.outcome = _outcome("evil/lookalike:latest\n")
        assert si.server_identity_ok(SAGE_URL, "sage") is False

    def test_no_container_on_the_port_refuses_and_names_remedies(
            self, docker, caplog):
        docker.outcome = _outcome("")
        with caplog.at_level("WARNING"):
            assert si.server_identity_ok(SAGE_URL, "sage") is False
        text = caplog.text
        assert "raptor-sage-setup" in text
        assert "SAGE_SERVER_TRUSTED" in text

    def test_docker_missing_refuses(self, docker):
        docker.outcome = _outcome(
            returncode=None, stderr="command_not_found: docker")
        assert si.server_identity_ok(SAGE_URL, "sage") is False

    def test_docker_timeout_refuses(self, docker):
        docker.outcome = _outcome(returncode=None, timed_out=True)
        assert si.server_identity_ok(SAGE_URL, "sage") is False

    def test_truncated_ps_output_refuses(self, docker):
        # A head-dropped listing could have lost the squatter's line —
        # parsing consumers refuse truncated outcomes.
        docker.outcome = _outcome(
            si.compose_pinned_image("sage") + "\n", truncated=True)
        assert si.server_identity_ok(SAGE_URL, "sage") is False

    def test_unparseable_url_refuses(self, docker):
        assert si.server_identity_ok("http://", "sage") is False
        assert docker.calls == 0

    def test_hostile_image_name_is_escaped_in_the_warning(
            self, docker, caplog):
        docker.outcome = _outcome("evil\x1b]0;spoof\x07img:1\n")
        with caplog.at_level("WARNING"):
            assert si.server_identity_ok(SAGE_URL, "sage") is False
        assert "\x1b" not in caplog.text
        assert "\\x1b" in caplog.text


class TestBypasses:
    def test_non_loopback_url_is_out_of_gate_scope(self, docker):
        assert si.server_identity_ok("http://sage.internal:8090", "sage")
        assert docker.calls == 0

    def test_operator_trust_flag_skips_the_probe(self, docker, monkeypatch):
        monkeypatch.setenv("SAGE_SERVER_TRUSTED", "1")
        assert si.server_identity_ok(SAGE_URL, "sage") is True
        assert docker.calls == 0

    def test_falsy_trust_flag_does_not_skip(self, docker, monkeypatch):
        monkeypatch.setenv("SAGE_SERVER_TRUSTED", "0")
        docker.outcome = _outcome("")
        assert si.server_identity_ok(SAGE_URL, "sage") is False
        assert docker.calls == 1


class TestVerdictCache:
    def test_verdict_is_cached_within_ttl(self, docker):
        docker.outcome = _outcome(si.compose_pinned_image("sage") + "\n")
        assert si.server_identity_ok(SAGE_URL, "sage") is True
        assert si.server_identity_ok(SAGE_URL, "sage") is True
        assert docker.calls == 1

    def test_expired_verdict_reprobes(self, docker, monkeypatch):
        clock = [1000.0]
        monkeypatch.setattr(
            si, "time", types.SimpleNamespace(monotonic=lambda: clock[0]))
        docker.outcome = _outcome(si.compose_pinned_image("sage") + "\n")
        assert si.server_identity_ok(SAGE_URL, "sage") is True
        clock[0] += si._GATE_TTL_SECONDS + 1.0
        # The sidecar died and a squatter took the port — the re-probe
        # must notice rather than serve the stale verdict.
        docker.outcome = _outcome("evil/lookalike:latest\n")
        assert si.server_identity_ok(SAGE_URL, "sage") is False
        assert docker.calls == 2

    def test_services_cache_independently(self, docker):
        docker.outcome = _outcome(si.compose_pinned_image("sage") + "\n")
        assert si.server_identity_ok(SAGE_URL, "sage") is True
        docker.outcome = _outcome("")
        assert si.server_identity_ok("http://localhost:11435", "ollama") \
            is False
        assert docker.calls == 2


class _DummyIdentity:
    @classmethod
    def default(cls):
        return cls()

    @classmethod
    def from_file(cls, path):
        return cls()


class TestClientWiring:
    """The gate verdict decides client acquisition in core.sage.client
    (overriding the package conftest's always-True patch in-test)."""

    @pytest.fixture
    def fake_sdk(self, monkeypatch):
        monkeypatch.setattr(client_mod, "_ensure_sdk", lambda: True)
        monkeypatch.setattr(client_mod, "_AgentIdentity", _DummyIdentity)
        monkeypatch.setattr(
            client_mod, "_SyncSageClient",
            lambda **kwargs: SimpleNamespace(**kwargs))
        monkeypatch.setattr(
            client_mod, "harden_identity_key_perms", lambda p=None: None)

    def test_get_client_refuses_on_gate_refusal(
            self, fake_sdk, monkeypatch):
        monkeypatch.setattr(
            client_mod, "server_identity_ok", lambda url, service: False)
        sc = client_mod.SageClient(SageConfig(enabled=True))
        assert sc._get_client() is None

    def test_get_client_serves_on_gate_pass(self, fake_sdk, monkeypatch):
        seen = []

        def gate(url, service):
            seen.append((url, service))
            return True

        monkeypatch.setattr(client_mod, "server_identity_ok", gate)
        sc = client_mod.SageClient(SageConfig(enabled=True))
        assert sc._get_client() is not None
        assert seen == [(SAGE_URL, "sage")]

    def test_gate_rechecked_on_every_acquisition(
            self, fake_sdk, monkeypatch):
        # A cached SDK client must not outlive the verdict: when the
        # sidecar dies mid-session, the next acquisition refuses.
        verdicts = iter([True, False])
        monkeypatch.setattr(
            client_mod, "server_identity_ok",
            lambda url, service: next(verdicts))
        sc = client_mod.SageClient(SageConfig(enabled=True))
        assert sc._get_client() is not None
        assert sc._get_client() is None

    def test_is_available_false_on_gate_refusal(
            self, fake_sdk, monkeypatch):
        # A squatter answering /health with 200 must still read as
        # down — the gate runs before the health probe.
        monkeypatch.setattr(
            client_mod, "server_identity_ok", lambda url, service: False)
        resp = MagicMock(status_code=200)
        resp.json.return_value = {"status": "healthy"}
        import httpx
        monkeypatch.setattr(httpx, "get", lambda *a, **k: resp)
        sc = client_mod.SageClient(SageConfig(enabled=True))
        assert sc.is_available() is False

    def test_is_available_true_on_gate_pass(self, fake_sdk, monkeypatch):
        resp = MagicMock(status_code=200)
        resp.json.return_value = {"status": "healthy"}
        import httpx
        monkeypatch.setattr(httpx, "get", lambda *a, **k: resp)
        sc = client_mod.SageClient(SageConfig(enabled=True))
        assert sc.is_available() is True


class TestOllamaWiring:
    def test_direct_embed_refuses_on_gate_refusal(self, monkeypatch):
        posts = []
        import httpx
        monkeypatch.setattr(
            httpx, "post", lambda *a, **k: posts.append(a) or MagicMock())
        monkeypatch.setattr(
            client_mod, "server_identity_ok", lambda url, service: False)
        assert client_mod._embed_via_ollama("text") is None
        assert posts == []

    def test_direct_embed_serves_on_gate_pass(self, monkeypatch):
        seen = []

        def gate(url, service):
            seen.append(service)
            return True

        monkeypatch.setattr(client_mod, "server_identity_ok", gate)
        resp = MagicMock(status_code=200)
        resp.json.return_value = {"embeddings": [[0.5, 0.25]]}
        import httpx
        monkeypatch.setattr(httpx, "post", lambda *a, **k: resp)
        assert client_mod._embed_via_ollama("text") == [0.5, 0.25]
        assert seen == ["ollama"]
