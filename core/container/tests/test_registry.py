"""Contract tests for core.container.registry — probe mechanics."""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

from core.container import registry as rg
from core.container.proc import RunOutcome

# ── candidates ────────────────────────────────────────────────────────


def test_cascade_mirrors_first_hub_last() -> None:
    refs = rg.candidate_refs("redis", "7.0")
    assert refs[0] == "mirror.gcr.io/library/redis:7.0"
    assert refs[1] == "public.ecr.aws/docker/library/redis:7.0"
    assert refs.index("redis:7.0") > refs.index("mcr.microsoft.com/redis:7.0")
    assert "vulhub/redis:7.0" in refs
    assert len(refs) == len(set(refs))  # deduped


def test_empty_inputs_yield_no_candidates() -> None:
    assert rg.candidate_refs("", "7.0") == []
    assert rg.candidate_refs("redis", "  ") == []


# ── registry token normalization + denylist ──────────────────────────


def test_normalize_token_strips_scheme_port_path() -> None:
    assert rg.normalize_registry_token("https://Mirror.GCR.io:443/v2/") == \
        "mirror.gcr.io"
    assert rg.normalize_registry_token("index.docker.io") == "docker.io"
    assert rg.normalize_registry_token("dockerhub") == "docker.io"
    assert rg.normalize_registry_token("") == ""


def test_deny_dockerhub_drops_bare_and_library_refs() -> None:
    refs = rg.candidate_refs("redis", "7.0")
    kept = rg.filter_denied_registries(refs, "docker.io")
    assert all("docker.io" not in c for c in kept)
    assert "redis:7.0" not in kept
    assert "library/redis:7.0" not in kept
    assert "vulhub/redis:7.0" not in kept
    assert "mirror.gcr.io/library/redis:7.0" in kept


def test_deny_named_mirror_only() -> None:
    refs = rg.candidate_refs("redis", "7.0")
    kept = rg.filter_denied_registries(refs, "https://mirror.gcr.io")
    assert "mirror.gcr.io/library/redis:7.0" not in kept
    assert "redis:7.0" in kept


def test_empty_denylist_is_noop() -> None:
    refs = rg.candidate_refs("redis", "7.0")
    assert rg.filter_denied_registries(refs, "") == refs
    assert rg.filter_denied_registries(refs, " , ") == refs


# ── failure classification ────────────────────────────────────────────


def test_429_classified_rate_limited_not_transport() -> None:
    assert rg.classify_inspect_failure(
        "received unexpected HTTP status: 429 Too Many Requests"
    ) == "rate_limited"
    assert rg.classify_inspect_failure("toomanyrequests: slow down") == \
        "rate_limited"


def test_classify_permanent_and_transient() -> None:
    assert rg.classify_inspect_failure("manifest unknown") == "not_found"
    assert rg.classify_inspect_failure("unauthorized") == "auth"
    assert rg.classify_inspect_failure("i/o timeout") == "transport"
    assert rg.classify_inspect_failure("") == "transport"
    assert rg.classify_inspect_failure("mystery") == "transport"


def test_worst_class_priority() -> None:
    assert rg.worst_inspect_class({"not_found", "rate_limited"}) == \
        "rate_limited"
    assert rg.worst_inspect_class({"auth", "transport"}) == "transport"
    assert rg.worst_inspect_class({"not_found", "auth"}) == "auth"
    assert rg.worst_inspect_class(set()) == "not_found"


# ── payload parsing + digest pick/pin ─────────────────────────────────

_LIST_PAYLOAD = [
    {"Descriptor": {"platform": {"os": "linux", "architecture": "amd64"},
                    "digest": "sha256:aaa"}},
    {"Descriptor": {"platform": {"os": "linux", "architecture": "arm64"},
                    "digest": "sha256:bbb"}},
    # BuildKit cache entry — advertised platform, no runtime bytes.
    {"Descriptor": {"platform": {"os": "unknown", "architecture": "unknown"},
                    "digest": "sha256:ccc"}},
    # Duplicate platform — first digest wins.
    {"Descriptor": {"platform": {"os": "linux", "architecture": "amd64"},
                    "digest": "sha256:ddd"}},
]


def test_parse_manifest_list_payload() -> None:
    platforms, digests = rg.parse_inspect_payload(_LIST_PAYLOAD)
    assert "linux/amd64" in platforms and "linux/arm64" in platforms
    assert "unknown/unknown" not in platforms
    assert digests["linux/amd64"] == "sha256:aaa"  # first wins


def test_parse_single_descriptor_payload() -> None:
    single = {"Descriptor": {"platform": {"os": "linux",
                                          "architecture": "amd64"},
                             "digest": "sha256:eee"}}
    platforms, digests = rg.parse_inspect_payload(single)
    assert platforms == ["linux/amd64"]
    assert digests == {"linux/amd64": "sha256:eee"}


def test_pin_digest_ref() -> None:
    assert rg.pin_digest_ref("redis:7.0", "sha256:x") == "redis@sha256:x"
    assert rg.pin_digest_ref("redis", "sha256:x") == "redis@sha256:x"


def test_pick_digest_native_then_rosetta_then_none() -> None:
    per_arch = {"linux/amd64": "sha256:a", "linux/arm64": "sha256:b"}
    assert rg.pick_digest_for_host(
        per_arch, host_platform="linux/arm64", rosetta_available=False
    ) == ("linux/arm64", "sha256:b")
    amd_only = {"linux/amd64": "sha256:a"}
    assert rg.pick_digest_for_host(
        amd_only, host_platform="linux/arm64", rosetta_available=True
    ) == ("linux/amd64", "sha256:a")
    assert rg.pick_digest_for_host(
        amd_only, host_platform="linux/arm64", rosetta_available=False
    ) is None


# ── probe retry policy ────────────────────────────────────────────────


def _outcome(rc: int | None, stdout: str = "", stderr: str = "",
             timed_out: bool = False) -> RunOutcome:
    return RunOutcome(returncode=rc, stdout=stdout, stderr=stderr,
                      timed_out=timed_out)


def test_probe_permanent_failure_no_retry() -> None:
    with patch.object(rg, "run_cli",
                      return_value=_outcome(1, stderr="manifest unknown")) as m:
        result, klass = rg.probe_manifest("x:1", sleep=lambda _s: None)
    assert result is None and klass == "not_found"
    assert m.call_count == 1


def test_probe_transient_retries_once_with_injected_sleep() -> None:
    slept: list[float] = []
    outcomes = [_outcome(1, stderr="i/o timeout"),
                _outcome(0, stdout='{"Descriptor": {"platform": '
                                   '{"os": "linux", "architecture": "amd64"},'
                                   ' "digest": "sha256:a"}}')]

    def run(cmd: list[str], **_kw: Any) -> RunOutcome:
        return outcomes.pop(0)

    with patch.object(rg, "run_cli", side_effect=run):
        result, klass = rg.probe_manifest("x:1", sleep=slept.append)
    assert klass == "ok" and result is not None
    assert slept == [rg.RETRY_BACKOFF_TRANSPORT_S]


def test_probe_missing_docker_cli_is_transport() -> None:
    with patch.object(rg, "run_cli",
                      return_value=_outcome(None,
                                            stderr="command_not_found: x")):
        result, klass = rg.probe_manifest("x:1", enable_retry=False)
    assert result is None and klass == "transport"


def test_probe_keeps_proxy_env_for_client_side_registry_call() -> None:
    """manifest inspect contacts the registry from the CLIENT process —
    the ambient proxy env must ride along (the daemon's proxy config
    only covers daemon-side pulls)."""
    seen: dict[str, Any] = {}

    def run(cmd: list[str], **kw: Any) -> RunOutcome:
        seen.update(kw)
        return _outcome(1, stderr="manifest unknown")

    with patch.object(rg, "run_cli", side_effect=run):
        rg.probe_manifest("x:1", enable_retry=False)
    assert seen.get("keep_env") == rg.PROXY_ENV_VARS


# ── probe authority allowlist (agent-shaped refs are untrusted) ───────


def test_candidate_refs_reject_authority_and_digest_smuggling() -> None:
    # ':' would smuggle a port-bearing registry authority into the bare
    # {product}:{version} candidates; '@' would smuggle a digest pin.
    assert rg.candidate_refs("10.0.0.1:5000/x", "1.0") == []
    assert rg.candidate_refs("nginx@sha256:abcd", "1.0") == []
    assert rg.candidate_refs("nginx x", "1.0") == []
    assert rg.candidate_refs("nginx", "1.0/../evil") == []
    assert rg.candidate_refs("nginx", "1.0:extra") == []
    # Documented pivot form: a mirror path (no ':' / '@') stays valid.
    refs = rg.candidate_refs("mirror.gcr.io/library/ubuntu", "22.04")
    assert "mirror.gcr.io/library/ubuntu:22.04" in refs


def test_registry_authority_resolution() -> None:
    assert rg.registry_authority("redis:7.0") == "docker.io"
    assert rg.registry_authority("library/redis:7.0") == "docker.io"
    assert rg.registry_authority("vulhub/redis:7.0") == "docker.io"
    assert rg.registry_authority("mirror.gcr.io/library/redis:7.0") == \
        "mirror.gcr.io"
    assert rg.registry_authority("localhost/x:1") == "localhost"
    assert rg.registry_authority("index.docker.io/library/x:1") == "docker.io"
    # Explicit ports are preserved — a port-bearing authority is a
    # DIFFERENT network endpoint and never inherits the bare host's
    # allowlisting (quay.io:8080 != quay.io).
    assert rg.registry_authority("10.0.0.1:5000/x:1") == "10.0.0.1:5000"
    assert rg.registry_authority("quay.io:8080/x:1") == "quay.io:8080"
    assert rg.registry_authority("index.docker.io:1337/x:1") == \
        "docker.io:1337"
    assert rg.registry_authority("[2001:db8::1]:5000/x:1") == \
        "2001:db8::1:5000"


def test_probe_denies_allowlisted_host_with_explicit_port(
        monkeypatch) -> None:
    """quay.io:8080 must not pass as quay.io (adversarial-review F4):
    the probe would otherwise be issued to an arbitrary port on an
    allowlisted host."""
    monkeypatch.delenv("RAPTOR_REGISTRY_ALLOW", raising=False)
    calls: list[list[str]] = []

    def spy(cmd: list[str], **_kw: Any) -> RunOutcome:
        calls.append(list(cmd))
        return RunOutcome(returncode=0, stdout="[]", stderr="",
                          timed_out=False)

    with patch.object(rg, "run_cli", side_effect=spy):
        for ref in ("quay.io:8080/x:1", "docker.io:1337/x:1",
                    "ghcr.io:22/x:1"):
            result, klass, _stderr = rg.probe_manifest_once(
                ref, timeout_seconds=5)
            assert result is None and klass == "denied", ref
    assert calls == []  # no probe ever issued


def test_probe_denies_off_allowlist_authority_without_network(
        monkeypatch) -> None:
    monkeypatch.delenv("RAPTOR_REGISTRY_ALLOW", raising=False)
    calls: list[list[str]] = []

    def spy(cmd: list[str], **_kw: Any) -> RunOutcome:
        calls.append(list(cmd))
        return RunOutcome(returncode=0, stdout="{}", stderr="",
                          timed_out=False)

    with patch.object(rg, "run_cli", side_effect=spy):
        result, klass, stderr = rg.probe_manifest_once(
            "10.0.0.1:5000/x:1", timeout_seconds=5)
    assert result is None and klass == "denied"
    assert "not in the probe allowlist" in stderr
    assert calls == []  # the probe was never issued

    # denied is permanent — probe_manifest must not burn a retry.
    with patch.object(rg, "run_cli", side_effect=spy):
        result, klass = rg.probe_manifest("internal.corp/x:1")
    assert result is None and klass == "denied" and calls == []


def test_probe_allowlist_operator_extension(monkeypatch) -> None:
    monkeypatch.setenv("RAPTOR_REGISTRY_ALLOW",
                       "https://registry.example:5000/v2/, my-mirror.local")
    hosts = rg.allowed_registry_hosts()
    # Port-bearing entries keep their port; bare entries stay bare.
    assert "registry.example:5000" in hosts and "my-mirror.local" in hosts
    assert rg.DEFAULT_REGISTRY_ALLOWLIST <= hosts

    def ok(cmd: list[str], **_kw: Any) -> RunOutcome:
        return RunOutcome(returncode=0, stdout="[]", stderr="",
                          timed_out=False)

    with patch.object(rg, "run_cli", side_effect=ok):
        _result, klass, _stderr = rg.probe_manifest_once(
            "registry.example:5000/x:1", timeout_seconds=5)
        assert klass != "denied"
        # The allowlisted endpoint is host:port — a different port (or
        # the bare host) on the same name stays denied.
        _result, klass, _stderr = rg.probe_manifest_once(
            "registry.example:9999/x:1", timeout_seconds=5)
        assert klass == "denied"
        _result, klass, _stderr = rg.probe_manifest_once(
            "registry.example/x:1", timeout_seconds=5)
        assert klass == "denied"
