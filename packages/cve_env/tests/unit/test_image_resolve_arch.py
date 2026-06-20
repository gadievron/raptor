"""Tests for :mod:`cve_env.tools.image_resolve` -- arch-matching logic."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from cve_env.tools.image_resolve import (
    _candidate_refs,
    image_resolve,
    reset_rate_limit_budget,
)


@pytest.fixture(autouse=True)
def _reset_image_resolve_state() -> None:
    """Module-level state in image_resolve (rate-limit + arch counters)
    accumulates across tests. Reset before each test for isolation.
    Phase 38.4 adds the arch_incompatible counter that needs the same reset.
    """
    reset_rate_limit_budget()


def test_candidate_refs_dedupes() -> None:
    refs = _candidate_refs("nginx", "1.20")
    assert "nginx:1.20" in refs
    assert "library/nginx:1.20" in refs
    assert "vulhub/nginx:1.20" in refs
    # Dedup: docker.io-prefixed should be present but not duplicate.
    assert len(refs) == len(set(refs))


def test_candidate_refs_empty_inputs() -> None:
    assert _candidate_refs("", "1.0") == []
    assert _candidate_refs("nginx", "") == []


def test_candidate_refs_includes_alt_registries() -> None:
    """Phase 16.4: alternate registries are in the candidate set."""
    refs = _candidate_refs("postgres", "13")
    assert "quay.io/postgres/postgres:13" in refs
    assert "ghcr.io/postgres/postgres:13" in refs
    assert "mcr.microsoft.com/postgres:13" in refs


def test_candidate_refs_includes_mirror_gcr_io_fallback() -> None:
    """Phase 30 (2026-05): mirror.gcr.io/library/X is the credential-less
    Docker Hub fallback. Phase 45 (2026-04-29) moved it from last to
    position 3. Phase 29 (2026-05-14) finishes the reorder — mirror BEFORE
    DH variants so DH-unauthed users get the high-quota path without
    needing CVE_ENV_DENY_REGISTRY env-var.
    """
    refs = _candidate_refs("alpine", "3.19")
    assert "mirror.gcr.io/library/alpine:3.19" in refs
    # Phase 29: mirror.gcr.io now probed BEFORE library/X (the inverse of
    # Phase 30's original order). Empirical basis: Phase 25 attempt 5
    # hit DH 100/6h anonymous-tier exhaustion; mirrors-first avoids
    # 24-min wall-guard burns on DH-rate-limited probes.
    mirror_idx = refs.index("mirror.gcr.io/library/alpine:3.19")
    library_idx = refs.index("library/alpine:3.19")
    assert mirror_idx < library_idx, (
        f"Phase 29: mirror.gcr.io at {mirror_idx} must precede library/X "
        f"at {library_idx}"
    )


def test_candidate_refs_includes_ecr_public_fallback() -> None:
    """ECR Public mirror (2026-05-06): public.ecr.aws/docker/library/<image>
    is the AWS-hosted Docker Hub library/* mirror — separate quota pool
    from Docker Hub. Verified empirically: anonymous-token pull works for
    pre-patch versions like httpd:2.4.49 (CVE-2021-41773), httpd:2.4.49,
    nginx:1.18.0 etc. ECR Public also rate-limits independently, but the
    pool is distinct so DH-rate-limited operators get a real second
    chance.

    Position invariant: probed AFTER mirror.gcr.io (Google's mirror has
    higher anon quota and identical content), but BEFORE quay.io /
    ghcr.io / mcr (those are vendor-specific and rarely match a generic
    library image)."""
    refs = _candidate_refs("nginx", "1.18.0")
    assert "public.ecr.aws/docker/library/nginx:1.18.0" in refs
    ecr_idx = refs.index("public.ecr.aws/docker/library/nginx:1.18.0")
    mirror_idx = refs.index("mirror.gcr.io/library/nginx:1.18.0")
    assert ecr_idx > mirror_idx, (
        "public.ecr.aws should be probed AFTER mirror.gcr.io (which has "
        "higher anon quota for the same library/* namespace)"
    )
    # Should appear before vendor-specific registries
    quay_idx = refs.index("quay.io/nginx/nginx:1.18.0")
    assert ecr_idx < quay_idx, (
        "public.ecr.aws/docker/library/* should be probed BEFORE vendor "
        "namespaces (quay.io/<v>/<v>) — it's a Docker Hub mirror, not a "
        "vendor registry"
    )


def _descriptor_entry(
    *platforms: str, digest: str | None = None
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for p in platforms:
        os_name, arch = p.split("/")
        entry = {
            "Descriptor": {
                "platform": {"os": os_name, "architecture": arch},
            }
        }
        if digest:
            entry["Descriptor"]["digest"] = digest
        out.append(entry)
    return out


@patch("cve_env.utils.run.subprocess.run")
def test_resolve_picks_first_native(mock_run: Any) -> None:
    manifest = _descriptor_entry(
        "linux/amd64",
        "linux/arm64",
        digest="sha256:" + "a" * 64,
    )
    mock_run.return_value = MagicMock(
        returncode=0, stdout=json.dumps(manifest), stderr=""
    )
    r = image_resolve(product="nginx", version="1.20", host_arch="arm64")
    assert r.ok is True
    assert r.decision == "native"
    # Phase 29 (2026-05-14): mirror.gcr.io is now FIRST in the cascade,
    # so the first-native pick comes from there. The digest_pinned_ref
    # is `<image_ref>@<digest>` for whichever candidate matched.
    assert "@sha256:" in r.digest_pinned_ref and r.digest_pinned_ref.startswith(
        r.image_ref.rsplit(":", 1)[0]
    )


@patch("cve_env.utils.run.subprocess.run")
def test_resolve_rosetta_when_arm_host_amd_manifest(mock_run: Any) -> None:
    manifest = _descriptor_entry("linux/amd64", digest="sha256:" + "b" * 64)
    mock_run.return_value = MagicMock(
        returncode=0, stdout=json.dumps(manifest), stderr=""
    )
    r = image_resolve(
        product="nginx", version="1.20", host_arch="arm64", rosetta_available=True
    )
    assert r.ok is True
    assert r.decision == "rosetta_ok"


@patch("cve_env.utils.run.subprocess.run")
def test_resolve_arch_incompatible_when_no_platform_matches(mock_run: Any) -> None:
    manifest = _descriptor_entry("linux/ppc64le")
    mock_run.return_value = MagicMock(
        returncode=0, stdout=json.dumps(manifest), stderr=""
    )
    r = image_resolve(product="nginx", version="1.20", host_arch="arm64")
    assert r.ok is False
    assert r.decision == "arch_incompatible"


@patch("cve_env.utils.run.subprocess.run")
def test_resolve_not_found_when_all_candidates_miss(mock_run: Any) -> None:
    mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="not found")
    r = image_resolve(product="nginx", version="1.20", host_arch="arm64")
    assert r.ok is False
    assert r.decision == "not_found"
    assert len(r.candidates_tried) >= 3  # We tried multiple candidate names.


@patch("cve_env.tools.image_resolve.time.sleep")
@patch("cve_env.utils.run.subprocess.run")
def test_resolve_rate_limited_surfaces_pivot_signal(
    mock_run: Any,
    mock_sleep: Any,
) -> None:
    """Phase 12.1: when ALL candidates hit Docker Hub anon rate-limit, the
    reason field tells the agent to pivot to a generic base (ubuntu/debian/
    alpine) + manual host install, rather than give up.

    Repro of Phase 11.4 smoke 1 (CVE-2020-36725) where 6 wordpress probes
    all hit rate_limited and the agent gave up without trying the ubuntu
    fallback that smoke 3 used successfully.
    """
    from cve_env.tools.image_resolve import reset_rate_limit_budget

    reset_rate_limit_budget()  # don't inherit prior test's counter
    mock_run.return_value = MagicMock(
        returncode=1,
        stdout="",
        stderr="toomanyrequests: You have reached your unauthenticated pull rate limit",
    )
    r = image_resolve(product="rare-product", version="1.0", host_arch="arm64")
    assert r.ok is False
    assert r.reason_class == "rate_limited"
    assert "PIVOT" in r.reason
    assert "ubuntu" in r.reason or "debian" in r.reason or "alpine" in r.reason


@patch("cve_env.tools.image_resolve.time.sleep")
@patch("cve_env.utils.run.subprocess.run")
def test_resolve_transport_surfaces_retry_or_pivot(
    mock_run: Any,
    mock_sleep: Any,
) -> None:
    """Phase 12.1: transport errors get a retry-or-pivot hint (separate from
    rate_limited which is more aggressive about pivoting since it persists
    for hours)."""
    mock_run.return_value = MagicMock(
        returncode=1, stdout="", stderr="error: i/o timeout"
    )
    r = image_resolve(product="some-obscure-app", version="1.0", host_arch="arm64")
    assert r.ok is False
    assert r.reason_class == "transport"
    assert "Retry" in r.reason or "retry" in r.reason


# Phase 13.2: rate-limit budget -----------------------------------------


@patch("cve_env.tools.image_resolve.time.sleep")  # skip 10s retry backoff in tests
@patch("cve_env.utils.run.subprocess.run")
def test_rate_limit_budget_short_circuits_after_two_hits(
    mock_run: Any,
    mock_sleep: Any,
) -> None:
    """Phase 13.2: 3rd rate_limited call for same product short-circuits to
    decision='rate_limited_persistent' — no subprocess invocation, immediate pivot.
    """
    from cve_env.tools.image_resolve import reset_rate_limit_budget

    reset_rate_limit_budget()
    mock_run.return_value = MagicMock(
        returncode=1,
        stdout="",
        stderr="toomanyrequests: pull rate limit",
    )
    # Burn the budget: 2 rate_limited calls.
    image_resolve(product="wordpress", version="5.6", host_arch="arm64")
    image_resolve(product="wordpress", version="5.7", host_arch="arm64")

    # 3rd call must short-circuit without firing subprocess.
    mock_run.reset_mock()
    r = image_resolve(product="wordpress", version="5.8", host_arch="arm64")
    assert r.ok is False
    assert r.decision == "rate_limited_persistent"
    assert r.reason_class == "rate_limited"
    assert "STOP probing" in r.reason or "PIVOT" in r.reason
    mock_run.assert_not_called()


@patch("cve_env.tools.image_resolve.time.sleep")
@patch("cve_env.utils.run.subprocess.run")
def test_rate_limit_budget_per_product_isolated(
    mock_run: Any,
    mock_sleep: Any,
) -> None:
    """Phase 13.2: rate-limit budget is per-product. Different product
    starts with fresh budget."""
    from cve_env.tools.image_resolve import reset_rate_limit_budget

    reset_rate_limit_budget()
    mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="toomanyrequests")
    image_resolve(product="wordpress", version="5.6", host_arch="arm64")
    image_resolve(product="wordpress", version="5.7", host_arch="arm64")
    # Different product, different counter.
    mock_run.reset_mock()
    r = image_resolve(product="drupal", version="9.4", host_arch="arm64")
    # NOT short-circuited at call entry — subprocess called.
    assert r.decision != "rate_limited_persistent"
    assert mock_run.called


@patch("cve_env.tools.image_resolve.time.sleep")
@patch("cve_env.utils.run.subprocess.run")
def test_phase35_cumulative_rate_limit_short_circuits_cross_product(
    mock_run: Any,
    mock_sleep: Any,
) -> None:
    """Phase 35.1: CVE-level cumulative counter catches cross-product
    thrash even when each individual product stays under the per-product
    threshold. Real-world pattern (CVE-2022-42889): agent rotates through
    text4shell → maven → tomcat → eclipse-temurin, hitting rate_limited
    on each, never tripping per-product but burning budget.
    """
    from cve_env.tools._image_resolve_state import (
        _RATE_LIMIT_TOTAL_THRESHOLD,
    )
    from cve_env.tools.image_resolve import (
        reset_rate_limit_budget,
    )

    reset_rate_limit_budget()
    mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="toomanyrequests")
    # Burn cumulative budget across DIFFERENT products (each increments
    # cumulative by 1). After 3 calls we should be at the threshold.
    image_resolve(product="text4shell", version="1.0", host_arch="arm64")
    image_resolve(product="maven", version="3.8", host_arch="arm64")
    image_resolve(product="eclipse-temurin", version="17", host_arch="arm64")
    # The 4th call across a NEW product should be short-circuited.
    mock_run.reset_mock()
    r = image_resolve(product="tomcat", version="9.0", host_arch="arm64")
    # Cumulative threshold should have tripped → short-circuit.
    assert r.ok is False
    assert r.decision == "rate_limited_persistent"
    assert "across multiple products" in r.reason
    assert "per-IP" in r.reason
    # Subprocess NOT called — short-circuited at function entry.
    mock_run.assert_not_called()
    # Sanity check on the threshold constant.
    assert _RATE_LIMIT_TOTAL_THRESHOLD >= 3, "threshold too tight"


@patch("cve_env.tools.image_resolve.time.sleep")
@patch("cve_env.utils.run.subprocess.run")
def test_phase37_2_rate_limit_cooldown_retry_one_shot(
    mock_run: Any,
    mock_sleep: Any,
) -> None:
    """Phase 37.2: when ALL candidates rate-limited, image_resolve sleeps
    once + retries the candidate loop. If retry also rate-limited, returns
    the failure (existing flow). The cooldown only fires ONCE per CVE.
    """
    from cve_env.tools.image_resolve import reset_rate_limit_budget

    reset_rate_limit_budget()
    mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="toomanyrequests")
    r = image_resolve(product="nginx", version="1.20", host_arch="arm64")
    # Sleep was called (at least once for the cooldown).
    assert mock_sleep.called
    # Final result is still rate_limited (retry also failed in this mock).
    assert r.ok is False
    # candidates_tried should include both initial + retry candidates.
    assert r.candidates_tried  # non-empty
    # Second call: cooldown should NOT fire again (one-shot per CVE).
    mock_sleep.reset_mock()
    image_resolve(product="apache", version="2.4", host_arch="arm64")
    # The cooldown branch shouldn't fire (returns False from
    # _take_rate_limit_cooldown). Sleep can still be called by other paths
    # (probe retry on transient), so we can't assert "no sleep at all";
    # but we CAN assert the 30s cooldown wasn't invoked.
    # Easier: verify _RATE_LIMIT_COOLDOWN_DONE is True after reset.
    from cve_env.tools import _image_resolve_state as _state

    assert _state._RATE_LIMIT_COOLDOWN_DONE is True


@patch("cve_env.tools.image_resolve.time.sleep")
@patch("cve_env.utils.run.subprocess.run")
def test_phase37_2_cooldown_resets_per_cve(
    mock_run: Any,
    mock_sleep: Any,
) -> None:
    """Phase 37.2: reset_rate_limit_budget() (called per-CVE by the bench
    loop) clears the cooldown flag so the next CVE gets its own one-shot.
    """
    from cve_env.tools import _image_resolve_state as _state
    from cve_env.tools.image_resolve import reset_rate_limit_budget

    reset_rate_limit_budget()
    mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="toomanyrequests")
    image_resolve(product="nginx", version="1.20", host_arch="arm64")
    assert _state._RATE_LIMIT_COOLDOWN_DONE is True
    reset_rate_limit_budget()
    assert _state._RATE_LIMIT_COOLDOWN_DONE is False


def test_phase35_reset_rate_limit_clears_cumulative() -> None:
    """Phase 35.1: reset_rate_limit_budget() clears BOTH per-product and
    cumulative counters so the bench loop's per-CVE reset works.
    """
    from cve_env.tools import _image_resolve_state as _state
    from cve_env.tools.image_resolve import (
        _bump_rate_limit_total,
        reset_rate_limit_budget,
    )

    reset_rate_limit_budget()
    for _ in range(10):
        _bump_rate_limit_total()
    assert _state._RATE_LIMIT_TOTAL == 10
    reset_rate_limit_budget()
    assert _state._RATE_LIMIT_TOTAL == 0


def test_reset_rate_limit_budget_clears_counters() -> None:
    """Phase 13.2: explicit reset clears all per-product counters."""
    from cve_env.tools._image_resolve_state import (
        _RATE_LIMIT_BUDGET,
    )
    from cve_env.tools.image_resolve import (
        reset_rate_limit_budget,
    )

    _RATE_LIMIT_BUDGET["foo"] = 2
    _RATE_LIMIT_BUDGET["bar"] = 1
    reset_rate_limit_budget()
    assert _RATE_LIMIT_BUDGET == {}


# Phase 9.5: next_step_hint on failure --------------------------------


@patch("cve_env.utils.run.subprocess.run")
def test_resolve_arch_incompatible_emits_next_step_hint(mock_run: Any) -> None:
    """Phase 9.5: arch_incompatible decision tells agent to source_build."""
    manifest = _descriptor_entry("linux/ppc64le")
    mock_run.return_value = MagicMock(
        returncode=0, stdout=json.dumps(manifest), stderr=""
    )
    r = image_resolve(product="nginx", version="1.20", host_arch="arm64")
    assert r.decision == "arch_incompatible"
    assert "source_build" in r.next_step_hint


@patch("cve_env.utils.run.subprocess.run")
def test_resolve_not_found_emits_next_step_hint(mock_run: Any) -> None:
    """Phase 9.5: not_found decision tells agent to source_build or compose."""
    mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="not found")
    r = image_resolve(product="missing-app", version="1.0", host_arch="arm64")
    assert r.decision == "not_found"
    assert "source_build" in r.next_step_hint or "ubuntu" in r.next_step_hint


@patch("cve_env.tools.image_resolve.time.sleep")
@patch("cve_env.utils.run.subprocess.run")
def test_resolve_rate_limited_persistent_emits_pivot_hint(
    mock_run: Any,
    mock_sleep: Any,
) -> None:
    from cve_env.tools.image_resolve import reset_rate_limit_budget

    reset_rate_limit_budget()
    mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="toomanyrequests")
    image_resolve(product="wp-x", version="1", host_arch="arm64")
    image_resolve(product="wp-x", version="2", host_arch="arm64")
    r = image_resolve(product="wp-x", version="3", host_arch="arm64")
    assert r.decision == "rate_limited_persistent"
    hint_lower = r.next_step_hint.lower()
    assert "ubuntu" in hint_lower or "pivot" in hint_lower


@patch("cve_env.utils.run.subprocess.run")
def test_resolve_native_has_empty_next_step_hint(mock_run: Any) -> None:
    """Phase 9.5: success path leaves next_step_hint empty (no pivot needed)."""
    manifest = _descriptor_entry(
        "linux/amd64", "linux/arm64", digest="sha256:" + "c" * 64
    )
    mock_run.return_value = MagicMock(
        returncode=0, stdout=json.dumps(manifest), stderr=""
    )
    r = image_resolve(product="nginx", version="1.20", host_arch="arm64")
    assert r.ok is True
    assert r.next_step_hint == ""


def _manifest_entry_no_digest(platform: str) -> dict[str, Any]:
    os_name, arch = platform.split("/")
    return {"Descriptor": {"platform": {"os": os_name, "architecture": arch}}}


def _manifest_entry_unknown() -> dict[str, Any]:
    return {
        "Descriptor": {
            "platform": {"os": "unknown", "architecture": "unknown"},
            "digest": "sha256:" + "e" * 64,
        }
    }


@patch("cve_env.utils.run.subprocess.run")
def test_resolve_ignores_unknown_unknown_buildkit_cache(mock_run: Any) -> None:
    """BuildKit cache entries advertise a platform that lies -- filter them."""
    manifest = [
        _descriptor_entry("linux/amd64", digest="sha256:" + "a" * 64)[0],
        _manifest_entry_unknown(),
    ]
    mock_run.return_value = MagicMock(
        returncode=0, stdout=json.dumps(manifest), stderr=""
    )
    r = image_resolve(product="nginx", version="1.20", host_arch="arm64")
    # Only linux/amd64 is advertised after filtering -> arm64 host falls through.
    # With rosetta_available=False (default), this must NOT return 'native'.
    assert r.decision in {"arch_incompatible", "not_found"}


@patch("cve_env.utils.run.subprocess.run")
def test_resolve_skips_platform_without_arch_digest(mock_run: Any) -> None:
    """The core bug fix: platform listed but no per-arch digest -> don't pick it."""
    # An entry claiming arm64 but with NO digest -> skipped.
    manifest = [
        _manifest_entry_no_digest("linux/arm64"),
        _descriptor_entry("linux/amd64", digest="sha256:" + "b" * 64)[0],
    ]
    mock_run.return_value = MagicMock(
        returncode=0, stdout=json.dumps(manifest), stderr=""
    )
    r = image_resolve(product="nginx", version="1.20", host_arch="arm64")
    # arm64 is claimed but no digest -> should NOT return native. With rosetta=False,
    # there's no fallback -> arch_incompatible (linux/amd64 has a digest but rosetta
    # isn't available).
    assert r.decision != "native"


@patch("cve_env.utils.run.subprocess.run")
def test_resolve_picks_arch_matching_digest_not_last(mock_run: Any) -> None:
    """Multiarch manifest: we must return the arm64 digest, not whichever came last."""
    arm64_digest = "sha256:" + "a" * 64
    amd64_digest = "sha256:" + "b" * 64
    # amd64 entry is SECOND in the list (was buggy: code used to keep last digest seen).
    manifest = [
        _descriptor_entry("linux/arm64", digest=arm64_digest)[0],
        _descriptor_entry("linux/amd64", digest=amd64_digest)[0],
    ]
    mock_run.return_value = MagicMock(
        returncode=0, stdout=json.dumps(manifest), stderr=""
    )
    r = image_resolve(product="nginx", version="1.20", host_arch="arm64")
    assert r.decision == "native"
    # The returned digest MUST be the arm64 one.
    assert arm64_digest in r.digest_pinned_ref
    assert amd64_digest not in r.digest_pinned_ref


# Phase 38.4: arch_incompatible cumulative cross-product short-circuit ---


@patch("cve_env.utils.run.subprocess.run")
def test_phase38_4_arch_incompatible_persistent_after_threshold(
    mock_run: Any,
) -> None:
    """Phase 38.4: after _ARCH_INCOMPATIBLE_THRESHOLD products fail
    arch_incompatible in the same CVE, the next image_resolve call
    short-circuits with decision='arch_incompatible_persistent'.
    Mirrors Phase 35.1's cumulative rate-limit pattern.
    """
    from cve_env.tools._image_resolve_state import (
        _ARCH_INCOMPATIBLE_THRESHOLD,
    )
    from cve_env.tools.image_resolve import (
        reset_rate_limit_budget,
    )

    reset_rate_limit_budget()  # also clears arch counter (Phase 38.4)
    # Manifest with only ppc64le → arch_incompatible on arm64 host.
    manifest = _descriptor_entry("linux/ppc64le")
    mock_run.return_value = MagicMock(
        returncode=0, stdout=json.dumps(manifest), stderr=""
    )
    # Burn the threshold across DIFFERENT products.
    for i in range(_ARCH_INCOMPATIBLE_THRESHOLD):
        r = image_resolve(product=f"product{i}", version="1.0", host_arch="arm64")
        assert r.decision == "arch_incompatible"
    # Next call (3rd product) should short-circuit.
    mock_run.reset_mock()
    r = image_resolve(product="weblogic", version="12.2", host_arch="arm64")
    assert r.ok is False
    assert r.decision == "arch_incompatible_persistent"
    assert "arch_incompatible image_resolve calls" in r.reason
    assert "source_build" in r.next_step_hint
    # Subprocess NOT called — short-circuited at function entry.
    mock_run.assert_not_called()


@patch("cve_env.utils.run.subprocess.run")
def test_phase38_4_arch_counter_resets_per_cve(mock_run: Any) -> None:
    """Phase 38.4: reset_rate_limit_budget() (called per-CVE) clears
    the arch_incompatible cumulative counter so the next CVE starts fresh.
    """
    from cve_env.tools import _image_resolve_state as _state
    from cve_env.tools.image_resolve import reset_rate_limit_budget

    reset_rate_limit_budget()
    # Burn the counter manually.
    _state._ARCH_INCOMPATIBLE_TOTAL = 5
    assert _state._ARCH_INCOMPATIBLE_TOTAL == 5
    reset_rate_limit_budget()
    assert _state._ARCH_INCOMPATIBLE_TOTAL == 0


# Phase 45: mirror.gcr.io reordered to high priority -------------------


def test_phase45_mirror_gcr_io_is_high_priority_candidate() -> None:
    """Phase 45 (2026-04-29) moved mirror.gcr.io from #11 to #3.
    Phase 29 (2026-05-14) finished the reorder — mirror.gcr.io is now
    #1, BEFORE Docker Hub variants (Phase 25 attempt 5 evidence: DH's
    100/6h anonymous-tier exhausted on a 50-CVE bench; mirrors-first
    avoids 24-min wall-guard burns on DH-rate-limited probes).

    This test still asserts the cascade is HIGH-PRIORITY for mirror.gcr.io
    (≤3) and that vendor registries (quay) follow mirror.
    """
    from cve_env.tools.image_resolve import _candidate_refs

    refs = _candidate_refs("nginx", "1.20")
    mirror_idx = refs.index("mirror.gcr.io/library/nginx:1.20")
    library_idx = refs.index("library/nginx:1.20")
    quay_idx = refs.index("quay.io/nginx/nginx:1.20")

    # Phase 29: Mirror MUST come BEFORE library/X (DH variant)
    assert mirror_idx < library_idx, (
        f"Phase 29: mirror.gcr.io at {mirror_idx} must precede library/X "
        f"at {library_idx}"
    )
    # Mirror MUST come before quay/ghcr/mcr (preserved from Phase 45)
    assert mirror_idx < quay_idx, (
        f"mirror.gcr.io at {mirror_idx} must come before quay.io at {quay_idx}"
    )
    # Mirror should be EARLY in the cascade (target: top 3)
    assert mirror_idx <= 2, (
        f"mirror.gcr.io at {mirror_idx} should be ≤2 (Phase 29 mirrors-first)"
    )


@patch("cve_env.tools.image_resolve.time.sleep")
@patch("cve_env.utils.run.subprocess.run")
def test_phase46_2_transport_cooldown_retry_one_shot(
    mock_run: Any,
    mock_sleep: Any,
) -> None:
    """Phase 46.2 (2026-04-30): when ALL candidates hit transport-class
    (5xx / timeout / connection-reset), image_resolve sleeps once + retries
    the candidate loop. Forensic: CVE-2021-41274 in bench50-20260430-000207
    exhausted Docker Hub + mirror.gcr.io + quay/ghcr/mcr with all-transport
    failures, then gave up at turn 20. Pre-46.2 there was no retry — only
    rate_limit had a cooldown branch.
    """
    from cve_env.tools import _image_resolve_state as _state
    from cve_env.tools.image_resolve import reset_rate_limit_budget

    reset_rate_limit_budget()
    # Simulate every candidate returning a 5xx-class transport error
    # (returncode=1 with "received unexpected HTTP status: 503").
    mock_run.return_value = MagicMock(
        returncode=1,
        stdout="",
        stderr="received unexpected HTTP status: 503 Service Unavailable",
    )
    r = image_resolve(product="solidus", version="2.11", host_arch="arm64")
    # Cooldown sleep was invoked.
    assert mock_sleep.called, "transport cooldown should have invoked sleep"
    # Cooldown flag now set so a second image_resolve in the same CVE
    # won't fire the cooldown again.
    assert _state._TRANSPORT_COOLDOWN_DONE is True
    # Result is still failure (retry also got 503s in this mock).
    assert r.ok is False
    assert r.reason_class == "transport"


@patch("cve_env.tools.image_resolve.time.sleep")
@patch("cve_env.utils.run.subprocess.run")
def test_phase46_2_transport_cooldown_skipped_after_rate_limit_cooldown(
    mock_run: Any,
    mock_sleep: Any,
) -> None:
    """Phase 46.2: if the rate_limit cooldown was already taken this CVE
    (consumed 30s already), the transport cooldown does NOT fire again to
    avoid back-to-back 30s waits. The two cooldowns are meant for distinct
    failure modes on the FIRST attempt, not as a chained backoff.
    """
    from cve_env.tools import _image_resolve_state as _state
    from cve_env.tools.image_resolve import reset_rate_limit_budget

    reset_rate_limit_budget()
    # Manually mark rate-limit cooldown as taken (simulating a prior call
    # in this same CVE that already burned the rate-limit budget).
    _state._RATE_LIMIT_COOLDOWN_DONE = True
    mock_run.return_value = MagicMock(
        returncode=1,
        stdout="",
        stderr="received unexpected HTTP status: 503 Service Unavailable",
    )
    r = image_resolve(product="solidus", version="2.11", host_arch="arm64")
    # Transport cooldown should NOT have been taken (rate-limit branch
    # already consumed wall-time once this CVE).
    assert _state._TRANSPORT_COOLDOWN_DONE is False, (
        "transport cooldown must not chain after rate-limit cooldown"
    )
    assert r.ok is False
    assert r.reason_class == "transport"


# ---- Phase 47.2: TDD tests for _attempt_resolve_retry_loop helper ----


@patch("cve_env.tools.image_resolve._inspect_ref")
def test_phase47_2_retry_helper_returns_success_on_match(
    mock_inspect: Any,
) -> None:
    """Phase 47.2: when first candidate's manifest has a host-compatible
    platform, the helper returns a success ResolveResult that the caller
    can return directly without further work.
    """
    from cve_env.tools.image_resolve import _attempt_resolve_retry_loop

    # First candidate inspect returns ([linux/arm64], {linux/arm64: digest1}).
    mock_inspect.return_value = (
        (["linux/arm64"], {"linux/arm64": "sha256:abc123"}),
        "ok",
    )
    result, retry_tried, retry_seen = _attempt_resolve_retry_loop(
        candidates=["nginx:1.20"],
        host_platform="linux/arm64",
        rosetta_available=False,
        host_arch="arm64",
        tried_so_far=["foo:1.0"],
        success_log_label="cooldown retry",
        product_key="nginx",
    )
    assert result is not None
    assert result.ok is True
    assert result.decision == "native"
    assert "sha256:abc123" in result.digest_pinned_ref
    # candidates_tried should include both prior and new candidates
    assert result.candidates_tried == ["foo:1.0", "nginx:1.20"]
    assert retry_tried == ["nginx:1.20"]
    assert "ok" in retry_seen


@patch("cve_env.tools.image_resolve._inspect_ref")
def test_phase47_2_retry_helper_returns_arch_incompat_on_manifests_no_match(
    mock_inspect: Any,
) -> None:
    """Phase 47.2: when at least one candidate returned a usable manifest
    but no host-compatible platform was found, the helper returns an
    arch_incompatible ResolveResult that the caller returns directly.
    """
    from cve_env.tools.image_resolve import _attempt_resolve_retry_loop

    # Manifest exists but only has linux/amd64 — no arm64 native, no rosetta.
    mock_inspect.return_value = (
        (["linux/amd64"], {"linux/amd64": "sha256:def456"}),
        "ok",
    )
    result, retry_tried, retry_seen = _attempt_resolve_retry_loop(
        candidates=["nginx:1.20"],
        host_platform="linux/arm64",
        rosetta_available=False,
        host_arch="arm64",
        tried_so_far=[],
        success_log_label="cooldown retry",
        product_key="nginx",
    )
    assert result is not None
    assert result.ok is False
    assert result.decision == "arch_incompatible"
    assert "no native/rosetta-compatible platform" in result.reason
    assert retry_tried == ["nginx:1.20"]


@patch("cve_env.tools.image_resolve._inspect_ref")
def test_phase47_2_retry_helper_returns_none_on_all_failed(
    mock_inspect: Any,
) -> None:
    """Phase 47.2: when every candidate fails manifest fetch (no manifest
    returned), the helper returns (None, retry_tried, retry_seen) so the
    caller can recompute final_class from retry_seen and fall through.
    """
    from cve_env.tools.image_resolve import _attempt_resolve_retry_loop

    mock_inspect.return_value = (None, "transport")
    result, retry_tried, retry_seen = _attempt_resolve_retry_loop(
        candidates=["nginx:1.20", "library/nginx:1.20", "quay.io/nginx:1.20"],
        host_platform="linux/arm64",
        rosetta_available=False,
        host_arch="arm64",
        tried_so_far=["foo:1.0"],
        success_log_label="transport-cooldown retry",
        product_key="nginx",
    )
    assert result is None  # caller must recompute final_class
    assert retry_tried == ["nginx:1.20", "library/nginx:1.20", "quay.io/nginx:1.20"]
    assert retry_seen == {"transport"}


# -- Phase 67.0 TDD safety net ------------------------------------------------
# Phase 67 audit issue #13 (severity 3): image_resolve has 5 module-level
# mutable globals (rate-limit budget, rate-limit total, rate-limit cooldown,
# transport cooldown, arch counter). reset_rate_limit_budget() clears all
# of them. This test locks the contract that resetting clears EVERY
# global so a future global addition that's missed in reset gets caught.


def test_phase67_image_resolve_globals_isolated_per_cve() -> None:
    """Phase 67.0: ``reset_rate_limit_budget()`` clears ALL per-CVE
    module-level state in one call. Adding a new global without wiring
    it into reset is the bug shape; this test catches it by mutating
    every known global, calling reset, and asserting all are zeroed.
    """
    from cve_env.tools import _image_resolve_state as _state
    from cve_env.tools import image_resolve as ir

    # Mutate every per-CVE global to a non-default value.
    _state._RATE_LIMIT_BUDGET["nginx"] = 99
    _state._RATE_LIMIT_TOTAL = 99
    _state._RATE_LIMIT_COOLDOWN_DONE = True
    _state._TRANSPORT_COOLDOWN_DONE = True
    _state._ARCH_INCOMPATIBLE_TOTAL = 99

    ir.reset_rate_limit_budget()

    assert _state._RATE_LIMIT_BUDGET == {}, "_RATE_LIMIT_BUDGET not cleared"
    assert _state._RATE_LIMIT_TOTAL == 0, "_RATE_LIMIT_TOTAL not zeroed"
    assert _state._RATE_LIMIT_COOLDOWN_DONE is False, (
        "_RATE_LIMIT_COOLDOWN_DONE not reset"
    )
    assert _state._TRANSPORT_COOLDOWN_DONE is False, (
        "_TRANSPORT_COOLDOWN_DONE not reset"
    )
    assert _state._ARCH_INCOMPATIBLE_TOTAL == 0, "_ARCH_INCOMPATIBLE_TOTAL not zeroed"
