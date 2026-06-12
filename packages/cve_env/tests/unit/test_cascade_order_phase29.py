"""Phase 29 — image_resolve cascade reorder: mirrors first, Docker Hub last.

Phase 25 attempt 5 (2026-05-14) hit Docker Hub anonymous-tier exhaustion
(100/100 used in 6h window) on a 50-CVE bench. Workaround was
`CVE_ENV_DENY_REGISTRY=docker.io` env-var. Phase 29 makes mirrors-first
the default so DH-unauthed users get the high-quota path without needing
the env-var.

Order goal:
1. mirror.gcr.io/library/*       (Google mirror, ~9/10 anon-success on library/*)
2. public.ecr.aws/docker/library/* (AWS mirror, ~6/10)
3. quay.io / ghcr.io / mcr.microsoft.com (vendor registries, independent quotas)
4. Docker Hub variants LAST (bare, library/, vulhub/, docker.io/) — single
   rate-limit pool; probed only when mirrors miss (vulhub-compose, vendor
   namespaces).

`vulhub/*` stays in the cascade (just at lower priority) because the
images only exist on Docker Hub — when DH is reachable, vulhub-compose
path still works.

Per Phase 21.1 / 26.1 pattern: xfail(strict=True) RED → markers removed
atomically when 29.2 lands.
"""
from __future__ import annotations



def _try_candidate_refs():
    try:
        from cve_env.tools.image_resolve import _candidate_refs
        return _candidate_refs
    except ImportError:
        return None


def _index_of_prefix(cands: list[str], prefix: str) -> int:
    """First index of a candidate starting with prefix, or -1."""
    for i, c in enumerate(cands):
        if c.startswith(prefix):
            return i
    return -1


def _docker_hub_indices(cands: list[str]) -> list[int]:
    """Indices of all Docker-Hub-resolving candidates.

    Per `_filter_denied_registries`: bare `{p}:{v}`, `library/{p}:{v}`,
    `docker.io/...`, and any first-segment without `.` or `:` (e.g.,
    `vulhub/...`) resolve to Docker Hub.
    """
    out: list[int] = []
    for i, c in enumerate(cands):
        first = c.split("/", 1)[0].split(":", 1)[0]
        if "/" not in c:
            out.append(i)  # bare name → DH default
            continue
        if c.startswith("docker.io/"):
            out.append(i)
            continue
        if "." not in first and ":" not in first and first != "localhost":
            # e.g. "library/foo:1", "vulhub/foo:1"
            out.append(i)
    return out


# ---------------------------------------------------------------------------
# RED tests via xfail(strict=True). Removed atomically by Stage 29.2.
# ---------------------------------------------------------------------------


def test_mirror_gcr_io_precedes_all_docker_hub_variants():
    """mirror.gcr.io appears BEFORE every Docker Hub variant in the cascade."""
    fn = _try_candidate_refs()
    assert fn is not None
    cands = fn("ubuntu", "22.04")
    mirror_idx = _index_of_prefix(cands, "mirror.gcr.io/")
    assert mirror_idx >= 0, "mirror.gcr.io not in cascade"
    dh_indices = _docker_hub_indices(cands)
    assert dh_indices, "no DH candidates in cascade (sanity)"
    for dh_i in dh_indices:
        assert mirror_idx < dh_i, (
            f"mirror.gcr.io at index {mirror_idx} should precede DH variant "
            f"at index {dh_i} ({cands[dh_i]!r}). Full cascade: {cands}"
        )


def test_public_ecr_aws_precedes_all_docker_hub_variants():
    """public.ecr.aws appears BEFORE every Docker Hub variant in the cascade."""
    fn = _try_candidate_refs()
    assert fn is not None
    cands = fn("ubuntu", "22.04")
    ecr_idx = _index_of_prefix(cands, "public.ecr.aws/")
    assert ecr_idx >= 0
    dh_indices = _docker_hub_indices(cands)
    for dh_i in dh_indices:
        assert ecr_idx < dh_i, (
            f"public.ecr.aws at {ecr_idx} should precede DH at {dh_i} "
            f"({cands[dh_i]!r}). Full cascade: {cands}"
        )


def test_vendor_registries_precede_docker_hub_variants():
    """quay.io, ghcr.io, mcr.microsoft.com all precede every DH variant."""
    fn = _try_candidate_refs()
    assert fn is not None
    cands = fn("ubuntu", "22.04")
    dh_indices = _docker_hub_indices(cands)
    last_dh = min(dh_indices) if dh_indices else len(cands)
    for vendor in ("quay.io/", "ghcr.io/", "mcr.microsoft.com/"):
        v_idx = _index_of_prefix(cands, vendor)
        assert v_idx >= 0, f"{vendor!r} not in cascade"
        assert v_idx < last_dh, (
            f"{vendor!r} at {v_idx} should precede first DH variant at "
            f"{last_dh} ({cands[last_dh]!r}). Full cascade: {cands}"
        )


def test_vulhub_namespace_still_in_cascade():
    """vulhub/<product> is preserved (still on Docker Hub, only at lower priority).

    Phase 29 invariant: the reorder doesn't DROP any registry — only moves
    DH variants down. This test is GREEN today (vulhub in cascade) and must
    stay GREEN post-reorder.
    """
    fn = _try_candidate_refs()
    assert fn is not None
    cands = fn("openssl", "1.0.1f")
    vulhub_idx = _index_of_prefix(cands, "vulhub/")
    assert vulhub_idx >= 0, (
        f"vulhub/* dropped from cascade — vulhub-compose CVEs would all "
        f"fail when mirrors miss. Full cascade: {cands}"
    )
