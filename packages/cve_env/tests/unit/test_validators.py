"""Contract tests for :mod:`cve_env.validators`.

Each validator returns ``list[str]`` -- empty = accept; non-empty = reject.
These tests lock the load-bearing boundary cases (P10 + P11 + P14 + P17)
so a well-intentioned refactor can't loosen them.

Ported verbatim from cve-build-old/tests/unit/test_recovery_validators.py
with imports swapped to cve_env.
"""

from __future__ import annotations

import pytest

from cve_env.validators import (
    validate_dockerfile,
    validate_image_ref,
)

# -- validate_image_ref ---------------------------------------------------


def test_validate_image_ref_accepts_digest_pinned() -> None:
    ref = "docker.io/library/nginx@sha256:" + "a" * 64
    assert validate_image_ref(ref) == []


def test_validate_image_ref_rejects_latest() -> None:
    issues = validate_image_ref("nginx:latest")
    assert any("forbidden version tag" in i for i in issues)


@pytest.mark.parametrize("tag", ["latest", "stable", "lts", "current", "edge", "nightly"])
def test_validate_image_ref_rejects_every_forbidden_tag(tag: str) -> None:
    assert validate_image_ref(f"nginx:{tag}")


def test_validate_image_ref_rejects_tagged_but_not_digest_pinned() -> None:
    issues = validate_image_ref("nginx:1.20")
    assert any("digest-pinned" in i for i in issues)


def test_validate_image_ref_rejects_empty() -> None:
    issues = validate_image_ref("")
    # Phase 32.3: P14 prefix added.
    assert issues == ["P14: image_ref is empty"]


def test_validate_image_ref_rejects_malformed_digest() -> None:
    issues = validate_image_ref("nginx@sha256:abc123")
    assert any("malformed" in i for i in issues)


def test_validate_image_ref_rejects_bare_ref_without_digest_or_tag() -> None:
    """A bare ref (no ``@sha256:`` digest and no ``:`` tag) hits the P14
    'neither digest nor tag' branch."""
    issues = validate_image_ref("nginx")
    assert any("neither digest nor tag" in i for i in issues), (
        f"bare ref must yield the neither-digest-nor-tag P14 issue but got {issues!r}"
    )


# Phase 61.3 — P14 forbidden-tag check must work even when ref has digest --
#
# The bypass: ``nginx:latest@sha256:<digest>`` ends with ``:<digest>``
# (not ``:latest``), so ``lowered.endswith(":latest")`` failed. Fix is to
# strip ``@sha256:.*`` BEFORE the forbidden-tag scan.


def test_phase61_p14_rejects_latest_tag_with_digest_suffix() -> None:
    ref = "nginx:latest@sha256:" + "a" * 64
    issues = validate_image_ref(ref)
    assert any("forbidden version tag" in i and "latest" in i for i in issues), (
        f"P14 must reject :latest@sha256:... but got {issues!r}"
    )


def test_phase61_p14_rejects_nightly_tag_with_digest_suffix() -> None:
    ref = "myapp:nightly@sha256:" + "b" * 64
    issues = validate_image_ref(ref)
    assert any("forbidden version tag" in i and "nightly" in i for i in issues), (
        f"P14 must reject :nightly@sha256:... but got {issues!r}"
    )


def test_phase61_p14_legitimate_digest_pinned_versioned_still_passes() -> None:
    """Sanity: a non-forbidden tag + valid digest still validates clean."""
    ref = "nginx:1.20.1@sha256:" + "c" * 64
    assert validate_image_ref(ref) == []


# Security hardening — a stacked double ``@sha256:`` digest must not bypass P14
#
# ``nginx:latest@sha256:<64>@sha256:<64>`` is malformed (a real ref carries
# exactly one digest). The single-digest ``...$`` strip removed only the LAST
# digest, leaving ``nginx:latest@sha256:<64>`` whose tag check still failed,
# so ``:latest`` slipped through. The fix strips ALL trailing digests and
# rejects multi-digest refs outright.


def test_p14_rejects_latest_hidden_behind_double_digest() -> None:
    ref = "nginx:latest@sha256:" + "a" * 64 + "@sha256:" + "b" * 64
    issues = validate_image_ref(ref)
    assert any("forbidden version tag" in i and "latest" in i for i in issues), (
        f"P14 must see :latest behind stacked digests but got {issues!r}"
    )


def test_p14_rejects_multiple_stacked_digests_as_malformed() -> None:
    ref = "nginx:1.20.1@sha256:" + "a" * 64 + "@sha256:" + "b" * 64
    issues = validate_image_ref(ref)
    assert any("multiple sha256 digests" in i for i in issues), (
        f"multi-digest ref must be rejected but got {issues!r}"
    )


# -- validate_dockerfile --------------------------------------------------


def test_validate_dockerfile_accepts_pinned_from() -> None:
    good = 'FROM nginx:1.20.0\nCMD ["nginx", "-g", "daemon off;"]\n'
    assert validate_dockerfile(good) == []


def test_validate_dockerfile_rejects_latest_tag() -> None:
    bad = 'FROM nginx:latest\nCMD ["nginx", "-g", "daemon off;"]\n'
    issues = validate_dockerfile(bad)
    assert issues

