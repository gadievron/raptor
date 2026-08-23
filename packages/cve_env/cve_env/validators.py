"""Shared correctness gates for the agent tool belt.

Tools with image-ref or Dockerfile inputs delegate into this module so
the correctness invariants (P14 digest-pin, P17 no-priv) live in one
place rather than re-implemented per tool.

Guards are pure functions: they return a list of issue strings (empty
list = artifact acceptable). The caller (tool handler) turns a
non-empty list into a rejection with the joined reasons.

Coverage:

* :func:`validate_image_ref` -- no forbidden tags; must be digest-pinned
  if pullable.
* :func:`validate_dockerfile` -- delegates to
  :func:`cve_env.utils.dockerfile_hygiene.validate_dockerfile_semantics`.

Patch-shape validators (validate_build_patch, validate_run_patch,
validate_resolve_patch, validate_verify_plan_patch) were removed along
with the patch_apply tool — neither was ever called across benched runs.
"""

from __future__ import annotations

from cve_env.policy import (
    FORBIDDEN_VERSION_TAGS,
    SHA256_DIGEST_SUFFIX_RE,
    SHA256_MULTI_DIGEST_RE,
)
from cve_env.utils.dockerfile_hygiene import validate_dockerfile_semantics

# Alias for back-compat with internal callers; canonical name is
# ``SHA256_DIGEST_SUFFIX_RE`` in cve_env.policy.
_SHA256_DIGEST_RE = SHA256_DIGEST_SUFFIX_RE


def validate_image_ref(image_ref: str) -> list[str]:
    """Reject forbidden version tags and non-digest-pinned pullable refs.

    A Tier-1-equivalent proposal (registry substitution, community rebuild)
    must be digest-pinned. Built refs (Dockerfile output) are checked
    separately via :func:`validate_dockerfile` -- they never carry a
    digest before build.

    Contract: return an empty list iff ``image_ref`` is acceptable to
    re-enter the pipeline as a pullable reference.
    """
    issues: list[str] = []
    if not image_ref:
        return ["P14: image_ref is empty"]

    # Strip the ``@sha256:<digest>`` suffix BEFORE the forbidden-tag scan.
    # Otherwise ``nginx:latest@sha256:<digest>`` ends with ``:<digest>``
    # and ``endswith(":latest")`` silently fails — defense bypassable.
    ref_for_tag_check = _SHA256_DIGEST_RE.sub("", image_ref)
    lowered = ref_for_tag_check.lower()
    for tag in FORBIDDEN_VERSION_TAGS:
        suffix = f":{tag}"
        if lowered == tag or lowered.endswith(suffix):
            issues.append(f"P14: image_ref uses forbidden version tag {tag!r}")
            break

    if "@sha256:" in image_ref:
        if SHA256_MULTI_DIGEST_RE.search(image_ref):
            issues.append("P14: image_ref carries multiple sha256 digests (malformed)")
        elif not _SHA256_DIGEST_RE.search(image_ref):
            issues.append("P14: image_ref claims a digest but it is malformed")
    elif ":" in image_ref:
        issues.append(
            "P14: image_ref must be digest-pinned (@sha256:...) "
            "to be reused as a pullable ref"
        )
    else:
        issues.append("P14: image_ref has neither digest nor tag")

    return issues


def validate_dockerfile(dockerfile_text: str) -> list[str]:
    """Delegate to the shared hygiene check; no ``strict`` flag."""
    return validate_dockerfile_semantics(dockerfile_text)
