"""GitLab CI parser — ``.gitlab-ci.yml`` / ``.gitlab-ci.yaml``.

GitLab CI declares jobs that run in containers. The container
image is specified via top-level or per-job ``image:`` and
``services:``:

    image: python:3.11

    services:
      - postgres:16-alpine

    test:
      image: ghcr.io/myorg/test-runner:v2
      services:
        - redis:7

This parser walks both shapes:

  * Top-level ``image:`` — applies to every job that doesn't
    override.
  * Top-level ``services:`` — array of service-container refs
    (each entry is either a string ``image_ref`` or a dict
    ``{name: image_ref, alias: ...}``).
  * Per-job ``<job>.image:`` — overrides the top-level for that
    job.
  * Per-job ``<job>.services:`` — appended to the top-level set.

Each unique image ref emits one Dependency with ``ecosystem="OCI"``,
``source_kind="gitlab_ci"``. Same SBOM-visibility-only treatment
as ``compose.py`` — CVE matching against the OS packages inside
each image is the deferred B9-fetcher unification work.

What we don't cover:

  * ``include:`` references (sub-component pins to other GitLab
    CI configs) — comparable to GHA's ``uses:``. Could be a
    follow-up parser; less standardised than GHA.
  * ``trigger:`` (downstream pipeline triggers) — not a dep.
  * GitLab Runner version pins — runner config is operator-side,
    not in the YAML.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any
from collections.abc import Iterable

from core.oci.image_ref import split_image_ref as _split_image_ref

from ..models import Confidence, Dependency
from ..models import classify_pin_style as _classify_pin_style
from . import _safe_read, register

logger = logging.getLogger(__name__)


ECOSYSTEM = "OCI"
_PURL_TYPE = "oci"


# GitLab CI top-level keys that aren't jobs (per the GitLab CI/CD
# YAML keyword list). Filtering them out prevents emitting "deps"
# for ``image:`` / ``services:`` / ``variables:`` / etc. as if they
# were jobs with sub-image fields.
_RESERVED_KEYS: set[str] = {
    "image", "services", "variables", "stages", "default",
    "include", "before_script", "after_script", "workflow",
    "cache", "artifacts", "pages", "trigger",
}


@register(filenames=[".gitlab-ci.yml", ".gitlab-ci.yaml"])
def parse(path: Path) -> list[Dependency]:
    text = _safe_read.read_bounded(path, follow_symlinks=False)
    if text is None:
        # ``read_bounded`` already logged the underlying reason.
        return []
    try:
        import yaml                 # type: ignore[import-untyped]
        from .._yaml_fast import safe_load
    except ImportError:
        logger.debug(
            "sca.parsers.gitlab_ci: PyYAML not installed; skipping %s",
            path,
        )
        return []
    try:
        data = safe_load(text)
    except yaml.YAMLError as e:
        logger.warning(
            "sca.parsers.gitlab_ci: YAML parse failed for %s: %s",
            path, e,
        )
        return []
    if not isinstance(data, dict):
        return []

    refs: list[tuple[str, str]] = []
    # ``(image_ref, source_context)`` — context goes into
    # source_extra so operators see "from top-level image" vs
    # "from job test:image".

    refs.extend(_extract_image(data, label="top-level"))
    refs.extend(_extract_services(data, label="top-level services"))

    default_block = data.get("default")
    if isinstance(default_block, dict):
        refs.extend(_extract_image(default_block, label="default"))
        refs.extend(_extract_services(default_block, label="default services"))

    # Per-job sweep: skip reserved keys. A "job" is any other
    # top-level mapping whose value is itself a dict.
    for job_name, job in data.items():
        if not isinstance(job_name, str):
            continue
        if job_name in _RESERVED_KEYS:
            continue
        if job_name.startswith("."):
            # GitLab convention: leading-dot keys are hidden /
            # template anchors, not real jobs. Their image: refs
            # WILL flow into actual jobs via ``extends:``, so we
            # still extract them.
            pass
        if not isinstance(job, dict):
            continue
        refs.extend(_extract_image(job, label=f"job {job_name}"))
        refs.extend(_extract_services(
            job, label=f"job {job_name} services",
        ))

    # Dedup by (image_ref, source_context) so the same ref used in
    # multiple places emits one row per usage location — preserves
    # provenance.
    seen: set[tuple[str, str]] = set()
    out: list[Dependency] = []
    for image_ref, ctx in refs:
        key = (image_ref, ctx)
        if key in seen:
            continue
        seen.add(key)
        dep = _build_dep(
            image_ref=image_ref, context=ctx, declared_in=path,
        )
        if dep is not None:
            out.append(dep)
    return out


def _extract_image(
    block: Any, *, label: str,
) -> Iterable[tuple[str, str]]:
    """Pull an ``image:`` field from a job or top-level block."""
    if not isinstance(block, dict):
        return
    image = block.get("image")
    if isinstance(image, str) and image.strip():
        yield image.strip(), f"{label} image"
    elif isinstance(image, dict):
        # GitLab supports ``image: { name: ..., entrypoint: ... }``.
        name = image.get("name")
        if isinstance(name, str) and name.strip():
            yield name.strip(), f"{label} image"


def _extract_services(
    block: Any, *, label: str,
) -> Iterable[tuple[str, str]]:
    """Pull each entry from a ``services:`` array."""
    if not isinstance(block, dict):
        return
    services = block.get("services")
    if not isinstance(services, list):
        return
    for entry in services:
        if isinstance(entry, str) and entry.strip():
            yield entry.strip(), label
        elif isinstance(entry, dict):
            name = entry.get("name")
            if isinstance(name, str) and name.strip():
                yield name.strip(), label


def _build_dep(
    *,
    image_ref: str,
    context: str,
    declared_in: Path,
) -> Dependency | None:
    name, version = _split_image_ref(image_ref)
    if not name:
        return None

    purl = f"pkg:{_PURL_TYPE}/{name}"
    if version:
        purl += f"@{version}"

    return Dependency(
        ecosystem=ECOSYSTEM,
        name=name,
        version=version,
        declared_in=declared_in,
        scope="main",
        is_lockfile=False,
        pin_style=_classify_pin_style(version),
        direct=True,
        purl=purl,
        parser_confidence=Confidence(
            "high",
            reason=f".gitlab-ci.yml {context}: {image_ref}",
        ),
        source_kind="gitlab_ci",
        source_extra={"context": context, "image_ref": image_ref},
    )
