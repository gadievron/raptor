"""Kubernetes manifest parser — extracts image refs from
``kind:`` workloads.

Real cluster operators routinely ship YAML manifests alongside
their app code: ``kustomize`` overlays, raw ``Deployment`` files,
``StatefulSet`` / ``DaemonSet`` / ``Pod`` / ``Job`` /
``CronJob`` / ``ReplicaSet`` etc. Each carries one or more
container images via ``spec.containers[].image`` (and
``spec.initContainers[].image``).

This parser walks YAML files in the target, identifies the ones
whose top-level ``kind:`` is a known workload shape, and emits
one Dependency per image with ``ecosystem="OCI"`` and
``source_kind="k8s"``. The unified ``scan_image_sources`` then
fetches each unique image's OS-package SBOM via
``core.oci``.

Supports multi-document YAML (``---``-separated) — common in
``manifests/`` directories that bundle several resources in one
file.

What's NOT covered:

  * ``kustomization.yaml`` ``images:`` field (image overrides) —
    operators typically pair these with the resources they
    override; the resources' images are already detected.
  * Helm-templated manifests (``{{ .Values.image }}`` etc.) —
    template values, not concrete refs. Operators wanting Helm
    coverage should run ``helm template`` first then scan the
    rendered output.
  * Custom CRDs whose image fields don't follow the standard
    ``spec.containers[].image`` shape (e.g. operator-installed
    Argo / Tekton tasks). Out of scope for first cut.
  * ``imagePullSecrets`` — auth, not deps.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

from ..models import Confidence, Dependency, PinStyle
from . import register

logger = logging.getLogger(__name__)


ECOSYSTEM = "OCI"
_PURL_TYPE = "oci"


# Workload kinds that carry images via ``spec.containers[]`` (or
# ``spec.template.spec.containers[]`` for higher-level wrappers).
_WORKLOAD_KINDS = {
    "Pod",
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "ReplicaSet",
    "ReplicationController",
    "Job",
    "CronJob",
}


@register(predicate=lambda p: _is_k8s_manifest(p))
def parse(path: Path) -> List[Dependency]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.warning(
            "sca.parsers.kubernetes: read failed for %s: %s", path, e,
        )
        return []
    try:
        import yaml                 # type: ignore[import-untyped]
        from .._yaml_fast import safe_load_all
    except ImportError:
        logger.debug(
            "sca.parsers.kubernetes: PyYAML not installed; skipping %s",
            path,
        )
        return []
    try:
        # Multi-document YAML — common for ``manifests/`` bundles.
        documents = list(safe_load_all(text))
    except yaml.YAMLError as e:
        # DEBUG, not WARNING: the kubernetes parser is content-sniffing
        # every ``.yml`` / ``.yaml`` in the tree, since file extension
        # alone can't distinguish K8s manifests from arbitrary YAML
        # (Helm templates, OpenAPI specs, GitHub Actions workflows,
        # test fixtures with custom YAML tags). Most YAMLs fail this
        # parse and that's expected — the dispatcher just treats them
        # as non-K8s. Logging at WARNING dumped 100s of unactionable
        # lines on istio (900 YAMLs) and manageiq (Ruby YAML with
        # ``!ruby/object`` tags).
        logger.debug(
            "sca.parsers.kubernetes: YAML parse failed for %s: %s",
            path, e,
        )
        return []

    out: List[Dependency] = []
    for doc in documents:
        if not isinstance(doc, dict):
            continue
        kind = doc.get("kind")
        if not isinstance(kind, str) or kind not in _WORKLOAD_KINDS:
            continue
        for image_ref, kind_ctx, container_name in _extract_images(
            doc, kind=kind,
        ):
            dep = _build_dep(
                image_ref=image_ref,
                kind_ctx=kind_ctx,
                container_name=container_name,
                declared_in=path,
            )
            if dep is not None:
                out.append(dep)
    return out


def _is_k8s_manifest(path: Path) -> bool:
    """Match YAML files that look like Kubernetes manifests.

    Conservative — only files NOT matched by other YAML parsers
    (compose, GitLab CI, Helm Chart, pre-commit). Determined at
    parse-time by checking the ``kind:`` top-level field; the
    predicate's job is just to route YAMLs that aren't claimed
    elsewhere through this parser.
    """
    if path.suffix.lower() not in (".yml", ".yaml"):
        return False
    name = path.name.lower()
    # Compose / GitLab CI / Helm Chart / pre-commit handled by their
    # own parsers; skip those filenames here.
    if name.startswith("docker-compose") or name.startswith("compose."):
        return False
    if name in ("compose.yml", "compose.yaml"):
        return False
    if name in (".gitlab-ci.yml", ".gitlab-ci.yaml"):
        return False
    if name in ("chart.yaml", "chart.lock"):
        return False
    if name in (".pre-commit-config.yaml", ".pre-commit-config.yml"):
        return False
    # GHA workflows are handled by ``inline_installs.parse_gha_workflow``.
    parts = path.parts
    for j in range(len(parts) - 2):
        if parts[j] == ".github" and parts[j + 1] == "workflows":
            return False
    # Composite-action manifests handled by GHA parser.
    if name in ("action.yml", "action.yaml"):
        return False
    return True


def _extract_images(
    doc: dict, *, kind: str,
) -> Iterable[Tuple[str, str, Optional[str]]]:
    """Yield ``(image_ref, kind_context, container_name)`` for each
    container image found in this workload doc.

    ``Pod`` carries containers at ``spec.containers[]``;
    ``Deployment`` / ``StatefulSet`` / etc. wrap them in
    ``spec.template.spec.containers[]``. We probe both depths.
    """
    spec = doc.get("spec")
    if not isinstance(spec, dict):
        return
    # Higher-level workload wrappers nest under ``template.spec``.
    template_spec = spec
    template = spec.get("template")
    if isinstance(template, dict):
        ts = template.get("spec")
        if isinstance(ts, dict):
            template_spec = ts

    metadata = doc.get("metadata") or {}
    workload_name = (
        metadata.get("name") if isinstance(metadata, dict) else None
    )
    label = f"{kind}/{workload_name}" if workload_name else kind

    for container_field in ("containers", "initContainers", "ephemeralContainers"):
        containers = template_spec.get(container_field)
        if not isinstance(containers, list):
            continue
        for container in containers:
            if not isinstance(container, dict):
                continue
            image = container.get("image")
            if not isinstance(image, str) or not image.strip():
                continue
            yield (
                image.strip(),
                f"{label} {container_field}",
                container.get("name") if isinstance(
                    container.get("name"), str,
                ) else None,
            )


def _build_dep(
    *,
    image_ref: str,
    kind_ctx: str,
    container_name: Optional[str],
    declared_in: Path,
) -> Optional[Dependency]:
    name, version = _split_image_ref(image_ref)
    if not name:
        return None
    purl = f"pkg:{_PURL_TYPE}/{name}"
    if version:
        purl += f"@{version}"

    extra: dict = {"context": kind_ctx, "image_ref": image_ref}
    if container_name:
        extra["container"] = container_name

    return Dependency(
        ecosystem=ECOSYSTEM,
        name=name,
        version=version,
        declared_in=declared_in,
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.EXACT if version else PinStyle.WILDCARD,
        direct=True,
        purl=purl,
        parser_confidence=Confidence(
            "high",
            reason=f"k8s {kind_ctx}: {image_ref}",
        ),
        source_kind="k8s",
        source_extra=extra,
    )


def _split_image_ref(ref: str) -> tuple:
    """Same logic as ``compose._split_image_ref`` and ``gitlab_ci._split_image_ref``.
    Duplicated for parser-loose-coupling; refactor into
    ``core.oci.image_ref`` if a fourth consumer surfaces."""
    if "@" in ref:
        name, _, digest = ref.rpartition("@")
        return name, digest if digest else None
    last_slash = ref.rfind("/")
    rest = ref[last_slash + 1:] if last_slash >= 0 else ref
    if ":" in rest:
        prefix = ref[:last_slash + 1] if last_slash >= 0 else ""
        rest_name, _, tag = rest.partition(":")
        return prefix + rest_name, tag if tag else None
    return ref, None
