"""Docker Compose parser — ``docker-compose.yml`` /
``docker-compose.yaml`` / ``compose.yml`` / ``compose.yaml``.

Compose declares services that the operator runs together. Each
service typically pulls an OCI image:

    services:
      db:
        image: postgres:16-alpine
      cache:
        image: redis:7.2-alpine
      app:
        build: ./app          # local; not a registry pull

This parser extracts the ``services.<name>.image`` references and
emits one Dependency per service with ``ecosystem="OCI"`` and the
image ref as the version. Local-build services (``build:`` without
``image:``) and version-controlled refs (``image:`` pointing at a
local path or unset) are skipped.

What this commit does NOT do (deferred — memo'd):

  * Fetch each image's SBOM the way ``packages/sca/dockerfile_from``
    does for Dockerfile FROM. That's a refactor splitting B9's
    ``scan_dockerfiles`` into discovery vs SBOM-fetch — the
    fetch path can then be shared across Dockerfile FROM,
    compose ``image:``, and GitLab CI ``image:``. Until then,
    these compose-emitted Deps appear in the SBOM for visibility
    but the report's CVE matcher skips them (no ``OCI`` ecosystem
    in OSV).

The cross-link to B9: when an operator's project has both a
Dockerfile (which B9 scans for OS packages) and a compose file
(which lists app-runtime images like postgres / redis / nginx),
the compose parser doesn't double-report — Dockerfile FROM
images and compose images are typically distinct (FROM is the
build base, compose images are the runtime services).

What this is NOT:

  * Kubernetes manifest scanning — separate file shape (``apiVersion:
    apps/v1`` etc.). Could be a future parser.
  * Docker Swarm stack files — same compose syntax; the parser
    matches them too (filename patterns are common).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, List, Optional

from ..models import Confidence, Dependency, PinStyle
from . import register

logger = logging.getLogger(__name__)


ECOSYSTEM = "OCI"
_PURL_TYPE = "oci"

# Compose v2 / v3 / current — top-level ``services:`` map.
_SERVICES_KEY = "services"


@register(predicate=lambda p: _is_compose_file(p))
def parse(path: Path) -> List[Dependency]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.warning(
            "sca.parsers.compose: read failed for %s: %s", path, e,
        )
        return []
    try:
        import yaml                 # type: ignore[import-untyped]
        from .._yaml_fast import safe_load
    except ImportError:
        logger.debug(
            "sca.parsers.compose: PyYAML not installed; skipping %s",
            path,
        )
        return []
    # Pre-check: real docker-compose files start with a top-level
    # key at column 0 (``services:``, ``version:``, ``networks:``,
    # ``volumes:``, ``configs:``, ``secrets:``, ``x-...``). Files
    # whose first non-blank, non-comment line is INDENTED are
    # fragments — meant to be ``include``d into a parent file,
    # not parsed standalone. Grafana's ``devenv/docker/blocks/*/
    # docker-compose.yaml`` files follow this pattern. Demoting
    # the parse-failure log line to DEBUG for these because the
    # fragment isn't operator-controllable content (vendored
    # third-party / generated) and the WARN noise from a real
    # 200-project sweep dominates the operator's view.
    is_fragment = False
    for line in text.splitlines():
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        # First content line — if indented, this is a fragment.
        if line != stripped:
            is_fragment = True
        break

    try:
        data = safe_load(text)
    except yaml.YAMLError as e:
        if is_fragment:
            logger.debug(
                "sca.parsers.compose: skipping fragment %s: %s",
                path, e,
            )
        else:
            logger.warning(
                "sca.parsers.compose: YAML parse failed for %s: %s",
                path, e,
            )
        return []
    if not isinstance(data, dict):
        return []

    services = data.get(_SERVICES_KEY)
    if not isinstance(services, dict):
        return []

    out: List[Dependency] = []
    for service_name, service in services.items():
        dep = _build_dep(
            service_name=service_name,
            service=service,
            declared_in=path,
        )
        if dep is not None:
            out.append(dep)
    return out


def _is_compose_file(path: Path) -> bool:
    """Match ``docker-compose.yml`` / ``docker-compose.yaml`` /
    ``compose.yml`` / ``compose.yaml``, plus operator-specific
    overlays like ``docker-compose.dev.yml``.

    Doesn't match ``compose.yml`` files NOT at the project root
    or under an obvious compose-config directory — too many false
    positives (some unrelated tools use ``compose.yaml`` names).
    Conservative match: name must start with ``compose`` or
    ``docker-compose``.
    """
    if path.suffix.lower() not in (".yml", ".yaml"):
        return False
    name = path.name.lower()
    if name.startswith("docker-compose"):
        return True
    if name == "compose.yml" or name == "compose.yaml":
        return True
    if name.startswith("compose.") and name.endswith((".yml", ".yaml")):
        # ``compose.dev.yml`` etc. — common operator pattern.
        return True
    return False


def _build_dep(
    *,
    service_name: Any,
    service: Any,
    declared_in: Path,
) -> Optional[Dependency]:
    if not isinstance(service_name, str) or not service_name:
        return None
    if not isinstance(service, dict):
        return None
    image = service.get("image")
    if not isinstance(image, str) or not image.strip():
        return None
    image = image.strip()

    name, version = _split_image_ref(image)
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
        pin_style=PinStyle.EXACT if version else PinStyle.WILDCARD,
        direct=True,
        purl=purl,
        parser_confidence=Confidence(
            "high",
            reason=(
                f"docker-compose service {service_name!r} pinned to "
                f"{image}"
            ),
        ),
        source_kind="compose",
        source_extra={"service": service_name, "image_ref": image},
    )


def _split_image_ref(ref: str) -> tuple:
    """Split an OCI image reference into (name, tag).

    ``postgres:16`` → ``("postgres", "16")``
    ``ghcr.io/x/y:1.2`` → ``("ghcr.io/x/y", "1.2")``
    ``alpine`` (no tag) → ``("alpine", None)``
    ``foo@sha256:abc...`` → ``("foo", "sha256:abc...")``  (digest pin)
    """
    # Digest pin first (``name@sha256:...``).
    if "@" in ref:
        name, _, digest = ref.rpartition("@")
        return name, digest if digest else None
    # Tag pin (last colon, but only AFTER the last slash so we
    # don't confuse a registry port like ``localhost:5000``).
    last_slash = ref.rfind("/")
    rest = ref[last_slash + 1:] if last_slash >= 0 else ref
    if ":" in rest:
        prefix = ref[:last_slash + 1] if last_slash >= 0 else ""
        rest_name, _, tag = rest.partition(":")
        return prefix + rest_name, tag if tag else None
    return ref, None
