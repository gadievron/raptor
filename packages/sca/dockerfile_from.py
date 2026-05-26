"""Dockerfile FROM base-image scanning.

When a target contains a Dockerfile, the operator's deployment
unit isn't just the project tree — it's the project tree
*overlaid on a base image*. CVEs in the base image's installed
packages (Debian / Alpine / Red Hat) are real production CVEs
even when no manifest in the project ever mentioned them.

This module reads each ``FROM <image>`` line, resolves the image
through an OCI registry (using :mod:`core.oci`), pulls the
installed-package state from layer files (``var/lib/dpkg/status``
/ ``lib/apk/db/installed`` / ``var/lib/rpm/rpmdb.sqlite``), and
emits ``Dependency`` rows so they flow through the same
OSV / KEV / EPSS pipeline as direct project deps.

What this is NOT:

  * **Image vulnerability scanning**: we don't pull every layer's
    full file tree, don't run ``ldd`` against binaries, don't
    catalogue everything Trivy / Grype would. We pull the OS
    package database, query OSV for OS-package advisories, and
    surface those.
  * **Build-stage analysis**: in a multi-stage Dockerfile,
    intermediate-stage packages may be discarded by the time the
    final image lands. We scan every FROM by default — this
    over-reports rather than under-reports, but the
    ``source_extra.stage_name`` field on each Dependency lets
    operators filter "intermediate stages" out in their report
    review.
  * **Authenticated private-registry pulls** beyond what
    :mod:`core.oci.auth` already supports (env vars, docker config
    inline auths). credsStore / credHelpers are deliberately
    refused — see ``core/oci/auth.py``.

Behaviour under failure:

  * Network unreachable / registry returns 5xx → log warning,
    skip that image, continue with other Dockerfiles. Don't
    abort the whole SCA run for one unreachable image.
  * Layer extraction fails (corrupt blob, malformed package db) →
    skip that layer, log debug. Other layers in the same image
    still produce Deps.
  * ``--offline`` flag → skip the whole pass.

Caching:

  * Per-digest results cached forever (digest is content-
    addressed; a digest's SBOM doesn't change).
  * Tag-to-digest mapping cached for 24h (tag content can drift,
    so we re-resolve daily but rely on the digest cache for the
    SBOM itself).

Sandbox: when invoking from a sandboxed run, the registry hosts
returned by :func:`core.oci.registry_hosts_for` must be on the
``proxy_hosts`` allowlist. The pipeline caller is responsible for
plumbing those through; this module just calls ``http``.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from core.dockerfile import parse_dockerfile
from core.oci import parse_image_ref, registry_hosts_for
from core.oci.blob import extract_files_from_layer
from core.oci.client import OciRegistryClient
from core.oci.manifest import (
    is_image_index,
    is_image_manifest,
    parse_image_index,
    parse_image_manifest,
    select_platform,
)
from core.oci.sbom import (
    InstalledPackage,
    LAYER_FILE_PATHS,
    packages_from_layer_files,
)

from .models import Confidence, Dependency, PinStyle

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


_DOCKERFILE_NAMES = {"Dockerfile", "Containerfile"}


def _is_dockerfile(path: Path) -> bool:
    """Match Dockerfile / Containerfile / Dockerfile.<variant> /
    <variant>.Dockerfile / *.dockerfile.

    Same shape as ``discovery._is_inline_install_source`` but
    Dockerfile-only — devcontainer.json, shell scripts, and GHA
    workflows don't carry a base image.
    """
    name = path.name
    if name in _DOCKERFILE_NAMES:
        return True
    if name.startswith("Dockerfile.") or name.endswith(".Dockerfile"):
        return True
    if path.suffix == ".dockerfile":
        return True
    return False


# Directory names that almost certainly carry test fixtures or CI
# infrastructure rather than production-deployable container images.
# Excluded from image discovery (NOT from manifest discovery, which
# happens via discovery.find_manifests with a different set —
# tests/composer.json IS a real dep declaration we want to scan).
#
# Concrete cases caught:
# - spring-boot's ``ci/images/spring-boot-jdk*-ci-image/Dockerfile``
#   (JDK early-access tags long since purged from Docker Hub —
#   triggered the spring-boot-2.1 stress-sweep outlier)
# - pterodactyl / istio / strapi test fixtures referencing
#   sample images from old tutorials
# - any project's ``test/Dockerfile`` for integration-test setup
_IMAGE_DISCOVERY_EXCLUDE_PARENT_DIRS = frozenset({
    "test", "tests", "testing",
    "ci",            # CI infrastructure dockerfiles, not the app
    "fixtures", "fixture",
    "examples", "example", "sample", "samples",
})


def _path_under_excluded_image_parent(p: Path, target: Path) -> bool:
    """True when any directory between ``target`` and ``p`` matches
    a name in ``_IMAGE_DISCOVERY_EXCLUDE_PARENT_DIRS`` (lowercased
    comparison)."""
    try:
        rel = p.resolve().relative_to(target.resolve())
    except ValueError:
        return False
    for part in rel.parts[:-1]:  # exclude file basename
        if part.lower() in _IMAGE_DISCOVERY_EXCLUDE_PARENT_DIRS:
            return True
    return False


def find_dockerfiles(target: Path) -> List[Path]:
    """Walk the target and return Dockerfiles to scan.

    Skips conventional excluded directories (vendor, node_modules,
    .git, etc.) — same set the manifest discovery walker uses.
    Additionally skips Dockerfiles under test/ci/fixture/example
    parent directories: those are integration-test setup or CI
    infrastructure, not the project's runtime base image, and
    routinely reference long-purged tags that burn manifest-fetch
    budget without producing actionable findings.
    """
    from .discovery import EXCLUDED_DIR_NAMES

    out: List[Path] = []
    for root, dirs, files in os.walk(target):
        dirs[:] = [
            d for d in dirs
            if d not in EXCLUDED_DIR_NAMES and not d.startswith(".")
        ]
        for f in files:
            p = Path(root) / f
            if not _is_dockerfile(p):
                continue
            if _path_under_excluded_image_parent(p, target):
                continue
            out.append(p)
    out.sort()
    return out


# ---------------------------------------------------------------------------
# FROM extraction
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FromEntry:
    """One ``FROM`` line resolved to an image ref.

    ``stage_name`` is the AS-name (``FROM x AS builder`` →
    ``"builder"``); ``None`` for the final / un-named stage.
    """
    image: str
    stage_name: Optional[str]
    line: int


def extract_from_lines(dockerfile_text: str) -> List[FromEntry]:
    """Return one :class:`FromEntry` per FROM that references an
    actual image (not a previous stage name).

    ``FROM scratch`` is excluded — no base packages.
    ``FROM <stage_name>`` (referencing an earlier ``AS <name>``) is
    excluded — that's intra-Dockerfile reuse, not a registry pull.
    """
    instructions = parse_dockerfile(dockerfile_text)
    stage_names: Set[str] = set()
    out: List[FromEntry] = []
    for inst in instructions:
        if inst.directive != "FROM":
            continue
        # Multi-stage AS-name — track for cross-stage filtering and
        # carry through on FromEntry.
        if inst.stage_name:
            stage_names.add(inst.stage_name)
        # The args are the post-FROM token list. ``--platform=linux/amd64``
        # is a frontend flag we strip; the image ref is the first
        # non-flag token.
        image = _extract_image_token(inst.args)
        if image is None:
            continue
        if image == "scratch":
            continue
        if image in stage_names:
            # FROM referencing an earlier AS-name — intra-Dockerfile
            # reuse, no registry pull. The packages from the
            # referenced stage are already covered when we scanned
            # that stage's own FROM.
            continue
        out.append(FromEntry(
            image=image,
            stage_name=inst.stage_name,
            line=inst.line,
        ))
    return out


def _extract_image_token(args: str) -> Optional[str]:
    """Extract the image reference from a FROM's args, skipping
    ``--platform`` / ``--key=value`` frontend flags."""
    for tok in args.split():
        if tok.startswith("--"):
            continue
        if tok.upper() == "AS":
            return None
        return tok
    return None


# Hostnames that are deliberately unresolvable — test-stub registries
# (used in fixture YAMLs to ensure the parser handles syntax without
# making real registry calls), example-domain placeholders, and
# obvious "fill-this-in" hostnames.
_UNRESOLVABLE_HOSTS = frozenset({
    "fake.docker.io", "fake.io",
    "example.com", "example.org",
    "your.registry.com", "your-registry.com",
})


def _is_unresolvable_image_ref(image: str) -> bool:
    """True for image refs that cannot be resolved against any
    real registry — saves the OCI client an HTTP round-trip plus
    its full retry budget (up to 383s per fetch).

    Covers four categories:

      1. Helm template placeholders: ``{{ .Values.global.hub }}``,
         ``{{$.Values.image}}`` etc. Common in ``charts/*/values.yaml``
         and the rendered manifest examples shipped alongside.
      2. Env-substitution syntax: ``docker.io/istio/base:${BASE_VERSION}``,
         ``${IMAGE}``. Only resolvable at deploy time after CI
         substitutes; we have no way to materialise it.
      3. Test-stub hostnames: ``fake.docker.io/...``,
         ``example.com/...``. Deliberately unreachable in the
         fixture data.
      4. Bare empty / whitespace-only refs.

    Conservative — when in doubt, NOT unresolvable (let the OCI
    client decide). False negatives produce extra HTTP calls;
    false positives silently drop legitimate refs.
    """
    if not isinstance(image, str):
        return True
    s = image.strip()
    if not s:
        return True
    # Helm template placeholder anywhere in the ref. ``{{`` covers
    # both bare placeholders and refs like
    # ``{{ .Values.image.repository }}:{{ .Values.image.tag }}``.
    if "{{" in s or "}}" in s:
        return True
    # Env-substitution anywhere — even partial like
    # ``istio/base:${BASE_VERSION}`` is unresolvable.
    if "${" in s:
        return True
    # Test-stub hostname (host segment ends at first ``/`` or ``:``).
    host = s.split("/", 1)[0].split(":", 1)[0].lower()
    if host in _UNRESOLVABLE_HOSTS:
        return True
    return False


# ---------------------------------------------------------------------------
# Image SBOM fetch
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ImageSbom:
    """All installed packages found in an image, plus the digest
    we resolved the tag to.

    ``layer_count_scanned`` is for diagnostics — operators can see
    "we pulled 3 layers" in the log even when 0 packages came back
    (some images have no recognised package db, e.g. distroless).
    """
    image_ref: str
    digest: Optional[str]
    packages: Tuple[InstalledPackage, ...]
    layer_count_scanned: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Serialise for the cross-run JsonCache. Versions and names
        are plain strings; ecosystem is the OSV string. The
        ``image_ref`` is informational — the cache is keyed on
        ``digest``, but we keep the ref for diagnostic logging."""
        return {
            "image_ref": self.image_ref,
            "digest": self.digest,
            "layer_count_scanned": self.layer_count_scanned,
            "packages": [
                {"ecosystem": p.ecosystem,
                 "name": p.name,
                 "version": p.version}
                for p in self.packages
            ],
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ImageSbom":
        return cls(
            image_ref=d.get("image_ref", "") or "",
            digest=d.get("digest"),
            layer_count_scanned=int(d.get("layer_count_scanned", 0) or 0),
            packages=tuple(
                InstalledPackage(
                    ecosystem=p.get("ecosystem", "") or "",
                    name=p.get("name", "") or "",
                    version=p.get("version", "") or "",
                )
                for p in (d.get("packages") or [])
                if isinstance(p, dict)
            ),
        )


def fetch_image_sbom(
    image: str,
    *,
    client: OciRegistryClient,
    platform_os: str = "linux",
    platform_arch: str = "amd64",
    max_layer_bytes: int = 256 * 1024 * 1024,
    digest_cache: Optional[Dict[str, "ImageSbom"]] = None,
    disk_cache: Optional[Any] = None,
) -> Optional[ImageSbom]:
    """Pull the OS-package SBOM for ``image``.

    Returns ``None`` on resolution failure (image not found,
    registry unreachable, manifest parse error). Caller decides how
    to surface (log + skip, in this module's case).

    Layers above ``max_layer_bytes`` are skipped — base images are
    typically small (alpine ~5 MB, debian-slim ~30 MB), and a
    multi-GB layer is almost always a final-stage app blob that
    couldn't carry useful OS package data anyway.
    """
    try:
        ref = parse_image_ref(image)
    except ValueError as e:
        # ``image@<not-a-digest>`` (e.g. ``bitnami/kafka@3.7.0``) is a
        # common operator typo where ``@`` was used instead of ``:``
        # for the tag separator. We can't safely re-interpret it
        # (a truncated digest would also land here, and silently
        # rewriting it to a tag could mask a real malformation), so
        # we skip — but at DEBUG level, not WARNING. Operators
        # asking SCA to scan a directory containing Helm-rendered
        # YAML or third-party docker-compose files shouldn't see
        # WARN-level noise for upstream-authored content the
        # operator doesn't control. The earlier behaviour fired
        # WARN per occurrence; the May 2026 200-project sweep
        # produced 4 such WARNs from one project's vendored
        # compose files alone.
        if "malformed digest" in str(e):
            logger.debug(
                "sca.dockerfile_from: image ref %r uses @ for tag "
                "(should be :); skipping: %s",
                image, e,
            )
        else:
            logger.warning(
                "sca.dockerfile_from: cannot parse image ref %r: %s",
                image, e,
            )
        return None
    except Exception as e:                          # noqa: BLE001
        logger.warning(
            "sca.dockerfile_from: cannot parse image ref %r: %s",
            image, e,
        )
        return None

    # Negative-cache short-circuit. ``image`` refs that previously
    # 404'd or otherwise failed cleanly get a marker in the disk
    # cache with a 1-hour TTL. Re-scanning a Dockerfile with stale
    # FROM tags (e.g. spring-boot-2.1's ``openjdk:11-ea-28-jdk``,
    # an early-access build long since purged from Docker Hub)
    # would otherwise burn ~15-20s per ref every run on the
    # auth-dance-then-404 path. Disk-backed because the fail state
    # is stable across operator re-runs against unchanged
    # Dockerfiles.
    _NEGATIVE_KEY_PREFIX = "negative-fetch:"
    _NEGATIVE_TTL = 3600  # 1 hour
    negative_key = _NEGATIVE_KEY_PREFIX + image
    if disk_cache is not None:
        if disk_cache.get(negative_key, ttl_seconds=_NEGATIVE_TTL):
            return None

    # Tag → digest cache check. Once we know that ``ubuntu:24.04``
    # resolved to ``sha256:abc...`` on disk, subsequent scans can
    # skip the manifest+platform-drill HTTP round-trips entirely
    # and look up the SBOM directly by digest. The mapping is
    # cached TTL_FOREVER because the resolved digest IS the image
    # at that moment in time — even if the registry later moves
    # the tag to a different digest, the OLD digest is still a
    # valid (immutable, content-addressed) image whose SBOM
    # remains accurate. Operators wanting to pick up a re-pushed
    # tag run ``raptor-sca clean-cache``.
    _TAG_DIGEST_KEY_PREFIX = "tag-digest:"
    tag_digest_key = _TAG_DIGEST_KEY_PREFIX + image
    if disk_cache is not None:
        from core.json.cache import TTL_FOREVER
        cached_digest = disk_cache.get(
            tag_digest_key, ttl_seconds=TTL_FOREVER,
        )
        if isinstance(cached_digest, str) and cached_digest:
            # Try to skip ALL network calls — if the SBOM-by-digest
            # cache also has the platform-resolved blob, we return
            # without ever touching the registry.
            if (digest_cache is not None
                    and cached_digest in digest_cache):
                cached = digest_cache[cached_digest]
                return ImageSbom(
                    image_ref=image,
                    digest=cached_digest,
                    packages=cached.packages,
                    layer_count_scanned=cached.layer_count_scanned,
                )
            disk_value = disk_cache.get(
                cached_digest, ttl_seconds=TTL_FOREVER,
            )
            if isinstance(disk_value, dict):
                restored = ImageSbom.from_dict(disk_value)
                if digest_cache is not None:
                    digest_cache[cached_digest] = restored
                return ImageSbom(
                    image_ref=image,
                    digest=cached_digest,
                    packages=restored.packages,
                    layer_count_scanned=restored.layer_count_scanned,
                )
            # Tag → digest known but SBOM evicted; fall through to
            # the normal fetch path below — we'll re-resolve via
            # the registry. The cached mapping isn't wrong, just
            # stale-paired.

    try:
        manifest_resp = client.fetch_manifest(ref)
    except Exception as e:                          # noqa: BLE001
        # DEBUG, not WARNING: per-image fetch failures are routine
        # when scanning multi-image-source projects — private
        # registries, missing tags, anonymous-pull rate limits, and
        # 302 redirects we don't follow are expected categories.
        # Logging at WARNING dumped 60+ lines on istio's 87-image
        # tree. The empty SBOM the caller gets is the actionable
        # signal; per-image diagnostics belong in --verbose.
        logger.debug(
            "sca.dockerfile_from: failed to fetch manifest for %s: %s",
            image, e,
        )
        # Persist a negative marker so re-scans don't repeat the
        # full auth+retry dance on the same broken ref.
        if disk_cache is not None:
            disk_cache.put(
                negative_key, {"failed": True},
                ttl_seconds=_NEGATIVE_TTL,
            )
        return None

    # Drill through image-index → per-platform manifest if needed.
    parsed = manifest_resp.parsed
    media_type = manifest_resp.content_type
    target_digest = manifest_resp.digest

    if is_image_index(media_type):
        entries = parse_image_index(parsed)
        pick = select_platform(
            entries, os=platform_os, architecture=platform_arch,
        )
        if pick is None:
            logger.warning(
                "sca.dockerfile_from: no %s/%s manifest in index for %s",
                platform_os, platform_arch, image,
            )
            return None
        try:
            sub = client.fetch_manifest(ref, reference=pick.digest)
        except Exception as e:                      # noqa: BLE001
            logger.warning(
                "sca.dockerfile_from: failed to fetch sub-manifest "
                "%s for %s: %s", pick.digest, image, e,
            )
            return None
        parsed = sub.parsed
        media_type = sub.content_type
        target_digest = pick.digest

    if not is_image_manifest(media_type):
        logger.warning(
            "sca.dockerfile_from: unexpected media type %s for %s",
            media_type, image,
        )
        return None

    # Persist the tag → digest mapping now that we've resolved it.
    # TTL_FOREVER because the digest IS immutable; operator-purge
    # via ``raptor-sca clean-cache`` to refresh.
    if disk_cache is not None and target_digest:
        from core.json.cache import TTL_FOREVER
        disk_cache.put(
            tag_digest_key, target_digest,
            ttl_seconds=TTL_FOREVER,
        )

    # Cache short-circuit on the resolved digest. Two cache levels:
    #   * ``digest_cache`` — in-memory dict, per ``scan_dockerfiles``
    #     invocation. Cheap; covers "same base image referenced from
    #     multiple Dockerfiles in one run".
    #   * ``disk_cache`` — JsonCache, persists across runs. Covers
    #     "operator re-runs SCA tomorrow against an unchanged base
    #     image". Digests are content-addressed, so cached entries
    #     are stored ``TTL_FOREVER``.
    if target_digest:
        if digest_cache is not None and target_digest in digest_cache:
            cached = digest_cache[target_digest]
            return ImageSbom(
                image_ref=image,
                digest=target_digest,
                packages=cached.packages,
                layer_count_scanned=cached.layer_count_scanned,
            )
        if disk_cache is not None:
            from core.json.cache import TTL_FOREVER
            disk_value = disk_cache.get(
                target_digest, ttl_seconds=TTL_FOREVER,
            )
            if isinstance(disk_value, dict):
                restored = ImageSbom.from_dict(disk_value)
                # Promote into the in-memory tier so subsequent calls
                # in this run skip the disk hit too.
                if digest_cache is not None:
                    digest_cache[target_digest] = restored
                return ImageSbom(
                    image_ref=image,
                    digest=target_digest,
                    packages=restored.packages,
                    layer_count_scanned=restored.layer_count_scanned,
                )

    image_manifest = parse_image_manifest(parsed)

    # Aggregate package-state file content across layers. Later
    # layers override earlier ones (Docker overlay-fs semantics) —
    # ``packages_from_layer_files`` handles that ordering.
    layer_files: Dict[str, bytes] = {}
    layers_scanned = 0
    wanted = set(LAYER_FILE_PATHS.keys())
    for layer in image_manifest.layers:
        if layer.size and layer.size > max_layer_bytes:
            logger.debug(
                "sca.dockerfile_from: skipping oversized layer %s (%d B)",
                layer.digest, layer.size,
            )
            continue
        try:
            chunks = client.stream_blob(ref, layer.digest)
            files = extract_files_from_layer(chunks, wanted)
        except Exception as e:                      # noqa: BLE001
            logger.debug(
                "sca.dockerfile_from: failed to extract layer %s: %s",
                layer.digest, e,
            )
            continue
        layers_scanned += 1
        # Later layers override earlier — direct overwrite mirrors
        # overlay-fs "later wins" semantics.
        for path, content in files.items():
            layer_files[path] = content

    packages = tuple(packages_from_layer_files(layer_files))
    sbom = ImageSbom(
        image_ref=image,
        digest=target_digest,
        packages=packages,
        layer_count_scanned=layers_scanned,
    )
    if target_digest:
        if digest_cache is not None:
            digest_cache[target_digest] = sbom
        if disk_cache is not None:
            from core.json.cache import TTL_FOREVER
            disk_cache.put(
                target_digest, sbom.to_dict(), ttl_seconds=TTL_FOREVER,
            )
    return sbom


# ---------------------------------------------------------------------------
# SBOM → Dependency mapping
# ---------------------------------------------------------------------------


_PIN_CONFIDENCE = Confidence(
    "high",
    reason="OS package db carries exact installed version",
)


_PURL_TYPE_BY_ECOSYSTEM = {
    "Debian": "deb",
    "Ubuntu": "deb",
    "Alpine": "apk",
    "Red Hat": "rpm",
}


def packages_to_dependencies(
    packages: Iterable[InstalledPackage],
    *,
    declared_in: Path,
    image_ref: Optional[str] = None,
    digest: Optional[str] = None,
    stage_name: Optional[str] = None,
) -> List[Dependency]:
    """Convert installed-package records into Dependency rows.

    All Deps share ``declared_in`` (the Dockerfile path),
    ``source_kind="dockerfile_from"``, and a high
    ``parser_confidence`` (the data came from a real package db,
    not a regex over a RUN line).

    ``image_ref`` / ``digest`` / ``stage_name`` (when supplied)
    populate ``source_extra`` so reports can group findings by base
    image and surface which build stage produced them — e.g. a
    multi-stage build's intermediate ``builder`` stage's findings
    can be filtered out from a final-image-focused review.
    """
    extra: Optional[Dict[str, Any]] = None
    # ``image_ref`` is the gate: when the caller has any image
    # context, we record the full triple — including ``stage_name=
    # None`` for the final / un-named stage. ``None`` is a
    # meaningful value (the final stage), distinct from "stage info
    # wasn't supplied".
    if image_ref:
        extra = {"image": image_ref, "stage_name": stage_name}
        if digest:
            extra["digest"] = digest

    out: List[Dependency] = []
    for pkg in packages:
        if not pkg.name or not pkg.version:
            continue
        purl_type = _PURL_TYPE_BY_ECOSYSTEM.get(
            pkg.ecosystem, pkg.ecosystem.lower(),
        )
        purl = f"pkg:{purl_type}/{pkg.name}@{pkg.version}"
        out.append(Dependency(
            ecosystem=pkg.ecosystem,
            name=pkg.name,
            version=pkg.version,
            declared_in=declared_in,
            scope="main",
            is_lockfile=True,
            pin_style=PinStyle.EXACT,
            direct=True,
            purl=purl,
            parser_confidence=_PIN_CONFIDENCE,
            source_kind="dockerfile_from",
            source_extra=dict(extra) if extra else None,
        ))
    return out


# ---------------------------------------------------------------------------
# Public entry — pipeline wiring
# ---------------------------------------------------------------------------


def scan_dockerfiles(
    target: Path,
    *,
    client: Optional[OciRegistryClient] = None,
    platform_os: str = "linux",
    platform_arch: str = "amd64",
    cache: Optional[Any] = None,
) -> List[Dependency]:
    """Discover Dockerfiles in ``target``, fetch each FROM's
    SBOM, and return the Dependency rows.

    Supplying ``client`` lets tests inject a mock; production
    callers can pass ``None`` and accept the default (anonymous
    pulls via ``core.http.default_client()``).

    ``cache`` is a :class:`core.json.cache.JsonCache` namespaced for
    Dockerfile-FROM SBOMs. Per-digest entries are stored
    ``TTL_FOREVER`` since digests are content-addressed. When ``None``
    is passed, the per-run in-memory dict is the only cache tier
    (correct behaviour for tests; production callers should pass a
    cache so re-runs against unchanged base images don't re-fetch).

    Returns an empty list when the target has no Dockerfiles, when
    every FROM was unresolvable, or when ``client`` rejected every
    request.
    """
    dockerfiles = find_dockerfiles(target)
    if not dockerfiles:
        return []

    if client is None:
        # Lazy default to avoid pulling core.http into module load
        # when the caller wires its own client.
        from core.http import default_client
        client = OciRegistryClient(http=default_client())

    deps: List[Dependency] = []
    digest_cache: Dict[str, ImageSbom] = {}
    for dockerfile in dockerfiles:
        try:
            text = dockerfile.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            logger.warning(
                "sca.dockerfile_from: cannot read %s: %s", dockerfile, e,
            )
            continue
        for entry in extract_from_lines(text):
            sbom = fetch_image_sbom(
                entry.image,
                client=client,
                platform_os=platform_os,
                platform_arch=platform_arch,
                digest_cache=digest_cache,
                disk_cache=cache,
            )
            if sbom is None or not sbom.packages:
                continue
            deps.extend(packages_to_dependencies(
                sbom.packages,
                declared_in=dockerfile,
                image_ref=entry.image,
                digest=sbom.digest,
                stage_name=entry.stage_name,
            ))
    return deps


# ---------------------------------------------------------------------------
# Image-source unification
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ImageRefSource:
    """One image reference discovered from any image-source file
    (Dockerfile FROM, docker-compose ``image:``, GitLab CI ``image:``
    / ``services:``).

    The unified ``scan_image_sources`` walker dedups by ``image``
    so the same registry image referenced from multiple sources
    fetches the SBOM once.
    """
    image: str
    declared_in: Path
    source_kind: str            # "dockerfile_from" / "compose" / "gitlab_ci"
    stage_name: Optional[str] = None    # only for Dockerfile multi-stage


def find_compose_image_refs(target: Path) -> List[ImageRefSource]:
    """Walk the target for docker-compose files, extract each
    service's ``image:`` ref. Skip services that only ``build:``
    (local build, no registry pull)."""
    out: List[ImageRefSource] = []
    try:
        import yaml
        from ._yaml_fast import safe_load
    except ImportError:
        return out
    from .parsers.compose import _is_compose_file
    for root, dirs, files in os.walk(target):
        from .discovery import EXCLUDED_DIR_NAMES
        dirs[:] = [
            d for d in dirs
            if d not in EXCLUDED_DIR_NAMES and not d.startswith(".")
        ]
        for f in files:
            p = Path(root) / f
            if not _is_compose_file(p):
                continue
            if _path_under_excluded_image_parent(p, target):
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
                data = safe_load(text)
            except (OSError, yaml.YAMLError):
                continue
            if not isinstance(data, dict):
                continue
            services = data.get("services") or {}
            if not isinstance(services, dict):
                continue
            for svc_name, svc in services.items():
                if not isinstance(svc, dict):
                    continue
                image = svc.get("image")
                if isinstance(image, str) and image.strip():
                    out.append(ImageRefSource(
                        image=image.strip(),
                        declared_in=p,
                        source_kind="compose",
                    ))
    return out


def find_gitlab_ci_image_refs(target: Path) -> List[ImageRefSource]:
    """Walk the target for ``.gitlab-ci.yml`` / ``.gitlab-ci.yaml``,
    extract every top-level + per-job ``image:`` ref plus
    ``services:`` array entries."""
    out: List[ImageRefSource] = []
    try:
        import yaml
        from ._yaml_fast import safe_load
    except ImportError:
        return out
    from .discovery import EXCLUDED_DIR_NAMES
    for root, dirs, files in os.walk(target):
        dirs[:] = [
            d for d in dirs
            if d not in EXCLUDED_DIR_NAMES and not d.startswith(".")
        ]
        for f in files:
            if f not in (".gitlab-ci.yml", ".gitlab-ci.yaml"):
                continue
            p = Path(root) / f
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
                data = safe_load(text)
            except (OSError, yaml.YAMLError):
                continue
            if not isinstance(data, dict):
                continue
            for image, _ctx in _walk_gitlab_image_refs(data):
                out.append(ImageRefSource(
                    image=image, declared_in=p, source_kind="gitlab_ci",
                ))
    return out


def _walk_gitlab_image_refs(data: dict):
    """Yield ``(image_ref, context)`` for every image: / services:
    in a parsed GitLab CI config. Lifted from the parser's logic."""
    _RESERVED = {
        "image", "services", "variables", "stages", "default",
        "include", "before_script", "after_script", "workflow",
        "cache", "artifacts", "pages", "trigger",
    }

    def _from(block, label):
        if not isinstance(block, dict):
            return
        image = block.get("image")
        if isinstance(image, str) and image.strip():
            yield image.strip(), label
        elif isinstance(image, dict):
            name = image.get("name")
            if isinstance(name, str) and name.strip():
                yield name.strip(), label
        services = block.get("services")
        if isinstance(services, list):
            for entry in services:
                if isinstance(entry, str) and entry.strip():
                    yield entry.strip(), label
                elif isinstance(entry, dict):
                    name = entry.get("name")
                    if isinstance(name, str) and name.strip():
                        yield name.strip(), label

    yield from _from(data, "top-level")
    for k, v in data.items():
        if not isinstance(k, str) or k in _RESERVED:
            continue
        if not isinstance(v, dict):
            continue
        yield from _from(v, f"job {k}")


def find_kubernetes_image_refs(target: Path) -> List[ImageRefSource]:
    """Walk the target for Kubernetes manifest YAMLs, extract the
    container images declared by each workload kind."""
    out: List[ImageRefSource] = []
    try:
        import yaml
        from ._yaml_fast import safe_load_all
    except ImportError:
        return out
    from .parsers.kubernetes import _is_k8s_manifest, _WORKLOAD_KINDS
    from .discovery import EXCLUDED_DIR_NAMES
    for root, dirs, files in os.walk(target):
        dirs[:] = [
            d for d in dirs
            if d not in EXCLUDED_DIR_NAMES and not d.startswith(".")
        ]
        for f in files:
            p = Path(root) / f
            if not _is_k8s_manifest(p):
                continue
            if _path_under_excluded_image_parent(p, target):
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
                docs = list(safe_load_all(text))
            except (OSError, yaml.YAMLError):
                continue
            for doc in docs:
                if not isinstance(doc, dict):
                    continue
                kind = doc.get("kind")
                if not isinstance(kind, str) or kind not in _WORKLOAD_KINDS:
                    continue
                spec = doc.get("spec")
                if not isinstance(spec, dict):
                    continue
                template_spec = spec
                template = spec.get("template")
                if isinstance(template, dict):
                    ts = template.get("spec")
                    if isinstance(ts, dict):
                        template_spec = ts
                for cf in (
                    "containers", "initContainers", "ephemeralContainers",
                ):
                    containers = template_spec.get(cf)
                    if not isinstance(containers, list):
                        continue
                    for container in containers:
                        if not isinstance(container, dict):
                            continue
                        image = container.get("image")
                        if isinstance(image, str) and image.strip():
                            out.append(ImageRefSource(
                                image=image.strip(),
                                declared_in=p,
                                source_kind="k8s",
                            ))
    return out


def find_all_image_refs(target: Path) -> List[ImageRefSource]:
    """Discover every image reference in the target tree across
    Dockerfile FROM, docker-compose ``image:``, GitLab CI ``image:``
    + ``services:``, and Kubernetes ``spec.containers[].image``.
    Output is the flat list — caller dedupes by ``image`` if the
    SBOM-fetch tier wants only-once semantics."""
    out: List[ImageRefSource] = []
    for dockerfile in find_dockerfiles(target):
        try:
            text = dockerfile.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for entry in extract_from_lines(text):
            out.append(ImageRefSource(
                image=entry.image,
                declared_in=dockerfile,
                source_kind="dockerfile_from",
                stage_name=entry.stage_name,
            ))
    out.extend(find_compose_image_refs(target))
    out.extend(find_gitlab_ci_image_refs(target))
    out.extend(find_kubernetes_image_refs(target))
    return out


def scan_image_sources(
    target: Path,
    *,
    client: Optional[OciRegistryClient] = None,
    platform_os: str = "linux",
    platform_arch: str = "amd64",
    cache: Optional[Any] = None,
) -> List[Dependency]:
    """Discover every image reference under ``target`` (Dockerfiles,
    docker-compose, GitLab CI), fetch each unique image's OS-package
    SBOM via ``core.oci``, and return the Dependency rows.

    Same fetcher + cache plumbing as :func:`scan_dockerfiles`, but
    operates on the union of all OCI image-source files. The
    Dockerfile-only entry point stays for backwards compatibility
    + tests; production pipeline calls this.

    Each unique ``image`` ref is fetched once even when referenced
    from multiple sources (one Dockerfile FROM + one compose
    service + one GitLab CI image with the same image: postgres:16
    fetches the SBOM exactly once).
    """
    refs = find_all_image_refs(target)
    # Drop image refs we can't resolve at parse time — Helm template
    # placeholders, env-substitution syntax, and known-test-stub
    # hostnames. Pre-filtering here saves the per-image registry
    # round-trip (and its retry budget — up to 383s per fetch under
    # the default backoff schedule when a registry returns 5xx/429).
    # On the istio-1.4 corpus sample this drops scan wall-clock from
    # ~9 minutes to under 2 (16+ Helm refs were generating 401/429
    # storms against docker.io).
    filtered_refs = [r for r in refs if not _is_unresolvable_image_ref(r.image)]
    if not filtered_refs:
        return []
    refs = filtered_refs

    if client is None:
        from core.http import default_client
        client = OciRegistryClient(http=default_client())

    deps: List[Dependency] = []
    digest_cache: Dict[str, ImageSbom] = {}
    seen_images: Dict[str, Optional[ImageSbom]] = {}

    # Fetch SBOMs for unique images in parallel — each call is an
    # OCI registry HTTP round-trip (~300-400ms). Sequential walk
    # of even 4 unique images costs >1.2s; pool brings it to one
    # round-trip. The dedup pass below ensures one fetch per image
    # regardless of how many refs point at it.
    unique_images = []
    seen: set = set()
    for ref in refs:
        if ref.image in seen:
            continue
        seen.add(ref.image)
        unique_images.append(ref.image)
    if unique_images:
        from concurrent.futures import ThreadPoolExecutor
        def _fetch_one(image: str):
            return image, fetch_image_sbom(
                image, client=client,
                platform_os=platform_os,
                platform_arch=platform_arch,
                digest_cache=digest_cache,
                disk_cache=cache,
            )
        # Cap at 8 — most repos have far fewer unique images, and
        # bigger pools just queue more work onto the egress proxy.
        max_workers = min(8, max(1, len(unique_images)))
        with ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="sca-oci-sbom",
        ) as pool:
            for image, sbom in pool.map(_fetch_one, unique_images):
                # ``None`` is recorded so the per-ref loop below
                # treats the fetch as known-bad without retrying.
                seen_images[image] = sbom

    for ref in refs:
        sbom = seen_images.get(ref.image)
        if sbom is None or not sbom.packages:
            continue
        deps.extend(packages_to_dependencies(
            sbom.packages,
            declared_in=ref.declared_in,
            image_ref=ref.image,
            digest=sbom.digest,
            stage_name=ref.stage_name,
        ))
    return deps


def image_source_registry_hosts(target: Path) -> List[str]:
    """Generalisation of :func:`dockerfile_registry_hosts` covering
    every image-source file. Returns the union of registry
    hostnames the sandbox must allow for the OCI client to fetch
    every image referenced in the target — Dockerfile FROM,
    compose ``image:``, GitLab CI ``image:`` / ``services:``.

    Same best-effort + sorted-output contract."""
    found: set = set()
    for ref in find_all_image_refs(target):
        try:
            hosts = registry_hosts_for(ref.image)
        except Exception as e:                      # noqa: BLE001
            logger.debug(
                "sca.dockerfile_from: cannot resolve hosts for "
                "%s in %s: %s", ref.image, ref.declared_in, e,
            )
            continue
        found.update(hosts)
    return sorted(found)


def dockerfile_registry_hosts(target: Path) -> List[str]:
    """Return the union of registry hostnames the sandbox needs to
    allow for every base image referenced in every Dockerfile under
    ``target``.

    This is the sandbox-config-time companion to
    :func:`scan_dockerfiles`. Operators running SCA inside a
    sandboxed run pass the result of this through to the sandbox's
    ``proxy_hosts`` allowlist; without it the OCI client's
    manifest / blob requests fail at the proxy with no useful
    error.

    Parsing is best-effort: a malformed Dockerfile or an
    unparseable image ref logs a debug line and is skipped, never
    aborts the walk. An empty list is a valid result (no Dockerfiles
    in the target, or none with a registry-pulled FROM).

    Output is deduplicated and sorted for deterministic
    allowlist composition.
    """
    found: set = set()
    for dockerfile in find_dockerfiles(target):
        try:
            text = dockerfile.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            logger.debug(
                "sca.dockerfile_from: cannot read %s for sandbox host "
                "extraction: %s", dockerfile, e,
            )
            continue
        for entry in extract_from_lines(text):
            try:
                hosts = registry_hosts_for(entry.image)
            except Exception as e:                  # noqa: BLE001
                logger.debug(
                    "sca.dockerfile_from: cannot resolve hosts for "
                    "%s in %s: %s", entry.image, dockerfile, e,
                )
                continue
            found.update(hosts)
    return sorted(found)


__all__ = [
    "FromEntry",
    "ImageRefSource",
    "ImageSbom",
    "dockerfile_registry_hosts",
    "extract_from_lines",
    "fetch_image_sbom",
    "find_all_image_refs",
    "find_compose_image_refs",
    "find_dockerfiles",
    "find_gitlab_ci_image_refs",
    "find_kubernetes_image_refs",
    "image_source_registry_hosts",
    "packages_to_dependencies",
    "scan_dockerfiles",
    "scan_image_sources",
]
