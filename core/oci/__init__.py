"""OCI / Docker registry primitives — image references, manifests,
blob streaming, and per-image SBOM extraction.

This is shared substrate, shipped + tested but **not yet wired into
any `packages/*` consumer.** The primitives — pulling manifests,
streaming layer blobs, extracting package-manager state, mapping into
existing OSV ecosystem strings — mirror the pattern that ``core/http``,
``core/llm``, ``core/inventory`` already follow, so when consumers
land they share one substrate rather than reinventing.

Planned consumers (aspirational, none currently import ``core.oci.*``):

  * ``packages/sca`` — base-image SBOM as a Dependency source for
    CVE matching
  * ``packages/cve_diff`` — image-vs-image diff for security
    advisories
  * ``packages/llm_analysis`` (``/scan``, ``/agentic``) — surface
    base-image context for analysis prompts
  * ``packages/code_understanding`` (``/audit``) — include base-image
    SBOMs in code review

A docstring-vs-reality regression test
(``core/oci/tests/test_package_docstring_consumers.py``, F057) keeps
this list honest: any name appearing above "Planned consumers:" must
exist as a directory under ``packages/`` AND contain a real ``core.oci``
import.

Module map:

  * :mod:`core.oci.image_ref` — parse + canonicalise image references
    (``python:3.11`` → ``docker.io/library/python:3.11``).
  * :mod:`core.oci.registry_hosts` — image_ref → list[str] of hosts
    the sandbox must allow for fetch to succeed.
  * :mod:`core.oci.auth` — three-layer auth chain (anonymous bearer
    token → ``~/.docker/config.json`` inline auths → per-registry
    env vars).
  * :mod:`core.oci.client` — Registry HTTP API v2 client built on
    :class:`core.http.HttpClient`. Manifest + blob endpoints.
  * :mod:`core.oci.manifest` — OCI Image Manifest v1 + Docker
    Manifest Schema 2 + Image Index (multi-arch) parsing.
  * :mod:`core.oci.blob` — gzipped layer-tar streaming with targeted
    file extraction.
  * :mod:`core.oci.sbom` — extract installed-package lists from
    layer files (dpkg / apk / rpm).

Limitations (deliberate; see ``core/oci/README.md`` for full
discussion):
  * Anonymous + ``docker config.json`` inline auths only;
    ``credsStore`` / ``credHelpers`` shell-out is refused (security).
  * Single platform per pull (default ``linux/amd64``,
    ``--platform`` override). Pulling all architectures of a
    multi-arch image is wasteful for SBOM purposes.
  * Older RPM databases (Berkeley DB, used through CentOS 7) are
    not parsed; modern SQLite-backed ``rpmdb.sqlite`` only.
  * Cosign / sigstore signature verification not implemented in this
    substrate — see follow-up memo.
"""

from .image_ref import ImageRef, parse_image_ref
from .registry_hosts import registry_hosts_for

__all__ = [
    "ImageRef",
    "parse_image_ref",
    "registry_hosts_for",
]
