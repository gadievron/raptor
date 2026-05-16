"""Parse + canonicalise OCI / Docker image references.

A reference can take many shapes operators write naturally:

  * ``python``                                          — implicit ``library`` + ``latest``
  * ``python:3.11``                                     — implicit ``library``
  * ``library/python:3.11``                             — implicit ``docker.io``
  * ``docker.io/library/python:3.11``                   — fully qualified
  * ``ghcr.io/anthropic/claude-code:0.1``               — non-Docker-Hub registry
  * ``1234.dkr.ecr.us-east-1.amazonaws.com/img:tag``    — ECR (registry inferred from host shape)
  * ``python@sha256:abc…``                              — digest pin
  * ``python:3.11@sha256:abc…``                         — tag + digest

This module canonicalises all of those into a single
:class:`ImageRef` with explicit ``registry``, ``repository``,
``tag``, and ``digest``. Downstream consumers (auth, manifest fetch,
host allowlist) work off the canonical form so they don't repeat the
parsing logic.

References:
  * Docker Distribution registry-2 spec, ``reference.go`` (the
    canonical implementation we're aiming for).
  * OCI Image Spec — image references section.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


# Regex split-points kept simple + verified by tests; not the full
# distribution spec grammar but covers the shapes operators write.
# Anything that fails canonicalisation is rejected with a clear
# error so consumers don't paper over malformed input.
_DIGEST_RE = re.compile(
    r"^(?P<algo>[A-Za-z][A-Za-z0-9]*(?:[-_+.][A-Za-z0-9]+)*)"
    r":(?P<hex>[A-Fa-f0-9]{32,})$"
)


@dataclass(frozen=True)
class ImageRef:
    """Canonicalised OCI image reference.

    Always carries an explicit ``registry`` and ``repository``;
    ``tag`` defaults to ``"latest"`` when neither tag nor digest is
    supplied. ``digest`` is None when not given.

    Construct via :func:`parse_image_ref` rather than directly so
    short-form refs (``python``) get the implicit defaults applied
    consistently.
    """

    registry: str            # e.g. "docker.io", "ghcr.io"
    repository: str          # e.g. "library/python", "anthropic/claude-code"
    tag: Optional[str]       # e.g. "3.11", or None when only digest is given
    digest: Optional[str]    # "sha256:..." or None

    def to_canonical(self) -> str:
        """Round-trippable canonical form: ``<registry>/<repo>[:<tag>][@<digest>]``."""
        parts = [f"{self.registry}/{self.repository}"]
        if self.tag:
            parts[-1] += f":{self.tag}"
        if self.digest:
            parts[-1] += f"@{self.digest}"
        return parts[0]

    @property
    def reference(self) -> str:
        """The reference for HTTP API endpoints — digest if available
        (immutable), else tag. Never None: fall back to ``"latest"``."""
        return self.digest or self.tag or "latest"


def parse_image_ref(s: str) -> ImageRef:
    """Parse a Docker / OCI image reference into :class:`ImageRef`.

    Defaults applied for short-form references:
      * No registry component → ``docker.io``
      * Single-segment repository on docker.io → prefixed with
        ``library/`` (Docker Hub's namespace for official images)
      * No tag and no digest → tag defaults to ``"latest"``

    Raises :class:`ValueError` on malformed input. Errors name the
    specific malformation so operators don't have to re-derive the
    grammar from the message.
    """
    s = s.strip()
    if not s:
        raise ValueError("empty image reference")

    # Split off the digest first — it's the unambiguous suffix.
    digest: Optional[str] = None
    if "@" in s:
        s, digest = s.rsplit("@", 1)
        if not _DIGEST_RE.match(digest):
            raise ValueError(
                f"malformed digest {digest!r}; expected "
                f"<algorithm>:<hex>"
            )

    # The registry is the first ``/``-separated segment IF it looks
    # like a host (contains a ``.`` or ``:`` or is exactly
    # ``localhost``). Otherwise it's the first part of the
    # repository. This matches the Distribution spec's heuristic:
    # without a host-shaped first segment, default to docker.io.
    registry: str
    repo_and_tag: str
    if "/" in s:
        first, rest = s.split("/", 1)
        if (
            first == "localhost"
            or "." in first
            or ":" in first
        ):
            registry = first
            repo_and_tag = rest
        else:
            registry = "docker.io"
            repo_and_tag = s
    else:
        registry = "docker.io"
        repo_and_tag = s

    # Split repo from tag. Tag is what follows the LAST ``:``, but
    # only if it doesn't contain a ``/`` (a colon in the registry
    # part — like ``localhost:5000`` — has already been handled
    # above).
    tag: Optional[str]
    if ":" in repo_and_tag:
        repository, tag = repo_and_tag.rsplit(":", 1)
        if "/" in tag:
            # The colon was in the repo path, not a tag separator.
            # Re-merge.
            repository = repo_and_tag
            tag = None
    else:
        repository = repo_and_tag
        tag = None

    if not repository:
        raise ValueError(f"image reference missing repository: {s!r}")

    # Docker Hub's "library" prefix for single-segment refs (the
    # ``python`` → ``library/python`` convention).
    if registry == "docker.io" and "/" not in repository:
        repository = f"library/{repository}"

    # Default tag when neither tag nor digest given. Operators using
    # ``latest`` get explicit blame; not silently failing.
    if tag is None and digest is None:
        tag = "latest"

    return ImageRef(
        registry=registry, repository=repository, tag=tag, digest=digest,
    )


__all__ = ["ImageRef", "parse_image_ref"]
