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


# Regex split-points kept simple + verified by tests; not the full
# distribution spec grammar but covers the shapes operators write.
# Anything that fails canonicalisation is rejected with a clear
# error so consumers don't paper over malformed input.
_DIGEST_RE = re.compile(
    r"^(?P<algo>[A-Za-z][A-Za-z0-9]*(?:[-_+.][A-Za-z0-9]+)*)"
    r":(?P<hex>[A-Fa-f0-9]{32,})$"
)

# The one digest algorithm the client can actually verify: content
# addresses are recomputed as sha256 over response bytes, so a pin in
# any other algorithm (sha512:, md5:, ...) would be fetched and used
# with NO content authentication. Refused loudly at parse time —
# a quietly-accepted-but-unverifiable pin is strictly worse than an
# error the operator can act on.
_SHA256_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


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
    tag: str | None       # e.g. "3.11", or None when only digest is given
    digest: str | None    # "sha256:..." or None

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
        msg = "empty image reference"
        raise ValueError(msg)

    # Split off the digest first — it's the unambiguous suffix.
    digest: str | None = None
    if "@" in s:
        s, digest = s.rsplit("@", 1)
        m = _DIGEST_RE.match(digest)
        if not m:
            raise ValueError(
                f"malformed digest {digest!r}; expected "
                f"<algorithm>:<hex>"
            )
        # Canonicalise case (hex digests and algorithm names are
        # case-insensitive in operator input; registries emit
        # lowercase) before the algorithm gate.
        digest = digest.lower()
        if not _SHA256_DIGEST_RE.match(digest):
            raise ValueError(
                f"unsupported digest algorithm in {digest!r}: only "
                f"sha256:<64 hex> pins are supported — content "
                f"addresses are recomputed as sha256, so any other "
                f"algorithm cannot be verified"
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
    tag: str | None
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
        msg = f"image reference missing repository: {s!r}"
        raise ValueError(msg)

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


def split_image_ref(ref: str) -> tuple[str, str | None]:
    """Split an OCI image reference into ``(name, tag-or-digest)``.

    ``postgres:16`` → ``("postgres", "16")``
    ``ghcr.io/x/y:1.2`` → ``("ghcr.io/x/y", "1.2")``
    ``alpine`` (no tag) → ``("alpine", None)``
    ``foo@sha256:abc...`` → ``("foo", "sha256:abc...")``  (digest pin)

    Lightweight, lossy sibling of :func:`parse_image_ref`: no
    registry / repository canonicalisation, no implicit defaults,
    never raises. Container-manifest parsers use it to pull a name +
    pin out of whatever operators wrote, without imposing Docker Hub
    conventions on the name.
    """
    # Digest pin first (``name@sha256:...``).
    if "@" in ref:
        name, _, digest = ref.rpartition("@")
        if ":" in name.rsplit("/", 1)[-1]:
            name = name.rsplit(":", 1)[0]
        return name, digest or None
    # Tag pin (last colon, but only AFTER the last slash so we
    # don't confuse a registry port like ``localhost:5000``).
    last_slash = ref.rfind("/")
    rest = ref[last_slash + 1:] if last_slash >= 0 else ref
    if ":" in rest:
        prefix = ref[:last_slash + 1] if last_slash >= 0 else ""
        rest_name, _, tag = rest.partition(":")
        return prefix + rest_name, tag or None
    return ref, None


__all__ = ["ImageRef", "parse_image_ref", "split_image_ref"]
