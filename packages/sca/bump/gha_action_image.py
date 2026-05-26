"""Resolve a GHA ``uses:`` reference to its underlying OCI image.

When a GitHub Actions workflow does ``uses: owner/repo@vX``, three
shapes are possible:

  1. **JavaScript / composite action** — ``action.yml`` declares
     ``runs.using: node20`` or ``runs.using: composite``. The
     action ships as a git repo with JS or YAML; no OCI image is
     involved. Out of scope for the binary-capability-delta
     detector.
  2. **Docker-container action with pre-built image** —
     ``runs.using: docker`` + ``runs.image: docker://<image>:<tag>``
     (or ``image:<tag>`` without prefix). Resolves to an OCI ref
     this module returns.
  3. **Docker-container action with Dockerfile** —
     ``runs.using: docker`` + ``runs.image: Dockerfile`` (or a
     relative path to one). The image only exists after a build;
     we don't run that. Out of scope.

The resolver fetches ``action.yml`` (or ``action.yaml``) from the
raw-content CDN — unauthenticated, no rate-limit pressure on the
operator's GitHub API budget. Tries ``.yml`` first since it's the
overwhelmingly more common extension; falls back to ``.yaml``.

Failure modes are routine when scanning GHA-heavy projects
(actions that aren't Docker-flavoured, deleted refs, sub-action
paths the existing GHA enumerator doesn't carry through). Every
failure returns ``None`` with a debug log — the bumper treats
that as "no binary-tier signal for this candidate".

Out of scope this revision
- **Sub-action paths**. ``uses: owner/repo/sub/dir@vX`` —
  ``action.yml`` is at ``sub/dir/action.yml``, not the repo root.
  The GHA-uses enumerator drops the subpath today; the
  ``BumpCandidate`` only carries ``owner/repo``. Sub-action
  resolution requires a candidate-shape change; deferred.
- **Authenticated fetches** for private repos. raw.github
  doesn't require auth for public repos and that's the
  capability-delta-relevant case (private action images aren't
  the supply-chain risk we're targeting).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from core.http import HttpClient

logger = logging.getLogger(__name__)


_RAW_GITHUB = "https://raw.githubusercontent.com"

# Cap on action.yml size. Real-world action.yml files are <10KB;
# 256KB is a generous ceiling that defends against pathological /
# malicious responses without truncating legitimate files.
_MAX_ACTION_YML_BYTES = 256 * 1024


@dataclass(frozen=True)
class GhaActionImage:
    """One Docker-container GHA action resolved to its OCI image.

    ``repo`` and ``ref`` are the inputs (so callers can correlate
    back to the originating ``uses:`` line). ``image_ref`` is the
    cleaned OCI string ready for ``fetch_image_binary``.
    """

    repo: str
    ref: str
    image_ref: str


def resolve_gha_action_image(
    repo: str,
    ref: str,
    *,
    http: HttpClient,
) -> Optional[GhaActionImage]:
    """Fetch ``action.yml`` from ``<repo>@<ref>`` and return the
    OCI image ref when the action uses Docker-container shape.

    Returns ``None`` for:
      * Non-Docker actions (JS / composite / unknown ``runs.using``)
      * Dockerfile-based actions (no pre-built image to diff)
      * Any fetch / parse failure
    """
    text = _fetch_action_yml(repo, ref, http=http)
    if text is None:
        return None
    image_ref = _parse_docker_action_image(text)
    if image_ref is None:
        return None
    return GhaActionImage(repo=repo, ref=ref, image_ref=image_ref)


def _fetch_action_yml(
    repo: str, ref: str, *, http: HttpClient,
) -> Optional[str]:
    """GET ``raw.githubusercontent.com/<repo>/<ref>/action.yml``,
    fall back to ``action.yaml``. Returns the decoded UTF-8 text,
    or None on any failure.

    ``ref`` is URL-safe by construction in the GHA-uses enumerator
    (tags + SHAs match the same regex as the bumper's
    ``current_version`` field — alphanumerics + ``.`` + ``-`` +
    ``_``); we don't sanitise here beyond that.
    """
    for ext in ("yml", "yaml"):
        url = f"{_RAW_GITHUB}/{repo}/{ref}/action.{ext}"
        try:
            blob = http.get_bytes(
                url, max_bytes=_MAX_ACTION_YML_BYTES,
            )
        except Exception as e:                        # noqa: BLE001
            logger.debug(
                "sca.bump.gha_action_image: action.%s fetch "
                "failed for %s@%s: %s", ext, repo, ref, e,
            )
            continue
        if not blob:
            continue
        try:
            return blob.decode("utf-8")
        except UnicodeDecodeError as e:
            logger.debug(
                "sca.bump.gha_action_image: action.%s decode failed "
                "for %s@%s: %s", ext, repo, ref, e,
            )
            continue
    return None


def _parse_docker_action_image(text: str) -> Optional[str]:
    """Parse an ``action.yml`` body and return the OCI image ref
    when this is a Docker-container action with a pre-built image.

    Returns ``None`` for:
      * YAML parse failure
      * ``runs.using`` missing or not ``"docker"`` (case-insensitive)
      * ``runs.image`` missing
      * ``runs.image`` referencing a Dockerfile (Dockerfile,
        ./path/Dockerfile, etc.)

    The ``docker://`` URI prefix is stripped — the OCI client
    consumes plain image refs.
    """
    try:
        import yaml             # type: ignore[import-untyped]
    except ImportError:
        logger.debug(
            "sca.bump.gha_action_image: PyYAML not installed; "
            "cannot resolve GHA action images",
        )
        return None

    try:
        loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
        data = yaml.load(text, Loader=loader)
    except Exception as e:                            # noqa: BLE001
        logger.debug(
            "sca.bump.gha_action_image: action.yml parse failed: %s",
            e,
        )
        return None

    if not isinstance(data, dict):
        return None
    runs = data.get("runs")
    if not isinstance(runs, dict):
        return None
    using = runs.get("using")
    if not isinstance(using, str) or using.strip().lower() != "docker":
        return None
    image = runs.get("image")
    if not isinstance(image, str) or not image.strip():
        return None
    image = image.strip()

    # Dockerfile / relative-path references can't be diffed without
    # a build step. Skip.
    lowered = image.lower()
    if lowered == "dockerfile" or lowered.endswith(".dockerfile"):
        return None
    if image.startswith("./") or image.startswith("../"):
        return None
    # Bare ``Dockerfile`` with a directory prefix (e.g.
    # ``app/Dockerfile``) also signals build-time.
    if "/" in image and image.rsplit("/", 1)[-1].lower() in (
        "dockerfile",
    ):
        return None

    # ``docker://`` URI form — strip the prefix.
    if image.lower().startswith("docker://"):
        image = image[len("docker://"):]

    return image


__all__ = [
    "GhaActionImage",
    "resolve_gha_action_image",
]
