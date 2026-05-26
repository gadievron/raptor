"""YAML ``image:`` ref in-place rewriter.

Handles three file shapes the bumper-orchestrator emits
candidates for:

* docker-compose files (``compose.yml`` / ``docker-compose.yml``)
* Kubernetes manifests (any ``.yml`` / ``.yaml`` with k8s shape)
* GitLab CI files (``.gitlab-ci.yml``)

All three use the same ``image: <ref>`` line shape. One rewriter
covers them via predicate-OR registration.

The bumper-orchestrator emits :class:`RewriteEdit` records with
``locator`` = ``"{registry}/{repository}"`` (the same convention
``dockerfile_from`` uses for FROM lines). The line shape differs
from Dockerfile's ``FROM`` but the semantics — match by locator,
rewrite the tag, preserve quoting / comments / indentation — are
the same."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import List

from . import RewriteEdit, RewriteResult, register

logger = logging.getLogger(__name__)


def _is_compose_file(path: Path) -> bool:
    """Match compose / docker-compose YAML files. Mirrors the
    discovery predicate in ``parsers/compose.py``."""
    if path.suffix.lower() not in (".yml", ".yaml"):
        return False
    name = path.name.lower()
    if name.startswith("docker-compose"):
        return True
    if name in ("compose.yml", "compose.yaml"):
        return True
    if name.startswith("compose.") and name.endswith((".yml", ".yaml")):
        return True
    return False


def _is_gitlab_ci_file(path: Path) -> bool:
    """Match ``.gitlab-ci.yml`` / ``.gitlab-ci.yaml``."""
    return path.name in (".gitlab-ci.yml", ".gitlab-ci.yaml")


def _is_k8s_manifest(path: Path) -> bool:
    """Match k8s YAML manifests. Deliberately conservative —
    rather than parsing every YAML to check for kind/apiVersion
    (the parser does that), we register the same broad predicate
    the parser uses (``.yml`` / ``.yaml`` with k8s-shaped path
    segments). The actual line-shape match in
    ``_apply_one_image`` is conservative enough that touching a
    non-k8s YAML with no ``image:`` line is a silent no-op."""
    if path.suffix.lower() not in (".yml", ".yaml"):
        return False
    # Avoid colliding with files the other rewriters own. GHA
    # workflows under ``.github/workflows/`` route to ``gha_uses``.
    parts = path.parts
    for i in range(len(parts) - 2):
        if parts[i] == ".github" and parts[i + 1] == "workflows":
            return False
    # Compose-shaped names also routed to this same rewriter
    # (the predicate-OR registration), but ``_is_compose_file``
    # is a subset of "yaml file" so we don't need a separate
    # check here.
    return True


def _is_yaml_image_target(path: Path) -> bool:
    """Combined predicate: any YAML file the rewriter might
    edit. The actual rewrite is gated by line-shape matching, so
    a YAML file with no ``image:`` line is a silent no-op."""
    if _is_compose_file(path):
        return True
    if _is_gitlab_ci_file(path):
        return True
    return _is_k8s_manifest(path)


@register(predicate=_is_yaml_image_target)
def rewrite_yaml_image(
    path: Path, edits: List[RewriteEdit],
) -> List[RewriteResult]:
    """Apply image-tag edits to YAML ``image:`` lines in place.

    Each edit's locator is ``"{registry}/{repository}"``; we
    match both canonical and short forms (Docker's
    ``library/python`` ↔ ``python`` shorthand) the same way
    ``dockerfile_from`` does."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        return [RewriteResult(edit=e2, applied=False,
                              reason=f"error: read failed: {e}")
                for e2 in edits]

    new_text = text
    results: List[RewriteResult] = []
    for edit in edits:
        new_text, result = _apply_one_image(new_text, edit)
        results.append(result)

    if any(r.applied for r in results):
        try:
            _atomic_write(path, new_text)
        except OSError as e:
            return [RewriteResult(edit=r.edit, applied=False,
                                  reason=f"error: write failed: {e}")
                    for r in results]
    return results


def _apply_one_image(
    text: str, edit: RewriteEdit,
) -> "tuple[str, RewriteResult]":
    """Apply one ``image: <ref>:<tag>`` edit.

    Locator forms accepted in the file:
      * Canonical: ``image: docker.io/library/python:3.12``
      * Short (docker.io implicit): ``image: python:3.12``
      * Sub-namespace short: ``image: library/python:3.12``
    """
    locator = edit.locator
    forms = [locator]
    # Only docker.io has short forms (``image: python:3.12`` is implicitly
    # ``docker.io/library/python:3.12``). Parse the registry component
    # explicitly via split — avoids ``startswith`` host checks that look
    # like incomplete URL sanitisation to scanners (this isn't a URL,
    # but the lexical shape is the same).
    registry, _, rest = locator.partition("/")
    if registry == "docker.io" and rest:
        namespace, _, image = rest.partition("/")
        if namespace == "library" and image:
            forms.append(image)
            forms.append(f"library/{image}")
            forms.append(f"docker.io/{image}")
        else:
            forms.append(rest)
    image_alternates = "|".join(re.escape(f) for f in forms)
    # YAML ``image:`` shape. Supports:
    #   * Bare: ``    image: foo/bar:tag``
    #   * Quoted: ``    image: "foo/bar:tag"``
    #   * After list marker: ``    - image: foo/bar:tag``
    pattern = re.compile(
        rf"^(\s*(?:-\s+)?image:\s*[\"']?(?:{image_alternates}):)"
        rf"([^\s\"'#]+)"                  # tag (non-greedy, stops at qt/ws/#)
        rf"([\"'\s#]|$)",                  # boundary
        re.MULTILINE,
    )
    match = pattern.search(text)
    if match is None:
        return text, RewriteResult(
            edit=edit, applied=False, reason="not_found",
        )
    current_tag = match.group(2)
    if current_tag == edit.new_value:
        return text, RewriteResult(
            edit=edit, applied=False, reason="no_change",
        )
    if current_tag != edit.old_value:
        return text, RewriteResult(
            edit=edit, applied=False,
            reason=(
                f"value_mismatch: file has {current_tag!r}, "
                f"plan expected {edit.old_value!r}"
            ),
        )
    new_text = pattern.sub(
        rf"\g<1>{edit.new_value}\g<3>",
        text, count=1,
    )
    return new_text, RewriteResult(
        edit=edit, applied=True, reason="applied",
    )


def _atomic_write(path: Path, content: str) -> None:
    """Atomic tempfile + rename (shared pattern with other
    rewriters)."""
    try:
        from .._atomic import atomic_write_text
        atomic_write_text(path, content)
        return
    except ImportError:
        pass
    import os
    import tempfile
    fd, tmp = tempfile.mkstemp(
        dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp",
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.replace(tmp, str(path))
    except Exception:                # noqa: BLE001
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
