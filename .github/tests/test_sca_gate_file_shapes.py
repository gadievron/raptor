"""sca-pr-gate triggers must cover the SCA scanner's file-shape universe.

The gate's ``pull_request.paths`` list was hand-synced against
``packages/sca/file_shapes.py`` and had drifted: a PR editing only
``compose.yaml`` (a shape every full scan parses) never fired the
gate — no diff comment, no severity fail. This oracle derives the
requirement from the scanner surface itself: every public shape
predicate must have example paths, every example must satisfy its
predicate against the LIVE module (so a changed grammar invalidates
its examples), and every example must fire at least one trigger glob
— a new parser-supported shape cannot ship without its trigger.

Declared bounds, documented rather than silently missed:

* Glob matching here is the conservative GitHub translation (``*``
  within a segment, ``**`` across segments, and ``**/name`` requiring
  at least one leading segment) — examples therefore live in a
  subdirectory, sidestepping the root-level ``**/`` ambiguity in
  GitHub's matcher.
* ``is_compose_file`` matches case-insensitively; path globs are
  case-sensitive. An all-caps ``COMPOSE.YML`` reaches the scanner but
  not the gate — accepted, the ecosystem convention is lowercase.
* ``is_gitlab_ci_file`` matches by basename anywhere; the gate keys
  on the conventional root files (``.gitlab-ci.yml`` /
  ``.gitlab-ci.yaml``), so the gitlab examples are root-level.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

_WORKFLOW = REPO / ".github" / "workflows" / "sca-pr-gate.yml"
_SHAPES = REPO / "packages" / "sca" / "file_shapes.py"


def _load_file_shapes():
    # Loaded by file path: the module is stdlib-pure, and going through
    # the package import would drag packages.sca dependencies into a
    # pytest-only CI job.
    spec = importlib.util.spec_from_file_location("_sca_file_shapes",
                                                  _SHAPES)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _trigger_paths() -> list[str]:
    text = _WORKFLOW.read_text(encoding="utf-8")
    block = re.search(
        r"pull_request:\s*\n\s*paths:\n((?:\s*- '[^']+'\n)+)", text,
    )
    assert block, "sca-pr-gate.yml pull_request paths block not found"
    return re.findall(r"- '([^']+)'", block.group(1))


def _gh_match(pattern: str, path: str) -> bool:
    """Conservative GitHub Actions path-filter glob translation:
    ``*`` matches within a segment, ``**`` across segments."""
    rx = re.escape(pattern)
    rx = rx.replace(re.escape("**"), "\x00")
    rx = rx.replace(re.escape("*"), "[^/]*")
    rx = rx.replace("\x00", ".*")
    return re.fullmatch(rx, path) is not None


#: predicate name -> example paths that must (a) satisfy the predicate
#: and (b) fire the gate's path triggers.
EXAMPLES: dict[str, tuple[str, ...]] = {
    "is_dockerfile": (
        "svc/Dockerfile",
        "svc/Dockerfile.dev",
        "svc/Containerfile",
        "svc/api.Dockerfile",
        "svc/api.dockerfile",
    ),
    "is_compose_file": (
        "svc/compose.yml",
        "svc/compose.yaml",
        "svc/docker-compose.yml",
        "svc/docker-compose.dev.yaml",
        "svc/compose.override.yml",
        "svc/compose.override.yaml",
    ),
    "is_gha_workflow": (
        ".github/workflows/ci.yml",
        ".github/workflows/ci.yaml",
    ),
    "is_gha_workflow_or_action": (
        ".github/workflows/ci.yml",
        "actions/setup/action.yml",
        "actions/setup/action.yaml",
    ),
    "is_gitlab_ci_file": (
        ".gitlab-ci.yml",
        ".gitlab-ci.yaml",
    ),
}


def test_every_shape_predicate_has_examples() -> None:
    """Totality, both directions: a NEW public predicate in
    file_shapes fails here until it gets examples (and, via the
    coverage test, triggers); a removed one drops its stale row."""
    mod = _load_file_shapes()
    predicates = sorted(
        name for name in dir(mod)
        if name.startswith("is_") and callable(getattr(mod, name))
    )
    assert predicates == sorted(EXAMPLES), (
        "file_shapes predicates and the example table diverged — "
        "update EXAMPLES (and the sca-pr-gate triggers) for the "
        "changed shape universe"
    )


def test_examples_satisfy_their_predicates() -> None:
    """The derivation direction: examples are validated against the
    live scanner surface, so they cannot rot into asserting coverage
    of shapes the scanner no longer parses."""
    mod = _load_file_shapes()
    for name, examples in EXAMPLES.items():
        predicate = getattr(mod, name)
        for example in examples:
            assert predicate(Path(example)), (
                f"{name} no longer matches example {example!r} — "
                "the shape grammar changed; update the example and "
                "re-check the gate triggers"
            )


def test_triggers_cover_every_scanner_shape() -> None:
    triggers = _trigger_paths()
    assert triggers, "no triggers extracted"
    uncovered = sorted(
        f"{name}: {example}"
        for name, examples in EXAMPLES.items()
        for example in examples
        if not any(_gh_match(t, example) for t in triggers)
    )
    assert not uncovered, (
        "SCA scanner file shape(s) with no sca-pr-gate path trigger — "
        "a PR editing only such a file skips the gate:\n  "
        + "\n  ".join(uncovered)
    )
