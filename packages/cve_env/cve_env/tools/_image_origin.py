"""Classify Docker image references as external (registry-pulled) vs
locally-built.

Used by docker_run / docker_build / docker_compose_up to decide whether to
append `--pull always` / `--pull`. External images MUST be pulled fresh
every time (per user directive: never use a local cache). Locally-built
images (no upstream) cannot be pulled — `--pull` would fail — so they're
skipped.

Heuristic (no docker call needed; pure-Python; testable):
- empty                       → local (defensive default)
- starts with 'cve-'          → local (source_build naming convention)
- starts with 'localhost/'    → local (explicit local registry)
- equals 'scratch'            → local (special never-pulls reference)
- otherwise                   → external

Bare names like 'debian:11' / 'redis' / 'python:3.12' are CANONICAL Docker
Hub default-namespace images (library/X) and MUST be classified external — a
naive '/' check misses them, causing docker_build to skip --pull for
FROM debian:11 → cache-leak.

Why err-toward-external: misclassifying local as external causes `--pull`
to fail loudly (test suite catches it). Misclassifying external as local
silently re-uses a stale cache — the bug this guards against. DO NOT relax.
"""

from __future__ import annotations


def _is_external_image(image: str) -> bool:
    """Return True iff `image` came from a public registry (and therefore
    should get `--pull` on docker run/build/compose). False for locally-
    built images (source_build output, localhost/, scratch).
    """
    if not image:
        return False
    if image == "scratch":
        return False
    if image.startswith("localhost/"):
        return False
    return not image.startswith("cve-")
