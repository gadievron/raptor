"""Resolve the Debian suite a Dockerfile base image pins to.

A ``RUN apt-get install`` line installs from the apt sources of the base
image governing its build stage. To pin an apt package to an *installable*
version we need that base image's Debian suite (codename / alias) — which
is exactly what madison's ``s=`` filter accepts.

The suite lives in the image tag: ``debian:bookworm``, ``debian:12`` and
``python:3.12-bookworm-slim`` all resolve to ``bookworm``;
``debian:stable`` to ``stable``. Non-Debian bases (``ubuntu:22.04``,
``alpine``, ``scratch``) and undeterminable ones (a ``$ARG`` image,
``python:3.12`` whose Debian release isn't in the tag) resolve to ``None``
so the caller skips rather than guesses.

Codename→alias drift (``bookworm`` was *stable*, is *oldstable* in 2026)
is left to madison's server-side resolution — we pass the codename through
untouched.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from core.dockerfile.parser import Instruction

# Debian release codenames (recent + current + announced) and the suite
# aliases madison accepts.
_CODENAMES = {
    "stretch", "buster", "bullseye", "bookworm", "trixie", "forky", "duke",
    "sid",
}
_ALIASES = {
    "stable", "testing", "unstable", "oldstable", "oldoldstable",
    "experimental",
}
_DEBIAN_SUITES = _CODENAMES | _ALIASES

# Numeric tags (``debian:12``). Release numbers are permanent, so this map
# does not drift — unlike codename↔alias, which madison resolves for us.
_NUMBER_TO_CODENAME = {
    "9": "stretch", "10": "buster", "11": "bullseye", "12": "bookworm",
    "13": "trixie", "14": "forky",
}


def debian_suite_from_image(image_ref: str) -> Optional[str]:
    """Return the Debian suite token a base image pins to, or ``None``.

    The token is a codename (``bookworm``) or alias (``stable``) suitable
    for madison's ``s=`` filter. ``None`` means "not a determinable Debian
    suite" — the caller should skip, not guess.
    """
    if not image_ref:
        return None
    # Drop a ``@sha256:…`` digest, then take the final path component so a
    # registry ``host[:port]/namespace/`` prefix can't be mistaken for the
    # repo:tag split.
    ref = image_ref.strip().split("@", 1)[0]
    repo_tag = ref.rsplit("/", 1)[-1]
    if ":" in repo_tag:
        repo, tag = repo_tag.split(":", 1)
    else:
        repo, tag = repo_tag, ""
    # A recognisable Debian codename/alias anywhere in the tag wins. This
    # also covers Debian-derived images (python:3.12-bookworm-slim,
    # node:20-bullseye); tag components are ``-``-separated.
    for part in tag.split("-"):
        if part in _DEBIAN_SUITES:
            return part
    # A bare ``debian`` image: numeric tag via the permanent release map;
    # an empty / ``latest`` tag is the current stable.
    if repo == "debian":
        if tag in _NUMBER_TO_CODENAME:
            return _NUMBER_TO_CODENAME[tag]
        if tag in ("", "latest"):
            return "stable"
    return None


def _from_image_ref(args: str) -> Optional[str]:
    """The image reference of a ``FROM`` instruction's args.

    Skips a leading ``--platform=…`` flag and stops at an ``AS`` clause;
    returns the first bare token (the image or a referenced stage name).
    """
    for tok in args.split():
        if tok.upper() == "AS":
            break
        if tok.startswith("--"):
            continue
        return tok
    return None


def stage_image_map(instructions: List[Instruction]) -> Dict[Optional[str], str]:
    """Map each build stage to the image ref of its governing ``FROM``.

    The key is the stage name (``None`` for a ``FROM`` with no ``AS``).
    ``FROM <prev-stage>`` chains are followed to the underlying image, so a
    ``RUN apt-get install`` in a stage built ``FROM builder`` resolves to
    ``builder``'s base image.
    """
    raw: Dict[Optional[str], str] = {}
    order: List[Optional[str]] = []
    for inst in instructions:
        if inst.directive != "FROM":
            continue
        img = _from_image_ref(inst.args)
        if img is None:
            continue
        raw[inst.stage_name] = img
        order.append(inst.stage_name)

    stage_names = set(raw)
    resolved: Dict[Optional[str], str] = {}
    for stage in order:
        img = raw[stage]
        seen: set = set()
        while img in stage_names and img not in seen:
            seen.add(img)
            img = raw[img]
        resolved[stage] = img
    return resolved


__all__ = ["debian_suite_from_image", "stage_image_map"]
