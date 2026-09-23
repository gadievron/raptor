"""Producer→renderer contract for registry metadata prompt blocks.

The maintainer-trust and slopsquat renderers read a fixed key
vocabulary (``RENDERED_KEYS``); the live producers fetch RAW registry
documents — PyPI JSON (``info``/``releases``/``urls``) and npm
packuments (``maintainers``/``time``/``repository``/``readme``/
``versions``) — whose keys never matched that contract, so both LLM
stages were fed (nearly) empty evidence blocks and attached verdicts
as if a registry assessment had happened.

:func:`build_registry_view` is THE seam constructor: every producer
that hands registry metadata to these renderers must project the raw
document through it, and the renderers consume maintainer entries
through :func:`iter_maintainers` so hostile entry shapes (non-dict,
non-string fields — the exact class ``_clean_maintainers`` exists
for) degrade instead of raising out of the review stage.

Total on hostile input: ``build_registry_view`` never raises — a
poisoned-proxy / hostile-registry document degrades to a smaller (or
empty) view for that one dependency.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from typing import Any

logger = logging.getLogger(__name__)

#: The exact key vocabulary the renderers consume. Keys absent from a
#: view simply render nothing; keys outside this set are never read.
RENDERED_KEYS = frozenset({
    "maintainers",
    "publish_dates",
    "repository_url",
    "download_count",
    "deprecated",
    "first_publish",
    "latest_publish",
    "readme_preview",
    "stars",
    "open_issues",
    "last_commit_date",
})

#: How many recent publish timestamps a view carries (the renderers
#: truncate to 10; carrying more is dead prompt weight).
_MAX_PUBLISH_DATES = 10


def iter_maintainers(
    meta: dict[str, Any], limit: int,
) -> Iterator[tuple[str, str, str]]:
    """Yield up to *limit* ``(name, email, added)`` strings for rendering.

    Junk entries (non-dict rows, non-string fields) are skipped — the
    packument is hostile input, and one poisoned row must not abort
    the whole review stage with an AttributeError.
    """
    maintainers = meta.get("maintainers")
    if not isinstance(maintainers, list):
        return
    yielded = 0
    for m in maintainers:
        if yielded >= limit:
            return
        if not isinstance(m, dict):
            continue
        name = m.get("name") or m.get("username") or "?"
        if not isinstance(name, str):
            name = "?"
        email = m.get("email")
        added = m.get("added")
        yield (
            name,
            email if isinstance(email, str) else "",
            added if isinstance(added, str) else "",
        )
        yielded += 1


def build_registry_view(
    ecosystem: str, raw: dict[str, Any] | None,
) -> dict[str, Any]:
    """Project a raw registry document onto the renderer contract.

    *ecosystem* selects the projection (``PyPI`` / ``npm`` — the two
    ecosystems the review stages fetch); anything else, or a non-dict
    document, yields ``{}`` (the renderers then show only the package
    header lines).
    """
    if not isinstance(raw, dict):
        return {}
    eco = (ecosystem or "").lower()
    try:
        if eco == "pypi":
            view = _view_pypi(raw)
        elif eco == "npm":
            view = _view_npm(raw)
        else:
            return {}
    except Exception:  # noqa: BLE001 — hostile doc degrades, never aborts
        logger.debug(
            "registry_view: %s projection failed on hostile document",
            eco, exc_info=True,
        )
        return {}
    unexpected = set(view) - RENDERED_KEYS
    if unexpected:
        # Contract enforcement, not a debug assert (which -O strips):
        # a key the renderers don't know about must never ride the
        # projection into the prompt. Strip it and flag the
        # projection bug loudly.
        logger.warning(
            "registry_view: %s projection produced unrendered keys "
            "%s — dropped (projection bug)", eco, sorted(unexpected),
        )
        for key in unexpected:
            view.pop(key)
    return view


def _view_pypi(raw: dict[str, Any]) -> dict[str, Any]:
    from packages.sca.supply_chain.registry_metadata import _from_pypi

    view: dict[str, Any] = {}
    meta = _from_pypi(raw)
    if meta.maintainers:
        view["maintainers"] = meta.maintainers
    if meta.first_publish:
        view["first_publish"] = meta.first_publish.isoformat()
    if meta.latest_publish:
        view["latest_publish"] = meta.latest_publish.isoformat()

    publish_dates = _pypi_publish_dates(raw)
    if publish_dates:
        view["publish_dates"] = publish_dates

    info = raw.get("info")
    info = info if isinstance(info, dict) else {}
    repo = _pypi_repository_url(info)
    if repo:
        view["repository_url"] = repo
    description = info.get("description")
    if isinstance(description, str) and description.strip():
        view["readme_preview"] = description
    if info.get("yanked") is True:
        reason = info.get("yanked_reason")
        view["deprecated"] = (
            reason if isinstance(reason, str) and reason else "yanked"
        )
    return view


def _pypi_publish_dates(raw: dict[str, Any]) -> list[str]:
    from packages.sca.supply_chain.registry_metadata import _parse_iso

    releases = raw.get("releases")
    if not isinstance(releases, dict):
        return []
    stamps = []
    for files in releases.values():
        if not isinstance(files, list):
            continue
        earliest = None
        for f in files:
            if not isinstance(f, dict):
                continue
            ts = _parse_iso(f.get("upload_time_iso_8601"))
            if ts is not None and (earliest is None or ts < earliest):
                earliest = ts
        if earliest is not None:
            stamps.append(earliest)
    stamps.sort()
    return [ts.isoformat() for ts in stamps[-_MAX_PUBLISH_DATES:]]


def _pypi_repository_url(info: dict[str, Any]) -> str:
    project_urls = info.get("project_urls")
    if isinstance(project_urls, dict):
        for wanted in ("repository", "source", "source code", "homepage"):
            for key, url in project_urls.items():
                if (
                    isinstance(key, str)
                    and key.lower() == wanted
                    and isinstance(url, str)
                ):
                    return url
    home = info.get("home_page")
    return home if isinstance(home, str) else ""


def _view_npm(raw: dict[str, Any]) -> dict[str, Any]:
    from packages.sca.supply_chain.registry_metadata import (
        _clean_maintainers,
        _from_npm,
    )

    view: dict[str, Any] = {}
    meta = _from_npm(raw)
    maintainers = meta.maintainers or _clean_maintainers(
        raw.get("maintainers"),
    )
    if maintainers:
        view["maintainers"] = maintainers
    if meta.first_publish:
        view["first_publish"] = meta.first_publish.isoformat()
    if meta.latest_publish:
        view["latest_publish"] = meta.latest_publish.isoformat()

    publish_dates = _npm_publish_dates(raw)
    if publish_dates:
        view["publish_dates"] = publish_dates

    repo = raw.get("repository")
    if isinstance(repo, dict):
        url = repo.get("url")
        if isinstance(url, str) and url:
            view["repository_url"] = url
    elif isinstance(repo, str) and repo:
        view["repository_url"] = repo

    readme = raw.get("readme")
    if isinstance(readme, str) and readme.strip():
        view["readme_preview"] = readme

    deprecated = _npm_latest_deprecation(raw)
    if deprecated:
        view["deprecated"] = deprecated
    return view


def _npm_publish_dates(raw: dict[str, Any]) -> list[str]:
    from packages.sca.supply_chain.registry_metadata import _parse_iso

    times = raw.get("time")
    if not isinstance(times, dict):
        return []
    stamps = []
    for key, value in times.items():
        if key in ("created", "modified") or not isinstance(value, str):
            continue
        ts = _parse_iso(value)
        if ts is not None:
            stamps.append(ts)
    stamps.sort()
    return [ts.isoformat() for ts in stamps[-_MAX_PUBLISH_DATES:]]


def _npm_latest_deprecation(raw: dict[str, Any]) -> str:
    dist_tags = raw.get("dist-tags")
    versions = raw.get("versions")
    if not isinstance(dist_tags, dict) or not isinstance(versions, dict):
        return ""
    latest = dist_tags.get("latest")
    ver_doc = versions.get(latest) if isinstance(latest, str) else None
    if not isinstance(ver_doc, dict):
        return ""
    deprecated = ver_doc.get("deprecated")
    if isinstance(deprecated, str) and deprecated:
        return deprecated
    return "deprecated" if deprecated is True else ""


__all__ = [
    "RENDERED_KEYS",
    "build_registry_view",
    "iter_maintainers",
]
