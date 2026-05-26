"""``uv.lock`` parser.

uv (https://docs.astral.sh/uv/) is a fast Python package manager
from astral-sh; ``uv.lock`` is its TOML lockfile (uv 0.4+, growing
adoption fast).

Schema (uv 0.4 / lockfile version 1):

    version = 1
    revision = 1
    requires-python = ">=3.11"

    [[package]]
    name = "requests"
    version = "2.31.0"
    source = { registry = "https://pypi.org/simple" }
    dependencies = [
        { name = "charset-normalizer" },
        { name = "idna" },
        { name = "urllib3" },
    ]
    sdist = { ... }

    [[package]]
    name = "myproject"
    version = "0.1.0"
    source = { virtual = "." }       # the project itself
    dependencies = [{ name = "requests" }]

This parser:

  * Walks the ``[[package]]`` array.
  * Skips the project itself — entries with ``source = { virtual
    = "..." }`` are the operator's project (Python virtual
    package), not deps.
  * Skips entries with ``source = { editable = "..." }`` or
    ``source = { directory = "..." }`` — local-path overrides
    that aren't registry-published.
  * Emits ``ecosystem="PyPI"`` Dependency rows with
    ``is_lockfile=True``, ``direct=False`` (uv.lock contains
    the full resolved tree; direct/transitive isn't directly
    queryable from the lockfile shape — operator-side
    ``pyproject.toml`` is the source of truth for "direct").
  * ``pin_style=PinStyle.EXACT`` since lockfile versions are
    always pinned.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, List, Optional

from ..models import Confidence, Dependency, PinStyle
from . import register

try:
    import tomllib                  # Python 3.11+
except ImportError:                 # pragma: no cover
    import tomli as tomllib         # type: ignore[no-redef]

logger = logging.getLogger(__name__)


ECOSYSTEM = "PyPI"
_PURL_TYPE = "pypi"


@register(filenames=["uv.lock"])
def parse(path: Path) -> List[Dependency]:
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except OSError as e:
        logger.warning(
            "sca.parsers.uv_lock: read failed for %s: %s", path, e,
        )
        return []
    except tomllib.TOMLDecodeError as e:
        logger.warning(
            "sca.parsers.uv_lock: TOML parse failed for %s: %s",
            path, e,
        )
        return []
    if not isinstance(data, dict):
        return []

    packages = data.get("package")
    if not isinstance(packages, list):
        return []

    out: List[Dependency] = []
    for pkg in packages:
        dep = _build_dep(pkg, declared_in=path)
        if dep is not None:
            out.append(dep)
    return out


def _build_dep(
    pkg: Any, *, declared_in: Path,
) -> Optional[Dependency]:
    if not isinstance(pkg, dict):
        return None
    name = pkg.get("name")
    version = pkg.get("version")
    if not isinstance(name, str) or not name.strip():
        return None
    if not isinstance(version, str) or not version.strip():
        return None
    name = name.strip()
    version = version.strip()

    source = pkg.get("source") or {}
    if not isinstance(source, dict):
        source = {}

    # Skip the project's own row (``virtual``) and local
    # editables / directories — these aren't registry-published
    # deps.
    if any(k in source for k in ("virtual", "editable", "directory")):
        return None

    # Git sources keep the version (some commit SHA or tag) but
    # CVE matching against PyPI won't fire. Mark with PinStyle.GIT
    # for transparency.
    pin_style = (
        PinStyle.GIT if "git" in source else PinStyle.EXACT
    )

    return Dependency(
        ecosystem=ECOSYSTEM,
        name=name,
        version=version,
        declared_in=declared_in,
        scope="main",
        is_lockfile=True,
        pin_style=pin_style,
        # uv.lock includes the full resolved tree; direct vs
        # transitive distinction lives in the project's
        # pyproject.toml. Mark all as not-direct so the joined
        # view defers to the manifest-side parser when both are
        # present.
        direct=False,
        purl=f"pkg:{_PURL_TYPE}/{name}@{version}",
        parser_confidence=Confidence(
            "high",
            reason="uv.lock pinned dependency",
        ),
    )
