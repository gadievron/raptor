"""Per-ecosystem registry clients (version listing, metadata).

Each ecosystem has a small Protocol-conforming class that fetches
``available versions`` for a package. Used by the ``harden`` planner to
pick the latest safe version for loose-pinned deps; will also feed
recent-publish / maintainer-change supply-chain checks (Follow-up).

Why not OSV: OSV gives us *advisories* keyed by version range, not the
authoritative version list. For ``harden`` we need to know "what versions
of `requests` exist" before we can pick one; OSV alone is insufficient.

Why per-ecosystem rather than one big client: each registry's JSON shape
is different (PyPI flat ``releases`` map; npm nested ``versions`` map;
crates.io paginated; etc.). Wrapping each in its own module keeps the
shape-translation local.
"""

from __future__ import annotations

from typing import List, Protocol


class RegistryClient(Protocol):
    """Returns the available versions of a package, newest-first.

    Pre-release / yanked / withdrawn versions are filtered by the
    implementation; the caller receives only versions that an operator
    could realistically pin to.
    """

    ecosystem: str

    def list_versions(self, name: str) -> List[str]:
        """List published versions of ``name`` from this ecosystem.

        Order: newest first (registries typically return arbitrary order;
        the implementation sorts).
        """
        ...


from . import crates as _crates       # noqa: E402,F401
from . import debian as _debian       # noqa: E402,F401
from . import golang as _golang       # noqa: E402,F401
from . import homebrew as _homebrew   # noqa: E402,F401
from . import maven as _maven         # noqa: E402,F401
from . import npm as _npm             # noqa: E402,F401
from . import nuget as _nuget         # noqa: E402,F401
from . import packagist as _packagist  # noqa: E402,F401
from . import pypi as _pypi           # noqa: E402,F401
from . import rubygems as _rubygems   # noqa: E402,F401


__all__ = ["RegistryClient"]
