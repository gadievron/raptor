"""pnpm-lock.yaml parser — pnpm's lockfile (YAML).

Three on-disk shapes share one filename:

- **lockfileVersion <6** (pnpm 7-): top-level ``dependencies`` /
  ``devDependencies`` / ``optionalDependencies`` blocks; ``packages`` keys
  are slash-separated: ``/lodash/4.17.21`` or ``/@scope/name/1.0``.

- **lockfileVersion 6.x** (pnpm 8): an ``importers`` map with one entry
  per workspace path (``.`` for the root); each importer has ``dependencies``
  / ``devDependencies`` / ``peerDependencies`` / ``optionalDependencies``
  with ``{specifier, version}`` records. ``packages`` keys are
  ``/name@version`` (or ``/@scope/name@version``), with peer-dep
  resolution parenthesised into the version (``/jest@29.0.3(typescript@5.0)``).

- **lockfileVersion 9.x** (pnpm 9+): same ``importers`` map, but
  ``packages`` keys drop the leading slash (``name@version``,
  ``@scope/name@version``) and carry package metadata only; the resolved
  dependency graph moves to a sibling ``snapshots`` map whose keys carry
  the peer suffix (``jest@29.0.3(typescript@5.0.4)``) and whose values
  hold the transitive ``dependencies`` records. We union both maps —
  ``packages`` for the canonical (name, version) set and ``snapshots``
  for anything only materialised there — deduping on (name, version).

Direct vs transitive: a name listed under any importer's dependency
buckets is direct in that workspace. The ``packages`` map is the union
of every workspace's resolved tree.

npm aliases: an importer entry ``my-lodash: {specifier:
"npm:lodash@^4.17.21", …}`` installs the REAL package — the
``packages`` / ``snapshots`` rows already carry it, so the alias only
has to be joined back: the real package's row stays ``direct=True``
and the alias spelling is preserved in ``Dependency.alias_name``.

Pin style: lockfile rows are resolved → EXACT, unless ``resolution.tarball``
or ``resolution.repo`` indicate a git/url source.
"""

from __future__ import annotations

import logging
import re
from typing import Any, TYPE_CHECKING

from ..models import Confidence, Dependency, PinStyle
from ._base import PARSE_ESCAPE_ERRORS, build_purl, lockfile_confidence
from . import _safe_read, register
from ._npm_alias import split_npm_alias

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

ECOSYSTEM = "npm"

try:
    import yaml as _yaml  # type: ignore[import-untyped]

    from .._yaml_fast import safe_load as _safe_load
    _AVAILABLE = True
except ImportError:                       # pragma: no cover — env-dependent
    _yaml = None                          # type: ignore[assignment]
    _safe_load = None                     # type: ignore[assignment]
    _AVAILABLE = False
    logger.warning(
        "sca.parsers.pnpm_lock: 'PyYAML' not installed — pnpm-lock.yaml "
        "files will be skipped. `pip install PyYAML` to enable."
    )


def parse(path: Path) -> list[Dependency]:
    if not _AVAILABLE:
        logger.warning(
            "sca.parsers.pnpm_lock: skipping %s — 'PyYAML' not installed", path,
        )
        return []
    text = _safe_read.read_bounded(path, follow_symlinks=False)
    if text is None:
        # ``read_bounded`` already logged the underlying reason.
        return []
    try:
        data = _safe_load(text)           # type: ignore[misc]
    except (_yaml.YAMLError, *PARSE_ESCAPE_ERRORS) as e:  # type: ignore[union-attr]  # hostile-input escape classes
        logger.warning(
            "sca.parsers.pnpm_lock: YAML parse failed for %s: %s", path, e
        )
        return []
    if not isinstance(data, dict):
        return []

    direct_names, alias_by_real = _collect_direct_names(data)
    packages = data.get("packages")
    if not isinstance(packages, dict):
        packages = {}
    # v9+: the resolved graph lives under ``snapshots`` (keys carry the
    # peer suffix). Union it with ``packages`` so transitives that only
    # materialise there still produce rows; (name, version) dedup below
    # collapses the overlap.
    snapshots = data.get("snapshots")
    if not isinstance(snapshots, dict):
        snapshots = {}
    if not packages and not snapshots:
        return []

    deps: list[Dependency] = []
    seen: set[tuple[str, str | None]] = set()
    for source in (packages, snapshots):
        for key, entry in source.items():
            if not isinstance(key, str):
                continue
            name, version = _split_packages_key(key)
            if name is None:
                continue
            if not isinstance(entry, dict):
                entry = {}
            scope = _scope_from_entry(entry)
            pin_style, version_for_record = _classify_packages_entry(
                entry, version,
            )
            if (name, version_for_record) in seen:
                continue
            seen.add((name, version_for_record))

            deps.append(Dependency(
                ecosystem=ECOSYSTEM,
                name=name,
                version=version_for_record,
                declared_in=path,
                scope=scope,
                is_lockfile=True,
                pin_style=pin_style,
                direct=name in direct_names,
                purl=build_purl("npm", name, version_for_record),
                parser_confidence=_confidence(pin_style, version_for_record),
                alias_name=(alias_by_real.get((name, version_for_record))
                            or alias_by_real.get((name, None))
                            or None),
            ))
    if not deps:
        # A non-empty packages/snapshots map that produced zero rows
        # means the key format wasn't recognised — surface it instead
        # of silently reporting a clean project (this is exactly how
        # lockfileVersion 9 read as zero deps before v9 support).
        logger.warning(
            "sca.parsers.pnpm_lock: lockfile parse failed for %s: "
            "%d packages / %d snapshots entries but none parsed "
            "(lockfileVersion %r — unrecognised key format)",
            path, len(packages), len(snapshots),
            data.get("lockfileVersion"),
        )
    return deps


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _collect_direct_names(
    data: dict[str, Any],
) -> tuple[set[str], dict[tuple[str, str | None], str]]:
    """``(direct_names, alias_by_real)`` from the importer buckets.

    Aliased entries (``my-lodash: {specifier: "npm:lodash@^4.17.21",
    …}``) are declared under the ALIAS key, but the ``packages`` /
    ``snapshots`` maps — where rows are emitted from — carry the REAL
    package. Resolving the alias here (a) keeps the real package's
    row ``direct=True`` and (b) preserves the alias spelling for
    ``Dependency.alias_name``. Without it the aliased dep's row read
    as transitive and the alias was silently dropped.

    ``alias_by_real`` is keyed ``(real_name, resolved_version)`` — the
    canonical alias use case is TWO aliases of the same package at
    different versions side by side (``lodash-old`` / ``lodash-new``),
    so a name-only key would attribute one alias to both rows. A
    ``(real_name, None)`` fallback covers entries whose importer
    version didn't parse; it is dropped (empty sentinel) when two
    different aliases would contend for it.
    """
    names: set[str] = set()
    alias_by_real: dict[tuple[str, str | None], str] = {}
    importers = data.get("importers")
    if isinstance(importers, dict):
        for imp in importers.values():
            if isinstance(imp, dict):
                _extract_direct_keys(imp, names, alias_by_real)
    # v5 shape — direct deps live at the top level.
    _extract_direct_keys(data, names, alias_by_real)
    return names, alias_by_real


def _extract_direct_keys(
    scope_holder: dict[str, Any],
    names: set[str],
    alias_by_real: dict[tuple[str, str | None], str],
) -> None:
    for bucket in (
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ):
        block = scope_holder.get(bucket)
        if not isinstance(block, dict):
            continue
        for k, v in block.items():
            if not isinstance(k, str):
                continue
            resolved = _alias_target(k, v)
            if resolved is not None:
                real, ver = resolved
                names.add(real)
                if ver is not None:
                    alias_by_real.setdefault((real, ver), k)
                # Version-blind fallback; ambiguity (two aliases of the
                # same real package) blanks it rather than guessing.
                fb = (real, None)
                if fb not in alias_by_real:
                    alias_by_real[fb] = k
                elif alias_by_real[fb] != k:
                    alias_by_real[fb] = ""
            else:
                names.add(k)


def _alias_target(
    declared: str, value: Any,
) -> tuple[str, str | None] | None:
    """``(installed_name, resolved_version)`` for an aliased importer
    entry, else None.

    v6/v9 importers: ``{specifier: "npm:lodash@^4.17.21", version:
    "/lodash@4.17.4"}`` (v6) / ``version: "lodash@4.17.4"`` (v9) — the
    specifier carries the alias protocol, the version field names the
    resolved real package (peer suffixes stripped like packages keys).
    v5 top-level: ``my-lodash: "/lodash/4.17.21"`` — the value is a
    packages-map key naming the real package.
    """
    if isinstance(value, dict):
        spec = value.get("specifier")
        if not isinstance(spec, str):
            return None
        split = split_npm_alias(spec)
        if split is None or split[0] == declared:
            return None
        real = split[0]
        ver: str | None = None
        vfield = value.get("version")
        if isinstance(vfield, str) and vfield:
            vname, vver = _split_packages_key(vfield)
            if vname == real and vver:
                ver = vver
        return real, ver
    if isinstance(value, str) and value.startswith("/"):
        v5_real, v5_version = _split_packages_key(value)
        if v5_real is not None and v5_real != declared:
            return v5_real, v5_version
    return None


# Match v6 (/name@version, /@scope/name@version) and v5 (/name/version,
# /@scope/name/version). The ``@`` form is preferred — most modern files.
# The name segment forbids ``@`` so a ``(peer@x)`` suffix in the version
# doesn't get glued into the name by greedy matching.
_KEY_V6 = re.compile(r"^/(?P<name>(?:@[^/]+/)?[^/@]+)@(?P<version>.+)$")
_KEY_V5 = re.compile(r"^/(?P<name>(?:@[^/]+/)?[^/]+)/(?P<version>.+)$")


def _split_packages_key(key: str) -> tuple[str | None, str | None]:
    """Recover (name, version) from a ``packages``/``snapshots`` map key."""
    # The v6 ``@`` form is anchored at the rightmost ``@`` *after* the
    # name segment; scoped packages contain a leading ``@`` too. Match
    # v6 first, then fall back to v5 slash form. Keys without a leading
    # slash are the v9 form.
    if not key.startswith("/"):
        return _split_v9_key(key)
    m = _KEY_V6.match(key)
    if m:
        version = _strip_version_suffix(m.group("version"))
        return m.group("name"), version
    m = _KEY_V5.match(key)
    if m:
        version = _strip_version_suffix(m.group("version"))
        return m.group("name"), version
    return None, None


# Version tokens that mark a non-registry source in a v9 key
# (``mypkg@file:packages/x``, ``pkg@https://…``). No registry version →
# no OSV match key; the entry's ``resolution`` block still classifies
# the pin style.
_V9_NON_REGISTRY_PREFIXES = (
    "file:", "link:", "workspace:", "http:", "https:", "git:", "git+",
    "github:", "github.com/",
)


def _split_v9_key(key: str) -> tuple[str | None, str | None]:
    """Recover (name, version) from a v9 key without a leading slash.

    ``name@version`` / ``@scope/name@version``; snapshot keys append a
    parenthesised peer suffix (``jest@29.0.3(typescript@5.0.4)``) which
    is stripped like the v6 form. npm names cannot contain ``@`` beyond
    the scope prefix, so the first ``@`` after the (optional) scope
    separator splits name from version.
    """
    if key.startswith("@"):
        slash = key.find("/")
        if slash == -1:
            return None, None
        at = key.find("@", slash)
    else:
        at = key.find("@")
    if at <= 0 or at >= len(key) - 1:
        return None, None
    name = key[:at]
    version = _strip_version_suffix(key[at + 1:])
    if not version:
        return None, None
    if version.startswith(_V9_NON_REGISTRY_PREFIXES):
        return name, None
    return name, version


def _strip_version_suffix(version: str) -> str:
    """Drop pnpm's trailing peer-dep annotations from a version.

    pnpm encodes peer-dep resolution into the lockfile key in two forms:
    v6+: ``29.0.3(typescript@5.0)`` (parenthesised)
    v5:  ``29.0.3_typescript@5.0.0`` (underscore-separated)
    The OSV-relevant version is just the leading version; the tail is metadata.
    """
    paren = version.find("(")
    if paren > 0:
        return version[:paren]
    underscore = version.find("_")
    if underscore > 0:
        return version[:underscore]
    return version


def _scope_from_entry(entry: dict[str, Any]) -> str:
    if entry.get("dev") is True:
        return "dev"
    if entry.get("peer") is True:
        return "peer"
    if entry.get("optional") is True:
        return "optional"
    return "main"


def _classify_packages_entry(
    entry: dict[str, Any], version: str | None
) -> tuple[PinStyle, str | None]:
    resolution = entry.get("resolution")
    if isinstance(resolution, dict):
        if "repo" in resolution or "commit" in resolution:
            return PinStyle.GIT, version
        tarball = resolution.get("tarball")
        if isinstance(tarball, str) and tarball.startswith("file:"):
            return PinStyle.PATH, version
    if version is None:
        return PinStyle.WILDCARD, None
    return PinStyle.EXACT, version



def _confidence(pin_style: PinStyle, version: str | None) -> Confidence:
    return lockfile_confidence(
        pin_style, version,
        git_reason="pnpm-lock.yaml git source",
        path_reason="pnpm-lock.yaml file source",
        unversioned_reason="pnpm-lock.yaml entry without version",
        resolved_reason="pnpm-lock.yaml resolved entry",
    )


register(filenames=["pnpm-lock.yaml"])(parse)
