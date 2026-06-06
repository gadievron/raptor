"""npm install-hook scanner.

Reads each ``package.json`` we already discovered, looks at its
``scripts`` table, and flags lifecycle hooks that fire automatically at
``npm install`` time:

    preinstall, install, postinstall, prepare, prepublish, prepublishOnly

Two severity levels:

- **install_hook_suspicious** — the script contains one of a small list
  of high-signal patterns we know attackers use (curl-pipe-shell,
  base64-decode-eval, raw network downloads, eval of fetched content).
  ``high`` severity, ``high`` confidence — operators usually want to
  block on these.
- **install_hook_suspicious** with ``low`` severity — a hook is present
  but doesn't match the dangerous patterns. Most legitimate packages
  use postinstall for compile-native-binary or print-banner; the row
  exists for SBOM-style awareness, not to block CI.

We only inspect the *project's* ``package.json``. Scanning every
dependency's package.json requires walking ``node_modules`` and is a
follow-up — see ``packages/sca/supply_chain/__init__.py`` for the gap
note.
"""

from __future__ import annotations

import json as _json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List

from ..models import Confidence, Dependency, Manifest, PinStyle
from . import _hook_patterns, _intree_resolve

logger = logging.getLogger(__name__)

_LIFECYCLE_KEYS = (
    # Fires on every ``npm install`` of the package.
    "preinstall", "install", "postinstall",
    # ``prepare`` fires after ``npm install`` (no args) AND before
    # ``npm publish``.  Both surfaces are attack-relevant.
    "prepare",
    # ``prepublish`` is deprecated but on npm < 4 also ran at install
    # time.  Kept for legacy-tarball coverage.
    "prepublish",
    # NOTE: ``prepublishOnly`` is INTENTIONALLY EXCLUDED.  Per npm
    # docs (https://docs.npmjs.com/cli/v10/using-npm/scripts) it
    # fires only on ``npm publish`` and NEVER at install time, so
    # an install-hook-class signal here is wrong-by-construction
    # (FP-flooded rails' ``actioncable`` / ``activestorage``
    # sub-packages on stress sweep — both use ``prepublishOnly`` for
    # legitimate copy-source-tree prep).
)



@dataclass(frozen=True)
class InstallHookHit:
    """One install-hook entry plus the patterns it triggered."""

    script_key: str            # "postinstall" / "preinstall" / ...
    script_body: str           # raw command string
    reasons: List[str]         # zero or more dangerous-pattern hits
    # In-tree targets the hook body references — see
    # ``_intree_resolve``.  Empty list when the body references no
    # in-tree paths (the legitimate ``node-gyp rebuild`` case).
    # When any entry is a ``binary``, this hook is the Iron Worm
    # archetype: a lifecycle script executing a payload bundled in
    # the package's own tarball.  ``binary_in_package`` (Phase 3)
    # independently flags the same path; composite scoring then
    # promotes the pair to critical.
    intree_targets: tuple = ()
    # Phase 5 conjunction flags — composite scoring promotes when
    # BOTH are set AND the host package isn't in the publish-helpers
    # allowlist.  Iron Worm + npm-credential-stealer shapes.
    reads_credentials: bool = False
    has_publish_action: bool = False


def scan_manifests(
    manifests: Iterable[Manifest],
    deps: Iterable[Dependency],
) -> List["InstallHookFinding"]:
    """Inspect every npm ``package.json`` and emit findings."""
    out: List["InstallHookFinding"] = []
    deps_list = list(deps)
    for m in manifests:
        if m.path.name != "package.json" or m.is_lockfile:
            continue
        # The install hook is OWNED BY the package itself, not by
        # any of its dependencies.  Synthesize a host dep using the
        # package's OWN name from ``data.name``; only fall back to
        # the placeholder name when the manifest lacks one.  The
        # previous behaviour returned the FIRST dep declared in the
        # manifest, which mis-attributed (e.g. rails actioncable's
        # hook came back as belonging to spark-md5, its first
        # dependency, not to @rails/actioncable itself).
        host = _resolve_host(m, deps_list)
        out.extend(_scan_one(m.path, host))
    return out


def _resolve_host(
    manifest: Manifest, deps: List[Dependency],
) -> Dependency:
    """Return a Dependency whose ``name`` is the package's OWN name.

    Strategy:
      1. Read ``data.name`` from the manifest.
      2. If a dep in ``deps`` matches that name AND is declared at
         this manifest path, return it (preserves the parser's
         confidence / pin metadata).
      3. Otherwise synthesise a placeholder with the package's
         own name.
      4. Fallback to the generic placeholder when reading the name
         fails.
    """
    try:
        text = manifest.path.read_text(encoding="utf-8", errors="replace")
        data = _json.loads(text)
    except (OSError, _json.JSONDecodeError):
        return _placeholder_for_manifest(manifest)
    if not isinstance(data, dict):
        return _placeholder_for_manifest(manifest)
    pkg_name = data.get("name")
    if not isinstance(pkg_name, str) or not pkg_name:
        return _placeholder_for_manifest(manifest)
    for d in deps:
        if (d.declared_in == manifest.path
                and d.name == pkg_name):
            return d
    return Dependency(
        ecosystem=manifest.ecosystem,
        name=pkg_name,
        version=(data.get("version")
                 if isinstance(data.get("version"), str) else None),
        declared_in=manifest.path,
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.UNKNOWN,
        direct=True,
        purl=f"pkg:{manifest.ecosystem.lower()}/{pkg_name}",
        parser_confidence=Confidence(
            "high",
            reason="package's own name from manifest data.name",
        ),
    )


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class InstallHookFinding:
    """Internal carrier — converted to ``SupplyChainFinding`` by the
    orchestrator. Kept separate so this module has zero dependency on
    the findings layer."""

    dependency: Dependency
    hit: InstallHookHit
    severity: str
    confidence: Confidence


def _scan_one(path: Path, host: Dependency) -> List[InstallHookFinding]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.debug("sca.supply_chain.install_hooks: %s read failed: %s",
                     path, e)
        return []
    try:
        data = _json.loads(text)
    except _json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    scripts = data.get("scripts")
    if not isinstance(scripts, dict):
        return []
    out: List[InstallHookFinding] = []
    for key in _LIFECYCLE_KEYS:
        body = scripts.get(key)
        if not isinstance(body, str) or not body.strip():
            continue
        analysis = _hook_patterns.analyse_body(body)
        # Resolve in-tree path references from the body.  Adversarial
        # safety + classification logic lives in
        # :mod:`_intree_resolve`.  Failures here are silent — never
        # fail a scan on a path-resolution edge case.
        try:
            intree_targets = tuple(
                _intree_resolve.resolve_intree_targets(body, path.parent),
            )
        except Exception as exc:                     # pragma: no cover
            logger.debug(
                "sca.supply_chain.install_hooks: intree resolve raised %r "
                "for %s — continuing without intree evidence",
                exc, path,
            )
            intree_targets = ()
        intree_has_binary = any(
            t.is_executable_payload for t in intree_targets
        )
        hit = InstallHookHit(
            script_key=key,
            script_body=body.strip(),
            reasons=analysis.reasons,
            intree_targets=intree_targets,
            reads_credentials=analysis.reads_credentials,
            has_publish_action=analysis.has_publish_action,
        )
        # Phase 5 worm-shape: install hook reads credentials AND
        # invokes a publish action.  Suppress when the host package
        # is in the publish-helpers allowlist (semantic-release et
        # al. legitimately do both at runtime; the malicious shape
        # is doing it from an INSTALL hook on an unrelated package).
        worm_shape = (
            analysis.reads_credentials
            and analysis.has_publish_action
            and not _hook_patterns.is_publish_helper(host)
        )
        if analysis.reasons:
            out.append(InstallHookFinding(
                dependency=host,
                hit=hit,
                severity="high",
                confidence=Confidence(
                    "high",
                    reason="install hook matches known-dangerous pattern",
                ),
            ))
        elif worm_shape:
            # Standalone-high: an install hook that BOTH reads
            # credentials AND invokes a publish action is the
            # self-replication footprint.  Composite scoring on top
            # promotes further when paired with BINARY/EGRESS.
            out.append(InstallHookFinding(
                dependency=host,
                hit=hit,
                severity="high",
                confidence=Confidence(
                    "high",
                    reason=(
                        "install hook reads credentials AND invokes "
                        "a publish action (self-replication shape)"
                    ),
                ),
            ))
        elif intree_has_binary:
            # Hook executes a binary that ships in the package's own
            # source tree.  Promote from ``low`` (the generic "hook
            # present" branch) to ``medium`` standalone; composite
            # scoring (Phase 1) then pairs this HOOK family signal
            # with the BINARY family signal that
            # :mod:`binary_in_package` (Phase 3) emits at the same
            # path → critical.
            out.append(InstallHookFinding(
                dependency=host,
                hit=hit,
                severity="medium",
                confidence=Confidence(
                    "high",
                    reason=(
                        "install hook executes a binary that ships in "
                        "the same source tree"
                    ),
                ),
            ))
        else:
            out.append(InstallHookFinding(
                dependency=host,
                hit=hit,
                severity="low",
                confidence=Confidence(
                    "medium",
                    reason="install hook present; behaviour not auto-flagged",
                ),
            ))
    return out


def _placeholder_for_manifest(manifest: Manifest) -> Dependency:
    return Dependency(
        ecosystem=manifest.ecosystem,
        name="<package.json>",
        version=None,
        declared_in=manifest.path,
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.UNKNOWN,
        direct=True,
        purl="",
        parser_confidence=Confidence(
            "low", reason="placeholder for install-hook finding host",
        ),
    )


__all__ = ["InstallHookFinding", "InstallHookHit", "scan_manifests"]
