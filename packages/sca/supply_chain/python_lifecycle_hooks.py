"""Python ``setup.py`` lifecycle-hook scanner.

When a project ships an sdist (source distribution), ``pip install``
EXECUTES ``setup.py`` as part of building the wheel.  An attacker
who controls ``setup.py`` runs arbitrary code on every install —
the Python equivalent of npm's ``postinstall`` hook.

This adapter uses the shared :mod:`_hook_patterns` substrate so the
credential-read (C) and publish-action (G) detection, the
worm-shape conjunction, the dangerous-pattern list, and the
publish-helpers allowlist all match the npm semantics exactly.

# Adversarial model

What this adapter must defend against:

  * **AST-defeating obfuscation** — ``setup.py`` is Python source.
    An attacker who base64-encodes the dangerous payload at module
    level evades regex matching.  The ``_DANGEROUS_PATTERNS``
    substrate includes shell-shaped ``base64`` patterns (pipe-to-
    decoder); Python-native ``base64.b64decode(...)`` calls are NOT
    currently detected.  Same regime as npm — we don't claim
    AST-precise detection.
  * **Reading other manifest files** — ``setup.py`` commonly reads
    ``README.md`` / ``VERSION`` / ``CHANGELOG.md``.  False positives
    on those are not credential reads (the C-set is keyed on
    credential-bearing paths like ``~/.aws/`` and ``~/.npmrc``, not
    arbitrary file reads).
  * **Conditional execution** — ``if sys.platform == 'darwin'``
    wraps a payload.  We don't track Python control flow; we report
    any pattern hit regardless of static unreachability.  Reviewers
    decide.
  * **pyproject.toml + PEP 517 builds** — modern Python packaging
    invokes the build backend (``setuptools.build_meta``,
    ``poetry.core.masonry.api``, ``flit_core.buildapi``,
    ``hatchling.build``) rather than executing ``setup.py``
    directly.  But sdists still ship ``setup.py`` in many cases for
    legacy compatibility; we scan whichever exists.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from collections.abc import Iterable

from ..models import Confidence, Dependency, Manifest
from . import _hook_patterns, _own_host

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PythonLifecycleHit:
    """Result of scanning one Python lifecycle hook (``setup.py`` /
    ``pyproject.toml`` build hook)."""

    script_key: str             # "setup.py" / "pyproject.toml:build-system"
    script_body: str            # body text (truncated downstream)
    reasons: list[str]
    reads_credentials: bool
    has_publish_action: bool


@dataclass(frozen=True)
class PythonLifecycleFinding:
    """Internal carrier — converted to ``SupplyChainFinding`` by the
    orchestrator."""

    dependency: Dependency
    hit: PythonLifecycleHit
    severity: str
    confidence: Confidence


def scan_manifests(
    manifests: Iterable[Manifest],
    deps: Iterable[Dependency],
) -> list[PythonLifecycleFinding]:
    """Inspect every Python project's ``setup.py`` and emit findings.

    ``pyproject.toml`` lifecycle scanning is out of scope here —
    PEP 517 build backends are themselves trusted code paths; the
    HOOK-shaped risk lives in ``setup.py`` (still required for
    sdist + legacy compatibility on most packages today).
    """
    del deps  # host is a pure function of the manifest (see below)
    out: list[PythonLifecycleFinding] = []
    seen_dirs: set = set()
    for m in manifests:
        if m.ecosystem != "PyPI":
            continue
        manifest_dir = m.path.parent
        if manifest_dir in seen_dirs:
            continue
        seen_dirs.add(manifest_dir)
        # The hook is OWNED BY the package itself — anchor to the
        # project's own name (pyproject.toml), never to whichever
        # dep the parser happened to emit first: that mis-attributed
        # the finding to an innocent third party and keyed the
        # publish-helper worm-shape suppression on the wrong name.
        host = _own_host.resolve_own_host(
            m,
            reason="placeholder for python-lifecycle-hook finding host",
            placeholder_name="<setup.py>",
        )
        out.extend(_scan_setup_py(manifest_dir, host))
    return out


def _scan_setup_py(
    manifest_dir: Path, host: Dependency,
) -> list[PythonLifecycleFinding]:
    setup_py = manifest_dir / "setup.py"
    if not setup_py.is_file():
        return []
    try:
        body = setup_py.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.debug(
            "sca.supply_chain.python_lifecycle_hooks: %s read failed: %s",
            setup_py, e,
        )
        return []
    analysis = _hook_patterns.analyse_body(body)
    hit = PythonLifecycleHit(
        script_key="setup.py",
        script_body=body.strip(),
        reasons=analysis.reasons,
        reads_credentials=analysis.reads_credentials,
        has_publish_action=analysis.has_publish_action,
    )
    worm_conjunction = (
        analysis.reads_credentials and analysis.has_publish_action
    )
    worm_shape = (
        worm_conjunction
        and not _hook_patterns.is_attested_publish_helper(host)
    )
    if analysis.reasons:
        return [PythonLifecycleFinding(
            dependency=host,
            hit=hit,
            severity="high",
            confidence=Confidence(
                "high",
                reason="setup.py matches known-dangerous pattern",
            ),
        )]
    if worm_shape:
        return [PythonLifecycleFinding(
            dependency=host,
            hit=hit,
            severity="high",
            confidence=Confidence(
                "high",
                reason=(
                    "setup.py reads credentials AND invokes a "
                    "publish action (self-replication shape)"
                ),
            ),
        )]
    if worm_conjunction:
        # Worm conjunction fired but the host is an ATTESTED publish
        # helper — suppress the HIGH promotion, but keep a
        # low-severity row (parity with the npm adapter's
        # fall-through) so the HOOK family survives for the composite
        # chokepoint and the suppression stays operator-visible.
        return [PythonLifecycleFinding(
            dependency=host,
            hit=hit,
            severity="low",
            confidence=Confidence(
                "medium",
                reason=(
                    "setup.py reads credentials and invokes a publish "
                    "action, but the package is an attested publish "
                    "helper — worm-shape promotion suppressed"
                ),
            ),
        )]
    # FP-tightening: ``setup.py`` is the default state for legacy
    # Python packages; emitting on mere presence floods reports.
    # Only the pattern-hit and worm-shape branches earn a finding.
    return []


__all__ = [
    "PythonLifecycleFinding",
    "PythonLifecycleHit",
    "scan_manifests",
]
