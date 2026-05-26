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
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional

from ..models import Confidence, Dependency, Manifest, PinStyle

logger = logging.getLogger(__name__)

_LIFECYCLE_KEYS = (
    "preinstall", "install", "postinstall",
    "prepare", "prepublish", "prepublishOnly",
)

# Patterns we treat as actively-malicious-shaped. False positives are
# tolerable here — operators get a row to triage, not a build break.
# Each entry is (regex, short reason).
_DANGEROUS_PATTERNS = (
    (re.compile(r"\bcurl\s+[^|]*\s*\|\s*(?:bash|sh|zsh)\b"),
     "curl piped to shell"),
    (re.compile(r"\bwget\s+[^|]*\s*\|\s*(?:bash|sh)\b"),
     "wget piped to shell"),
    (re.compile(r"\bnc\s+(?:-[^ ]+\s+)*[\w.\-]+\s+\d+"),
     "netcat to remote host"),
    (re.compile(r"\bbash\s+-c\s+[\"']?\$\("),
     "bash -c with command substitution"),
    (re.compile(r"\beval\s*\("),
     "eval() call"),
    (re.compile(r"\bnode\s+-e\b"),
     "node -e (inline JS execution)"),
    (re.compile(r"\bpython\s+-c\b"),
     "python -c (inline code execution)"),
    (re.compile(r"base64\s+(?:-d|--decode)\s*\|"),
     "base64 piped to decoder"),
    (re.compile(r"echo\s+[A-Za-z0-9+/=]{40,}\s*\|\s*base64"),
     "long base64 blob piped"),
    # Legacy npm token exfiltration via env vars.
    (re.compile(r"\$\{?NPM_TOKEN\}?"),
     "references NPM_TOKEN"),
    (re.compile(r"process\.env\.[A-Z_]*TOKEN"),
     "references *TOKEN env var"),
    # Shell to a non-standard registry mirror.
    (re.compile(r"https?://[\w.\-]*(?:bit\.ly|tinyurl|pastebin|raw\.githubusercontent)"),
     "URL to a paste/CDN host"),
)


@dataclass(frozen=True)
class InstallHookHit:
    """One install-hook entry plus the patterns it triggered."""

    script_key: str            # "postinstall" / "preinstall" / ...
    script_body: str           # raw command string
    reasons: List[str]         # zero or more dangerous-pattern hits


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
        host = _host_dep(deps_list, m) or _placeholder_for_manifest(m)
        out.extend(_scan_one(m.path, host))
    return out


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
        reasons = [why for rgx, why in _DANGEROUS_PATTERNS
                   if rgx.search(body)]
        hit = InstallHookHit(script_key=key,
                             script_body=body.strip(),
                             reasons=reasons)
        if reasons:
            out.append(InstallHookFinding(
                dependency=host,
                hit=hit,
                severity="high",
                confidence=Confidence(
                    "high",
                    reason="install hook matches known-dangerous pattern",
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


def _host_dep(deps: List[Dependency], manifest: Manifest) -> Optional[Dependency]:
    for d in deps:
        if d.declared_in == manifest.path:
            return d
    return None


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
