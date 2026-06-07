"""Shared substrate for lifecycle-hook pattern detection across
ecosystems.

The npm install-hook detector (``install_hooks.py``) historically
owned three pattern groups: ``_DANGEROUS_PATTERNS`` (curl-pipe-shell,
base64-decode-eval, ...), ``_CREDENTIAL_READ_PATTERNS`` (AWS/kube/
GPG/npmrc/SSH/...), and ``_PUBLISH_ACTION_PATTERNS`` (npm/cargo/
twine publish, gh release, git push).  Those patterns are
ecosystem-agnostic — every supply-chain hook attack lands a shell
command somewhere, and the same shell vocabulary applies whether
the hook is an npm ``postinstall`` script, a Cargo ``build.rs``, a
Python ``setup.py``, a Composer ``post-install-cmd``, or a RubyGems
``extconf.rb``.

This module holds the canonical pattern definitions + the
worm-shape decision logic so every ecosystem adapter applies the
same standard.  The publish-helpers allowlist also lives here —
loaded once, shared across adapters.

# Adversarial model

What the substrate must defend against:

  * **Pattern drift across adapters** — without a shared substrate
    each adapter would accumulate its own pattern list that diverged
    over time.  Defence: one canonical definition; every adapter
    imports from here.
  * **Allowlist semantics drift** — same problem for the
    publish-helpers allowlist.  Defence: one loader function,
    cached.
  * **Worm-shape FP regression** — if every adapter re-implemented
    the conjunction logic, an FP fix in one would not propagate.
    Defence: the conjunction lives in :func:`analyse_body` so all
    adapters get the same answer.
"""

from __future__ import annotations

import json as _json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

from ..models import Dependency

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pattern groups
# ---------------------------------------------------------------------------

# Dangerous shell shapes — high-FP-tolerance.  Each entry is
# (regex, short reason).  Reasons surface in the finding.
_DANGEROUS_PATTERNS: Tuple[Tuple[re.Pattern, str], ...] = (
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
    (re.compile(r"\bruby\s+-e\b"),
     "ruby -e (inline code execution)"),
    (re.compile(r"\bphp\s+-r\b"),
     "php -r (inline code execution)"),
    (re.compile(r"base64\s+(?:-d|--decode)\s*\|"),
     "base64 piped to decoder"),
    (re.compile(r"echo\s+[A-Za-z0-9+/=]{40,}\s*\|\s*base64"),
     "long base64 blob piped"),
    # Legacy npm token exfiltration via env vars.
    (re.compile(r"\$\{?NPM_TOKEN\}?"),
     "references NPM_TOKEN"),
    (re.compile(r"process\.env\.[A-Z_]*TOKEN"),
     "references *TOKEN env var"),
    # Shell to a paste/CDN host.
    (re.compile(
        r"https?://[\w.\-]*"
        r"(?:bit\.ly|tinyurl|pastebin|raw\.githubusercontent)"
    ),
     "URL to a paste/CDN host"),
)


# Credential-read patterns (Phase 5 C-set).
_CREDENTIAL_READ_PATTERNS: Tuple[re.Pattern, ...] = (
    re.compile(r"~/\.aws/(?:credentials|config)"),
    re.compile(r"~/\.kube/config"),
    re.compile(r"~/\.gnupg"),
    re.compile(r"\bgpg\s+--?(?:list-secret|export-secret)"),
    re.compile(r"~/\.npmrc"),
    re.compile(r"~/\.cargo/credentials"),
    re.compile(r"~/\.pypirc"),
    re.compile(r"~/\.gem/credentials"),
    re.compile(r"~/\.composer/auth\.json"),
    re.compile(r"~/\.ssh/(?:id_|authorized_keys|known_hosts)"),
    re.compile(r"~/\.config/gh/hosts"),
    re.compile(r"~/\.docker/config"),
    # Environment-variable equivalents.
    re.compile(
        r"\$\{?AWS_(?:ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN)"
    ),
    re.compile(r"\$\{?KUBECONFIG"),
    re.compile(r"\$\{?GITHUB_TOKEN|\$\{?GH_TOKEN"),
    re.compile(r"\$\{?CARGO_REGISTRY_TOKEN"),
    re.compile(r"\$\{?TWINE_PASSWORD|\$\{?TWINE_USERNAME"),
    re.compile(r"\$\{?GEM_HOST_API_KEY"),
    re.compile(r"\$\{?COMPOSER_AUTH"),
)


# Publish-action patterns (Phase 5 G-set).  Each tool gets TWO
# matchers:
#   * Shell-syntax form (``twine upload``)
#   * Quoted-pair form (``"twine" ... "upload"``) — covers
#     Python subprocess-list ``['twine', 'upload']``, Rust
#     ``Command::new("twine").arg("upload")``, Go
#     ``exec.Command("twine", "upload")``, and any other syntax
#     that quotes the tool and verb within ~60 chars of each other
#
# The quoted-pair regex allows up to 80 chars between the tool and
# verb to handle method-chained shapes
# (``.new("twine")\n   .arg("upload")``) while staying tight enough
# to avoid coincidental long-distance matches.  We exclude only
# quotes — they signal a new string literal which would mean the
# match is spanning unrelated content.
_QP = r"[^\"']{0,80}?"


def _quoted_pair(tool: str, verb: str) -> str:
    """Build a quoted-pair regex source matching either single- or
    double-quoted ``tool`` followed within ``_QP`` chars by quoted
    ``verb``."""
    return rf'[\'"]{tool}[\'"]{_QP}[\'"]{verb}[\'"]'


_PUBLISH_ACTION_PATTERNS: Tuple[re.Pattern, ...] = (
    re.compile(r"\bnpm\s+publish\b"),
    re.compile(_quoted_pair("npm", "publish")),
    re.compile(r"\byarn\s+publish\b"),
    re.compile(r"\bpnpm\s+publish\b"),
    re.compile(r"\bcargo\s+publish\b"),
    re.compile(_quoted_pair("cargo", "publish")),
    re.compile(r"\btwine\s+upload\b"),
    re.compile(_quoted_pair("twine", "upload")),
    re.compile(r"\bpython\s+-m\s+build\b"),
    re.compile(r"\bgem\s+push\b"),
    re.compile(_quoted_pair("gem", "push")),
    re.compile(r"\bcomposer\s+(?:upload|publish)\b"),
    re.compile(r"\bgh\s+release\s+create\b"),
    re.compile(r"\bgh\s+api\s+repos?/[^/]+/[^/]+/contents"),
    re.compile(r"\bgit\s+push\b"),
    re.compile(_quoted_pair("git", "push")),
)


# ---------------------------------------------------------------------------
# Publish-helpers allowlist
# ---------------------------------------------------------------------------

_PUBLISH_HELPERS_CACHE: Optional[frozenset] = None
_PUBLISH_HELPERS_SCOPES_CACHE: Optional[frozenset] = None


def _publish_helpers_path() -> Path:
    return Path(__file__).resolve().parents[1] / "data" / "publish_helpers.json"


def load_publish_helpers() -> Tuple[frozenset, frozenset]:
    """Return ``(exact_names, scope_prefixes)`` from the
    ``publish_helpers.json`` data file.  Cached after first call."""
    global _PUBLISH_HELPERS_CACHE, _PUBLISH_HELPERS_SCOPES_CACHE
    if _PUBLISH_HELPERS_CACHE is not None:
        return _PUBLISH_HELPERS_CACHE, _PUBLISH_HELPERS_SCOPES_CACHE
    path = _publish_helpers_path()
    exact: set = set()
    scopes: set = set()
    try:
        with path.open(encoding="utf-8") as fh:
            blob = _json.load(fh)
    except (OSError, _json.JSONDecodeError) as e:
        logger.debug(
            "sca.supply_chain._hook_patterns: publish_helpers.json "
            "load failed: %s (proceeding with empty allowlist)",
            e,
        )
        _PUBLISH_HELPERS_CACHE = frozenset()
        _PUBLISH_HELPERS_SCOPES_CACHE = frozenset()
        return _PUBLISH_HELPERS_CACHE, _PUBLISH_HELPERS_SCOPES_CACHE
    for name in blob.get("names", []):
        if not isinstance(name, str):
            continue
        if name.endswith("/*"):
            scopes.add(name[:-1])
        else:
            exact.add(name)
    _PUBLISH_HELPERS_CACHE = frozenset(exact)
    _PUBLISH_HELPERS_SCOPES_CACHE = frozenset(scopes)
    return _PUBLISH_HELPERS_CACHE, _PUBLISH_HELPERS_SCOPES_CACHE


def is_publish_helper(dep: Dependency) -> bool:
    """True iff ``dep.name`` matches the publish-helpers allowlist."""
    exact, scopes = load_publish_helpers()
    name = dep.name or ""
    if name in exact:
        return True
    for scope in scopes:
        if name.startswith(scope):
            return True
    return False


# ---------------------------------------------------------------------------
# Per-hook analysis
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HookAnalysis:
    """Result of scanning one hook body with the shared substrate."""

    reasons: List[str]               # ``_DANGEROUS_PATTERNS`` matches
    reads_credentials: bool          # any C-set match
    has_publish_action: bool         # any G-set match


def analyse_body(body: str) -> HookAnalysis:
    """Apply every substrate pattern to ``body`` and return the
    consolidated analysis.  Adapters call this on every hook body
    they enumerate; the caller then decides severity per the
    standard rules:

      * reasons non-empty → high (known-dangerous shape)
      * reads_credentials AND has_publish_action AND NOT
        publish-helper host → high (self-replication shape)
      * otherwise → low (hook present, behaviour not flagged)
    """
    reasons = [why for rgx, why in _DANGEROUS_PATTERNS if rgx.search(body)]
    reads_credentials = any(
        rgx.search(body) for rgx in _CREDENTIAL_READ_PATTERNS
    )
    has_publish_action = any(
        rgx.search(body) for rgx in _PUBLISH_ACTION_PATTERNS
    )
    return HookAnalysis(
        reasons=reasons,
        reads_credentials=reads_credentials,
        has_publish_action=has_publish_action,
    )


__all__ = [
    "HookAnalysis",
    "analyse_body",
    "is_publish_helper",
    "load_publish_helpers",
]
