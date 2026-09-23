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

import logging
import re
from dataclasses import dataclass
from pathlib import Path

from core.json import load_json_bounded

from ..discovery import (
    VENDOR_INSTALL_DIR_NAMES as _VENDOR_INSTALL_DIR_NAMES,
)

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..models import Dependency

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pattern groups
# ---------------------------------------------------------------------------

# Dangerous shell shapes — high-FP-tolerance.  Each entry is
# (regex, short reason).  Reasons surface in the finding.
_DANGEROUS_PATTERNS: tuple[tuple[re.Pattern, str], ...] = (
    # Single run-consuming class between the tool and the pipe — the
    # previous ``\s+[^|]*\s*`` form had three adjacent overlapping
    # quantifiers (the negated class includes whitespace), which was
    # quadratic on "curl" + long whitespace runs with no pipe.
    (re.compile(r"\bcurl\b[^|\n]*\|\s*(?:bash|sh|zsh)\b"),
     "curl piped to shell"),
    (re.compile(r"\bwget\b[^|\n]*\|\s*(?:bash|sh|zsh)\b"),
     "wget piped to shell"),
    (re.compile(r"\bnc\s+(?:-[^ ]+\s+)*[\w.\-]+\s+\d+"),
     "netcat to remote host"),
    (re.compile(r"\bbash\s+-c\s+[\"']?\$\("),
     "bash -c with command substitution"),
    (re.compile(r"\beval\s*\("),
     "eval() call"),
    (re.compile(r"\bnode\s+-e\b"),
     "node -e (inline JS execution)"),
    # ``[0-9.]*`` covers the versioned binary names hooks actually
    # spell — ``python3 -c`` / ``python3.12 -c`` — which the bare
    # ``python`` word-boundary form silently missed.
    (re.compile(r"\bpython[0-9.]*\s+-c\b"),
     "python -c (inline code execution)"),
    (re.compile(r"\bruby\s+-e\b"),
     "ruby -e (inline code execution)"),
    (re.compile(r"\bphp\s+-r\b"),
     "php -r (inline code execution)"),
    (re.compile(r"\bperl\s+-e\b"),
     "perl -e (inline code execution)"),
    (re.compile(r"\bdeno\s+eval\b"),
     "deno eval (inline code execution)"),
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
_CREDENTIAL_READ_PATTERNS: tuple[re.Pattern, ...] = (
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


_PUBLISH_ACTION_PATTERNS: tuple[re.Pattern, ...] = (
    re.compile(r"\bnpm\s+publish\b"),
    re.compile(_quoted_pair("npm", "publish")),
    re.compile(r"\byarn\s+publish\b"),
    re.compile(_quoted_pair("yarn", "publish")),
    re.compile(r"\bpnpm\s+publish\b"),
    re.compile(_quoted_pair("pnpm", "publish")),
    re.compile(r"\bcargo\s+publish\b"),
    re.compile(_quoted_pair("cargo", "publish")),
    re.compile(r"\btwine\s+upload\b"),
    re.compile(_quoted_pair("twine", "upload")),
    re.compile(r"\bgem\s+push\b"),
    re.compile(_quoted_pair("gem", "push")),
    re.compile(r"\bcomposer\s+(?:upload|publish)\b"),
    re.compile(_quoted_pair("composer", "publish")),
    re.compile(r"\bgh\s+release\s+create\b"),
    re.compile(r"\bgh\s+api\s+repos?/[^/]+/[^/]+/contents"),
    re.compile(r"\bgit\s+push\b"),
    re.compile(_quoted_pair("git", "push")),
)


# ---------------------------------------------------------------------------
# Publish-helpers allowlist
# ---------------------------------------------------------------------------

# ``{ecosystem: (exact_names, scope_prefixes)}`` — see
# :func:`load_publish_helpers`.
_PUBLISH_HELPERS_CACHE: dict[str, tuple[frozenset, frozenset]] | None = None


def _publish_helpers_path() -> Path:
    return Path(__file__).resolve().parents[1] / "data" / "publish_helpers.json"


def load_publish_helpers() -> dict[str, tuple[frozenset, frozenset]]:
    """Return ``{ecosystem: (exact_names, scope_prefixes)}`` from the
    ``publish_helpers.json`` data file.  Cached after first call.

    The allowlist is keyed PER ECOSYSTEM: a package name is
    self-declared manifest content, so an ecosystem-blind match would
    let e.g. a RubyGems gem calling itself ``twine`` or ``np`` ride a
    PyPI / npm tool's suppression.  A legacy flat ``names`` list (the
    pre-keyed file shape) is honoured as npm-only — narrowing, never
    widening, when an operator ships the old shape.
    """
    global _PUBLISH_HELPERS_CACHE
    if _PUBLISH_HELPERS_CACHE is not None:
        return _PUBLISH_HELPERS_CACHE
    path = _publish_helpers_path()
    per_eco: dict[str, tuple[frozenset, frozenset]] = {}
    try:
        # Repo-bundled data file; ValueError also covers the
        # byte-budget refusal.
        blob = load_json_bounded(path, max_bytes=8 * 1024 * 1024)
    except (OSError, ValueError) as e:
        logger.debug(
            "sca.supply_chain._hook_patterns: publish_helpers.json "
            "load failed: %s (proceeding with empty allowlist)",
            e,
        )
        _PUBLISH_HELPERS_CACHE = {}
        return _PUBLISH_HELPERS_CACHE
    ecosystems = blob.get("ecosystems")
    if not isinstance(ecosystems, dict):
        # Legacy flat shape: every entry was in practice an npm tool
        # (plus twine / build, which the keyed bundle moves to PyPI).
        ecosystems = {"npm": blob.get("names", [])}
    for eco, names in ecosystems.items():
        if not isinstance(eco, str) or not isinstance(names, list):
            continue
        exact: set = set()
        scopes: set = set()
        for name in names:
            if not isinstance(name, str):
                continue
            if name.endswith("/*"):
                scopes.add(name[:-1])
            else:
                exact.add(name)
        per_eco[eco] = (frozenset(exact), frozenset(scopes))
    _PUBLISH_HELPERS_CACHE = per_eco
    return _PUBLISH_HELPERS_CACHE


def is_publish_helper(dep: Dependency) -> bool:
    """True iff ``dep.name`` matches its OWN ecosystem's entry in the
    publish-helpers allowlist.

    Name-only check — for worm-shape SUPPRESSION decisions use
    :func:`is_attested_publish_helper`: the name is self-declared in
    the scanned manifest, so on its own it is attacker-satisfiable.
    """
    entry = load_publish_helpers().get(dep.ecosystem or "")
    if entry is None:
        return False
    exact, scopes = entry
    name = dep.name or ""
    if name in exact:
        return True
    return any(name.startswith(scope) for scope in scopes)


# Vendor directories whose entry layout binds a directory name to the
# installed package's registry name (the package manager, not the
# package, chooses the path). Used to corroborate a self-declared
# allowlist name before it may suppress the worm-shape promotion.
#
# INVARIANT: attestation only means anything because discovery NEVER
# yields manifests from these directories — so a manifest whose
# ``declared_in`` sits under one can only have come from a scan
# rooted inside a real vendor tree, not from a hostile repo
# committing a fake one.  The set is therefore discovery's own
# ``VENDOR_INSTALL_DIR_NAMES`` (single source — those names stay
# pruned even inside discovery's composite-actions carve-out).
# ``gems`` / ``site-packages`` / ``dist-packages`` were dropped
# because the discovery walk DOES descend into them: a committed
# ``gems/np/package.json`` (e.g. pulled into the install graph via
# ``"workspaces": ["gems/*"]``) was discovered, scanned, and
# self-attested its allowlisted name.  A drift test pins the subset
# relation against ``EXCLUDED_DIR_NAMES``.
_VENDOR_DIR_NAMES = frozenset(_VENDOR_INSTALL_DIR_NAMES)


def is_attested_publish_helper(dep: Dependency) -> bool:
    """True iff ``dep.name`` is an allowlisted publish helper AND the
    manifest's on-disk location corroborates that self-declared name.

    The allowlist name comes from the scanned manifest itself, so a
    malicious package could simply DECLARE ``"name": "np"`` and have
    its credential-read+publish install hook demoted. Suppression
    therefore requires attestation: the manifest must sit inside a
    recognised vendor directory whose entry is named after the
    package (``node_modules/np/package.json``, scoped npm
    ``node_modules/@semantic-release/github/package.json``, RubyGems
    ``gems/<name>-<version>/...``). A top-level project claiming an
    allowlisted name gets NO suppression — its worm-shape hook fires
    at full severity.

    Residual (documented): every vendor name here is also excluded
    from the discovery walk, so an in-tree fake vendor dir never
    reaches the adapters; what remains is a scan ROOTED inside a
    hostile vendor-shaped tree (operator explicitly pointed the tool
    at it), and the composite chokepoint still sees the hook
    evidence in that case.
    """
    if not is_publish_helper(dep):
        return False
    declared_in = dep.declared_in
    if declared_in is None:
        return False
    parts = Path(declared_in).parts
    name = dep.name or ""
    if not name or len(parts) < 2:
        return False
    # Directory chain naming the package, immediately under a vendor
    # dir. Scoped npm names span two path components.
    name_parts = tuple(p for p in name.split("/") if p)
    dirs = parts[:-1]

    def _entry_matches(entry: str, leaf: str) -> bool:
        # Exact, or gems-style "<name>-<version>" entry.
        if entry == leaf:
            return True
        version = dep.version or ""
        return bool(version) and entry == f"{leaf}-{version}"

    n = len(name_parts)
    if len(dirs) < n + 1:
        return False
    # Defense in depth for the walk-unreachability invariant: refuse
    # attestation for any path routed through a ``.github`` segment.
    # Discovery deliberately carves exceptions under ``.github``
    # (composite-action dirs keep names the generic exclude list
    # would prune), so CI-metadata trees are exactly where a hostile
    # repo gets attacker-chosen layout walked — a real package
    # manager never installs a vendor tree there.  Checked over
    # EVERY segment, not just the chain adjacent to the manifest, so
    # nesting depth can't dodge it.
    if ".github" in dirs:
        return False
    tail = dirs[-n:]
    if not all(
        _entry_matches(seg, leaf) for seg, leaf in zip(tail, name_parts)
    ):
        return False
    return dirs[-n - 1] in _VENDOR_DIR_NAMES


# ---------------------------------------------------------------------------
# Per-hook analysis
# ---------------------------------------------------------------------------


# Per-CHUNK regex input bound. The substrate is shared by two body
# classes with very different sizes: manifest SCRIPT STRINGS (a line
# or two of shell) and ENTIRE attacker-authored source files
# (setup.py / build.rs / extconf.rb via the whole-file adapters).
# The old behaviour capped the WHOLE body at this bound and silently
# scanned only the prefix — 16 KB of plausible boilerplate followed
# by the payload was a total, zero-cost evasion of every
# dangerous-pattern / credential / worm signal for the file
# adapters. Bodies are now scanned IN FULL (up to
# ``_MAX_HOOK_SCAN_BYTES``) in line-aligned chunks of this size:
# every regex input stays bounded, so an accidentally-superlinear
# pattern costs at most per-chunk work, while the patterns
# themselves are line-local and linear (test_hook_patterns_redos
# pins both), making total work linear in body size.
_MAX_HOOK_BODY_BYTES = 16 * 1024

# Total pattern-scan budget per body. Legitimate build scripts sit
# far below this; content beyond it is NOT silently ignored — the
# analysis fails toward review by appending
# :data:`SCAN_TRUNCATED_REASON` (adapters classify reasons as high),
# so padding a payload past the budget flags the file instead of
# hiding it.
_MAX_HOOK_SCAN_BYTES = 256 * 1024

# Reason row appended whenever any part of the body went unscanned
# (total budget hit, or a single line longer than the chunk bound
# was cut). Severity follows the standard reasons rule — the
# unscanned remainder cannot be attested, so the hook is surfaced
# for manual review rather than silently passed.
SCAN_TRUNCATED_REASON = (
    "hook body exceeds the pattern-scan bound "
    "(unscanned remainder cannot be attested — review manually)"
)


def _scan_chunks(body: str) -> tuple[list[str], bool]:
    """Split ``body`` into line-aligned chunks of at most
    ``_MAX_HOOK_BODY_BYTES``, covering at most
    ``_MAX_HOOK_SCAN_BYTES``. Returns ``(chunks, truncated)`` —
    ``truncated`` is True when any content was left unscanned.

    Chunks split on ``"\n"`` ONLY — deliberately NOT
    ``str.splitlines()``. The split points must match the pattern
    grammar's line model: the substrate regexes treat only ``\n``
    as a line terminator (their ``[^|\n]``-style classes match
    straight through NEL / VT / FF / LS / PS), so a splitlines
    boundary would turn those characters into silent seam points —
    an attacker-placed ``\x85`` inside a match span at a chunk
    flush split the match across chunks with ``truncated=False``.
    With ``\n``-only splitting every pattern-visible line lands
    whole in some chunk; only a single ``\n``-line longer than the
    chunk bound is cut (and reported truncated)."""
    if len(body) <= _MAX_HOOK_BODY_BYTES:
        return [body], False
    truncated = False
    scan_body = body
    if len(scan_body) > _MAX_HOOK_SCAN_BYTES:
        scan_body = scan_body[:_MAX_HOOK_SCAN_BYTES]
        truncated = True
    chunks: list[str] = []
    buf: list[str] = []
    buf_len = 0
    segments = scan_body.split("\n")
    lines = [
        seg + "\n" if i < len(segments) - 1 else seg
        for i, seg in enumerate(segments)
    ]
    if lines and not lines[-1]:
        lines.pop()
    for line in lines:
        n = len(line)
        if n > _MAX_HOOK_BODY_BYTES:
            if buf:
                chunks.append("".join(buf))
                buf, buf_len = [], 0
            chunks.append(line[:_MAX_HOOK_BODY_BYTES])
            truncated = True
            continue
        if buf_len + n > _MAX_HOOK_BODY_BYTES:
            chunks.append("".join(buf))
            buf, buf_len = [], 0
        buf.append(line)
        buf_len += n
    if buf:
        chunks.append("".join(buf))
    return chunks, truncated


@dataclass(frozen=True)
class HookAnalysis:
    """Result of scanning one hook body with the shared substrate."""

    reasons: list[str]               # ``_DANGEROUS_PATTERNS`` matches
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

    The body is scanned in full through line-aligned chunks (see
    ``_scan_chunks``); when anything was left unscanned, the
    truncation itself becomes a reason row — the analysis fails
    toward review, never toward silence.
    """
    chunks, truncated = _scan_chunks(body)
    reasons = [
        why for rgx, why in _DANGEROUS_PATTERNS
        if any(rgx.search(c) for c in chunks)
    ]
    if truncated:
        logger.debug(
            "sca.supply_chain._hook_patterns: hook body of %d bytes "
            "exceeds the scan bound; flagging the unscanned remainder",
            len(body),
        )
        reasons.append(SCAN_TRUNCATED_REASON)
    reads_credentials = any(
        any(rgx.search(c) for c in chunks)
        for rgx in _CREDENTIAL_READ_PATTERNS
    )
    has_publish_action = any(
        any(rgx.search(c) for c in chunks)
        for rgx in _PUBLISH_ACTION_PATTERNS
    )
    return HookAnalysis(
        reasons=reasons,
        reads_credentials=reads_credentials,
        has_publish_action=has_publish_action,
    )


__all__ = [
    "HookAnalysis",
    "SCAN_TRUNCATED_REASON",
    "analyse_body",
    "is_publish_helper",
    "load_publish_helpers",
]
