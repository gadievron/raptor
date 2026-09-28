"""
core/security/_trust_common.py

Shared helper layer for the target-repo trust gates:

    core/security/cc_trust.py      (Claude Code config check)
    core/security/codeql_trust.py  (CodeQL pack/config check)

Same consolidation as :mod:`core.security.capped_read`, which owns the
hardened open/read both gates delegate to: each gate previously carried
a private, hand-synced copy of this layer — output sanitisation
(``_safe`` / ``_truncate`` / ``_mask``), the ``Finding`` / ``FileScan``
result shapes, the scan-report renderer, and the fail-closed
resolve-and-stat gate on supplied targets. One home ends the hand-sync;
the gates keep their genuinely different domain walks (settings/MCP
JSON vs pack/config YAML) in their own modules.

Both gates are FAIL-CLOSED by design: a target the checker cannot
resolve, stat, read, or parse is refused, never waved through, and the
operator's ``--trust-repo`` override downgrades a refusal to
warn-and-proceed — it never silences it. Nothing in this module may
weaken that posture.

Everything rendered here can carry attacker-chosen bytes (paths, config
values, exception text from hostile filesystems), so every rendered
string rides through :func:`safe_text`, values that can embed
credentials ride through :func:`mask`, and lengths are bounded by
:func:`truncate`.
"""

from __future__ import annotations

import os
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from core.security.capped_read import read_capped

# RAPTOR repo root = core/security/_trust_common.py -> ../../
# Both gates skip scanning RAPTOR's own repo (operator running RAPTOR
# against itself is implicitly trusted).
RAPTOR_DIR = Path(__file__).resolve().parents[2]

# One cap for every trust-gate config read. Real config/pack files are
# tiny (<10 KiB); the cap bounds the JSON/YAML parsers' memory exposure
# and anything over it is refused as oversized/unreadable — a BLOCKING
# finding, so a smaller cap can only move a file toward refusal, never
# wave it through. Both directions matter when touching this value:
# raising it widens parser exposure on attacker-supplied bytes;
# lowering it starts refusing larger legitimate configs (operators
# override per run via --trust-repo, so refusal is recoverable).
MAX_TRUST_CONFIG_BYTES = 1_000_000


def read_trust_config(path: Path) -> bytes | None:
    """Read up to ``MAX_TRUST_CONFIG_BYTES``; delegates the hardened
    open/read (O_NOFOLLOW, non-regular refusal, cap) to
    :func:`core.security.capped_read.read_capped`. None = refuse
    (fail-closed: callers treat an unreadable candidate as a blocking
    finding, never as absent)."""
    return read_capped(path, MAX_TRUST_CONFIG_BYTES)

# U+2028/U+2029 line-separators — Zl/Zp categories slip past the Cc/Cf
# strip below but terminals render them as newlines, which could split
# gate output. Escaped spellings deliberately: the literal characters
# are invisible in an editor, so a reviewer cannot tell the set from a
# pair of ordinary quoted blanks — and an accidental "cleanup" to real
# spaces would silently disable the defence while corrupting every
# space in sanitised output.
EXTRA_STRIP = frozenset({"\u2028", "\u2029"})


def safe_text(s: str) -> str:
    """Strip Unicode control/format chars and line/paragraph separators.
    Defends against ANSI escapes, Trojan Source bidi (CVE-2021-42574),
    zero-width chars, and line-separator-driven output splitting."""
    return "".join(
        c if c == "\t" or (
            c not in EXTRA_STRIP
            and unicodedata.category(c) not in ("Cc", "Cf")
        ) else "?"
        for c in s
    )


def truncate(s: str, limit: int = 80) -> str:
    """Sanitise via :func:`safe_text`, then bound to ``limit`` chars
    with an explicit ellipsis marker."""
    safe = safe_text(s)
    return safe[:limit] + "..." if len(safe) > limit else safe


def mask(s: str, keep: int = 8) -> str:
    """Render a secret-bearing config value without echoing it.

    Scan output lands on stdout and from there in retained CI logs, so
    credential-helper commands, env values, MCP/extractor/build-hook
    command lines must not be printed verbatim — a leaked config file
    would otherwise republish its secrets into every build log. Keep a
    short prefix (enough to identify the binary/helper for triage),
    redact the tail, and show the length so distinct values remain
    distinguishable. ``keep=0`` fully redacts — used for env values,
    where the value IS the secret and even a prefix is a partial leak.
    """
    safe = safe_text(s)
    if not safe:
        return "(empty)"
    # A prefix of a value no longer than ``keep`` IS the value —
    # fully redact rather than echo it whole.
    prefix = safe[:keep] if 0 < keep < len(safe) else ""
    return f"{prefix}*** ({len(safe)} chars)"


@dataclass
class Finding:
    """One labelled row in the per-file findings table."""
    label: str          # e.g. "apiKeyHelper", "extractor", "env LD_PRELOAD"
    value: str          # rendered (sanitised/masked) value for the row
    blocking: bool      # True = blocks dispatch; False = info only


@dataclass
class FileScan:
    """Findings for one inspected file."""
    path: Path
    findings: list[Finding] = field(default_factory=list)

    def has_blocking(self) -> bool:
        return any(f.blocking for f in self.findings)


def resolve_supplied_target(
    repo_path: str,
    trust_override: bool,
    subject: str,
) -> tuple[str | None, bool]:
    """Resolve and stat a supplied target path, failing closed.

    A SUPPLIED target the checker cannot resolve or stat is refused,
    not waved through: these lanes previously returned "clean", but
    that verdict had examined nothing — a vanished (TOCTOU), mistyped,
    or pathological path skipped the gate entirely while the caller
    went on to use the same spelling. The trust override downgrades to
    warn-and-proceed exactly like a real finding, so the launcher's
    "Override: --trust-repo" hint stays truthful.

    Returns ``(resolved, refuse)``. When ``resolved`` is a path string
    the caller proceeds to its scan (``refuse`` is False). When
    ``resolved`` is None the path could not be examined and ``refuse``
    is the gate verdict: True unless the trust override was active.

    ``subject`` names what the gate inspects for the operator-facing
    message (e.g. ``"Claude Code config"`` / ``"CodeQL pack config"``).
    """
    try:
        resolved = str(Path(repo_path).resolve())
        os.stat(resolved)
    except (ValueError, OSError) as e:
        reason = getattr(e, "strerror", None) or type(e).__name__
        shown = truncate(safe_text(repo_path), limit=200)
        if trust_override:
            print(f"raptor: cannot examine {shown} for {subject} "
                  f"({safe_text(str(reason))}) — proceeding "
                  f"(trust override active)")
            return None, False
        # Caller-neutral phrasing: some call sites use the return only
        # as an early warning and enforce at later re-check sites.
        print(f"raptor: cannot examine {shown} for {subject} "
              f"({safe_text(str(reason))}) — treating as dangerous")
        return None, True
    return resolved, False


def render_scan_report(
    target: Path,
    scans: Sequence[FileScan],
    any_blocking: bool,
    trust_override: bool,
    subject: str,
) -> None:
    """Pure rendering — separated from the gates' scan functions so a
    cache (or any scan-once path) doesn't suppress the operator-visible
    warning on re-invocation, and the scans stay side-effect free.

    ``subject`` names what was scanned (e.g. ``"Claude Code config"`` /
    ``"CodeQL pack config"``).
    """
    safe_target = safe_text(str(target))
    if any_blocking:
        if trust_override:
            print(f"raptor: {safe_target} has dangerous {subject} "
                  f"(trust override active):")
        else:
            print(f"raptor: {safe_target} has dangerous {subject}:")
    else:
        print(f"raptor: {safe_target} has {subject}:")

    for fs in scans:
        try:
            rel = fs.path.relative_to(target)
        except ValueError:
            rel = fs.path
        print(f"  {safe_text(str(rel))}")
        if not fs.findings:
            continue
        label_w = max(len(f.label) for f in fs.findings) + 2
        for f in fs.findings:
            print(f"    {f.label:<{label_w}}{f.value}")
