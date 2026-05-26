"""Operator / finder identity — the WHO of a run (citation-only).

This is the human half of run provenance: who to credit when a finding from
this run is published (#485). It is deliberately minimal and deliberately
explicit:

  * **Per-uid, local config.** Read from ``~/.raptor/identity.json`` — $HOME-
    rooted, so each OS user on a shared box has their own, with no extra
    machinery.
  * **Never auto-detected.** We do NOT fall back to ``$USER`` / ``git config
    user.email`` / a GitHub handle — those would leak the operator's real
    identity into a published citation without consent (the same leak the
    public_view redaction exists to prevent). The uid scopes *where* the file
    lives; the operator types *what* is in it.
  * **No default.** Absent / empty / nameless file ⇒ ``None`` — *no* identity
    asserted (no placeholder "Raptor User"). The manifest then omits ``who``
    entirely, and ``/cite`` gates on its presence: setting a public-facing
    identity is the deliberate, informed act of consent.

The value is operator-chosen and publish-intended by construction, so the
fields are an allowlisted ``{name, handle?, url?}``.
"""

from __future__ import annotations

import json
import unicodedata
from pathlib import Path
from typing import Dict, Optional

# $HOME-rooted ⇒ per-uid isolation for free. Same dir as the inventory cache.
IDENTITY_PATH = Path.home() / ".raptor" / "identity.json"

# A real identity file is tiny; cap the read so a huge/symlinked file can't OOM
# the hot start path (`who` is sealed on every start_run).
_MAX_FILE_BYTES = 64 * 1024
_FIELD_MAXLEN = {"name": 256, "handle": 128, "url": 2048}


def _clean_field(value: object, maxlen: int) -> Optional[str]:
    """A field is usable iff it's a non-empty, length-bounded string with no
    control/format characters — the latter rejected because ``who`` is sealed
    into a publish-bound manifest, and control bytes / ANSI escapes / unicode
    bidi-overrides would inject into or spoof a rendered citation. Returns the
    stripped value or None."""
    if not isinstance(value, str):
        return None
    s = value.strip()
    if not s or len(s) > maxlen:
        return None
    # Unicode category 'C*' = control (Cc) / format (Cf, incl. RTL-override +
    # zero-width) / surrogate / private / unassigned. None belong in a name.
    if any(unicodedata.category(ch).startswith("C") for ch in s):
        return None
    return s


def load_finder_identity(path: Optional[Path] = None) -> Optional[Dict[str, str]]:
    """The operator's public-facing identity, or ``None`` when unset.

    Returns ``{"name": ..., "handle"?: ..., "url"?: ...}`` — name required and
    non-empty (a file without a usable name is treated as unset; there is no
    default). ``None`` on absent / unreadable / malformed file, so a broken
    config never breaks a run — it just means "no identity asserted".
    """
    p = path or IDENTITY_PATH
    try:
        if not p.exists() or p.stat().st_size > _MAX_FILE_BYTES:
            return None  # absent, or implausibly large (DoS / not a real config)
        data = json.loads(p.read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    name = _clean_field(data.get("name"), _FIELD_MAXLEN["name"])
    if not name:
        return None  # no usable name ⇒ not set (never a placeholder default)
    out: Dict[str, str] = {"name": name}
    for key in ("handle", "url"):
        val = _clean_field(data.get(key), _FIELD_MAXLEN[key])
        if val:
            out[key] = val
    return out
