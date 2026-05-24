"""Extract a *macro definition config* — the preprocessor symbols a build is
known to define or leave undefined — for config-aware ``#ifdef`` resolution.

This is deliberately an ALLOWLIST, not a guess. A symbol is reported as
known-defined or known-undefined ONLY when a build artifact says so
explicitly:

  * ``compile_commands.json`` — ``-DNAME[=val]`` (defined) / ``-UNAME``
    (undefined), unioned across translation units. A symbol that is BOTH
    defined and undefined across entries is config-dependent project-wide,
    so it is dropped (left unknown).
  * ``.config`` (kernel Kconfig) — ``CONFIG_X=y|m`` (defined to "1") /
    ``# CONFIG_X is not set`` (undefined). Applies to ``CONFIG_*`` only.

Everything not explicitly named stays UNKNOWN. This is the load-bearing
soundness property: a symbol absent from the config might still be
``#define``d in an included header, so "absent" must never be read as
"undefined" — doing so would delete code that is live in the real build
(a false negative). The config-aware dead-arm detector only fires on KNOWN
symbols, so it can never over-fire relative to the real build.

Never raises on missing / malformed artifacts: returns an empty
``MacroConfig`` (``source='absent'``), which makes the detector degrade
to literal-only (``#if 0``) behaviour.
"""

from __future__ import annotations

import json
import logging
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class MacroConfig:
    """Known-defined / known-undefined preprocessor symbols for one build.

    ``defined`` maps name → value string (``"1"`` for a bare ``-DNAME``).
    ``undefined`` is the set of explicitly-undefined names. A name in
    neither is UNKNOWN — callers must treat unknown as config-dependent
    and leave the arm untouched.
    """

    defined: Dict[str, str] = field(default_factory=dict)
    undefined: frozenset = field(default_factory=frozenset)
    source: str = "absent"

    def __bool__(self) -> bool:
        return bool(self.defined or self.undefined)

    def is_defined(self, name: str) -> Optional[bool]:
        """``True`` known-defined, ``False`` known-undefined, ``None``
        unknown (config-dependent / possibly header-defined)."""
        if name in self.defined:
            return True
        if name in self.undefined:
            return False
        return None

    def value_of(self, name: str) -> Optional[str]:
        """Macro value if known-defined, else ``None``."""
        return self.defined.get(name)

    def fingerprint(self) -> str:
        """Deterministic short hash of the config's contents — empty string
        when the config is empty. Used to fold the config into the inventory
        cache key so a config change (e.g. a regenerated ``.config``)
        invalidates cached blanking even when file contents are unchanged."""
        if not self:
            return ""
        import hashlib
        payload = repr((sorted(self.defined.items()), sorted(self.undefined)))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


# A -D token: ``-DNAME`` | ``-DNAME=value``. Space-separated ``-D NAME`` is
# handled by the tokenizer (a lone ``-D`` consumes the next token).
_D_INLINE = re.compile(r"^-D(\w+)(?:=(.*))?$")
_U_INLINE = re.compile(r"^-U(\w+)$")


def _tokens(entry: dict) -> List[str]:
    """Command tokens for one compile_commands entry (``arguments`` array
    preferred; ``command`` string shlex-split)."""
    if isinstance(entry.get("arguments"), list):
        return [str(a) for a in entry["arguments"]]
    cmd = entry.get("command")
    if isinstance(cmd, str):
        try:
            return shlex.split(cmd)
        except ValueError:
            return cmd.split()
    return []


def _scan_tokens(tokens: List[str], defined: Dict[str, str],
                 undefined: set, conflict: set) -> None:
    """Accumulate -D/-U across one entry into the running union. A name seen
    both defined and undefined (here or in a prior entry) goes to
    ``conflict`` and is later dropped — it is config-dependent."""
    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        name = val = None
        is_undef = False
        if tok == "-D" and i + 1 < n:
            i += 1
            m = re.match(r"^(\w+)(?:=(.*))?$", tokens[i])
            if m:
                name, val = m.group(1), m.group(2)
        elif tok == "-U" and i + 1 < n:
            i += 1
            if re.match(r"^\w+$", tokens[i]):
                name, is_undef = tokens[i], True
        else:
            md = _D_INLINE.match(tok)
            mu = _U_INLINE.match(tok)
            if md:
                name, val = md.group(1), md.group(2)
            elif mu:
                name, is_undef = mu.group(1), True
        if name is not None:
            if is_undef:
                if name in defined:
                    conflict.add(name)
                undefined.add(name)
            else:
                if name in undefined:
                    conflict.add(name)
                defined[name] = "1" if val is None or val == "" else val
        i += 1


def _from_compile_commands(path: Path) -> MacroConfig:
    raw = path.read_text(errors="replace")
    entries = json.loads(raw)
    if not isinstance(entries, list) or not entries:
        return MacroConfig(source="compile_commands.json")
    defined: Dict[str, str] = {}
    undefined: set = set()
    conflict: set = set()
    for entry in entries:
        if isinstance(entry, dict):
            _scan_tokens(_tokens(entry), defined, undefined, conflict)
    # Drop conflicting symbols — defined in one TU, undefined in another →
    # genuinely config-dependent project-wide, so not safe to resolve.
    for name in conflict:
        defined.pop(name, None)
        undefined.discard(name)
    if not defined and not undefined:
        return MacroConfig(source="compile_commands.json")
    return MacroConfig(defined=defined, undefined=frozenset(undefined),
                       source="compile_commands.json")


def _from_kconfig(path: Path) -> MacroConfig:
    text = path.read_text(errors="replace")
    defined: Dict[str, str] = {}
    undefined: set = set()
    for m in re.finditer(r"^(CONFIG_[A-Z0-9_]+)=([ym])\s*$", text, re.MULTILINE):
        defined[m.group(1)] = "1"
    for m in re.finditer(r"^#\s*(CONFIG_[A-Z0-9_]+)\s+is\s+not\s+set\s*$",
                         text, re.MULTILINE):
        # A CONFIG_X set to =y elsewhere wins (shouldn't happen in a real
        # .config, but be deterministic): only mark undefined if not defined.
        if m.group(1) not in defined:
            undefined.add(m.group(1))
    if not defined and not undefined:
        return MacroConfig(source="kconfig")
    return MacroConfig(defined=defined, undefined=frozenset(undefined),
                       source="kconfig")


def _find_compile_commands(target: Path) -> Optional[Path]:
    for c in (target / "compile_commands.json",
              target / "build" / "compile_commands.json"):
        if c.is_file():
            return c
    return None


def extract_macro_config(target: Path) -> MacroConfig:
    """Probe ``target`` for an explicit macro-definition config.

    Priority: ``compile_commands.json`` (per-TU ``-D``/``-U``), then
    ``.config`` (kernel ``CONFIG_*``). First non-empty wins. Returns an
    empty :class:`MacroConfig` when nothing recognizable is present.
    """
    target = Path(target)
    if not target.is_dir():
        return MacroConfig()

    cc = _find_compile_commands(target)
    if cc is not None:
        try:
            mc = _from_compile_commands(cc)
            if mc:
                return mc
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            logger.debug("compile_commands.json macro parse failed: %s", exc)

    kconfig = target / ".config"
    if kconfig.is_file():
        try:
            mc = _from_kconfig(kconfig)
            if mc:
                return mc
        except OSError as exc:
            logger.debug(".config macro parse failed: %s", exc)

    return MacroConfig()


__all__ = ["MacroConfig", "extract_macro_config"]
