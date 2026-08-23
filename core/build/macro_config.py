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
import os
import re
import shlex
import stat
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)

# Byte budgets for the target-controlled build artifacts read below.
# These files live inside the scanned repo, so they are read hardened
# (symlink refused, regular-file only, fstat size gate before read)
# and bounded BEFORE the inventory's own gates ever see the content.
# Very large real-world compile_commands.json (Chromium-scale) are
# ~100 MiB; kernel .config files are a few hundred KiB.
_MAX_COMPILE_COMMANDS_BYTES = 256 * 1024 * 1024
_MAX_KCONFIG_BYTES = 8 * 1024 * 1024


def _read_bounded(path: Path, max_bytes: int) -> str:
    """Hardened read of a target-controlled config file.

    ``O_NOFOLLOW`` refuses a symlink at the final component (ELOOP →
    ``OSError``), the ``fstat`` gate refuses non-regular files and
    enforces the byte budget BEFORE any read, and the bounded read
    re-checks the cap in case the file grew in between. Raises
    ``OSError`` or ``ValueError`` on violation — every caller already
    degrades on those.
    """
    fd = os.open(str(path), os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"not a regular file: {path}")
        if st.st_size > max_bytes:
            raise ValueError(
                f"file size {st.st_size} exceeds {max_bytes} byte cap: "
                f"{path}"
            )
    except BaseException:
        os.close(fd)
        raise
    with os.fdopen(fd, "rb") as f:
        raw = f.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError(f"file grew past {max_bytes} byte cap: {path}")
    return raw.decode("utf-8", errors="replace")


@dataclass(frozen=True)
class MacroConfig:
    """Known-defined / known-undefined preprocessor symbols for one build.

    ``defined`` maps name → value string (``"1"`` for a bare ``-DNAME``).
    ``undefined`` is the set of explicitly-undefined names. A name in
    neither is UNKNOWN — callers must treat unknown as config-dependent
    and leave the arm untouched.
    """

    defined: dict[str, str] = field(default_factory=dict)
    undefined: frozenset = field(default_factory=frozenset)
    source: str = "absent"

    def __bool__(self) -> bool:
        return bool(self.defined or self.undefined)

    def is_defined(self, name: str) -> bool | None:
        """``True`` known-defined, ``False`` known-undefined, ``None``
        unknown (config-dependent / possibly header-defined)."""
        if name in self.defined:
            return True
        if name in self.undefined:
            return False
        return None

    def value_of(self, name: str) -> str | None:
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


def _tokens(entry: dict) -> list[str]:
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


def _scan_tokens(tokens: list[str], defined: dict[str, str],
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
    raw = _read_bounded(path, _MAX_COMPILE_COMMANDS_BYTES)
    try:
        entries = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        logger.warning("malformed compile_commands.json at %s", path)
        return MacroConfig(source="compile_commands.json")
    if not isinstance(entries, list) or not entries:
        return MacroConfig(source="compile_commands.json")
    defined: dict[str, str] = {}
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
    text = _read_bounded(path, _MAX_KCONFIG_BYTES)
    defined: dict[str, str] = {}
    undefined: set = set()
    for m in re.finditer(r"^(CONFIG_[A-Z0-9_]+)=([ym])\s*$", text, re.MULTILINE):
        defined[m.group(1)] = "1" if m.group(2) == "y" else "m"
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


def _find_compile_commands(target: Path) -> Path | None:
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
        except (OSError, ValueError) as exc:
            logger.debug(".config macro parse failed: %s", exc)

    return MacroConfig()


def extract_build_tus(target: Path) -> frozenset | None:
    """Set of absolute translation-unit paths in ``target``'s
    ``compile_commands.json`` (resolved so they match the inventory builder's
    file paths), or ``None`` when there is no parseable, non-empty
    compile_commands.

    ``None`` means build membership is UNKNOWN — the C/C++ build-membership
    witness must not fire (a source absent from an absent/empty manifest tells
    us nothing). Heuristic even when present: a compile_commands may be partial
    (one target, a sub-build), so a source's absence is evidence, not proof —
    the witness it feeds is surface-only.
    """
    target = Path(target)
    if not target.is_dir():
        return None
    cc = _find_compile_commands(target)
    if cc is None:
        return None
    try:
        entries = json.loads(_read_bounded(cc, _MAX_COMPILE_COMMANDS_BYTES))
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        logger.debug("compile_commands.json TU-set parse failed: %s", exc)
        return None
    if not isinstance(entries, list):
        return None
    tus = set()
    for e in entries:
        if not isinstance(e, dict):
            continue
        f = e.get("file")
        if not isinstance(f, str) or not f:
            continue
        p = Path(f)
        d = e.get("directory")
        if not p.is_absolute() and isinstance(d, str):
            p = Path(d) / f
        try:
            tus.add(str(p.resolve()))
        except OSError:
            tus.add(str(p))
    return frozenset(tus) if tus else None


__all__ = ["MacroConfig", "extract_build_tus", "extract_macro_config"]
