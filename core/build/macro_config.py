"""Extract a *macro definition config* — the preprocessor symbols a build is
known to define or leave undefined — for config-aware ``#ifdef`` resolution.

This is deliberately an ALLOWLIST, not a guess. A symbol is reported as
known-defined or known-undefined ONLY when a build artifact says so
explicitly:

  * ``compile_commands.json`` — ``-DNAME[=val]`` (defined) / ``-UNAME``
    (undefined), unioned across translation units. A symbol that is BOTH
    defined and undefined across entries is config-dependent project-wide,
    so it is dropped (left unknown).
  * ``.config`` (kernel Kconfig) — ``CONFIG_X=y`` (defined to "1") /
    ``CONFIG_X=m`` (defines ``CONFIG_X_MODULE``; ``CONFIG_X`` itself is
    undefined, matching autoconf.h) / ``# CONFIG_X is not set``
    (undefined). Applies to ``CONFIG_*`` only.

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
    ``OSError``), ``O_NONBLOCK`` keeps a FIFO from blocking ``open``
    itself (a writer-less FIFO otherwise hangs the unsandboxed parent
    BEFORE the fstat gate can refuse it), the ``fstat`` gate refuses
    non-regular files and enforces the byte budget BEFORE any read,
    and the bounded read re-checks the cap in case the file grew in
    between. ``O_NONBLOCK`` has no effect on regular-file reads.
    Raises ``OSError`` or ``ValueError`` on violation — every caller
    already degrades on those.
    """
    fd = os.open(
        str(path),
        os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC
        | getattr(os, "O_NONBLOCK", 0),
    )
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
# ASCII identifier class: C preprocessor macro names are ASCII; a
# Unicode-wide \w accumulated spellings the preprocessor never joins
# on (fail-safe direction, but noise in the allowlist).
_D_INLINE = re.compile(r"^-D(\w+)(?:=(.*))?$", re.ASCII)
_U_INLINE = re.compile(r"^-U(\w+)$", re.ASCII)


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
            m = re.match(r"^(\w+)(?:=(.*))?$", tokens[i], re.ASCII)
            if m:
                name, val = m.group(1), m.group(2)
        elif tok == "-U" and i + 1 < n:
            i += 1
            if re.match(r"^\w+$", tokens[i], re.ASCII):
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
                # -DNAME → "1" (C semantics); -DNAME= → the EMPTY
                # string — recording "1" made value_of() misread an
                # explicitly-empty macro as truthy.
                defined[name] = "1" if val is None else val
        i += 1


def _from_compile_commands(path: Path) -> MacroConfig:
    raw = _read_bounded(path, _MAX_COMPILE_COMMANDS_BYTES)
    if _nests_like_a_bomb(raw):
        logger.warning("deeply nested compile_commands.json at %s — "
                       "refused before parse", path)
        return MacroConfig(source="compile_commands.json")
    try:
        entries = json.loads(raw)
    except (json.JSONDecodeError, ValueError, RecursionError):
        # RecursionError: a nesting bomb past the pre-gate's scan
        # window — same degradation as malformed JSON (the module's
        # never-raises contract; the consumer is the inventory stage).
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


# Kconfig line grammar — ONE home for the pair (build_flags carried a
# byte-identical copy; duplicated grammar is the drift substrate this
# unit's adoption gaps grew from).
_KCONFIG_SET_RE = re.compile(r"^(CONFIG_[A-Z0-9_]+)=([ym])\s*$",
                             re.MULTILINE)
_KCONFIG_NOT_SET_RE = re.compile(
    r"^#\s*(CONFIG_[A-Z0-9_]+)\s+is\s+not\s+set\s*$", re.MULTILINE)


def _from_kconfig(path: Path) -> MacroConfig:
    text = _read_bounded(path, _MAX_KCONFIG_BYTES)
    defined: dict[str, str] = {}
    undefined: set = set()
    for m in _KCONFIG_SET_RE.finditer(text):
        name = m.group(1)
        if m.group(2) == "y":
            defined[name] = "1"
        else:
            # Tristate =m: the kernel's autoconf.h defines only
            # CONFIG_X_MODULE; CONFIG_X itself is undefined in every
            # TU (IS_ENABLED() checks both spellings). Marking
            # CONFIG_X defined here would blank #else / #ifndef arms
            # that the real build compiles — the exact false negative
            # this module's allowlist design exists to prevent.
            defined[name + "_MODULE"] = "1"
            undefined.add(name)
    for m in _KCONFIG_NOT_SET_RE.finditer(text):
        undefined.add(m.group(1))
    # A CONFIG_X seen both defined (=y) and undefined (=m duplicate or
    # "is not set" line) shouldn't happen in a real .config, but be
    # deterministic: defined wins.
    undefined -= set(defined)
    if not defined and not undefined:
        return MacroConfig(source="kconfig")
    return MacroConfig(defined=defined, undefined=frozenset(undefined),
                       source="kconfig")


# Nesting pre-gate for compile_commands.json. A legitimate manifest is
# a flat array of flat dicts (strings / arguments arrays — depth ~3);
# a planted nesting bomb ("[" * 200k) drives the JSON parser into
# RecursionError before any shape check while materialising a
# container per bracket. The gate scans a bounded document prefix so
# its own cost stays linear and small; a bomb buried past the window
# is caught by the RecursionError rows in the parse catch tuples —
# the gate is an early refusal for the common shape, the catch tuple
# is the never-raises guarantee.
_NESTING_SCAN_CHARS = 1_000_000
# Far above any legitimate compile_commands nesting (depth ~3) and far
# below the interpreter recursion limit the parser would otherwise hit.
_MAX_NESTING_DEPTH = 64
_ESCAPE_PAIR_RE = re.compile(r"\\.", re.DOTALL)
_NON_STRUCTURAL_RE = re.compile(r'[^\[\]{}"]+')


def _nests_like_a_bomb(raw: str) -> bool:
    """True when the leading structure nests past ``_MAX_NESTING_DEPTH``.

    C-speed reduction first (drop escape pairs, then every
    non-structural character), then one pass over the surviving
    bracket/quote skeleton with in-string tracking. Correct on
    well-formed JSON; on malformed input either answer is fine —
    the parser's own error (or RecursionError) is caught downstream.
    """
    skeleton = _NON_STRUCTURAL_RE.sub(
        "", _ESCAPE_PAIR_RE.sub("", raw[:_NESTING_SCAN_CHARS]))
    depth = 0
    in_string = False
    for ch in skeleton:
        if ch == '"':
            in_string = not in_string
        elif not in_string:
            if ch in "[{":
                depth += 1
                if depth > _MAX_NESTING_DEPTH:
                    return True
            else:
                depth -= 1
    return False


def _compile_commands_candidates(target: Path) -> list[Path]:
    """Readable ``compile_commands.json`` candidates, priority order.

    CMake convention puts the manifest under ``build/``; bear and
    Bazel at the project root — and the standard clangd layout
    SYMLINKS the root name at the build-dir copy
    (``ln -s build/compile_commands.json .``). The hardened reader
    refuses symlinks at the final component, so a root symlink used
    to zero all three extractors silently: candidate iteration
    stopped at the first ``is_file()`` hit, the O_NOFOLLOW open
    failed with ELOOP, and the fallback candidate was never tried.

    A candidate whose RESOLVED path leaves the (resolved) target tree
    is skipped with an operator-visible INFO — the symlink acceptance
    is an in-tree layout convenience, never a portal to host files.
    Accepted candidates contribute their resolved path, which the
    hardened reader then opens with O_NOFOLLOW intact. Callers
    ITERATE: one candidate failing to read or parse must not veto the
    next (this helper is the one home for the candidate list — it was
    previously duplicated byte-similar in build_flags).
    """
    out: list[Path] = []
    try:
        resolved_target = target.resolve()
    except OSError:
        return out
    for c in (target / "compile_commands.json",
              target / "build" / "compile_commands.json"):
        if not c.is_file():  # follows symlinks; FIFOs/dirs excluded
            continue
        try:
            resolved = c.resolve()
        except OSError:
            continue
        if resolved != c and not resolved.is_relative_to(resolved_target):
            logger.info(
                "compile_commands.json at %s resolves outside the "
                "target (%s) — skipped", c, resolved)
            continue
        out.append(resolved if resolved != c else c)
    return out


def extract_macro_config(target: Path) -> MacroConfig:
    """Probe ``target`` for an explicit macro-definition config.

    Priority: ``compile_commands.json`` (per-TU ``-D``/``-U``), then
    ``.config`` (kernel ``CONFIG_*``). First non-empty wins. Returns an
    empty :class:`MacroConfig` when nothing recognizable is present.
    """
    target = Path(target)
    if not target.is_dir():
        return MacroConfig()

    for cc in _compile_commands_candidates(target):
        try:
            mc = _from_compile_commands(cc)
            if mc:
                return mc
        except (OSError, json.JSONDecodeError, ValueError,
                RecursionError) as exc:
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
    entries = None
    for cc in _compile_commands_candidates(target):
        try:
            raw = _read_bounded(cc, _MAX_COMPILE_COMMANDS_BYTES)
            if _nests_like_a_bomb(raw):
                logger.warning("deeply nested compile_commands.json at %s "
                               "— refused before parse", cc)
                continue
            entries = json.loads(raw)
            break
        except (OSError, json.JSONDecodeError, ValueError,
                RecursionError) as exc:
            logger.debug("compile_commands.json TU-set parse failed: %s",
                         exc)
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
