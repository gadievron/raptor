"""Extract compiler / build hardening flags from a target's build artifacts.

Source priority:

  1. ``compile_commands.json`` — clang-style; highest signal because it
     records the exact gcc/clang invocation per translation unit.
  2. ``.config`` (Linux kernel ``Kconfig`` output) — well-structured,
     reliable for kernel-config-derived hardening (``CONFIG_FORTIFY_SOURCE``,
     ``CONFIG_STACK_PROTECTOR_STRONG``, ``CONFIG_KASAN`` …).
  3. ``Makefile`` / ``Kbuild`` / ``GNUmakefile`` — regex best-effort on
     ``CFLAGS`` / ``CPPFLAGS`` / ``EXTRA_CFLAGS`` lines. Many real
     Makefiles compute flags or include sub-makefiles we cannot follow;
     we mark this source as ``best_effort``.

The first source that yields a non-empty result wins. When none match,
the returned context has ``extraction_confidence='absent'``.

Hard invariant for consumers: ``extraction_confidence='absent'`` must
never be interpreted as "no hardening" — it means "we could not tell".
Every nullable field is ``None`` by default; only explicit-observation
flips to ``True`` / ``False``.

Two consumers planned at write time:
  * source_intel axis 1 (attribute interpretation — `__must_check`
    is compile-enforced iff ``werror_unused_result`` is True)
  * source_intel axis 6 (build-flags axis — surfaces the structured
    context directly to Stage D LLM evidence)

This module does NOT decide policy — it reports observed signals; the
LLM consumer at Stage D weights them.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1


# =====================================================================
# Public dataclass
# =====================================================================

@dataclass(frozen=True)
class BuildFlagsContext:
    """Hardening flags observed in the target's build configuration.

    Optional[bool] fields use three values:
      * ``True`` — explicitly observed enabled
      * ``False`` — explicitly observed disabled
      * ``None`` — no signal (NOT the same as disabled)
    """

    schema_version: int = SCHEMA_VERSION

    #: One of: "compile_commands.json" | "kconfig" | "makefile" | "absent".
    source: str = "absent"

    #: One of: "high" (compile_commands.json), "best_effort"
    #: (Makefile / Kconfig regex), or "absent".
    extraction_confidence: str = "absent"

    #: True iff ``-Werror=unused-result`` (or bare ``-Werror`` without
    #: a ``-Wno-error=unused-result`` exception) was observed. When
    #: True and source_intel detects ``__must_check`` on a function,
    #: the contract is compile-enforced; otherwise it's advisory.
    werror_unused_result: Optional[bool] = None

    #: Bare ``-Werror`` (no ``=spec``). When True, every warning is an
    #: error unless explicitly excepted.
    werror_all: Optional[bool] = None

    #: Integer level from ``-D_FORTIFY_SOURCE=N``. glibc accepts 1,2,3;
    #: kernel uses 1. ``None`` means not set.
    fortify_source_level: Optional[int] = None

    #: One of: "none" (``-fno-stack-protector``) | "weak"
    #: (``-fstack-protector``) | "strong" | "all" | "explicit" | None.
    stack_protector_level: Optional[str] = None

    #: ``False`` iff ``-fno-delete-null-pointer-checks`` observed
    #: (kernel default). ``True`` iff ``-fdelete-null-pointer-checks``
    #: explicit. ``None`` otherwise — default depends on -O level and
    #: compiler version, so we don't assume.
    delete_null_pointer_checks: Optional[bool] = None

    #: Sanitizer names from ``-fsanitize=NAME[,NAME…]`` (comma-split,
    #: deduped, order preserved). Kernel sanitizers via Kconfig also
    #: surface here as ``"kasan"`` / ``"ubsan"`` / etc.
    sanitizers_enabled: Tuple[str, ...] = ()

    #: Kernel ``CONFIG_*`` hardening keys observed in ``.config``.
    #: Maps key name → bool (True if ``=y``, False if ``# … is not set``).
    #: Empty when source is not ``kconfig``.
    relevant_configs: Tuple[Tuple[str, bool], ...] = ()


# =====================================================================
# Public API
# =====================================================================

def extract_flags(target: Path) -> BuildFlagsContext:
    """Probe ``target`` for build-hardening flag signals.

    Returns a frozen :class:`BuildFlagsContext`. Never raises on
    missing artifacts — non-existent target or no recognizable build
    files produces ``BuildFlagsContext()`` with default values
    (``source='absent'``, ``extraction_confidence='absent'``).
    """
    target = Path(target)
    if not target.is_dir():
        return BuildFlagsContext()

    # 1. compile_commands.json — highest signal
    cc_path = _find_compile_commands(target)
    if cc_path is not None:
        try:
            ctx = _from_compile_commands(cc_path)
            # If parse yielded actual signal, use it; else fall through
            if ctx.extraction_confidence != "absent":
                return ctx
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            logger.debug("compile_commands.json parse failed: %s", exc)

    # 2. .config — kernel build (reliable for CONFIG_* derived signals)
    kconfig_path = target / ".config"
    if kconfig_path.is_file():
        try:
            ctx = _from_kconfig(kconfig_path)
            if ctx.extraction_confidence != "absent":
                return ctx
        except OSError as exc:
            logger.debug(".config parse failed: %s", exc)

    # 3. Makefile / Kbuild — best-effort CFLAGS regex
    for mf_name in ("Makefile", "GNUmakefile", "Kbuild"):
        mf_path = target / mf_name
        if mf_path.is_file():
            try:
                ctx = _from_makefile(mf_path)
                if ctx.extraction_confidence != "absent":
                    return ctx
            except OSError as exc:
                logger.debug("%s parse failed: %s", mf_name, exc)
                continue

    return BuildFlagsContext()


# =====================================================================
# Source-specific extractors
# =====================================================================

def _find_compile_commands(target: Path) -> Optional[Path]:
    """Locate ``compile_commands.json``. CMake convention puts it in
    a build/ subdirectory; Bazel and bear at project root."""
    for candidate in (
        target / "compile_commands.json",
        target / "build" / "compile_commands.json",
    ):
        if candidate.is_file():
            return candidate
    return None


def _from_compile_commands(path: Path) -> BuildFlagsContext:
    """Parse clang-style ``compile_commands.json``.

    Each entry has either a ``command`` string or an ``arguments`` array.
    We union flags across all entries — different translation units may
    have different flags (e.g. some compiled with ``-DCONFIG_KASAN``),
    and we want the most-hardened observed setting per flag.
    """
    raw = path.read_text(errors="replace")
    entries = json.loads(raw)
    if not isinstance(entries, list) or not entries:
        return BuildFlagsContext(
            source="compile_commands.json",
            extraction_confidence="absent",
        )

    pieces: List[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if isinstance(entry.get("command"), str):
            pieces.append(entry["command"])
        elif isinstance(entry.get("arguments"), list):
            pieces.append(" ".join(str(a) for a in entry["arguments"]))
    combined = " ".join(pieces)
    return _parse_flag_string(
        combined,
        source="compile_commands.json",
        confidence="high",
    )


_HARDENING_CONFIGS: Tuple[str, ...] = (
    "CONFIG_FORTIFY_SOURCE",
    "CONFIG_HARDENED_USERCOPY",
    "CONFIG_STACK_PROTECTOR",
    "CONFIG_STACK_PROTECTOR_STRONG",
    "CONFIG_STACK_PROTECTOR_AUTO",
    "CONFIG_KASAN",
    "CONFIG_KASAN_GENERIC",
    "CONFIG_KASAN_SW_TAGS",
    "CONFIG_KASAN_HW_TAGS",
    "CONFIG_UBSAN",
    "CONFIG_KCOV",
    "CONFIG_RANDOMIZE_BASE",
    "CONFIG_PAGE_TABLE_ISOLATION",
    "CONFIG_GCC_PLUGIN_STRUCTLEAK",
    "CONFIG_GCC_PLUGIN_LATENT_ENTROPY",
    "CONFIG_GCC_PLUGIN_RANDSTRUCT",
    "CONFIG_REFCOUNT_FULL",
    "CONFIG_HARDENED_USERCOPY_PAGESPAN",
    "CONFIG_BUG_ON_DATA_CORRUPTION",
)


def _from_kconfig(path: Path) -> BuildFlagsContext:
    """Parse Linux kernel ``.config``. Recognises both forms:

      * ``CONFIG_FOO=y`` / ``CONFIG_FOO=m`` — enabled
      * ``# CONFIG_FOO is not set`` — explicitly disabled

    Returns the kernel-hardening subset only. Derives ``sanitizers_enabled``,
    ``stack_protector_level``, and ``fortify_source_level`` from the
    config bits since the kernel build doesn't surface raw compiler
    flags via this file.
    """
    text = path.read_text(errors="replace")
    configs: Dict[str, bool] = {}

    for m in re.finditer(
        r"^(CONFIG_[A-Z0-9_]+)=([ym])\s*$",
        text,
        re.MULTILINE,
    ):
        key = m.group(1)
        if key in _HARDENING_CONFIGS:
            configs[key] = True

    for m in re.finditer(
        r"^#\s*(CONFIG_[A-Z0-9_]+)\s+is\s+not\s+set\s*$",
        text,
        re.MULTILINE,
    ):
        key = m.group(1)
        if key in _HARDENING_CONFIGS:
            configs[key] = False

    if not configs:
        return BuildFlagsContext(
            source="kconfig",
            extraction_confidence="absent",
        )

    # Stack-protector level — strongest observed wins.
    stack_proto: Optional[str] = None
    if configs.get("CONFIG_STACK_PROTECTOR_STRONG"):
        stack_proto = "strong"
    elif configs.get("CONFIG_STACK_PROTECTOR"):
        stack_proto = "weak"

    # Sanitizers active.
    sanitizers: List[str] = []
    if configs.get("CONFIG_KASAN"):
        sanitizers.append("kasan")
    if configs.get("CONFIG_UBSAN"):
        sanitizers.append("ubsan")
    if configs.get("CONFIG_KCOV"):
        sanitizers.append("kcov")

    # Kernel FORTIFY_SOURCE doesn't tier — present means enabled.
    fortify: Optional[int] = 1 if configs.get("CONFIG_FORTIFY_SOURCE") else None

    return BuildFlagsContext(
        source="kconfig",
        extraction_confidence="best_effort",
        stack_protector_level=stack_proto,
        sanitizers_enabled=tuple(sanitizers),
        fortify_source_level=fortify,
        relevant_configs=tuple(sorted(configs.items())),
    )


_CFLAGS_LINE_RE = re.compile(
    r"^\s*(?:override\s+)?"
    r"(?:CFLAGS|CXXFLAGS|CPPFLAGS|COMMON_FLAGS|EXTRA_CFLAGS|"
    r"KBUILD_CFLAGS|HOSTCFLAGS|HOSTCXXFLAGS|TARGET_CFLAGS|AM_CFLAGS)"
    r"\s*[+:?]?=\s*(.+?)$",
    re.MULTILINE,
)


def _from_makefile(path: Path) -> BuildFlagsContext:
    """Regex best-effort scan of Makefile CFLAGS-family assignments.

    Handles GNU make assignment operators (``=``, ``+=``, ``:=``,
    ``?=``) and the common variants (``EXTRA_CFLAGS``,
    ``KBUILD_CFLAGS``, etc.). Does NOT resolve ``$(VAR)`` references
    or follow ``include`` directives — confidence is ``best_effort``
    accordingly.
    """
    text = path.read_text(errors="replace")
    pieces = [m.group(1) for m in _CFLAGS_LINE_RE.finditer(text)]
    if not pieces:
        return BuildFlagsContext(
            source="makefile",
            extraction_confidence="absent",
        )
    combined = " ".join(pieces)
    return _parse_flag_string(
        combined,
        source="makefile",
        confidence="best_effort",
    )


# =====================================================================
# Flag-string parser (shared by compile_commands and Makefile sources)
# =====================================================================

_FORTIFY_LEVEL_RE = re.compile(r"-D_FORTIFY_SOURCE=(\d+)")
_FORTIFY_BARE_RE = re.compile(r"-D_FORTIFY_SOURCE(?:\s|$)")
_FORTIFY_UNDEF_RE = re.compile(r"-U_FORTIFY_SOURCE(?:\s|$)")
_STACK_PROTO_RE = re.compile(
    r"-fstack-protector(?:-(strong|all|explicit))?(?:\s|$)"
)
_SANITIZE_RE = re.compile(r"-fsanitize=([a-zA-Z0-9_,-]+)")


def _parse_flag_string(
    text: str,
    *,
    source: str,
    confidence: str,
) -> BuildFlagsContext:
    """Scan a command-line / CFLAGS string for known hardening tokens."""

    # -- Werror handling -------------------------------------------------
    # `-Werror=unused-result` enables; `-Wno-error=unused-result` excepts.
    # Bare `-Werror` enables everything. Order: later wins per gcc, but
    # for v1 we treat any presence as the signal — if both are present
    # for unused-result, exception wins (False).
    has_bare_werror = bool(
        re.search(r"(?:^|\s)-Werror(?=\s|$)", text)
    )
    has_specific_werror = "-Werror=unused-result" in text
    has_excepted = "-Wno-error=unused-result" in text

    werror_unused_result: Optional[bool] = None
    if has_excepted:
        werror_unused_result = False
    elif has_specific_werror or has_bare_werror:
        werror_unused_result = True

    werror_all: Optional[bool] = True if has_bare_werror else None

    # -- _FORTIFY_SOURCE -------------------------------------------------
    fortify_source_level: Optional[int] = None
    if _FORTIFY_UNDEF_RE.search(text):
        fortify_source_level = 0
    else:
        m = _FORTIFY_LEVEL_RE.search(text)
        if m:
            fortify_source_level = int(m.group(1))
        elif _FORTIFY_BARE_RE.search(text):
            fortify_source_level = 1

    # -- Stack protector -------------------------------------------------
    stack_protector_level: Optional[str] = None
    if "-fno-stack-protector" in text:
        stack_protector_level = "none"
    else:
        m = _STACK_PROTO_RE.search(text)
        if m:
            stack_protector_level = m.group(1) or "weak"

    # -- delete-null-pointer-checks --------------------------------------
    delete_null_pointer_checks: Optional[bool] = None
    if "-fno-delete-null-pointer-checks" in text:
        delete_null_pointer_checks = False
    elif "-fdelete-null-pointer-checks" in text:
        delete_null_pointer_checks = True

    # -- Sanitizers ------------------------------------------------------
    sanitizers: List[str] = []
    for m in _SANITIZE_RE.finditer(text):
        for tok in m.group(1).split(","):
            tok = tok.strip()
            if tok and tok not in sanitizers:
                sanitizers.append(tok)

    # If we extracted NOTHING, mark absent rather than asserting "no
    # hardening" — the file is present but unparseable / empty.
    no_signal = (
        werror_unused_result is None
        and werror_all is None
        and fortify_source_level is None
        and stack_protector_level is None
        and delete_null_pointer_checks is None
        and not sanitizers
    )
    if no_signal:
        return BuildFlagsContext(
            source=source,
            extraction_confidence="absent",
        )

    return BuildFlagsContext(
        source=source,
        extraction_confidence=confidence,
        werror_unused_result=werror_unused_result,
        werror_all=werror_all,
        fortify_source_level=fortify_source_level,
        stack_protector_level=stack_protector_level,
        delete_null_pointer_checks=delete_null_pointer_checks,
        sanitizers_enabled=tuple(sanitizers),
    )
