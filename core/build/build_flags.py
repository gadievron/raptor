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

# Same hardened reader the sibling macro-config extractor uses for the
# identical file set: symlink refused, regular-file only (a FIFO at the
# path would otherwise hang the read), size gate before read. These
# files live inside the scanned repo — never read them unbounded.
from core.build.macro_config import (
    _MAX_COMPILE_COMMANDS_BYTES,
    _MAX_KCONFIG_BYTES,
    _compile_commands_candidates,
    _nests_like_a_bomb,
    _read_bounded,
)

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1

# Makefiles are hand-written and small; generated monsters exist but
# a CFLAGS regex scan over more than this is noise, not signal.
_MAX_MAKEFILE_BYTES = 8 * 1024 * 1024


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

    #: True iff the effective per-command setting makes unused-result
    #: warnings errors (``-Werror=unused-result``, or bare ``-Werror``
    #: without a ``-Wno-error=unused-result`` exception — specificity
    #: beats position, per gcc). When True and source_intel detects
    #: ``__must_check`` on a function, the contract is
    #: compile-enforced; otherwise it's advisory. Across translation
    #: units this reports the most-hardened observed setting.
    werror_unused_result: bool | None = None

    #: Bare ``-Werror`` (no ``=spec``). When True, every warning is an
    #: error unless explicitly excepted.
    werror_all: bool | None = None

    #: Effective ``_FORTIFY_SOURCE`` level: the LAST of conflicting
    #: ``-D_FORTIFY_SOURCE[=N]`` / ``-U_FORTIFY_SOURCE`` per command
    #: line wins, matching the preprocessor (``-U`` and ``=0`` are
    #: level 0 — explicitly disabled, distinct from ``None`` = no
    #: signal). glibc accepts 1,2,3; kernel uses 1. Across translation
    #: units the most-hardened observed level is reported.
    fortify_source_level: int | None = None

    #: One of: "none" (``-fno-stack-protector``) | "weak"
    #: (``-fstack-protector``) | "strong" | "all" | "explicit" | None.
    stack_protector_level: str | None = None

    #: ``False`` iff ``-fno-delete-null-pointer-checks`` observed
    #: (kernel default). ``True`` iff ``-fdelete-null-pointer-checks``
    #: explicit. ``None`` otherwise — default depends on -O level and
    #: compiler version, so we don't assume.
    delete_null_pointer_checks: bool | None = None

    #: Sanitizer names from ``-fsanitize=NAME[,NAME…]`` (comma-split,
    #: deduped, order preserved). Kernel sanitizers via Kconfig also
    #: surface here as ``"kasan"`` / ``"ubsan"`` / etc.
    sanitizers_enabled: tuple[str, ...] = ()

    #: Kernel ``CONFIG_*`` hardening keys observed in ``.config``.
    #: Maps key name → bool (True if ``=y``, False if ``# … is not set``).
    #: Empty when source is not ``kconfig``.
    relevant_configs: tuple[tuple[str, bool], ...] = ()


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

    # 1. compile_commands.json — highest signal. Candidates iterate:
    # a root candidate that fails to read (e.g. the clangd symlink
    # layout) or parse must not veto the build/ fallback.
    for cc_path in _compile_commands_candidates(target):
        try:
            ctx = _from_compile_commands(cc_path)
            # If parse yielded actual signal, use it; else fall through
            if ctx.extraction_confidence != "absent":
                return ctx
        except (OSError, json.JSONDecodeError, ValueError,
                RecursionError) as exc:
            logger.debug("compile_commands.json parse failed: %s", exc)

    # 2. .config — kernel build (reliable for CONFIG_* derived signals)
    kconfig_path = target / ".config"
    if kconfig_path.is_file():
        try:
            ctx = _from_kconfig(kconfig_path)
            if ctx.extraction_confidence != "absent":
                return ctx
        except (OSError, ValueError) as exc:
            logger.debug(".config parse failed: %s", exc)

    # 3. Makefile / Kbuild — best-effort CFLAGS regex. Name set
    # matches make's own lookup (GNUmakefile, makefile, Makefile —
    # the lowercase spelling had drifted out relative to the
    # detector's make entry) plus Kbuild.
    for mf_name in ("GNUmakefile", "makefile", "Makefile", "Kbuild"):
        mf_path = target / mf_name
        if mf_path.is_file():
            try:
                ctx = _from_makefile(mf_path)
                if ctx.extraction_confidence != "absent":
                    return ctx
            except (OSError, ValueError) as exc:
                logger.debug("%s parse failed: %s", mf_name, exc)
                continue

    return BuildFlagsContext()


# =====================================================================
# Source-specific extractors
# =====================================================================

def _from_compile_commands(path: Path) -> BuildFlagsContext:
    """Parse clang-style ``compile_commands.json``.

    Each entry has either a ``command`` string or an ``arguments`` array.
    Every field follows the same two-level rule the stack-protector
    field established:

      * WITHIN one command line, the compiler's own semantics decide
        (last of conflicting flags wins; ``-W(no-)error=<spec>``
        specificity beats bare ``-W(no-)error`` position, per gcc).
      * ACROSS translation units, the documented union is the
        most-hardened observed setting per field (max fortify level,
        werror-enforced over excepted, null-checks-preserved over
        deleted, strongest stack protector). Per-TU gaps are
        per-finding questions, not project posture; a concatenated
        parse instead let ONE TU's flags void or overstate the whole
        project's evidence in both directions.
    """
    raw = _read_bounded(path, _MAX_COMPILE_COMMANDS_BYTES)
    if _nests_like_a_bomb(raw):
        logger.warning("deeply nested compile_commands.json at %s — "
                       "refused before parse", path)
        return BuildFlagsContext(
            source="compile_commands.json",
            extraction_confidence="absent",
        )
    try:
        entries = json.loads(raw)
    except (json.JSONDecodeError, ValueError, RecursionError):
        # RecursionError: a nesting bomb past the pre-gate's scan
        # window degrades like malformed JSON (never-raises contract).
        logger.warning("malformed compile_commands.json at %s", path)
        return BuildFlagsContext(
            source="compile_commands.json",
            extraction_confidence="absent",
        )
    if not isinstance(entries, list) or not entries:
        return BuildFlagsContext(
            source="compile_commands.json",
            extraction_confidence="absent",
        )

    pieces: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if isinstance(entry.get("command"), str):
            pieces.append(entry["command"])
        elif isinstance(entry.get("arguments"), list):
            pieces.append(" ".join(str(a) for a in entry["arguments"]))

    per_tu = [
        _parse_flag_string(piece, source="compile_commands.json",
                           confidence="high")
        for piece in pieces
    ]

    # Most-hardened union per field (see docstring). True is the
    # hardened direction for the werror fields; for
    # delete_null_pointer_checks it is False (null checks PRESERVED —
    # the kernel-hardening setting).
    fortify_levels = [c.fortify_source_level for c in per_tu
                      if c.fortify_source_level is not None]
    fortify = max(fortify_levels) if fortify_levels else None
    werror_unused = _bool_union(
        (c.werror_unused_result for c in per_tu), hardened=True)
    werror_all = _bool_union(
        (c.werror_all for c in per_tu), hardened=True)
    dnpc = _bool_union(
        (c.delete_null_pointer_checks for c in per_tu), hardened=False)
    stack_levels = {c.stack_protector_level for c in per_tu}
    stack_levels.discard(None)
    stack = next(
        (lvl for lvl in _STACK_PROTO_ORDER if lvl in stack_levels), None)
    sanitizers: list[str] = []
    for c in per_tu:
        for tok in c.sanitizers_enabled:
            if tok not in sanitizers:
                sanitizers.append(tok)

    no_signal = (
        werror_unused is None and werror_all is None
        and fortify is None and stack is None and dnpc is None
        and not sanitizers
    )
    if no_signal:
        return BuildFlagsContext(
            source="compile_commands.json",
            extraction_confidence="absent",
        )
    return BuildFlagsContext(
        source="compile_commands.json",
        extraction_confidence="high",
        werror_unused_result=werror_unused,
        werror_all=werror_all,
        fortify_source_level=fortify,
        stack_protector_level=stack,
        delete_null_pointer_checks=dnpc,
        sanitizers_enabled=tuple(sanitizers),
    )


def _bool_union(values, *, hardened: bool) -> bool | None:
    """Most-hardened union of per-command tri-state observations:
    the *hardened* value wins when any command observed it, else the
    other explicit value, else no signal."""
    seen = {v for v in values if v is not None}
    if not seen:
        return None
    return hardened if hardened in seen else (not hardened)


# Kernel hardening / sanitizer keys recognised in ``.config``.
#
# Provenance (the credential_env source/transcribed discipline —
# a universe with no named mechanical source thins silently as the
# kernel renames options): transcribed 2026-09-22 from the kernel's
# own option homes — security/Kconfig.hardening (stackleak /
# init-on-alloc / zero-init / randstruct), lib/Kconfig.kasan /
# .kcsan / .kmsan / .kfence, arch Kconfig (CFI_CLANG,
# SHADOW_CALL_STACK, STRICT_KERNEL_RWX, RANDOMIZE_BASE,
# PAGE_TABLE_ISOLATION). Version notes are per-row; the unit suite
# pins the modern spellings in both .config directions so a deletion
# here fails there. Absent keys are the conservative direction (no
# signal, never "disabled") — the cost of staleness is silently
# THINNER Stage-D mitigation evidence on modern kernels, which is
# exactly why the transcription is stamped.
_HARDENING_CONFIGS: tuple[str, ...] = (
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
    "CONFIG_KMSAN",                  # kernel >= 6.1
    "CONFIG_KCSAN",                  # kernel >= 5.8
    "CONFIG_KFENCE",                 # kernel >= 5.12
    "CONFIG_RANDOMIZE_BASE",
    "CONFIG_PAGE_TABLE_ISOLATION",
    "CONFIG_GCC_PLUGIN_STRUCTLEAK",
    "CONFIG_GCC_PLUGIN_LATENT_ENTROPY",
    # randstruct: the GCC_PLUGIN_ spelling is < 5.19; 5.19 moved the
    # choice to RANDSTRUCT_FULL / RANDSTRUCT_PERFORMANCE (Clang can
    # provide it too, so the plugin prefix was dropped). Carrying only
    # the old spelling meant every modern .config yielded NO
    # randstruct signal.
    "CONFIG_GCC_PLUGIN_RANDSTRUCT",  # kernel < 5.19
    "CONFIG_RANDSTRUCT_FULL",        # kernel >= 5.19
    "CONFIG_RANDSTRUCT_PERFORMANCE",  # kernel >= 5.19
    "CONFIG_INIT_STACK_ALL_ZERO",    # kernel >= 5.9
    "CONFIG_CFI_CLANG",              # kernel >= 5.13
    "CONFIG_SHADOW_CALL_STACK",      # kernel >= 5.8
    "CONFIG_STRICT_KERNEL_RWX",      # kernel >= 4.11
    # Removed from kernels >= 5.5 (folded into refcount_t proper);
    # kept for the older trees still routinely scanned.
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
    text = _read_bounded(path, _MAX_KCONFIG_BYTES)
    configs: dict[str, bool] = {}

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
    stack_proto: str | None = None
    if configs.get("CONFIG_STACK_PROTECTOR_STRONG"):
        stack_proto = "strong"
    elif configs.get("CONFIG_STACK_PROTECTOR"):
        stack_proto = "weak"

    # Sanitizers active (the full Kconfig sanitizer family — a
    # KMSAN/KFENCE-instrumented kernel used to report
    # sanitizers_enabled=()).
    sanitizers: list[str] = []
    for key, name in (
        ("CONFIG_KASAN", "kasan"),
        ("CONFIG_KMSAN", "kmsan"),
        ("CONFIG_KCSAN", "kcsan"),
        ("CONFIG_KFENCE", "kfence"),
        ("CONFIG_UBSAN", "ubsan"),
        ("CONFIG_KCOV", "kcov"),
    ):
        if configs.get(key):
            sanitizers.append(name)

    # Kernel FORTIFY_SOURCE doesn't tier — present means enabled.
    fortify: int | None = 1 if configs.get("CONFIG_FORTIFY_SOURCE") else None

    return BuildFlagsContext(
        source="kconfig",
        extraction_confidence="best_effort",
        stack_protector_level=stack_proto,
        sanitizers_enabled=tuple(sanitizers),
        fortify_source_level=fortify,
        relevant_configs=tuple(sorted(configs.items())),
    )


# Horizontal-only indent — the MULTILINE ^\s* idiom is quadratic
# on blank-line runs in scanned Makefiles. Assignment operators cover
# the full GNU make family: = += ?= := ::= and the 4.4 immediate
# :::= (the missing modern spellings dropped whole CFLAGS lines).
_CFLAGS_LINE_RE = re.compile(
    r"^[^\S\n]*(?:override\s+)?"
    r"(?:CFLAGS|CXXFLAGS|CPPFLAGS|COMMON_FLAGS|EXTRA_CFLAGS|"
    r"KBUILD_CFLAGS|HOSTCFLAGS|HOSTCXXFLAGS|TARGET_CFLAGS|AM_CFLAGS)"
    r"\s*(?:\+|\?|:{1,3})?=\s*(.+?)$",
    re.MULTILINE,
)

# Backslash-newline continuations join before the line scan (make
# splices them with a single space) — a CFLAGS assignment continued
# across lines used to contribute only its first physical line.
_MAKE_CONTINUATION_RE = re.compile(r"\\\n[ \t]*")


def _from_makefile(path: Path) -> BuildFlagsContext:
    """Regex best-effort scan of Makefile CFLAGS-family assignments.

    Handles GNU make assignment operators (``=``, ``+=``, ``:=``,
    ``?=``) and the common variants (``EXTRA_CFLAGS``,
    ``KBUILD_CFLAGS``, etc.). Does NOT resolve ``$(VAR)`` references
    or follow ``include`` directives — confidence is ``best_effort``
    accordingly.
    """
    text = _MAKE_CONTINUATION_RE.sub(
        " ", _read_bounded(path, _MAX_MAKEFILE_BYTES))
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


def _fortify_from_text(text: str) -> int | None:
    """Effective ``_FORTIFY_SOURCE`` of ONE command line, last-wins.

    The preprocessor honours the LAST of conflicting ``-D``/``-U``
    for a macro. First-match / any-``-U``-voids misread both real
    idioms: the distro reset-then-set
    (``-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3`` → 3) lost its signal,
    and set-then-disable (``-D_FORTIFY_SOURCE=3 -D_FORTIFY_SOURCE=0``
    → gcc-effective 0) OVERSTATED hardening on an unhardened build.
    ``-U`` at the end is level 0 (explicitly off); ``None`` = no
    mention at all.
    """
    last: tuple[int, int] | None = None
    for m in _FORTIFY_UNDEF_RE.finditer(text):
        if last is None or m.start() > last[0]:
            last = (m.start(), 0)
    for m in _FORTIFY_LEVEL_RE.finditer(text):
        if last is None or m.start() > last[0]:
            last = (m.start(), int(m.group(1)))
    for m in _FORTIFY_BARE_RE.finditer(text):
        if last is None or m.start() > last[0]:
            last = (m.start(), 1)
    return last[1] if last else None


_WERROR_BARE_ON_RE = re.compile(r"(?:^|\s)-Werror(?=\s|$)")
_WERROR_BARE_OFF_RE = re.compile(r"(?:^|\s)-Wno-error(?=\s|$)")
_WERROR_UR_ON_RE = re.compile(r"(?:^|\s)-Werror=unused-result(?=\s|$)")
_WERROR_UR_OFF_RE = re.compile(r"(?:^|\s)-Wno-error=unused-result(?=\s|$)")


def _last_flag_polarity(
    text: str,
    on_re: re.Pattern,
    off_re: re.Pattern,
    *,
    on_value: bool = True,
) -> bool | None:
    """Polarity of the LAST of two conflicting flags in ONE command
    (gcc applies the later of an on/off pair), ``None`` when neither
    appears."""
    last: tuple[int, bool] | None = None
    for m in on_re.finditer(text):
        if last is None or m.start() > last[0]:
            last = (m.start(), on_value)
    for m in off_re.finditer(text):
        if last is None or m.start() > last[0]:
            last = (m.start(), not on_value)
    return last[1] if last else None


def _werror_unused_result_from_text(text: str) -> bool | None:
    """unused-result enforcement of ONE command line.

    gcc resolves ``-W(no-)error=<spec>`` against bare
    ``-W(no-)error`` by SPECIFICITY, independently of position; among
    equally-specific spellings the later wins.
    """
    specific = _last_flag_polarity(
        text, _WERROR_UR_ON_RE, _WERROR_UR_OFF_RE)
    if specific is not None:
        return specific
    return _last_flag_polarity(
        text, _WERROR_BARE_ON_RE, _WERROR_BARE_OFF_RE)


_DNPC_ON_RE = re.compile(r"-fdelete-null-pointer-checks(?:\s|$)")
_DNPC_OFF_RE = re.compile(r"-fno-delete-null-pointer-checks(?:\s|$)")
_STACK_PROTO_RE = re.compile(
    r"-fstack-protector(?:-(strong|all|explicit))?(?:\s|$)"
)

# Hardening order for the strongest-observed union across TUs (GCC
# semantics: -all guards every function, -strong the risky ones, the
# bare flag a narrower set, -explicit only attributed functions).
_STACK_PROTO_ORDER: tuple[str, ...] = (
    "all", "strong", "weak", "explicit", "none",
)

_STACK_PROTO_OFF_RE = re.compile(r"-fno-stack-protector(?:\s|$)")


def _stack_protector_from_text(text: str) -> str | None:
    """Stack-protector level of ONE command line, last-flag-wins.

    GCC applies the last of conflicting -fstack-protector*/-fno-
    stack-protector flags; "any -fno- anywhere dominates" misread a
    command that disables and then re-enables the protector.
    """
    last: tuple[int, str] | None = None
    for m in _STACK_PROTO_OFF_RE.finditer(text):
        if last is None or m.start() > last[0]:
            last = (m.start(), "none")
    for m in _STACK_PROTO_RE.finditer(text):
        if last is None or m.start() > last[0]:
            last = (m.start(), m.group(1) or "weak")
    return last[1] if last else None
_SANITIZE_RE = re.compile(r"-fsanitize=([a-zA-Z0-9_,-]+)")


def _parse_flag_string(
    text: str,
    *,
    source: str,
    confidence: str,
) -> BuildFlagsContext:
    """Scan ONE command line (or one accumulated CFLAGS stream — make
    concatenates, so the compiler sees the flags in this order) for
    known hardening tokens. Conflicting flags resolve like the
    compiler resolves them: last wins, except gcc's
    specificity-beats-position rule for ``-W(no-)error=<spec>``.
    Cross-command union is the CALLER's job (see
    ``_from_compile_commands``)."""

    # -- Werror handling -------------------------------------------------
    werror_unused_result = _werror_unused_result_from_text(text)
    werror_all = _last_flag_polarity(
        text, _WERROR_BARE_ON_RE, _WERROR_BARE_OFF_RE)
    if werror_all is False:
        # Bare -Wno-error only demotes; "everything is an error" was
        # never observed enabled — no signal rather than False.
        werror_all = None

    # -- _FORTIFY_SOURCE -------------------------------------------------
    fortify_source_level = _fortify_from_text(text)

    # -- Stack protector -------------------------------------------------
    stack_protector_level = _stack_protector_from_text(text)

    # -- delete-null-pointer-checks --------------------------------------
    delete_null_pointer_checks = _last_flag_polarity(
        text, _DNPC_ON_RE, _DNPC_OFF_RE)

    # -- Sanitizers ------------------------------------------------------
    sanitizers: list[str] = []
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
