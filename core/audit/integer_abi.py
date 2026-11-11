"""Target integer layouts and explicitly labelled host analysis assumptions.

Only audit entry points select a host default. Low-level proof consumers
still require a resolved layout, and never guess one from repository text.
"""

from dataclasses import replace
from typing import Any, Literal, cast
from core.smt_solver.integer_abi import (
    INTEGER_ABIS as INTEGER_ABIS, IntegerABI as IntegerABI,
    IntegerABIInput as IntegerABIInput, resolve_integer_abi as resolve_integer_abi,
    integer_abi_record as integer_abi_record, integer_abi_key as integer_abi_key,
)
from pathlib import Path
from core.source.streams import preserving_stream_error


def host_integer_abi() -> IntegerABI | None:
    """Measure the analysis process's native C layout, never the target's.

    ctypes measures the C ABI of this Python process without invoking a
    project compiler, executing target code, or trusting ambient CC flags.
    Unsupported representations remain unknown.
    """
    import sys
    try:
        import ctypes
    except ImportError:
        return None

    types = (ctypes.c_byte, ctypes.c_short, ctypes.c_int,
             ctypes.c_long, ctypes.c_longlong)
    widths = cast(tuple[int, int, int, int, int],
                  tuple(ctypes.sizeof(kind) * 8 for kind in types))
    if any(width not in {8, 16, 32, 64} for width in widths):
        return None
    # Check the representation we model instead of silently assuming that
    # every host has padding-free two's-complement signed integers.
    for kind, width in zip(types, widths):
        for value in (-1, -(1 << (width - 1)), (1 << (width - 1)) - 1):
            if bytes(kind(value)) != value.to_bytes(width // 8, sys.byteorder, signed=True):
                return None
    profile = next((abi.name for abi in INTEGER_ABIS.values()
                    if (abi.char_bits, abi.short_bits, abi.int_bits,
                        abi.long_bits, abi.long_long_bits) == widths), "custom")
    if profile == "ilp32" and ctypes.sizeof(ctypes.c_void_p) == 8:
        profile = "llp64"
    try:
        return IntegerABI(f"host-{profile}", *widths,
                          "twos-complement-no-padding", source="host-assumption")
    except ValueError:
        return None


def binary_integer_abi(target_path: Path) -> IntegerABI | None:
    """Resolve standard C data models from supported binary platforms.

    Reuse the bounded format parsers; never execute the artifact. A header
    identifies a platform ABI, not arbitrary compiler flags or source types.
    Ambiguous formats/platforms and universal Mach-O stay unknown rather
    than borrowing the analysis host's layout.
    """
    from core.source.gated import open_regular_gated

    try:
        with preserving_stream_error(open_regular_gated(target_path)) as handle:
            header = handle.read(64)
    except (OSError, ValueError):
        return None
    profile = None
    binary_format = ""
    if header[:4] == b"\x7fELF":
        from core.binary.elf import parse_elf
        meta = parse_elf(target_path)
        # System V/Linux, NetBSD, Solaris, FreeBSD and OpenBSD conventions.
        # Unknown OS ABIs and architectures can use different C data models.
        if meta is not None and len(header) >= 20 and header[7] in {0, 2, 3, 6, 9, 12}:
            machine = int.from_bytes(header[18:20], cast(Literal["little", "big"], meta.endianness))
            platform_bits = {
                2: {32},           # SPARC
                3: {32},           # i386
                8: {32, 64},       # MIPS
                10: {32},          # MIPS RS3 LE
                20: {32},          # PowerPC
                21: {64},          # PowerPC64
                22: {32, 64},      # S390
                40: {32},          # ARM
                43: {64},          # SPARC v9
                62: {32, 64},      # x86-64, including x32
                183: {32, 64},     # AArch64, including ILP32
                243: {32, 64},     # RISC-V
            }.get(machine, set())
            if meta.bits in platform_bits:
                profile = "lp64" if meta.bits == 64 else "ilp32"
                binary_format = "elf"
    elif header[:2] == b"MZ":
        from core.binary.pe import extract_pe_facts
        facts = extract_pe_facts(target_path)
        # PE is also used by EFI and non-Windows runtimes. Do not infer the
        # Windows C data model from the PE32+ magic alone.
        if facts is not None and facts.subsystem in {1, 2, 3, 8, 9, 16}:
            expected_bits = {0x014c: 32, 0x01c0: 32, 0x01c2: 32, 0x01c4: 32,
                             0x8664: 64, 0xaa64: 64}.get(facts.machine)
            if expected_bits == facts.bits:
                profile = "llp64" if facts.bits == 64 else "ilp32"
                binary_format = "pe"
    else:
        from packages.binary_analysis.macho import (
            THIN_MACHO_MAGICS, extract_macho_facts,
        )
        if header[:4] in THIN_MACHO_MAGICS:
            macho_facts = extract_macho_facts(target_path)
            if macho_facts is not None and len(macho_facts.slices) == 1:
                item = macho_facts.slices[0]
                expected_bits = {"x86": 32, "arm": 32, "ppc": 32,
                                 "x86_64": 64, "arm64": 64, "ppc64": 64}.get(item.arch)
                if expected_bits == item.bits:
                    profile = "lp64" if item.bits == 64 else "ilp32"
                    binary_format = "macho"
    if profile is None:
        return None
    return replace(INTEGER_ABIS[profile], name=f"binary-{binary_format}-{profile}",
                   source="binary-platform")


def select_integer_abi(
    value: IntegerABIInput, *, target_path: Path | None = None,
) -> str | dict[str, Any]:
    """Freeze an entry-point selection for workers, resume and proof caches.

    Explicit overrides win. Otherwise a binary supplies its platform layout,
    while a source directory uses the measured host assumption. Unknown
    binaries never fall back to the host. The explicit ``unknown`` sentinel
    disables default selection, including when replaying saved options.
    """
    if value == "unknown":
        return "unknown"
    if value is None:
        if target_path is not None and not Path(target_path).is_dir():
            abi = binary_integer_abi(Path(target_path))
        else:
            abi = host_integer_abi()
        return abi.record() if abi is not None else "unknown"
    abi = resolve_integer_abi(value)
    if abi is None:
        raise ValueError("unknown target integer ABI")
    return value if isinstance(value, str) else abi.record()
