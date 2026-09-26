"""Normalized cross-format binary facts — the aggregation layer over
the per-format shallow extractors.

One record shape for the three facts tiers so consumers (the
/describe target block, the manifest's per-kind facts arms, future
artifact-ledger rows) read ONE vocabulary instead of three:

- ELF     → :func:`core.binary.elf.extract_elf_facts` +
  :func:`core.binary.elf.parse_elf`
- PE      → :func:`core.binary.pe.extract_pe_facts`
- Mach-O  → :func:`packages.binary_analysis.macho.extract_macho_facts`

This layer AGGREGATES; it never re-parses. Every byte-level judgment
(bounds, caps, hostile-input degradation) lives in the landed
extractors — this module only maps their records into the shared
shape and derives a handful of cross-format verdict-free summaries
(``stripped``, the ``mitigations`` map). Field-level honesty rules:

- a fact the format tier cannot answer is ``None`` (never a
  fabricated False) — e.g. ``safeseh`` on PE32+, ``stripped`` on an
  ELF whose facts tier carries no symtab view;
- capped name lists keep honest COUNTS beside them, mirroring the
  extractors' own convention;
- ``caps_hit`` is the union of the underlying extraction's markers
  plus this layer's own retention markers.

Hostile-input contract (principle 9): every string field originating
in the parsed file (section names, library names, debug references)
is attacker-controlled text — length-capped at capture by the
extractors, carried here AS DATA, never escaped in this module;
``to_dict`` stamps ``derived_from_target: true`` so every renderer
knows to escape per the ``core.security.log_sanitisation`` contract
before terminal / report / prompt use.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Names retained on the normalized record per list (sections /
# linked libraries). The underlying extractors already bound their
# own retention; this cap bounds the RENDER-FACING record — a
# 4096-section crafted PE must not hand every consumer of the
# normalized shape a 4096-row list when the honest count field
# already carries the magnitude. 64 covers every real binary's
# section table and the linkage of all but the most plugin-heavy
# images (whose overflow is exactly what the count field is for);
# lower would trim real linkage from the visible list, higher only
# re-fans attacker text into every renderer.
_MAX_NAME_LIST = 64

# PE optional-header degradation markers (set by the extractor):
# under any of these, an unset DllCharacteristics bit or an empty
# data-directory slot may mean "field never read", not "feature
# absent" — the mapper renders None for such Falses instead of a
# fabricated confident boolean. Trues stay True: the extractor's
# defaults are all False, so a set bit is always an actual decoded
# read. `optional_header_truncated` is per-field at the extractor
# (a truncated data-dir tail can coexist with a fully-read
# DllCharacteristics); collapsing to None on ANY of the three is
# deliberately conservative — losing a real False to "unknown" is
# honest, the reverse is fabrication.
_PE_OPT_DEGRADED = ("optional_header_missing",
                    "optional_header_truncated",
                    "optional_magic_unknown")

# Mach-O stack-canary mitigation key derivation: the scan is
# name-presence evidence (see macho.MachOSliceFacts docs) — True =
# a canary symbol name is present, False = a scannable symtab was
# read completely and carried none, None = no symtab / degraded
# scan (markers say which). A capped or unreadable scan must not
# render a confident False.
_MACHO_SCAN_MARKERS = ("symtab_strings_capped",
                       "symtab_strings_unreadable")


@dataclass
class BinaryFormatFacts:
    """One artifact's normalized facts (for fat Mach-O: one SLICE —
    ``fat_slice_count`` says how many the container declares).

    ``mitigations`` maps per-format mitigation names to tri-state
    booleans (True/False = evidence-backed claim, None = not
    derivable at this tier). Keys are format-specific by design —
    inventing a cross-format "nx" would launder DEP, MH_ALLOW_STACK_
    EXECUTION and PT_GNU_STACK into one lossy bit.

    ``arch`` carries each extractor's native vocabulary unmapped
    (ELF e_machine names, PE machine names, Mach-O cputype names) —
    mixed granularity by design: "x86" means what the format tier
    said, and inventing a cross-format normalisation here would be a
    second arch vocabulary for consumers to drift against.

    ``entrypoint`` is format-native too: a PE value is the
    AddressOfEntryPoint RVA; a Mach-O value is the LC_MAIN ``entryoff``
    FILE OFFSET. Consumers must not compare them across formats.
    ELF stays None (the ELF facts tier carries no e_entry).
    """

    binary_format: str            # "elf" | "pe" | "macho"
    arch: str = "unknown"
    bits: int = 0
    endianness: str = ""
    size_bytes: int = 0
    section_count: int = 0
    section_names: list[str] = field(default_factory=list)
    linked_libraries: list[str] = field(default_factory=list)
    linked_library_count: int = 0
    import_count: int | None = None
    export_count: int | None = None
    entrypoint: int | None = None
    mitigations: dict[str, bool | None] = field(default_factory=dict)
    # True/False = evidence-backed; None = the format tier carries
    # no symbol-table view for this artifact (see each mapper).
    stripped: bool | None = None
    # External debug reference as the format names it: .gnu_debuglink
    # filename (ELF) / pdb basename (PE). Hostile text — escape at
    # render. None where the format's convention is identity-keyed
    # lookup only (Mach-O dSYM via UUID).
    debug_ref: str | None = None
    debug_directory_present: bool | None = None
    # Format-native identity hint (build-id / canonical RSDS
    # identity / LC_UUID hex) — display/correlation only; the
    # authoritative identity is core.binary.identity's front door.
    identity_hint: str | None = None
    fat_slice_count: int = 0      # 0 = not a fat container
    caps_hit: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        # Principle-9 stamp: section/library/debug-ref strings are
        # target bytes — renderers escape before any terminal /
        # report / prompt use.
        out["derived_from_target"] = True
        return out


def extract_format_facts(
    path: Path, *, macho_slice_arch: str | None = None,
) -> BinaryFormatFacts | None:
    """Normalized facts for ``path``, or ``None`` when the file is
    not a recognised ELF/PE/Mach-O or the format extractor refused
    it (their malformed-input contracts hold here — this function
    never raises past itself on file input).

    ``macho_slice_arch`` selects the fat slice to normalize
    (alias-tolerant, per :func:`packages.binary_analysis.macho.
    resolve_requested_slice`); default is the first walked slice.
    """
    p = Path(path)
    try:
        with p.open("rb") as f:
            magic = f.read(4)
        size_bytes = p.stat().st_size
    except OSError:
        return None
    if magic[:4] == b"\x7fELF":
        return _from_elf(p, size_bytes)
    if magic[:2] == b"MZ":
        return _from_pe(p, size_bytes)
    # Lazy import: Mach-O facts live beside the analysis pipeline
    # (precedent: core.binary.identity routes there for slice
    # identity) — hot ELF-only consumers never pay for it.
    try:
        from packages.binary_analysis.macho import (
            FAT_MACHO_MAGICS,
            THIN_MACHO_MAGICS,
        )
    except ImportError:
        return None
    if magic in THIN_MACHO_MAGICS or magic in FAT_MACHO_MAGICS:
        return _from_macho(p, size_bytes, macho_slice_arch)
    return None


def _capped(names: list[str], caps: set[str], marker: str) -> list[str]:
    if len(names) > _MAX_NAME_LIST:
        caps.add(marker)
        return names[:_MAX_NAME_LIST]
    return names


def _from_elf(p: Path, size_bytes: int) -> BinaryFormatFacts | None:
    from core.binary.elf import extract_elf_facts, parse_elf
    facts = extract_elf_facts(p)
    if facts is None:
        return None
    meta = parse_elf(p)
    caps = set(facts.caps_hit)
    section_names = _capped(
        [s.name for s in facts.section_entropy],
        caps, "facts_section_names_capped")
    libs = _capped(list(facts.needed), caps, "facts_libraries_capped")
    return BinaryFormatFacts(
        binary_format="elf",
        arch=meta.arch if meta else "unknown",
        bits=meta.bits if meta else 0,
        endianness=meta.endianness if meta else "",
        size_bytes=size_bytes,
        section_count=len(facts.section_entropy),
        section_names=section_names,
        linked_libraries=libs,
        linked_library_count=len(facts.needed),
        import_count=len(meta.imports) if meta else None,
        export_count=len(facts.exports),
        # The ELF facts tier deliberately carries no e_entry and no
        # .symtab view (exports come from .dynsym): entrypoint and
        # stripped-ness stay None rather than fabricating either.
        entrypoint=None,
        # ELF mitigation posture (RELRO/canary/fortify) belongs to
        # the exploit-feasibility tier, which reads program headers
        # and relocations this facts tier deliberately does not.
        mitigations={},
        stripped=None,
        debug_ref=facts.debuglink,
        debug_directory_present=None,
        identity_hint=facts.build_id,
        caps_hit=sorted(caps),
    )


def _from_pe(p: Path, size_bytes: int) -> BinaryFormatFacts | None:
    from core.binary.pe import extract_pe_facts
    facts = extract_pe_facts(p)
    if facts is None:
        return None
    caps = set(facts.caps_hit)
    lib_names = [dll.name for dll in facts.imports if dll.name]
    lib_names += [dll.name for dll in facts.delay_imports if dll.name]
    libs = _capped(lib_names, caps, "facts_libraries_capped")
    section_names = _capped(
        [s.name for s in facts.sections],
        caps, "facts_section_names_capped")
    export_count: int | None = None
    if facts.exports is not None:
        export_count = (len(facts.exports.named)
                        + len(facts.exports.ordinal_only))

    # Tri-state honesty under a degraded optional header (see
    # _PE_OPT_DEGRADED): a True flag is a decoded read either way;
    # a False may be an unread default — render None.
    opt_degraded = any(m in caps for m in _PE_OPT_DEGRADED)

    def _flag(value: bool) -> bool | None:
        if value:
            return True
        return None if opt_degraded else False

    debug_dir_present = _flag(facts.debug_directory_present)
    # "Stripped" = no debug references AT ALL (no debug directory,
    # no COFF symbol table). A recorded COFF symbol table settles it
    # False regardless of optional-header health; an absent debug
    # directory only counts as evidence when its data-dir slot was
    # actually readable.
    stripped: bool | None
    if facts.coff_symbol_count > 0 or debug_dir_present is True:
        stripped = False
    elif debug_dir_present is None:
        stripped = None
    else:
        stripped = True

    # AddressOfEntryPoint == 0 is a legitimate value (a DLL with no
    # entry) — it only becomes "unknown" when the optional header
    # never yielded the field.
    entrypoint: int | None = facts.entrypoint
    if facts.entrypoint == 0 and opt_degraded:
        entrypoint = None

    return BinaryFormatFacts(
        binary_format="pe",
        arch=facts.arch,
        bits=facts.bits,
        endianness="little",          # by format definition
        size_bytes=size_bytes,
        section_count=len(facts.sections),
        section_names=section_names,
        linked_libraries=libs,
        linked_library_count=len(lib_names),
        import_count=sum(dll.thunk_count for dll in facts.imports)
        + sum(dll.thunk_count for dll in facts.delay_imports),
        export_count=export_count,
        entrypoint=entrypoint,
        mitigations={
            "aslr": _flag(facts.aslr),
            "high_entropy_va": _flag(facts.high_entropy_va),
            "dep": _flag(facts.dep),
            "cfg": _flag(facts.cfg),
            # no_seh=1 moots SafeSEH: with SEH disabled image-wide,
            # a registered handler table is irrelevant — read the
            # pair together, never `safeseh` alone.
            "no_seh": _flag(facts.no_seh),
            "stack_cookie": facts.stack_cookie,   # extractor tri-states
            "safeseh": facts.safeseh,             # extractor tri-states
        },
        stripped=stripped,
        debug_ref=facts.pdb_basename,
        debug_directory_present=debug_dir_present,
        identity_hint=facts.debug_identity,
        caps_hit=sorted(caps),
    )


def _from_macho(
    p: Path, size_bytes: int, slice_arch: str | None,
) -> BinaryFormatFacts | None:
    from packages.binary_analysis.macho import extract_macho_facts
    facts = extract_macho_facts(p)
    if facts is None or not facts.slices:
        return None
    item = facts.slices[0]
    if slice_arch is not None:
        # The ONE shared alias-normalised arch match (the same
        # resolution `resolve_requested_slice` applies to analysis
        # slices) — never a private-alias reimplementation here.
        from packages.binary_analysis.macho import match_slice_arch
        matched = match_slice_arch(facts.slices, slice_arch)
        if matched is None:
            return None       # explicit request, no such slice
        item = matched
    caps = set(facts.caps_hit) | set(item.caps_hit)
    libs_all = (list(item.load_dylibs) + list(item.weak_dylibs)
                + list(item.reexport_dylibs))
    libs = _capped(libs_all, caps, "facts_libraries_capped")
    lib_count = sum(item.dylib_counts.values())
    section_names = _capped(
        [f"{seg.name},{sec.name}" for seg in item.segments
         for sec in seg.sections],
        caps, "facts_section_names_capped")
    nsyms = item.symtab.get("nsyms")
    stripped: bool | None = None
    if item.symtab:
        # nsyms == 0 is the fully-stripped shape; a populated table
        # with zero LOCAL symbols is the `strip -x` shape. Header
        # claims either way — like every fact at this tier.
        nlocal = item.dysymtab.get("nlocalsym")
        stripped = (nsyms == 0
                    or (nsyms is not None and nsyms > 0
                        and nlocal == 0))
    canary: bool | None
    if item.stack_canary_symbols:
        canary = True
    elif item.symtab and not any(
            m in item.caps_hit for m in _MACHO_SCAN_MARKERS):
        canary = False
    else:
        canary = None     # no symtab, or a degraded scan window
    return BinaryFormatFacts(
        binary_format="macho",
        arch=item.arch,
        bits=item.bits,
        endianness=item.endianness,
        size_bytes=size_bytes,
        section_count=sum(len(seg.sections) for seg in item.segments),
        section_names=section_names,
        linked_libraries=libs,
        linked_library_count=lib_count,
        import_count=item.dysymtab.get("nundefsym"),
        export_count=item.dysymtab.get("nextdefsym"),
        # LC_MAIN entryoff — a FILE OFFSET, not an RVA (see the
        # field docs; PE's value is the AddressOfEntryPoint RVA).
        entrypoint=item.entry_offset,
        mitigations={
            "pie": item.pie,
            "allow_stack_execution": item.allow_stack_execution,
            "no_heap_execution": item.no_heap_execution,
            "stack_canary": canary,
        },
        stripped=stripped,
        debug_ref=None,           # dSYM lookup is UUID-keyed
        debug_directory_present=None,
        identity_hint=item.uuid,
        fat_slice_count=facts.declared_slices if facts.is_fat else 0,
        caps_hit=sorted(caps),
    )


__all__ = ["BinaryFormatFacts", "extract_format_facts"]
