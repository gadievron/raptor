"""Single-binary target arm for ``/describe``.

When the operator points ``/describe`` at ONE compiled artifact
(ELF / PE / Mach-O — recognised by format magic, never by
extension), the source-tree shape machinery has nothing to say;
this module renders the normalized format facts instead
(:mod:`core.binary.facts`): format / arch / bits, sections, linked
libraries, import/export counts, the per-format mitigation map,
stripped-ness, debug references, and the identity front door's
canonical identity.

Read-only, like the rest of /describe: the facts extractors parse
bytes; the only subprocess this arm can trigger is the identity
front door's sandboxed ELF build-id probe (the same hardened read
the binary-oracle performs).

Display integrity (principle 9): every target-derived string
(section names, library names, debug references) is hostile text —
the TEXT renderer escapes each one through the
``core.security.log_sanitisation`` contract; the JSON renderer
serialises with ``ensure_ascii`` so control bytes leave as
``\\uXXXX`` escapes, and the payload carries the
``derived_from_target`` stamp from the facts layer.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.binary.facts import BinaryFormatFacts, extract_format_facts
from core.security.log_sanitisation import sanitise_for_terminal

# Names shown on one renderer line (the record itself retains up to
# the facts layer's cap; the honest counts always render).
_SHOWN_NAMES = 8


@dataclass(frozen=True)
class BinaryTargetReport:
    """One binary target's describe view. Pure data; renderers
    consume this."""

    target_path: Path
    facts: BinaryFormatFacts
    identity_kind: str = ""
    identity_value: str = ""


def is_binary_target(path: Path) -> bool:
    """Format-magic probe (never extension): does ``path`` look like
    an artifact the binary describe arm can serve? Mirrors the
    dispatch set of :func:`core.binary.facts.extract_format_facts`;
    unreadable files are not candidates (same contract as the
    per-format ``is_*`` probes)."""
    try:
        with Path(path).open("rb") as f:
            magic = f.read(4)
    except OSError:
        return False
    if magic[:4] == b"\x7fELF" or magic[:2] == b"MZ":
        return True
    try:
        from packages.binary_analysis.macho import (
            FAT_MACHO_MAGICS,
            THIN_MACHO_MAGICS,
        )
    except ImportError:
        return False
    return magic in THIN_MACHO_MAGICS or magic in FAT_MACHO_MAGICS


def build_binary_report(path: Path) -> BinaryTargetReport | None:
    """Facts + identity for one binary, or ``None`` when the format
    extractor refuses the bytes (the caller falls back to its
    existing refusal message)."""
    p = Path(path)
    facts = extract_format_facts(p)
    if facts is None:
        return None
    identity_kind = ""
    identity_value = ""
    try:
        from core.binary.identity import content_identity
        ident = content_identity(p)
        if ident is not None:
            identity_kind, identity_value = ident.kind, ident.value
    except Exception:  # noqa: BLE001 — identity is enrichment only
        pass
    return BinaryTargetReport(
        target_path=p,
        facts=facts,
        identity_kind=identity_kind,
        identity_value=identity_value,
    )


def _esc(text: str) -> str:
    return sanitise_for_terminal(text, max_len=80)


def _names_line(names: list[str], total: int) -> str:
    shown = ", ".join(_esc(name) for name in names[:_SHOWN_NAMES])
    if total > _SHOWN_NAMES:
        shown += ", …"
    return shown


def _tri(value: bool | None) -> str:
    if value is None:
        return "unknown"
    return "yes" if value else "no"


def format_binary_text(report: BinaryTargetReport) -> str:
    """Operator-facing block for one binary target."""
    facts = report.facts
    lines = ["Target analysis:"]
    lines.append(f"  Source: single binary {_esc(report.target_path.name)}")
    fmt = f"{facts.binary_format} {facts.arch}"
    if facts.bits:
        fmt += f" {facts.bits}-bit"
    if facts.endianness:
        fmt += f" {facts.endianness}-endian"
    lines.append(f"  Format: {fmt}")
    if facts.fat_slice_count:
        lines.append(
            f"  Fat container: {facts.fat_slice_count} slice(s) "
            f"declared; facts shown for the first walked slice")
    lines.append(f"  Size: {_short_size(facts.size_bytes)}")
    lines.append(
        f"  Sections: {facts.section_count}"
        + (f" ({_names_line(facts.section_names, facts.section_count)})"
           if facts.section_names else ""))
    lines.append(
        f"  Linked libraries: {facts.linked_library_count}"
        + (f" ({_names_line(facts.linked_libraries, facts.linked_library_count)})"
           if facts.linked_libraries else ""))
    counts = []
    if facts.import_count is not None:
        counts.append(f"imports {facts.import_count}")
    if facts.export_count is not None:
        counts.append(f"exports {facts.export_count}")
    if counts:
        lines.append(f"  Symbols: {', '.join(counts)}")
    if facts.mitigations:
        rendered = ", ".join(
            f"{key} {_tri(value)}"
            for key, value in facts.mitigations.items())
        lines.append(f"  Mitigations: {rendered}")
    lines.append(f"  Stripped: {_tri(facts.stripped)}")
    if facts.debug_ref:
        lines.append(f"  Debug reference: {_esc(facts.debug_ref)}")
    if report.identity_kind:
        lines.append(
            f"  Identity: {report.identity_kind} "
            f"{_esc(report.identity_value)}")
    elif facts.identity_hint:
        lines.append(f"  Identity hint: {_esc(facts.identity_hint)}")
    if facts.caps_hit:
        lines.append(
            "  Extraction gaps: "
            + ", ".join(_esc(marker) for marker in facts.caps_hit))
    lines.append("")
    # The path is operator-typed, but it may point inside a
    # target-controlled tree whose directory names are hostile —
    # same escape-at-render posture as every other field here.
    lines.append(
        "To start analysis, run /understand "
        f"{sanitise_for_terminal(str(report.target_path))} "
        "--map (binary mode).")
    return "\n".join(lines)


def format_binary_json(report: BinaryTargetReport) -> str:
    """Machine-readable serialisation. The facts payload carries the
    ``derived_from_target`` stamp; ``ensure_ascii`` keeps control
    bytes escaped on the wire."""
    doc: dict[str, Any] = {
        "target_path": str(report.target_path),
        "target_kind": "binary",
        "binary_facts": report.facts.to_dict(),
        "identity": {
            "kind": report.identity_kind,
            "value": report.identity_value,
        },
    }
    return json.dumps(doc, indent=2, ensure_ascii=True)


def _short_size(n: int) -> str:
    if n >= 1024 * 1024:
        return f"{n / (1024 * 1024):.1f} MB"
    if n >= 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n} B"


__all__ = [
    "BinaryTargetReport",
    "build_binary_report",
    "format_binary_json",
    "format_binary_text",
    "is_binary_target",
]
