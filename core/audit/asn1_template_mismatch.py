"""Declared-type vs accessed-type witness for OpenSSL ASN.1 templates.

An OpenSSL ASN.1 template (``ASN1_SEQUENCE``/``ASN1_CHOICE`` macro
table) is the authoritative runtime type of each member slot: the
decoder allocates what the template entry declares, whatever the C
struct declaration says. Code that then accesses a slot through
``ASN1_TYPE_cmp`` treats it as an ``ASN1_TYPE`` (the ANY container,
``{int type; union value;}``) — if the template declares a concrete
item instead of ``ASN1_ANY``, the decoder produced an ``ASN1_STRING``
and the access reinterprets its length field as a type discriminator
and its data pointer as a union of struct pointers (the CVE-2023-0286
shape: an ASN.1 CHOICE member declared as a concrete SEQUENCE but
compared as ANY).

This is a mechanical, detection-grade witness: both facts are read
from the SAME translation unit (template table + access site), no
type inference is attempted, and a match means exactly "the template
says the decoder builds X, the code compares it as ASN1_TYPE, and X
is not ASN1_ANY".

Generality tradeoff (documented per the channel design): the general
form of this class is "declared type of a union/CHOICE slot differs
from the type it is accessed as", which a CodeQL query over union
member types could express project-agnostically — but CodeQL degrades
to semgrep-taint in tool-light environments (including the corpus
runner), so a CodeQL-only witness would never fire there. This
scoped detector keys on the OpenSSL ASN.1 template DSL, a public,
widely-embedded API (OpenSSL, BoringSSL and LibreSSL derivatives,
vendored copies), and runs wherever Python runs. Template macro
names and the accessor are fixed protocol vocabulary (seed-set
policy), not learned project APIs.

Safety contract: boost-only. Adds detection-grade findings; never
suppresses or demotes.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

logger = logging.getLogger(__name__)

DETECTOR_NAME = "asn1_template_mismatch"

# Template entry: ASN1_IMP(STRUCT, d.field, DECLARED_TYPE, tag) and
# the EXP/SIMPLE/OPT spellings — the macro family that binds a member
# slot to the item type the decoder will construct (protocol
# vocabulary, not project API).
_TEMPLATE_ENTRY_RE = re.compile(
    r"\bASN1_(?:IMP|EXP|SIMPLE|IMP_OPT|EXP_OPT)\s*\(\s*"
    r"(?P<struct>\w+)\s*,\s*(?P<field>[\w.]+)\s*,\s*(?P<decl>\w+)",
)

# Access site: the slot compared as an ANY container. ``a->d.fld`` /
# ``a.d.fld`` / ``a->fld`` first-argument spellings.
_ANY_ACCESS_RE = re.compile(
    r"\bASN1_TYPE_cmp\s*\(\s*(?:\w+\s*(?:->|\.)\s*)+(?P<field>[\w.]+?)\s*[,)]",
)


@dataclass
class Asn1Mismatch:
    """One declared-vs-accessed type mismatch."""

    file: str
    line: int
    field: str
    declared: str
    struct: str

    def description(self) -> str:
        return (
            f"ASN.1 template declares {self.struct}.{self.field} as "
            f"{self.declared} (the decoder builds an ASN1_STRING-shaped "
            f"item), but the code compares it with ASN1_TYPE_cmp — the "
            f"ASN1_STRING is reinterpreted as an ASN1_TYPE "
            f"(length-as-type-discriminator, data-as-union): "
            f"declared-type vs accessed-type mismatch"
        )


def _template_types(source: str) -> dict[str, tuple[str, str]]:
    """Map each template member field to (declared_type, struct).

    Keyed by the full member path as spelled in the template
    (``d.someMember``) AND its tail component (``someMember``) so an
    access spelled through intermediate members still joins.
    """
    out: dict[str, tuple[str, str]] = {}
    for m in _TEMPLATE_ENTRY_RE.finditer(source):
        field = m.group("field")
        decl = m.group("decl")
        struct = m.group("struct")
        out.setdefault(field, (decl, struct))
        tail = field.rsplit(".", 1)[-1]
        out.setdefault(tail, (decl, struct))
    return out


def scan_source(file_path: str, source: str) -> list[Asn1Mismatch]:
    """Scan one C translation unit for template/access mismatches."""
    if "ASN1_TYPE_cmp" not in source:
        return []
    templates = _template_types(source)
    if not templates:
        return []
    findings: list[Asn1Mismatch] = []
    for m in _ANY_ACCESS_RE.finditer(source):
        field = m.group("field")
        hit = templates.get(field) or templates.get(
            field.rsplit(".", 1)[-1],
        )
        if hit is None:
            continue
        decl, struct = hit
        if decl == "ASN1_ANY":
            # The template really does build an ASN1_TYPE — the
            # access matches the declared type.
            continue
        line = source.count("\n", 0, m.start()) + 1
        findings.append(Asn1Mismatch(
            file=file_path, line=line, field=field,
            declared=decl, struct=struct,
        ))
    return findings


def scan_sources(
    source_texts: dict[str, str],
) -> list[Asn1Mismatch]:
    """Scan a {relpath: text} map (the mechanical-detector phase input)."""
    findings: list[Asn1Mismatch] = []
    for fp, text in source_texts.items():
        if not fp.endswith((".c", ".h")):
            continue
        try:
            findings.extend(scan_source(fp, text))
        except Exception:  # noqa: BLE001 — one file must not sink the phase
            logger.debug("asn1 template scan failed for %s", fp, exc_info=True)
    return findings
