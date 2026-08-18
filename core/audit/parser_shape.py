"""Structural parse/decode-shape metrics for gap prioritisation.

Why this exists: scoped-audit review receipts showed per-file review
slots going to the small exported siblings of external-format parsers
while the static workhorse that actually walks the untrusted bytes was
never scheduled — the entry-point tier keyed on visibility/header
membership, so a ``static`` decode routine competed on SLOC alone and
lost its slot to the machinery next to it.

Every signal here is structural or learned — never a project function
name:

* **byte-buffer input** — the signature takes a pointer-to-bytes
  parameter alongside an integer length/size parameter (the classic
  external-format surface).
* **cursor advance** — the body walks a pointer/offset through that
  buffer (``p += n``, ``*p++``, ``buf[off++]``).
* **length/size arithmetic density** — arithmetic or comparisons on
  length-ish identifiers per SLOC (``keylen - 8``, ``inlen < hdrlen``);
  where a decoder's bounds bugs live.
* **error-path density** — early error exits per SLOC (``goto err``,
  ``return NULL``, ``throw``/``raise``); dense error handling marks
  validation-heavy code whose ordering bugs are security bugs.
* **parser API calls** — the body calls a name from the function
  taxonomy's high-CVE-density parser catalog
  (:data:`core.function_taxonomy.PARSER_FUNCS`, seeds + harvested pack)
  or from the study-learned ``boundary_transfers`` vocabulary.
* **name morphology** — universal parse/decode tokens only
  (``parse``/``decode``/``deserial``/``unmarshal``/``unpack``); a weak
  signal that never classifies on its own.

Consumers: ``gaps._compute_priority`` (entry-tier lift for parser
workhorses regardless of visibility) and ``priority.score_functions``
(score components within a tier).
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any

# Score components below fire only above these floors so a single
# incidental `len - 1` or lone `return NULL` doesn't reclassify a
# function. Density floors are per-SLOC (0.04 ≈ one site per 25 lines).
LENGTH_ARITH_DENSITY_FLOOR = 0.04
LENGTH_ARITH_SITES_FLOOR = 2
ERROR_PATH_DENSITY_FLOOR = 0.05
ERROR_PATH_SITES_FLOOR = 2

_BYTE_PTR_RE = re.compile(
    r"(?:unsigned\s+char|u_char|uint8_t|int8_t|char|void|BYTE)"
    r"(?:\s+const)?\s*\*",
)
_INT_LEN_TYPE_RE = re.compile(
    r"\b(?:size_t|ssize_t|u?int(?:8|16|32|64)?(?:_t)?|unsigned(?:\s+int|"
    r"\s+long|\s+short)?|long|short|int)\b",
)
# One seed morpheme set (<= 9 entries, vocab-list policy) shared by
# the parameter-name check and the arithmetic-site scan.
_LEN_MORPHS = r"len|length|size|sz|cnt|count|nbytes|off|offset"
_LEN_NAME_RE = re.compile(_LEN_MORPHS, re.IGNORECASE)

_CURSOR_ADVANCE_RE = re.compile(
    r"\*?\s*\b[A-Za-z_]\w*\s*\+\+"          # p++ / *p++
    r"|\b[A-Za-z_]\w*\s*\+=\s*"             # p += n / off += n
    r"|\b[A-Za-z_]\w*\s*\[\s*\w+\s*\+\+\s*\]",  # buf[i++]
)

_LEN_ID = rf"[A-Za-z_]\w*(?:{_LEN_MORPHS})\w*"
_LEN_ARITH_RE = re.compile(
    rf"\b(?:{_LEN_ID})\s*(?:[-+*]|<<|>>|[<>]=?|==|!=)"
    rf"|(?:[-+*]|<<|>>)\s*\b(?:{_LEN_ID})\b",
    re.IGNORECASE,
)

_ERROR_PATH_RE = re.compile(
    r"\bgoto\s+\w*(?:err|fail|bad|cleanup|out|done)\w*"
    r"|\breturn\s+(?:NULL|nullptr|-\s*\d+|false)\b"
    r"|\bthrow\s+\w|\braise\s+\w",
)

_NAME_MORPH_RE = re.compile(
    r"parse|decode|deserial|unmarshal|unpack", re.IGNORECASE,
)

_CALLED_NAME_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")


@dataclass(frozen=True)
class ParserShape:
    """Structural metrics for one function (see module docstring)."""

    parser_shaped: bool = False
    byte_buffer_input: bool = False
    cursor_advance: bool = False
    length_arith_sites: int = 0
    length_arith_density: float = 0.0
    error_path_sites: int = 0
    error_path_density: float = 0.0
    parser_api_call: bool = False
    name_morphology: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _has_byte_buffer_signature(parameters: list[tuple] | None) -> bool:
    """Pointer-to-bytes param + integer length-ish param in one signature."""
    if not parameters:
        return False
    has_ptr = False
    has_len = False
    for entry in parameters:
        if isinstance(entry, (list, tuple)) and len(entry) >= 2:
            pname, ptype = str(entry[0] or ""), str(entry[1] or "")
        else:
            continue
        if ptype and _BYTE_PTR_RE.search(ptype):
            has_ptr = True
        elif ptype and _INT_LEN_TYPE_RE.search(ptype) and "*" not in ptype:
            if _LEN_NAME_RE.search(pname):
                has_len = True
    return has_ptr and has_len


def _taxonomy_parser_names() -> frozenset:
    try:
        from core.function_taxonomy import PARSER_FUNCS
        return PARSER_FUNCS
    except Exception:
        return frozenset()


def _learned_parser_names(domain_vocab: Any) -> set:
    names: set = set()
    for entry in getattr(domain_vocab, "boundary_transfers", None) or ():
        name = entry[0] if isinstance(entry, tuple) else entry
        if isinstance(name, str) and name:
            names.add(name)
    return names


def parser_shape(
    source: str | None,
    *,
    name: str = "",
    parameters: list[tuple] | None = None,
    sloc: int = 0,
    domain_vocab: Any = None,
) -> ParserShape:
    """Classify one function's parse/decode shape from its source slice.

    ``parameters`` uses the checklist metadata convention:
    ``[(name, type), ...]``. Missing source degrades to signature +
    morphology signals only. Never raises.
    """
    src = source or ""
    effective_sloc = sloc if sloc > 0 else max(len(src.splitlines()), 1)

    byte_buffer_input = _has_byte_buffer_signature(parameters)
    cursor_advance = bool(src) and bool(_CURSOR_ADVANCE_RE.search(src))
    length_arith_sites = len(_LEN_ARITH_RE.findall(src)) if src else 0
    error_path_sites = len(_ERROR_PATH_RE.findall(src)) if src else 0
    name_morphology = bool(name) and bool(_NAME_MORPH_RE.search(name))

    parser_api_call = False
    if src:
        called = set(_CALLED_NAME_RE.findall(src))
        called.discard(name)
        catalog = _taxonomy_parser_names()
        if called & catalog:
            parser_api_call = True
        elif domain_vocab is not None and called & _learned_parser_names(
            domain_vocab,
        ):
            parser_api_call = True

    parser_shaped = parser_api_call or (
        byte_buffer_input
        and (
            cursor_advance
            or length_arith_sites >= LENGTH_ARITH_SITES_FLOOR
            or name_morphology
        )
    )

    return ParserShape(
        parser_shaped=parser_shaped,
        byte_buffer_input=byte_buffer_input,
        cursor_advance=cursor_advance,
        length_arith_sites=length_arith_sites,
        length_arith_density=round(length_arith_sites / effective_sloc, 4),
        error_path_sites=error_path_sites,
        error_path_density=round(error_path_sites / effective_sloc, 4),
        parser_api_call=parser_api_call,
        name_morphology=name_morphology,
    )
