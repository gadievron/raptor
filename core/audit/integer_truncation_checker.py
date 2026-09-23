"""Integer truncation → allocation size mismatch detection.

Works on decompiled C. Finds the classic pattern:

  1. A wide value (uint32/ulong/size_t) is received from network or
     parameter
  2. Cast or assigned to a narrower type (uint16/ushort/short)
  3. The narrow value feeds a malloc/calloc/realloc
  4. The original wide value feeds a memcpy/memmove into the
     undersized buffer

This is the root cause behind many heap overflows — the overflow
itself is the symptom; the truncation is the bug.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from collections.abc import Sequence
from typing import Any

_APPLICABLE_CWES = frozenset({"CWE-190", "CWE-195", "CWE-680"})


def integer_truncation_applicable(cwe: str) -> bool:
    return cwe in _APPLICABLE_CWES


def is_integer_truncation_hypothesis(hypothesis: str) -> bool:
    h = hypothesis.lower()
    return any(k in h for k in (
        "integer truncat", "narrowing cast", "wide to narrow",
        "integer overflow", "integer wraparound",
    ))


@dataclass
class TruncationFinding:
    function: str
    file: str = ""
    line: int = 0
    wide_var: str = ""
    narrow_var: str = ""
    wide_type: str = ""
    narrow_type: str = ""
    alloc_call: str = ""
    copy_call: str = ""
    evidence: str = ""
    confidence: str = "medium"

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "function": self.function,
            "wide_var": self.wide_var,
            "narrow_var": self.narrow_var,
            "evidence": self.evidence,
            "confidence": self.confidence,
        }
        if self.file:
            d["file"] = self.file
        if self.line:
            d["line"] = self.line
        if self.wide_type:
            d["wide_type"] = self.wide_type
        if self.narrow_type:
            d["narrow_type"] = self.narrow_type
        if self.alloc_call:
            d["alloc_call"] = self.alloc_call
        if self.copy_call:
            d["copy_call"] = self.copy_call
        return d


_WIDE_TYPES = frozenset({
    "ulong", "unsigned long", "uint64_t", "size_t", "ssize_t",
    "uint64", "long", "int64_t", "int64", "DWORD64", "QWORD",
    "uint", "unsigned int", "uint32_t", "int32_t", "uint32",
    "int32", "DWORD", "unsigned",
})

_NARROW_TYPES = frozenset({
    "ushort", "unsigned short", "uint16_t", "short", "int16_t",
    "uint16", "int16", "WORD",
})

_VERY_NARROW_TYPES = frozenset({
    "uchar", "unsigned char", "uint8_t", "char", "int8_t",
    "uint8", "byte", "BYTE",
})

_TYPE_WIDTHS: dict[str, int] = {}
for _t in _VERY_NARROW_TYPES:
    _TYPE_WIDTHS[_t] = 8
for _t in _NARROW_TYPES:
    _TYPE_WIDTHS[_t] = 16
for _t in _WIDE_TYPES:
    _TYPE_WIDTHS[_t] = 32

_EXPLICIT_CAST_RE = re.compile(
    r'\b(\w+)\s*=\s*\(('
    + '|'.join(re.escape(t) for t in sorted(_NARROW_TYPES | _VERY_NARROW_TYPES, key=len, reverse=True))
    + r')\)\s*(\w+)',
)

_IMPLICIT_NARROW_DECL_RE = re.compile(
    r'\b('
    + '|'.join(re.escape(t) for t in sorted(_NARROW_TYPES | _VERY_NARROW_TYPES, key=len, reverse=True))
    + r')\s+(\w+)\s*=\s*(\w+)\s*;',
)

_ALLOC_RE = re.compile(
    r'(\w+)\s*=\s*(?:\([^)]*\)\s*)?(malloc|calloc|realloc)\s*\(([^)]+)\)',
)

_COPY_RE = re.compile(
    r'\b(memcpy|memmove|bcopy)\s*\(([^,]+),([^,]+),([^)]+)\)',
)

_RECV_SOURCES = frozenset({
    "recv", "recvfrom", "recvmsg", "read", "fread",
    "ntohs", "ntohl", "ntohll",
})

_NETWORK_PARSE_RE = re.compile(
    r'\b(\w+)\s*=\s*(?:\([^)]*\)\s*)?(?:'
    + '|'.join(re.escape(s) for s in sorted(_RECV_SOURCES, key=len, reverse=True))
    + r')\s*\(',
)

_PARAM_RE = re.compile(
    r'(?:int|uint|ulong|long|size_t|unsigned\s+int|unsigned\s+long'
    r'|int32_t|uint32_t|int64_t|uint64_t|uint16_t|ushort)\s+'
    r'(param_\d+|[a-z]\w*)',
)

_BYTE_ORDER_RE = re.compile(
    r'\b(\w+)\s*=\s*(?:\([^)]*\)\s*)?(?:ntohs|ntohl|ntohll|htons|htonl)\s*\(',
)


def _find_line(source: str, pos: int) -> int:
    return source[:pos].count('\n') + 1


def _is_network_tainted(source: str, var_name: str) -> bool:
    """Heuristic: is this variable likely network-sourced?"""
    for m in _NETWORK_PARSE_RE.finditer(source):
        if m.group(1) == var_name:
            return True
    for m in _BYTE_ORDER_RE.finditer(source):
        if m.group(1) == var_name:
            return True
    for m in _PARAM_RE.finditer(source):
        if m.group(1) == var_name:
            return True
    return False


def narrowing_sites_present(
    source: str, xref_source: str | None = None,
) -> bool:
    """Whether any narrowing site (explicit cast or implicit narrow
    declaration) appears in the checker's search space — the
    structural precondition ``check_integer_truncation`` requires
    before it can test anything. Consulted by the sweep wrapper so a
    model miss maps to inconclusive, never refuted."""
    search_source = source
    if xref_source:
        search_source = source + "\n" + xref_source
    return bool(
        _EXPLICIT_CAST_RE.search(search_source)
        or _IMPLICIT_NARROW_DECL_RE.search(search_source)
    )


def check_integer_truncation(
    function_name: str,
    source: str,
    *,
    file: str = "",
    xref_source: str | None = None,
) -> list[TruncationFinding]:
    """Analyse one decompiled function for integer truncation bugs.

    When *xref_source* is provided, extends the search for alloc/copy
    patterns into caller/callee decompilation (cross-function chains).
    """
    findings: list[TruncationFinding] = []
    primary_len = len(source)

    search_source = source
    if xref_source:
        # Newline sentinel: without it the primary's last line glues
        # to the xref blob's first and identifiers merge across the
        # seam — a truncated decompile ending mid-token minted a
        # cast/alloc/copy chain that exists in neither function
        # (same seam fixed in proto_length_checker).
        search_source = source + "\n" + xref_source

    narrows: dict[str, dict[str, str]] = {}

    for m in _EXPLICIT_CAST_RE.finditer(search_source):
        narrow_var = m.group(1)
        narrow_type = m.group(2)
        wide_var = m.group(3)
        narrows[narrow_var] = {
            "wide_var": wide_var,
            "narrow_type": narrow_type,
            "pos": str(m.start()),
        }

    for m in _IMPLICIT_NARROW_DECL_RE.finditer(search_source):
        narrow_type = m.group(1)
        narrow_var = m.group(2)
        wide_var = m.group(3)
        if narrow_var not in narrows:
            narrows[narrow_var] = {
                "wide_var": wide_var,
                "narrow_type": narrow_type,
                "pos": str(m.start()),
            }

    if not narrows:
        return findings

    allocs: dict[str, dict[str, Any]] = {}
    for m in _ALLOC_RE.finditer(search_source):
        buf_var = m.group(1).strip()
        alloc_fn = m.group(2)
        size_arg = m.group(3).strip()
        size_vars = re.findall(r'\b(\w+)\b', size_arg)
        allocs[buf_var] = {
            "fn": alloc_fn,
            "size_arg": size_arg,
            "size_vars": size_vars,
            "pos": m.start(),
        }

    for narrow_var, info in narrows.items():
        wide_var = info["wide_var"]
        narrow_type = info["narrow_type"]
        narrow_pos = int(info["pos"])

        for buf_var, alloc in allocs.items():
            if narrow_var not in alloc["size_vars"]:
                continue

            for m in _COPY_RE.finditer(search_source):
                dst = m.group(2).strip()
                copy_len = m.group(4).strip()
                dst_base = dst.split('[')[0].split('+')[0].strip()
                if dst_base != buf_var:
                    continue

                copy_vars = re.findall(r'\b(\w+)\b', copy_len)
                if wide_var in copy_vars:
                    is_xref = (
                        narrow_pos >= primary_len
                        or alloc["pos"] >= primary_len
                        or m.start() >= primary_len
                    )
                    if is_xref:
                        confidence = "medium"
                    else:
                        net_tainted = _is_network_tainted(
                            source, wide_var)
                        confidence = "high" if net_tainted else "medium"
                    line = (
                        0 if narrow_pos >= primary_len
                        else _find_line(source, narrow_pos)
                    )

                    findings.append(TruncationFinding(
                        function=function_name,
                        file=file,
                        line=line,
                        wide_var=wide_var,
                        narrow_var=narrow_var,
                        narrow_type=narrow_type,
                        alloc_call=alloc["fn"],
                        copy_call=m.group(1),
                        evidence=(
                            f"'{wide_var}' truncated to {narrow_type} "
                            f"as '{narrow_var}', used in "
                            f"{alloc['fn']}({alloc['size_arg']}); "
                            f"then {m.group(1)} copies {copy_len} bytes "
                            f"(using original wide '{wide_var}') "
                            f"into the undersized buffer"
                            + (" [cross-function]" if is_xref else "")
                        ),
                        confidence=confidence,
                    ))

    return findings


def format_findings(findings: Sequence[TruncationFinding]) -> str:
    if not findings:
        return "integer truncation checker: no truncation-to-alloc patterns found"

    lines = [f"### Integer truncation checker: {len(findings)} findings"]
    for f in findings:
        lines.append(
            f"- `{f.function}()` line {f.line}: "
            f"`{f.wide_var}` ({f.wide_type or '?'}) → "
            f"`{f.narrow_var}` ({f.narrow_type}) → "
            f"`{f.alloc_call}()` → `{f.copy_call}()`"
        )
        lines.append(f"  {f.evidence}")
        lines.append(f"  confidence: {f.confidence}")
    return "\n".join(lines)
