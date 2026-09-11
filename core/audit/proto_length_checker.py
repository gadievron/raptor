"""Protocol-parser length discipline checker.

Works on decompiled C. Finds the recv → parse-length → allocate → copy
pattern and checks whether the length field is bounded before use.

The classic network daemon bug: read a length field from the wire,
malloc(length), then recv(buf, length) — if length is unchecked, the
attacker controls the allocation size and can cause:
  - Integer truncation (length > 64K with a 16-bit cast)
  - Heap overflow (length larger than expected, copy overflows)
  - Denial of service (length = 0xFFFFFFFF, huge allocation)

This checker is protocol-agnostic — it matches the structural pattern,
not any specific wire format.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

_APPLICABLE_CWES = frozenset({"CWE-120", "CWE-131", "CWE-805"})


def proto_length_applicable(cwe: str) -> bool:
    return cwe in _APPLICABLE_CWES


def is_proto_length_hypothesis(hypothesis: str) -> bool:
    h = hypothesis.lower()
    return any(k in h for k in (
        "length field", "unbounded length", "protocol length",
        "unchecked length", "packet length",
    ))


@dataclass
class ProtoLengthFinding:
    function: str
    file: str = ""
    line: int = 0
    length_var: str = ""
    length_source: str = ""
    alloc_call: str = ""
    copy_call: str = ""
    max_check: str = ""
    evidence: str = ""
    confidence: str = "medium"

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "function": self.function,
            "length_var": self.length_var,
            "evidence": self.evidence,
            "confidence": self.confidence,
        }
        if self.file:
            d["file"] = self.file
        if self.line:
            d["line"] = self.line
        if self.length_source:
            d["length_source"] = self.length_source
        if self.alloc_call:
            d["alloc_call"] = self.alloc_call
        if self.copy_call:
            d["copy_call"] = self.copy_call
        if self.max_check:
            d["max_check"] = self.max_check
        return d


_RECV_RE = re.compile(
    r'\b(recv|recvfrom|read|fread|recvmsg)\s*\('
    r'([^,]+),'       # fd / stream
    r'\s*([^,]+),'    # buffer
    r'\s*([^,)]+)',   # length
)

_BYTE_EXTRACT_RE = re.compile(
    r'\b(\w+)\s*=\s*(?:\([^)]*\)\s*)?'
    r'(?:ntohs|ntohl|ntohll|be16toh|be32toh|be64toh|'
    r'le16toh|le32toh|le64toh|'
    r'EXTRACT_16BITS|EXTRACT_32BITS)\s*\(',
)

_FIELD_READ_RE = re.compile(
    r'\b(\w+)\s*=\s*'
    r'(?:\*\s*\([^)]*\)\s*\([^)]+\)|'          # *(type*)(buf + off)
    r'[a-zA-Z_]\w*(?:->|\.)\w+|'               # struct->field / struct.field
    r'(?:\([^)]*\)\s*)?[a-zA-Z_]\w*\[[^\]]+\]' # (cast)buf[idx]
    r')\s*;',
)

_ALLOC_RE = re.compile(
    r'(\w+)\s*=\s*(?:\([^)]*\)\s*)?(malloc|calloc|realloc)\s*\(([^)]+)\)',
)

_COPY_RE = re.compile(
    r'\b(memcpy|memmove|bcopy|strncpy)\s*\(([^,]+),([^,]+),([^)]+)\)',
)

_SECOND_RECV_RE = re.compile(
    r'\b(recv|recvfrom|read|fread)\s*\(([^,]+),\s*([^,]+),\s*([^,)]+)',
)

# Operator captured: acceptance must be direction-aware — a
# comparison only bounds the variable it caps ABOVE (see
# _var_has_upper_bound).
_MAX_CHECK_RE = re.compile(
    r'(?:if|while)\s*\([^)]*?'
    r'(\w+)\s*(>=|<=|>|<)\s*(\w+|\d+(?:x[\da-fA-F]+)?)'
    r'[^)]*\)',
)

_RETURN_CHECK_RE = re.compile(
    r'if\s*\([^)]*?(\w+)\s*(?:>|>=)\s*(\w+|\d+(?:x[\da-fA-F]+)?)[^)]*\)'
    r'\s*\{[^}]*?(?:return|goto|break|exit)',
)


def _find_line(source: str, pos: int) -> int:
    return source[:pos].count('\n') + 1


def _var_has_upper_bound(
    source: str,
    var_name: str,
    before_pos: int,
) -> Optional[str]:
    """Check if var_name has an upper-bound check before before_pos.

    Direction-aware: a comparison bounds var_name only when it caps
    it ABOVE — ``len < MAX`` / ``MAX >= len``.  Symmetric acceptance
    read ``while (i < len)`` (a bound on ``i``) as an upper bound on
    ``len`` and hid the classic recv → malloc(len) → copy bug behind
    its own copy loop.
    """
    prefix = source[:before_pos]
    for m in _RETURN_CHECK_RE.finditer(prefix):
        if m.group(1) == var_name:
            return m.group(2)
    for m in _MAX_CHECK_RE.finditer(prefix):
        lhs = m.group(1).strip()
        op = m.group(2)
        rhs = m.group(3).strip()
        if var_name == lhs and op in ("<", "<="):
            return rhs
        if var_name == rhs and op in (">", ">="):
            return lhs
    return None


def check_proto_length(
    function_name: str,
    source: str,
    *,
    file: str = "",
    xref_source: str | None = None,
) -> List[ProtoLengthFinding]:
    """Analyse one decompiled function for unbounded protocol lengths.

    When *xref_source* is provided, extends the search for recv/alloc/copy
    patterns into caller/callee decompilation (cross-function chains).
    """
    findings: List[ProtoLengthFinding] = []
    primary_len = len(source)

    search_source = source
    if xref_source:
        search_source = source + xref_source

    length_candidates: Dict[str, Dict[str, Any]] = {}

    for m in _BYTE_EXTRACT_RE.finditer(search_source):
        var = m.group(1)
        length_candidates[var] = {
            "source": "byte-order conversion",
            "pos": m.start(),
        }

    for m in _FIELD_READ_RE.finditer(search_source):
        var = m.group(1)
        if var not in length_candidates:
            length_candidates[var] = {
                "source": "struct/buffer field read",
                "pos": m.start(),
            }

    if not length_candidates:
        return findings

    allocs: Dict[str, Dict[str, Any]] = {}
    for m in _ALLOC_RE.finditer(search_source):
        buf_var = m.group(1).strip()
        alloc_fn = m.group(2)
        size_arg = m.group(3).strip()
        size_vars = set(re.findall(r'\b(\w+)\b', size_arg))
        allocs[buf_var] = {
            "fn": alloc_fn,
            "size_arg": size_arg,
            "size_vars": size_vars,
            "pos": m.start(),
        }

    for len_var, len_info in length_candidates.items():
        for buf_var, alloc in allocs.items():
            if len_var not in alloc["size_vars"]:
                continue
            if alloc["pos"] < len_info["pos"]:
                continue

            bound = _var_has_upper_bound(
                search_source, len_var, alloc["pos"])
            if bound is not None:
                continue

            for m in _COPY_RE.finditer(search_source):
                dst = m.group(2).strip()
                copy_len = m.group(4).strip()
                dst_base = dst.split('[')[0].split('+')[0].strip()
                if dst_base != buf_var:
                    continue
                copy_len_vars = set(re.findall(r'\b(\w+)\b', copy_len))
                if len_var not in copy_len_vars:
                    continue

                is_xref = (
                    len_info["pos"] >= primary_len
                    or alloc["pos"] >= primary_len
                    or m.start() >= primary_len
                )
                line = (
                    0 if len_info["pos"] >= primary_len
                    else _find_line(source, len_info["pos"])
                )
                findings.append(ProtoLengthFinding(
                    function=function_name,
                    file=file,
                    line=line,
                    length_var=len_var,
                    length_source=len_info["source"],
                    alloc_call=alloc["fn"],
                    copy_call=m.group(1),
                    evidence=(
                        f"'{len_var}' ({len_info['source']}) used in "
                        f"{alloc['fn']}({alloc['size_arg']}) with no "
                        f"upper-bound check, then {m.group(1)} copies "
                        f"{copy_len} bytes into the buffer"
                        + (" [cross-function]" if is_xref else "")
                    ),
                    confidence="medium" if is_xref else "high",
                ))

            for m in _SECOND_RECV_RE.finditer(search_source):
                if m.start() < alloc["pos"]:
                    continue
                recv_buf = m.group(3).strip()
                recv_len = m.group(4).strip()
                recv_buf_base = recv_buf.split('[')[0].split('+')[0].strip()
                if recv_buf_base != buf_var:
                    continue
                recv_len_vars = set(re.findall(r'\b(\w+)\b', recv_len))
                if len_var not in recv_len_vars:
                    continue

                is_xref = (
                    len_info["pos"] >= primary_len
                    or alloc["pos"] >= primary_len
                    or m.start() >= primary_len
                )
                line = (
                    0 if len_info["pos"] >= primary_len
                    else _find_line(source, len_info["pos"])
                )
                findings.append(ProtoLengthFinding(
                    function=function_name,
                    file=file,
                    line=line,
                    length_var=len_var,
                    length_source=len_info["source"],
                    alloc_call=alloc["fn"],
                    copy_call=m.group(1),
                    evidence=(
                        f"'{len_var}' ({len_info['source']}) used in "
                        f"{alloc['fn']}({alloc['size_arg']}) with no "
                        f"upper-bound check, then {m.group(1)}() reads "
                        f"{recv_len} bytes into the buffer"
                        + (" [cross-function]" if is_xref else "")
                    ),
                    confidence="medium" if is_xref else "high",
                ))

    for len_var, len_info in length_candidates.items():
        for m in _COPY_RE.finditer(search_source):
            if m.start() < len_info["pos"]:
                continue
            copy_len = m.group(4).strip()
            copy_len_vars = set(re.findall(r'\b(\w+)\b', copy_len))
            if len_var not in copy_len_vars:
                continue

            dst = m.group(2).strip()
            dst_base = dst.split('[')[0].split('+')[0].strip()
            if dst_base in allocs:
                continue

            bound = _var_has_upper_bound(
                search_source, len_var, m.start())
            if bound is not None:
                continue

            is_xref = (
                len_info["pos"] >= primary_len
                or m.start() >= primary_len
            )
            line = (
                0 if len_info["pos"] >= primary_len
                else _find_line(source, len_info["pos"])
            )
            findings.append(ProtoLengthFinding(
                function=function_name,
                file=file,
                line=line,
                length_var=len_var,
                length_source=len_info["source"],
                copy_call=m.group(1),
                evidence=(
                    f"'{len_var}' ({len_info['source']}) used as "
                    f"{m.group(1)} length with no upper-bound check; "
                    f"destination is not a freshly allocated buffer "
                    f"(stack/global/parameter)"
                    + (" [cross-function]" if is_xref else "")
                ),
                confidence="medium",
            ))

    seen: set[tuple[str, int]] = set()
    deduped: List[ProtoLengthFinding] = []
    for f in findings:
        key = (f.length_var, f.line)
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    return deduped


def format_findings(findings: Sequence[ProtoLengthFinding]) -> str:
    if not findings:
        return "protocol length checker: no unbounded length fields found"

    lines = [f"### Protocol length checker: {len(findings)} findings"]
    for f in findings:
        lines.append(
            f"- `{f.function}()` line {f.line}: "
            f"`{f.length_var}` ({f.length_source})"
        )
        lines.append(f"  {f.evidence}")
        lines.append(f"  confidence: {f.confidence}")
    return "\n".join(lines)
