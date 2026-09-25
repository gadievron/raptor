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


# The buffer and length arguments are \S-headed: the naive
# ``,\s*([^,]+)`` overlapped the whitespace span and the argument on
# whitespace — quadratic on a recv-opening line ending in a
# whitespace run with no comma. Captures unchanged (the greedy \s*
# already owned the leading whitespace); the dropped corner is a
# whitespace-only argument, not real C.
#
# All argument/cast windows in this pattern group are BOUNDED: with
# an unbounded window, hostile source that repeats the call head
# inside one delimiter-free run makes every head occurrence re-scan
# the rest of the run — quadratic in the function-source length. A
# real C argument expression sits far under the bounds (256 for a
# single cast/index operand, 1024 for an argument that may wrap
# across lines); past the bound the call stops matching instead of
# scanning without bound.
_RECV_RE = re.compile(
    r'\b(recv|recvfrom|read|fread|recvmsg)\s*\('
    r'([^,]{1,1024}),'                  # fd / stream
    r'\s*([^,\s][^,]{0,1023}),'        # buffer
    r'\s*([^,)\s][^,)]{0,1023})',      # length
)

_BYTE_EXTRACT_RE = re.compile(
    r'\b(\w+)\s*=\s*(?:\([^)]{0,256}\)\s*)?'
    r'(?:ntohs|ntohl|ntohll|be16toh|be32toh|be64toh|'
    r'le16toh|le32toh|le64toh|'
    r'EXTRACT_16BITS|EXTRACT_32BITS)\s*\(',
)

_FIELD_READ_RE = re.compile(
    r'\b(\w+)\s*=\s*'
    r'(?:\*\s*\([^)]{0,256}\)\s*\([^)]{1,256}\)|'  # *(type*)(buf + off)
    r'[a-zA-Z_]\w*(?:->|\.)\w+|'               # struct->field / struct.field
    r'(?:\([^)]{0,256}\)\s*)?[a-zA-Z_]\w*\[[^\]]{1,256}\]'  # (cast)buf[idx]
    r')\s*;',
)

# Variable group \b-pinned to a word start: unanchored bare `\w+`
# re-scans a hostile identifier run from every offset (quadratic);
# the dropped matches are mid-word suffix false tokens only.
_ALLOC_RE = re.compile(
    r'\b(\w+)\s*=\s*(?:\([^)]{0,256}\)\s*)?(malloc|calloc|realloc)\s*\(([^)]{1,1024})\)',
)

_COPY_RE = re.compile(
    r'\b(memcpy|memmove|bcopy|strncpy)\s*\(([^,]{1,1024}),([^,]{1,1024}),([^)]{1,1024})\)',
)

# Same \S-headed argument respelling as _RECV_RE above.
_SECOND_RECV_RE = re.compile(
    r'\b(recv|recvfrom|read|fread)\s*\(([^,]{1,1024}),\s*([^,\s][^,]{0,1023}),\s*([^,)\s][^,)]{0,1023})',
)

# Operator captured: acceptance must be direction-aware — a
# comparison only bounds the variable it caps ABOVE (see
# _var_has_upper_bound).
# \b pins the LHS group to a word start and the RHS group to its
# full word — each overlapped the neighbouring filler on word chars
# (quadratic on an identifier run with no operator or paren).
# Earliest-match captures unchanged.
# Both condition windows are BOUNDED (comparison within 200 chars of
# the open paren, close paren within 200 chars of the comparison):
# unbounded, a paren-free hostile run dense in comparison teasers
# costs every window split from every `if (` occurrence — worse than
# quadratic. A real C condition sits far under 200 chars; past the
# bound the check is not seen, which only widens the finding (a
# bounds check missed is never a suppressed one).
_MAX_CHECK_RE = re.compile(
    r'(?:if|while)\s*\([^)]{0,200}?'
    r'\b(\w+)\s*(>=|<=|>|<)\s*(\w+|\d+(?:x[\da-fA-F]+)?)\b'
    r'[^)]{0,200}\)',
)

# Same \b pin and window bounds as _MAX_CHECK_RE above; the brace
# body window is bounded like _GO-style blocks (1000 chars).
_RETURN_CHECK_RE = re.compile(
    r'if\s*\([^)]{0,200}?\b(\w+)\s*(?:>|>=)\s*(\w+|\d+(?:x[\da-fA-F]+)?)\b[^)]{0,200}\)'
    r'\s*\{[^}]{0,1000}?(?:return|goto|break|exit)',
)


def _find_line(source: str, pos: int) -> int:
    return source[:pos].count('\n') + 1


# Chunk marker the xref producer emits between concatenated neighbor
# decompilations — each marks the start of an independent function.
_XREF_SEGMENT_MARKER_RE = re.compile(
    r"(?m)^// --- (?:caller|callee): .+ ---$",
    # line-model: the xref producer emits these marker lines itself,
    # \n-joined — decompiled target text never anchors here
)


def _segment_bounds(
    search_source: str,
    primary_len: int,
) -> List[tuple]:
    """``[start, end)`` spans of independent functions.

    The primary function occupies ``[0, primary_len)``; the xref
    suffix is split on the producer's chunk markers.  Marker-less
    xref text stays one segment (no scoping information available).
    """
    bounds: List[tuple] = [(0, primary_len)]
    starts = [
        m.start()
        for m in _XREF_SEGMENT_MARKER_RE.finditer(
            search_source, primary_len,
        )
    ]
    if not starts:
        if primary_len < len(search_source):
            bounds.append((primary_len, len(search_source)))
        return bounds
    if starts[0] > primary_len:
        bounds.append((primary_len, starts[0]))
    for i, s in enumerate(starts):
        e = starts[i + 1] if i + 1 < len(starts) else len(search_source)
        bounds.append((s, e))
    return bounds


def _segment_start(pos: int, bounds: List[tuple]) -> int:
    for s, e in bounds:
        if s <= pos < e:
            return s
    return 0


def _var_has_upper_bound(
    source: str,
    var_name: str,
    before_pos: int,
    *,
    start: int = 0,
) -> Optional[str]:
    """Check if var_name has an upper-bound check before before_pos.

    Direction-aware: a comparison bounds var_name only when it caps
    it ABOVE — ``len < MAX`` / ``MAX >= len``.  Symmetric acceptance
    read ``while (i < len)`` (a bound on ``i``) as an upper bound on
    ``len`` and hid the classic recv → malloc(len) → copy bug behind
    its own copy loop.

    ``start`` scopes the scan to one function segment: the xref blob
    concatenates unrelated functions, and a same-named bound in a
    DIFFERENT function must not read as a guard on this chain.
    """
    prefix = source[start:before_pos]
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


def length_sites_present(
    source: str, xref_source: str | None = None,
) -> bool:
    """Whether any length-candidate site (byte-order conversion or
    struct/buffer field read) appears in the checker's search space —
    the structural precondition ``check_proto_length`` requires
    before it can test anything. Consulted by the sweep wrapper so a
    model miss maps to inconclusive, never refuted."""
    search_source = source
    if xref_source:
        search_source = source + "\n" + xref_source
    return bool(
        _BYTE_EXTRACT_RE.search(search_source)
        or _FIELD_READ_RE.search(search_source)
    )


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
    finding_keys: List[tuple] = []
    primary_len = len(source)

    search_source = source
    if xref_source:
        # Newline sentinel: without it the primary's last line glues
        # to the xref's first and the line-anchored regexes can match
        # across the seam.
        search_source = source + "\n" + xref_source
    segments = _segment_bounds(search_source, primary_len)

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
                search_source, len_var, alloc["pos"],
                start=_segment_start(alloc["pos"], segments))
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
                finding_keys.append(
                    (len_var, line, alloc["pos"], m.start()),
                )

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
                finding_keys.append(
                    (len_var, line, alloc["pos"], m.start()),
                )

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
                search_source, len_var, m.start(),
                start=_segment_start(m.start(), segments))
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
            finding_keys.append((len_var, line, -1, m.start()))

    # Dedup on (var, line, alloc pos, copy pos): cross-function
    # findings all report line 0, so a line-only key collapsed
    # distinct xref chains into one row.
    seen: set[tuple] = set()
    deduped: List[ProtoLengthFinding] = []
    for key, f in zip(finding_keys, findings):
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
