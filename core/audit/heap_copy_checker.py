"""Heap-size-to-copy-size mismatch detection.

Works on any C source — original or decompiled. Finds cases where:
  1. A buffer is allocated with size X (via malloc/calloc/realloc or
     stack array declaration)
  2. Data is copied into it with size Y (via memcpy/memmove/strcpy
     or checked wrappers with a dest_size argument)
  3. Y can exceed X — either provably (both are constants) or
     plausibly (Y is a function parameter with no bounds check
     against X on any path)

Supports checked-copy wrappers (e.g. fn(dst, dst_size, src, count))
that embed the dest_size as a separate argument — the checker extracts
both sizes from the call signature.

Usage::

    from core.audit.heap_copy_checker import check_decompiled_function

    findings = check_decompiled_function(
        "parse_route",
        c_source,
        file="target.c",
    )
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence


@dataclass
class HeapCopyFinding:
    """A heap-size-to-copy-size mismatch."""

    function: str
    file: str = ""
    line: int = 0
    copy_call: str = ""
    dest_var: str = ""
    dest_size: str = ""
    copy_size: str = ""
    evidence: str = ""
    confidence: str = "medium"
    is_cross_function: bool = False

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "function": self.function,
            "copy_call": self.copy_call,
            "dest_var": self.dest_var,
            "dest_size": self.dest_size,
            "copy_size": self.copy_size,
            "evidence": self.evidence,
            "confidence": self.confidence,
        }
        if self.file:
            d["file"] = self.file
        if self.line:
            d["line"] = self.line
        if self.is_cross_function:
            d["is_cross_function"] = True
        return d


# Patterns for checked-copy wrappers: fn(dst, dst_size, src, count)
_CHECKED_COPY_RE = re.compile(
    r'\b(\w*(?:memcpy|memmove)\w*)\s*\('
    r'([^,]+),'          # dst
    r'([^,]+),'          # dst_size
    r'([^,]+),'          # src
    r'([^)]+)\)',        # count
)

# Standard copy: memcpy(dst, src, len) / memmove(dst, src, len)
_STD_COPY_RE = re.compile(
    r'\b(memcpy|memmove)\s*\('
    r'([^,]+),'         # dst
    r'([^,]+),'         # src
    r'([^)]+)\)',       # len
)

# strcpy(dst, src) — unbounded by definition
_STRCPY_RE = re.compile(
    r'\b(strcpy)\s*\('
    r'([^,]+),'         # dst
    r'([^)]+)\)',       # src
)

# malloc/calloc/realloc
_ALLOC_RE = re.compile(
    r'(\w+)\s*=\s*(?:\([^)]*\)\s*)?'
    r'(malloc|calloc|realloc)\s*\(([^)]+)\)',
)

# Stack array: type name[SIZE]
_STACK_ARRAY_RE = re.compile(
    r'(?:char|uchar|uint8_t|byte|undefined[14]?)\s+'
    r'(\w+)\s*\[\s*(\d+)\s*\]',
)

# Comparison: if (var < N) or if (var > N) or similar.  The operator
# is captured — equality tests and lower bounds must not read as
# bounds checks (see _is_bounds_checked).
_COMPARISON_RE = re.compile(
    r'\b(?:if|while)\s*\([^)]*?'
    r'(\w+)\s*([<>]=?|==|!=)\s*(\w+|\d+(?:x[\da-fA-F]+)?)'
    r'[^)]*\)',
)

# Function parameter extraction
_PARAM_RE = re.compile(
    r'(?:int|uint|ulong|long|size_t|unsigned\s+int|unsigned\s+long'
    r'|int32_t|uint32_t|int64_t|uint64_t)\s+'
    r'(param_\d+|[a-z]\w*)',
)


def _try_parse_int(s: str) -> Optional[int]:
    """Parse an integer from a decompiled expression."""
    s = s.strip()
    try:
        if s.startswith("0x") or s.startswith("0X"):
            return int(s, 16)
        return int(s)
    except (ValueError, TypeError):
        return None


def _find_line_number(source: str, match_start: int) -> int:
    """Convert a character offset to a 1-based line number."""
    return source[:match_start].count('\n') + 1


def _is_bounds_checked(
    source: str,
    var_name: str,
    limit: str,
    copy_pos: int,
) -> bool:
    """Check if var_name is bounded against limit before copy_pos.

    Looks for if/while conditions that compare var_name against a
    constant or against the same limit expression.  Equality tests
    (``==`` / ``!=``) never bound a copy length — ``if (count != 0)``
    used to suppress an unchecked memcpy — and a constant comparison
    counts only when its direction actually caps the variable
    (``count < N`` / ``N > count``); a lower bound (``count > 0``)
    caps nothing.  A comparison against the exact limit expression is
    accepted in either direction: ``count < size`` guards the copy,
    ``count > size`` guards a bail, and without branch context both
    read as a check performed against the right quantity.
    """
    prefix = source[:copy_pos]
    for m in _COMPARISON_RE.finditer(prefix):
        lhs = m.group(1).strip()
        op = m.group(2)
        rhs = m.group(3).strip()
        if var_name not in (lhs, rhs):
            continue
        if op in ("==", "!="):
            continue
        var_is_lhs = lhs == var_name
        other = rhs if var_is_lhs else lhs
        if other == limit:
            return True
        caps_above = (
            (var_is_lhs and op in ("<", "<="))
            or (not var_is_lhs and op in (">", ">="))
        )
        if not caps_above:
            continue
        limit_int = _try_parse_int(limit)
        other_int = _try_parse_int(other)
        if limit_int is not None and other_int is not None \
                and other_int <= limit_int:
            return True
    return False


def check_decompiled_function(
    function_name: str,
    source: str,
    *,
    file: str = "",
) -> List[HeapCopyFinding]:
    """Analyse one decompiled C function for heap/copy size mismatches.

    Returns a list of findings, empty if none detected.
    """
    findings: List[HeapCopyFinding] = []

    # Collect allocation sizes: var -> (size_expr, size_int_or_None)
    alloc_sizes: Dict[str, tuple] = {}
    for m in _ALLOC_RE.finditer(source):
        var = m.group(1).strip()
        size_expr = m.group(3).strip()
        if m.group(2) == "calloc" and "," in size_expr:
            parts = size_expr.split(",", 1)
            n = _try_parse_int(parts[0].strip())
            sz = _try_parse_int(parts[1].strip())
            if n is not None and sz is not None:
                alloc_sizes[var] = (size_expr, n * sz)
            else:
                alloc_sizes[var] = (size_expr, None)
        else:
            alloc_sizes[var] = (size_expr, _try_parse_int(size_expr))

    # Collect stack array sizes: name -> (size_expr, size_int)
    stack_sizes: Dict[str, tuple] = {}
    for m in _STACK_ARRAY_RE.finditer(source):
        name = m.group(1)
        size_int = _try_parse_int(m.group(2))
        if size_int is not None:
            stack_sizes[name] = (m.group(2), size_int)

    # -- Checked-copy wrappers (4-arg: dst, dst_size, src, count) --
    for m in _CHECKED_COPY_RE.finditer(source):
        fn_name = m.group(1)
        if fn_name in ("memcpy", "memmove"):
            continue  # bare calls handled below
        dst = m.group(2).strip()
        dst_size_expr = m.group(3).strip()
        count_expr = m.group(5).strip()
        line = _find_line_number(source, m.start())

        dst_size_int = _try_parse_int(dst_size_expr)
        count_int = _try_parse_int(count_expr)

        # Case 1: both are constants and count > dest_size
        if dst_size_int is not None and count_int is not None:
            if count_int > dst_size_int:
                findings.append(HeapCopyFinding(
                    function=function_name,
                    file=file,
                    line=line,
                    copy_call=fn_name,
                    dest_var=dst,
                    dest_size=dst_size_expr,
                    copy_size=count_expr,
                    evidence=(
                        f"constant count ({count_int}) exceeds "
                        f"dest_size ({dst_size_int})"
                    ),
                    confidence="high",
                ))

        # Case 2: count is a variable (possibly attacker-controlled)
        elif dst_size_int is not None and count_int is None:
            count_var = count_expr.split('[')[0].split('(')[0].strip()
            if not _is_bounds_checked(
                source, count_var, dst_size_expr, m.start()
            ):
                findings.append(HeapCopyFinding(
                    function=function_name,
                    file=file,
                    line=line,
                    copy_call=fn_name,
                    dest_var=dst,
                    dest_size=dst_size_expr,
                    copy_size=count_expr,
                    evidence=(
                        f"count variable '{count_var}' not checked "
                        f"against dest_size ({dst_size_int}) before copy"
                    ),
                    confidence="medium",
                ))

    # -- Standard copy calls (3-arg: dst, src, len) --
    for m in _STD_COPY_RE.finditer(source):
        fn_name = m.group(1)
        dst = m.group(2).strip()
        len_expr = m.group(4).strip()
        line = _find_line_number(source, m.start())

        len_int = _try_parse_int(len_expr)
        dst_base = dst.split('[')[0].split('+')[0].strip()

        # Check against known allocation
        if dst_base in alloc_sizes:
            alloc_expr, alloc_int = alloc_sizes[dst_base]
            if alloc_int is not None and len_int is not None:
                if len_int > alloc_int:
                    findings.append(HeapCopyFinding(
                        function=function_name,
                        file=file,
                        line=line,
                        copy_call=fn_name,
                        dest_var=dst_base,
                        dest_size=alloc_expr,
                        copy_size=len_expr,
                        evidence=(
                            f"copy size ({len_int}) exceeds "
                            f"allocation ({alloc_int})"
                        ),
                        confidence="high",
                    ))
            elif alloc_int is not None and len_int is None:
                len_var = len_expr.split('[')[0].split('(')[0].strip()
                if not _is_bounds_checked(
                    source, len_var, alloc_expr, m.start()
                ):
                    findings.append(HeapCopyFinding(
                        function=function_name,
                        file=file,
                        line=line,
                        copy_call=fn_name,
                        dest_var=dst_base,
                        dest_size=alloc_expr,
                        copy_size=len_expr,
                        evidence=(
                            f"copy length '{len_var}' not checked "
                            f"against allocation ({alloc_int})"
                        ),
                        confidence="medium",
                    ))

        # Check against stack arrays
        if dst_base in stack_sizes:
            stack_expr, stack_int = stack_sizes[dst_base]
            if stack_int is not None and len_int is not None:
                if len_int > stack_int:
                    findings.append(HeapCopyFinding(
                        function=function_name,
                        file=file,
                        line=line,
                        copy_call=fn_name,
                        dest_var=dst_base,
                        dest_size=stack_expr,
                        copy_size=len_expr,
                        evidence=(
                            f"copy size ({len_int}) exceeds "
                            f"stack buffer ({stack_int})"
                        ),
                        confidence="high",
                    ))

    # -- strcpy (unbounded, check if dst has a known size) --
    for m in _STRCPY_RE.finditer(source):
        dst = m.group(2).strip()
        line = _find_line_number(source, m.start())
        dst_base = dst.split('[')[0].split('+')[0].strip()
        # Remove casts
        if '(' in dst_base and ')' in dst_base:
            cast_m = re.search(r'\)\s*(\w+)', dst_base)
            if cast_m:
                dst_base = cast_m.group(1)

        if dst_base in alloc_sizes:
            alloc_expr, alloc_int = alloc_sizes[dst_base]
            findings.append(HeapCopyFinding(
                function=function_name,
                file=file,
                line=line,
                copy_call="strcpy",
                dest_var=dst_base,
                dest_size=alloc_expr if alloc_int else "heap-allocated",
                copy_size="strlen(src)+1",
                evidence=(
                    f"strcpy into heap buffer (allocated {alloc_expr}) "
                    f"— no length bound"
                ),
                confidence="medium",
            ))

    return findings


_CALL_WITH_ARGS_RE = re.compile(
    r'\b(\w+)\s*\(([^)]*)\)',
)


def _param_copy_findings(
    callee: str,
    source: str,
    param_name: str,
    alloc_size: Optional[int],
    file: str,
) -> List[HeapCopyFinding]:
    """Copies in *source* whose destination is *param_name*, judged
    against the CALLER's allocation size.

    check_decompiled_function only reports copies into buffers the
    callee itself allocates, so the headline cross-function scenario —
    caller allocates, callee copies into the parameter — matched
    nothing and the pass was dead.  Findings only when the caller's
    size is known; an unknown allocation is inconclusive, never a
    finding.
    """
    findings: List[HeapCopyFinding] = []
    if alloc_size is None:
        return findings
    for m in _STD_COPY_RE.finditer(source):
        fn_name = m.group(1)
        dst = m.group(2).strip()
        len_expr = m.group(4).strip()
        dst_base = dst.split('[')[0].split('+')[0].strip()
        if dst_base != param_name:
            continue
        line = _find_line_number(source, m.start())
        len_int = _try_parse_int(len_expr)
        if len_int is not None:
            if len_int > alloc_size:
                findings.append(HeapCopyFinding(
                    function=callee,
                    file=file,
                    line=line,
                    copy_call=fn_name,
                    dest_var=param_name,
                    dest_size=str(alloc_size),
                    copy_size=len_expr,
                    evidence=(
                        f"constant copy size ({len_int}) exceeds the "
                        f"caller's allocation ({alloc_size})"
                    ),
                    confidence="high",
                ))
        else:
            len_var = len_expr.split('[')[0].split('(')[0].strip()
            if not _is_bounds_checked(
                source, len_var, str(alloc_size), m.start(),
            ):
                findings.append(HeapCopyFinding(
                    function=callee,
                    file=file,
                    line=line,
                    copy_call=fn_name,
                    dest_var=param_name,
                    dest_size=str(alloc_size),
                    copy_size=len_expr,
                    evidence=(
                        f"copy length '{len_var}' into the caller's "
                        f"{alloc_size}-byte buffer not checked in the "
                        f"callee"
                    ),
                    confidence="medium",
                ))
    for m in _STRCPY_RE.finditer(source):
        dst = m.group(2).strip()
        dst_base = dst.split('[')[0].split('+')[0].strip()
        if dst_base != param_name:
            continue
        findings.append(HeapCopyFinding(
            function=callee,
            file=file,
            line=_find_line_number(source, m.start()),
            copy_call="strcpy",
            dest_var=param_name,
            dest_size=str(alloc_size),
            copy_size="strlen(src)+1",
            evidence=(
                f"strcpy into the caller's {alloc_size}-byte buffer "
                f"— no length bound"
            ),
            confidence="medium",
        ))
    return findings


def check_cross_function(
    functions: Sequence[Dict[str, Any]],
    xrefs: Optional[Sequence[Dict[str, Any]]] = None,
    *,
    file: str = "",
) -> List[HeapCopyFinding]:
    """Cross-function analysis: track allocations through call boundaries.

    For each function that allocates a buffer and passes it to another
    function, check if the callee's copy operations on that parameter
    exceed the allocation size.

    Parameters
    ----------
    functions:
        List of function dicts with at least 'name' and 'decompilation'.
    xrefs:
        Optional cross-references from the Ghidra export.

    Returns
    -------
    List of cross-function findings.
    """
    findings: List[HeapCopyFinding] = []

    func_map: Dict[str, str] = {}
    for f in functions:
        name = f.get("name", "")
        decomp = f.get("decompilation", "")
        if name and decomp:
            func_map[name] = decomp

    for fname, source in func_map.items():
        # Collect allocations in this function: var → size
        allocs: Dict[str, Optional[int]] = {}
        for m in _ALLOC_RE.finditer(source):
            var = m.group(1).strip()
            size_expr = m.group(3).strip()
            allocs[var] = _try_parse_int(size_expr)

        if not allocs:
            continue

        # Find calls that pass allocated buffers to other functions
        for m in _CALL_WITH_ARGS_RE.finditer(source):
            callee = m.group(1).strip()
            if callee not in func_map or callee == fname:
                continue
            args = [a.strip() for a in m.group(2).split(",")]
            for pos, arg in enumerate(args):
                arg_base = arg.split('[')[0].split('+')[0].strip()
                if arg_base not in allocs:
                    continue
                alloc_size = allocs[arg_base]
                param_name = f"param_{pos + 1}"
                callee_src = func_map[callee]
                # Checked-copy wrappers with the parameter as dest
                # come from the callee's own analysis; plain copies
                # into the parameter need the caller's size, which
                # only this pass knows.
                callee_findings = [
                    cf for cf in check_decompiled_function(
                        callee, callee_src, file=file,
                    )
                    if cf.dest_var == param_name
                ] + _param_copy_findings(
                    callee, callee_src, param_name, alloc_size, file,
                )
                for cf in callee_findings:
                    cf.is_cross_function = True
                    size_note = (
                        f" (allocated {alloc_size} bytes)"
                        if alloc_size is not None
                        else ""
                    )
                    cf.evidence = (
                        f"[cross-function] '{fname}' allocates "
                        f"'{arg_base}'{size_note}, passes to "
                        f"'{callee}' as {param_name}: {cf.evidence}"
                    )
                    findings.append(cf)

    return findings


def format_findings(findings: Sequence[HeapCopyFinding]) -> str:
    """Render findings as readable text."""
    if not findings:
        return "heap-copy checker: no size mismatches found"

    lines = [f"### Heap-copy size checker: {len(findings)} findings"]
    for f in findings:
        cross = " [cross-function]" if f.is_cross_function else ""
        lines.append(
            f"- `{f.function}()` line {f.line}: "
            f"`{f.copy_call}({f.dest_var}, ..., {f.copy_size})`{cross}"
        )
        lines.append(f"  dest_size={f.dest_size}, {f.evidence}")
        lines.append(f"  confidence: {f.confidence}")
    return "\n".join(lines)
