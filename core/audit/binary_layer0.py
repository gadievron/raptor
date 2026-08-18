"""Layer 0: mechanical binary vulnerability pattern detection.

12 vulnerability patterns readable from compiled binaries without LLM
or expensive analysis.  Milliseconds per function, $0.

Pattern catalog:
  format_string       — printf family called with wrong argument count
  buffer_copy_size    — stack buffer smaller than copy count
  unchecked_return    — security-critical returns ignored
  sign_confusion      — signed-to-unsigned widening before size use
  compiler_security   — per-function stack canary, FORTIFY
  toctou              — check-then-use call sequences
  lock_imbalance      — acquire without release on some paths
  sensitive_clear     — missing explicit_bzero before return
  indirect_flow       — unprotected indirect calls/jumps
  inlined_ops         — rep movsb/stosb patterns
  dwarf_types         — exact types when debug info present
  elf_metadata        — binary-wide security posture

Each pattern produces findings at XREF_BACKED, HEADER_BACKED, or
HEURISTIC evidence tier depending on the analysis confidence.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from core.evidence import EvidenceTier

logger = logging.getLogger(__name__)


class PatternID:
    FORMAT_STRING = "L0-30.1"
    BUFFER_SIZE_MISMATCH = "L0-30.2"
    UNCHECKED_RETURN = "L0-30.3"
    SIGN_CONFUSION = "L0-30.4"
    COMPILER_SECURITY = "L0-30.5"
    TOCTOU = "L0-30.6"
    LOCK_IMBALANCE = "L0-30.7"
    MISSING_CLEAR = "L0-30.8"
    INDIRECT_FLOW = "L0-30.9"
    INLINED_OP = "L0-30.10"
    DWARF_ENHANCED = "L0-30.11"
    BINARY_METADATA = "L0-30.12"


_PRINTF_FAMILY = frozenset({
    "printf", "fprintf", "sprintf", "snprintf",
    "dprintf", "vprintf", "vfprintf", "vsprintf", "vsnprintf",
    "wprintf", "fwprintf", "swprintf",
    "syslog", "err", "errx", "warn", "warnx",
})

_CHECKED_RETURN_CALLS = frozenset({
    "malloc", "calloc", "realloc",
    "open", "fopen", "socket", "accept",
    "read", "write", "recv", "send",
    "mmap", "mprotect",
    "setuid", "setgid", "seteuid", "setegid",
    "chroot", "chdir",
    "SSL_read", "SSL_write", "SSL_connect",
    "pthread_mutex_lock", "pthread_create",
})

_TOCTOU_PAIRS = [
    (frozenset({"access"}), frozenset({"open", "fopen"})),
    (frozenset({"stat", "lstat"}), frozenset({"open", "readlink", "fopen"})),
    (frozenset({"realpath"}), frozenset({"open", "fopen"})),
    (frozenset({"opendir"}), frozenset({"unlink", "rename", "rmdir"})),
]

_LOCK_PAIRS = [
    ("pthread_mutex_lock", "pthread_mutex_unlock"),
    ("pthread_rwlock_rdlock", "pthread_rwlock_unlock"),
    ("pthread_rwlock_wrlock", "pthread_rwlock_unlock"),
    ("sem_wait", "sem_post"),
    ("EnterCriticalSection", "LeaveCriticalSection"),
]

_RESOURCE_PAIRS = [
    ("malloc", "free"),
    ("calloc", "free"),
    ("realloc", "free"),
    ("open", "close"),
    ("fopen", "fclose"),
    ("socket", "close"),
    ("mmap", "munmap"),
    ("dlopen", "dlclose"),
    ("SSL_new", "SSL_free"),
]

_SENSITIVE_NAME_FRAGMENTS = frozenset({
    "password", "passwd", "key", "secret", "token",
    "credential", "private", "passphrase", "auth",
    "encrypt", "decrypt", "cipher", "hmac",
})

_SECURE_CLEAR_CALLS = frozenset({
    "explicit_bzero", "SecureZeroMemory", "OPENSSL_cleanse",
    "sodium_memzero", "memset_s", "RtlSecureZeroMemory",
})


@dataclass
class Layer0Finding:
    """A finding from a Layer 0 binary pattern scan."""

    pattern_id: str
    function: str
    file: str = ""
    line: int = 0
    evidence_tier: str = EvidenceTier.XREF_BACKED
    description: str = ""
    detail: str = ""
    confidence: str = "high"
    vuln_type: str = ""
    dwarf_enhanced: bool = False

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "pattern_id": self.pattern_id,
            "function": self.function,
            "evidence_tier": self.evidence_tier,
            "description": self.description,
            "confidence": self.confidence,
        }
        if self.file:
            d["file"] = self.file
        if self.line:
            d["line"] = self.line
        if self.detail:
            d["detail"] = self.detail
        if self.vuln_type:
            d["vuln_type"] = self.vuln_type
        if self.dwarf_enhanced:
            d["dwarf_enhanced"] = True
        return d


@dataclass
class BinaryMetadata:
    """Binary-wide security posture from ELF/Mach-O headers."""

    has_pie: bool = False
    has_full_relro: bool = False
    has_partial_relro: bool = False
    has_nx: bool = False
    has_stack_canary: bool = False
    has_fortify: bool = False
    has_rpath: bool = False
    has_cfi: bool = False
    binary_path: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "has_pie": self.has_pie,
            "has_full_relro": self.has_full_relro,
            "has_partial_relro": self.has_partial_relro,
            "has_nx": self.has_nx,
            "has_stack_canary": self.has_stack_canary,
            "has_fortify": self.has_fortify,
            "has_rpath": self.has_rpath,
            "has_cfi": self.has_cfi,
            "binary_path": self.binary_path,
        }

    @property
    def missing_mitigations(self) -> List[str]:
        missing = []
        if not self.has_pie:
            missing.append("PIE")
        if not self.has_full_relro:
            missing.append("Full RELRO")
        if not self.has_nx:
            missing.append("NX")
        if not self.has_stack_canary:
            missing.append("Stack canary")
        if not self.has_fortify:
            missing.append("FORTIFY_SOURCE")
        return missing

    def to_finding(self) -> Optional[Layer0Finding]:
        missing = self.missing_mitigations
        if not missing:
            return None
        return Layer0Finding(
            pattern_id=PatternID.BINARY_METADATA,
            function="<binary>",
            file=self.binary_path,
            evidence_tier=EvidenceTier.HEADER_BACKED,
            description=f"missing mitigations: {', '.join(missing)}",
            confidence="high",
        )


@dataclass
class Layer0Result:
    """Aggregated results from Layer 0 scanning."""

    findings: List[Layer0Finding] = field(default_factory=list)
    metadata: Optional[BinaryMetadata] = None
    functions_scanned: int = 0
    patterns_checked: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "metadata": self.metadata.to_dict() if self.metadata else None,
            "functions_scanned": self.functions_scanned,
            "patterns_checked": self.patterns_checked,
            "finding_count": len(self.findings),
        }

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    def by_pattern(self) -> Dict[str, List[Layer0Finding]]:
        groups: Dict[str, List[Layer0Finding]] = {}
        for f in self.findings:
            groups.setdefault(f.pattern_id, []).append(f)
        return groups


# -- Pattern checkers --
# These operate on pre-extracted function data (call lists, instruction
# patterns, etc.) — the actual disassembly is done by the caller
# (r2 script or binary oracle).

def check_format_string(
    function: str,
    calls: Sequence[Dict[str, Any]],
    file: str = "",
) -> List[Layer0Finding]:
    """30.1: printf family called with argument count suggesting format string."""
    findings = []
    for call in calls:
        callee = call.get("callee", "")
        if callee not in _PRINTF_FAMILY:
            continue
        arg_count = call.get("arg_count", -1)
        if callee in ("printf", "wprintf", "syslog") and arg_count == 1:
            findings.append(Layer0Finding(
                pattern_id=PatternID.FORMAT_STRING,
                function=function, file=file,
                line=call.get("line", 0),
                description=(
                    f"{callee}() called with 1 argument "
                    f"(format string from caller's argument)"
                ),
                vuln_type="format_string",
            ))
        elif callee in ("fprintf", "dprintf") and arg_count == 2:
            findings.append(Layer0Finding(
                pattern_id=PatternID.FORMAT_STRING,
                function=function, file=file,
                line=call.get("line", 0),
                description=(
                    f"{callee}() called with 2 arguments "
                    f"(format string from caller's argument)"
                ),
                vuln_type="format_string",
            ))
    return findings


def check_unchecked_return(
    function: str,
    calls: Sequence[Dict[str, Any]],
    file: str = "",
) -> List[Layer0Finding]:
    """30.3: security-critical return values not checked."""
    findings = []
    for call in calls:
        callee = call.get("callee", "")
        if callee not in _CHECKED_RETURN_CALLS:
            continue
        if not call.get("return_checked", True):
            findings.append(Layer0Finding(
                pattern_id=PatternID.UNCHECKED_RETURN,
                function=function, file=file,
                line=call.get("line", 0),
                description=f"{callee}() return value not checked",
                confidence="high" if callee in ("malloc", "setuid") else "medium",
                vuln_type="unchecked_return",
            ))
    return findings


def check_toctou(
    function: str,
    calls: Sequence[Dict[str, Any]],
    file: str = "",
) -> List[Layer0Finding]:
    """30.6: time-of-check-to-time-of-use call pairs."""
    findings = []
    call_names = [c.get("callee", "") for c in calls]

    for check_set, use_set in _TOCTOU_PAIRS:
        has_check = any(c in check_set for c in call_names)
        has_use = any(c in use_set for c in call_names)
        if has_check and has_use:
            check_name = next(c for c in call_names if c in check_set)
            use_name = next(c for c in call_names if c in use_set)
            findings.append(Layer0Finding(
                pattern_id=PatternID.TOCTOU,
                function=function, file=file,
                description=f"TOCTOU: {check_name}() then {use_name}()",
                vuln_type="toctou",
            ))
    return findings


def check_lock_imbalance(
    function: str,
    calls: Sequence[Dict[str, Any]],
    return_paths: int = 1,
    file: str = "",
) -> List[Layer0Finding]:
    """30.7: lock acquired with no matching release anywhere in the
    function.

    Presence/absence heuristic, NOT path-sensitive: it cannot tell
    "released on the happy path but leaked on the error path" from
    "released everywhere" — only "no release call exists at all".
    (The finding text still frames the error path because that is
    where the leak bites when the heuristic fires.)"""
    findings = []
    call_names = [c.get("callee", "") for c in calls]

    for acquire, release in _LOCK_PAIRS:
        if acquire in call_names and release not in call_names:
            findings.append(Layer0Finding(
                pattern_id=PatternID.LOCK_IMBALANCE,
                function=function, file=file,
                description=(
                    f"{acquire}() without {release}() "
                    f"— possible deadlock on error path"
                ),
                confidence="high",
                vuln_type="deadlock",
            ))
    return findings


def check_missing_clear(
    function: str,
    calls: Sequence[Dict[str, Any]],
    file: str = "",
) -> List[Layer0Finding]:
    """30.8: sensitive data not cleared before return."""
    func_lower = function.lower()
    is_sensitive = any(frag in func_lower for frag in _SENSITIVE_NAME_FRAGMENTS)
    if not is_sensitive:
        return []

    call_names = {c.get("callee", "") for c in calls}
    has_secure_clear = bool(call_names & _SECURE_CLEAR_CALLS)
    has_memset = "memset" in call_names

    if has_secure_clear:
        return []

    # Plain memset does not satisfy the secure-clear requirement:
    # the compiler may elide a clear of a buffer that is dead after
    # the store (same position as check_inlined_ops). It does lower
    # confidence — the clear survives at some optimization levels.
    if has_memset:
        return [Layer0Finding(
            pattern_id=PatternID.MISSING_CLEAR,
            function=function, file=file,
            evidence_tier=EvidenceTier.HEURISTIC,
            description=(
                "sensitive function clears with plain memset() but no "
                "explicit_bzero/memset_s — compiler may elide the clear "
                "and secret data may persist on stack"
            ),
            confidence="low",
            vuln_type="sensitive_data_exposure",
        )]

    return [Layer0Finding(
        pattern_id=PatternID.MISSING_CLEAR,
        function=function, file=file,
        evidence_tier=EvidenceTier.HEURISTIC,
        description=(
            "sensitive function without explicit_bzero/memset_s "
            "before return — secret data may persist on stack"
        ),
        confidence="medium",
        vuln_type="sensitive_data_exposure",
    )]


def check_sign_confusion(
    function: str,
    instructions: Sequence[Dict[str, Any]],
    file: str = "",
) -> List[Layer0Finding]:
    """30.4: signed-to-unsigned widening (movsxd) before size argument."""
    findings = []
    for instr in instructions:
        mnemonic = instr.get("mnemonic", "")
        if mnemonic == "movsxd":
            context = instr.get("context", "")
            if any(kw in context for kw in ("malloc", "alloc", "memcpy", "size")):
                findings.append(Layer0Finding(
                    pattern_id=PatternID.SIGN_CONFUSION,
                    function=function, file=file,
                    line=instr.get("line", 0),
                    description=(
                        "movsxd (sign-extend) before size argument "
                        "— negative int becomes large unsigned"
                    ),
                    vuln_type="integer_overflow",
                ))
    return findings


def check_indirect_flow(
    function: str,
    indirect_calls: int = 0,
    has_cfi: bool = False,
    file: str = "",
) -> Optional[Layer0Finding]:
    """30.9: high density of unprotected indirect control transfers."""
    if indirect_calls <= 2:
        return None
    if has_cfi:
        return None
    return Layer0Finding(
        pattern_id=PatternID.INDIRECT_FLOW,
        function=function, file=file,
        evidence_tier=EvidenceTier.XREF_BACKED,
        description=(
            f"{indirect_calls} unprotected indirect calls/jumps "
            f"— control-flow hijack surface"
        ),
        confidence="medium",
        vuln_type="control_flow_hijack",
    )


_ALLOC_CALLS = frozenset({"malloc", "calloc", "alloca", "realloc"})

_COPY_CALLS = frozenset({
    "memcpy", "memmove", "strcpy", "strncpy", "strcat", "strncat",
    "bcopy", "wmemcpy", "wmemmove", "wcscpy", "wcsncpy",
})

_STACK_PROTECTOR_DISABLE_RE = re.compile(
    r"#\s*pragma\s+.*(?:no_stack_protector|optimize\s*\(\s*\"no-stack-protector\"\s*\))"
    r"|__attribute__\s*\(\s*\(\s*no_stack_protector\s*\)\s*\)"
    r"|__attribute__\s*\(\s*\(\s*optimize\s*\(\s*\"no-stack-protector\"\s*\)\s*\)\s*\)",
)

_SECURITY_CRITICAL_ATTR_RE = re.compile(
    r"__attribute__\s*\(\s*\(\s*(?:noinline|noreturn)\s*\)\s*\)"
    r".*?(?:auth|crypt|verify|check_pw|validate_token|hmac|sign|decrypt|encrypt)",
)

_VOLATILE_CLEAR_RE = re.compile(
    r"\bmemset\s*\([^)]*\)\s*;.*?(?:return\b|}\s*$)",
    re.DOTALL,
)

_EXPLICIT_CLEAR_RE = re.compile(
    r"\b(?:explicit_bzero|SecureZeroMemory|OPENSSL_cleanse|sodium_memzero|memset_s)\b",
)

_VOLATILE_KEYWORD_RE = re.compile(
    r"\bvolatile\b",
)

_SENSITIVE_STACK_RE = re.compile(
    r"\b(?:char|uint8_t|unsigned\s+char)\s+\w*(?:key|secret|password|passwd|token|private|passphrase|credential)\w*\s*\[",
)

_VOID_PTR_CAST_RE = re.compile(
    r"\(\s*(?:struct\s+)?\w+\s*\*\s*\)\s*(?:void_ptr|data|arg|ctx|opaque|cookie|user_data|priv)\b",
)

_UNRELATED_STRUCT_CAST_RE = re.compile(
    r"\(\s*struct\s+(\w+)\s*\*\s*\)\s*(?:\(\s*struct\s+(?!\1)\w+\s*\*\s*\)|\w+_(?:ptr|data|buf))\b",
)


def check_buffer_size_mismatch(
    function: str,
    calls: Sequence[Dict[str, Any]],
    file: str = "",
) -> List[Layer0Finding]:
    """30.2: buffer allocation size vs copy size discrepancy."""
    findings: List[Layer0Finding] = []

    alloc_sizes: Dict[str, int] = {}
    for call in calls:
        callee = call.get("callee", "")
        if callee in _ALLOC_CALLS:
            dest = call.get("dest_var", "")
            size = call.get("size", -1)
            if dest and isinstance(size, int) and size > 0:
                alloc_sizes[dest] = size

    for call in calls:
        callee = call.get("callee", "")
        if callee not in _COPY_CALLS:
            continue
        dest = call.get("dest_var", "")
        copy_size = call.get("size", -1)
        if not dest or not isinstance(copy_size, int) or copy_size <= 0:
            continue
        if dest in alloc_sizes and copy_size > alloc_sizes[dest]:
            findings.append(Layer0Finding(
                pattern_id=PatternID.BUFFER_SIZE_MISMATCH,
                function=function,
                file=file,
                line=call.get("line", 0),
                description=(
                    f"{callee}() copies {copy_size} bytes into "
                    f"buffer allocated with {alloc_sizes[dest]} bytes"
                ),
                confidence="high",
                vuln_type="buffer_overflow",
            ))

    return findings


def check_compiler_security(
    function: str,
    source: str,
    file: str = "",
) -> List[Layer0Finding]:
    """30.5: functions that disable compiler security features."""
    findings: List[Layer0Finding] = []

    for m in _STACK_PROTECTOR_DISABLE_RE.finditer(source):
        findings.append(Layer0Finding(
            pattern_id=PatternID.COMPILER_SECURITY,
            function=function,
            file=file,
            evidence_tier=EvidenceTier.XREF_BACKED,
            description=(
                "stack protector explicitly disabled — "
                "stack buffer overflows become exploitable"
            ),
            confidence="high",
            vuln_type="missing_mitigation",
        ))
        break  # one finding per function is sufficient

    for m in _SECURITY_CRITICAL_ATTR_RE.finditer(source):
        findings.append(Layer0Finding(
            pattern_id=PatternID.COMPILER_SECURITY,
            function=function,
            file=file,
            evidence_tier=EvidenceTier.HEURISTIC,
            description=(
                "noinline/noreturn on security-critical path — "
                "may alter control flow assumptions"
            ),
            confidence="medium",
            vuln_type="missing_mitigation",
        ))
        break

    return findings


def check_inlined_ops(
    function: str,
    source: str,
    file: str = "",
) -> List[Layer0Finding]:
    """30.10: inlined security operations that may be optimized away."""
    findings: List[Layer0Finding] = []

    if not _SENSITIVE_STACK_RE.search(source):
        return findings

    if _EXPLICIT_CLEAR_RE.search(source):
        return findings

    if _VOLATILE_CLEAR_RE.search(source) and not _VOLATILE_KEYWORD_RE.search(source):
        findings.append(Layer0Finding(
            pattern_id=PatternID.INLINED_OP,
            function=function,
            file=file,
            evidence_tier=EvidenceTier.HEURISTIC,
            description=(
                "memset on sensitive stack buffer before return "
                "without volatile — compiler may elide the clear"
            ),
            confidence="medium",
            vuln_type="sensitive_data_exposure",
        ))

    return findings


def check_dwarf_types(
    function: str,
    source: str,
    file: str = "",
) -> List[Layer0Finding]:
    """30.11: type confusion patterns visible in source/DWARF info."""
    findings: List[Layer0Finding] = []

    for m in _VOID_PTR_CAST_RE.finditer(source):
        findings.append(Layer0Finding(
            pattern_id=PatternID.DWARF_ENHANCED,
            function=function,
            file=file,
            evidence_tier=EvidenceTier.HEURISTIC,
            description=(
                "void* cast to typed pointer without validation — "
                "type confusion risk"
            ),
            confidence="medium",
            vuln_type="type_confusion",
            dwarf_enhanced=True,
        ))
        break

    for m in _UNRELATED_STRUCT_CAST_RE.finditer(source):
        findings.append(Layer0Finding(
            pattern_id=PatternID.DWARF_ENHANCED,
            function=function,
            file=file,
            evidence_tier=EvidenceTier.HEURISTIC,
            description=(
                f"cast between unrelated struct pointer types "
                f"(struct {m.group(1)}) — type confusion risk"
            ),
            confidence="medium",
            vuln_type="type_confusion",
            dwarf_enhanced=True,
        ))
        break

    return findings


# Coarse callee extraction from raw function source. Deliberately
# regex-level: Layer 0 is a cheap pre-sweep whose findings are
# hypothesis SIGNALS attached to the evidence index, never verdicts —
# a parse-grade extractor would cost more than the tier is worth.
# Callers that HAVE real call data (disassembly, call graphs) should
# pass it instead; this exists so a source-only caller no longer
# passes calls=[] and silently disables the six calls-based checks.
_CALLEE_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_CALLEE_KEYWORDS = frozenset({
    # C/C++ control flow / operators that precede '('
    "if", "for", "while", "switch", "return", "sizeof", "defined",
    "catch", "assert", "alignof", "typeof", "decltype", "case",
    # declaration-ish shapes the regex can hit
    "int", "char", "long", "short", "float", "double", "void",
    "unsigned", "signed", "struct", "union", "enum", "static",
    # Python / Go / JS keywords that precede '('
    "def", "lambda", "func", "function", "elif", "except",
    "raise", "with", "yield", "await", "not", "and", "or", "in",
})


def callees_from_source(source: str) -> List[Dict[str, Any]]:
    """Best-effort ``[{"callee": name}, ...]`` from function source.

    Over-approximates (a macro invocation and a call look identical;
    the function's own definition line contributes its name) — fine
    for the presence/absence checks above, the wrong tool for
    anything that counts.
    """
    seen: set[str] = set()
    out: List[Dict[str, Any]] = []
    for m in _CALLEE_RE.finditer(source):
        name = m.group(1)
        if name in _CALLEE_KEYWORDS or name in seen:
            continue
        seen.add(name)
        out.append({"callee": name})
    return out


def scan_function(
    function: str,
    calls: Sequence[Dict[str, Any]],
    *,
    instructions: Optional[Sequence[Dict[str, Any]]] = None,
    indirect_calls: int = 0,
    has_cfi: bool = False,
    return_paths: int = 1,
    source: str = "",
    file: str = "",
    language: str = "c",
) -> List[Layer0Finding]:
    """Run all applicable Layer 0 checks on a single function.

    ``language`` gates the C-idiom checks when the scan runs over
    SOURCE rather than disassembly: missing-secure-clear expects
    explicit_bzero/memset discipline that only exists in C-family
    code — on Python/Go/JS it fires on every function whose NAME
    contains a sensitive fragment (calibrated: 305 of 346 findings
    on a large mixed-language tree were exactly that shape).
    Default "c" preserves the binary-analysis callers' behaviour.
    """
    findings: List[Layer0Finding] = []
    c_family = language in ("c", "cpp", "c++", "objc")

    findings.extend(check_format_string(function, calls, file))
    findings.extend(check_buffer_size_mismatch(function, calls, file))
    findings.extend(check_unchecked_return(function, calls, file))
    findings.extend(check_toctou(function, calls, file))
    findings.extend(check_lock_imbalance(function, calls, return_paths, file))
    if c_family:
        findings.extend(check_missing_clear(function, calls, file))

    if instructions:
        findings.extend(check_sign_confusion(function, instructions, file))

    icf = check_indirect_flow(function, indirect_calls, has_cfi, file)
    if icf:
        findings.append(icf)

    if source:
        findings.extend(check_compiler_security(function, source, file))
        findings.extend(check_inlined_ops(function, source, file))
        findings.extend(check_dwarf_types(function, source, file))

    return findings


def format_layer0_context(
    findings: Sequence[Layer0Finding],
    metadata: Optional[BinaryMetadata] = None,
) -> str:
    """Render Layer 0 findings for LLM prompt injection."""
    if not findings and not metadata:
        return ""

    lines = ["### Binary Layer 0 (mechanical pattern scan)"]

    if metadata:
        missing = metadata.missing_mitigations
        if missing:
            lines.append(f"**Binary mitigations missing:** {', '.join(missing)}")
        else:
            lines.append("**Binary mitigations:** all present (PIE, RELRO, NX, canary, FORTIFY)")
        lines.append("")

    if findings:
        lines.append(f"**{len(findings)} mechanical findings:**")
        for f in findings[:15]:
            tier = f.evidence_tier.upper()
            lines.append(f"- [{tier}] `{f.function}()`: {f.description}")
        if len(findings) > 15:
            lines.append(f"  ...and {len(findings) - 15} more")

    return "\n".join(lines)


def format_layer0_summary(result: Layer0Result) -> str:
    if result.finding_count == 0:
        return "Layer 0: no mechanical findings"
    groups = result.by_pattern()
    parts = [f"{pid}={len(fs)}" for pid, fs in sorted(groups.items())]
    return (
        f"Layer 0: {result.finding_count} findings across "
        f"{len(groups)} patterns ({', '.join(parts[:5])})"
    )
