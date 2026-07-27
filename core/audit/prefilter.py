"""Mechanical pre-filter for /audit.

Runs cheap deterministic checks BEFORE the LLM call to:
  1. Skip trivial functions that cannot contain vulnerabilities
  2. Pre-identify known-pattern bugs via Semgrep rules
  3. Feed tool evidence into the LLM prompt so it reasons about
     evidence, not classifies from scratch

This is the architectural fix for the orchestrator's LLM-as-classifier
gap: the design says "LLM generates hypotheses; tools validate" but the
orchestrator was calling the LLM once for a verdict without any tool
input. The pre-filter runs tools first, and the LLM reasons about the
tool results.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from ._util import safe_join

logger = logging.getLogger(__name__)

_DANGEROUS_C_APIS = frozenset({
    "strcpy", "strcat", "sprintf", "gets", "scanf", "vsprintf",
    "memcpy", "memmove", "memset",
    "strncpy", "strncat", "snprintf",
    "malloc", "calloc", "realloc", "free",
    "fopen", "open", "read", "write", "recv", "send",
    "execve", "system", "popen",
    "atoi", "atol", "atof", "strtol", "strtoul",
    "ioctl", "fcntl", "mmap", "munmap",
})

_DANGEROUS_PY_APIS = frozenset({
    "eval", "exec", "compile",
    "os.system", "os.popen", "subprocess.call", "subprocess.run",
    "subprocess.Popen", "subprocess.check_output",
    "os.path.join", "open",
    "pickle.loads", "pickle.load", "yaml.load",
    "ctypes.CDLL", "ctypes.cdll",
    "__import__",
})

_SECURITY_SENSITIVE_NAMES = frozenset({
    "password", "passwd", "secret", "token", "key", "apikey",
    "api_key", "credential", "credentials", "auth", "private_key",
    "session", "cookie", "nonce", "salt", "hash", "digest",
    "passphrase", "pin", "otp", "totp", "hmac",
})

_LANG_EXTENSIONS = {
    ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
    ".py": "python", ".pyw": "python",
    ".java": "java",
    ".js": "javascript", ".ts": "typescript",
    ".go": "go",
    ".rs": "rust",
}


@dataclass
class PrefilterHit:
    """A single mechanical finding from pre-filtering."""
    rule_id: str
    message: str
    line: int = 0
    severity: str = "warning"
    tool: str = "prefilter"


@dataclass
class PrefilterResult:
    """Result of running the pre-filter on one function."""
    file: str
    function: str
    skip_llm: bool = False
    skip_reason: str = ""
    hits: List[PrefilterHit] = field(default_factory=list)
    has_dangerous_apis: bool = False
    has_pointer_ops: bool = False
    has_array_access: bool = False
    has_user_input: bool = False
    language: str = ""
    sloc: int = 0

    @property
    def mechanical_evidence(self) -> str:
        """Format hits as text for LLM context injection."""
        if not self.hits:
            return ""
        lines = ["### Mechanical pre-sweep results"]
        lines.append(
            "The following patterns were detected by deterministic tools "
            "BEFORE your review. Use these as starting points for "
            "hypothesis formation — do NOT simply repeat them as findings. "
            "Verify each via code reading and assess exploitability."
        )
        for hit in self.hits:
            lines.append(
                f"- **{hit.rule_id}** (line {hit.line}): {hit.message}"
            )
        return "\n".join(lines)


def detect_language(file_path: str) -> str:
    """Detect language from file extension."""
    suffix = Path(file_path).suffix.lower()
    return _LANG_EXTENSIONS.get(suffix, "")


def run_prefilter(
    *,
    target_path: Path,
    file_path: str,
    function_name: str,
    source: str,
    line_start: int = 0,
    line_end: int = 0,
    callers: Optional[List[Dict[str, Any]]] = None,
    callees: Optional[List[Dict[str, Any]]] = None,
    metadata: Optional[Dict[str, Any]] = None,
    sink_unreachable: bool = False,
) -> PrefilterResult:
    """Run mechanical pre-filter on a single function.

    This is intentionally cheap (no subprocess calls, no external tools).
    It analyses the source text directly for known patterns.

    Returns a PrefilterResult with skip_llm=True if the function is
    trivially clean, or hits populated with mechanical findings.
    """
    lang = detect_language(file_path)
    source_lines = [ln for ln in source.splitlines() if ln.strip()]
    sloc = len(source_lines)

    result = PrefilterResult(
        file=file_path,
        function=function_name,
        language=lang,
        sloc=sloc,
    )

    if lang in ("c", "cpp"):
        _check_c_patterns(result, source, line_start, callers, callees)
    elif lang == "python":
        _check_python_patterns(result, source, line_start, callers, callees)

    if _is_trivially_clean(result, source, callers, callees, metadata):
        result.skip_llm = True

    if not result.skip_llm and sink_unreachable:
        if _is_sink_unreachable_clean(result, source, sloc):
            result.skip_llm = True
            result.skip_reason = "no sink path + no logic-class signals"

    return result


def _is_trivially_clean(
    result: PrefilterResult,
    source: str,
    callers: Optional[List[Dict[str, Any]]],
    callees: Optional[List[Dict[str, Any]]],
    metadata: Optional[Dict[str, Any]],
) -> bool:
    """Determine if a function can be skipped without LLM review.

    Conservative: only skips functions that CANNOT contain vulnerabilities.
    A false skip_llm=True is a missed bug, so err toward sending to LLM.
    """
    if result.hits:
        return False

    if result.sloc > 8:
        return False

    if result.has_dangerous_apis or result.has_pointer_ops:
        return False

    if result.has_array_access or result.has_user_input:
        return False

    callees_list = callees or []
    if callees_list:
        callee_names = {c.get("name", "") for c in callees_list}
        if callee_names & _DANGEROUS_C_APIS:
            return False

    if _is_simple_accessor(source, result.language):
        result.skip_reason = "simple accessor (return field/constant)"
        return True

    return False


_AUTH_KEYWORDS = frozenset({
    "role", "permission", "session", "token", "auth", "authz",
    "authorize", "authenticate", "login", "logout", "privilege",
    "access_control", "acl", "rbac",
})

_CRYPTO_APIS = frozenset({
    "encrypt", "decrypt", "hash", "hmac", "sign", "verify",
    "digest", "cipher", "aes", "rsa", "sha", "md5",
    "pbkdf2", "scrypt", "bcrypt", "argon2",
    "EVP_", "RAND_", "SSL_", "TLS_",
})

_CONCURRENCY_OPS = frozenset({
    "mutex", "lock", "unlock", "atomic", "pthread_mutex",
    "spinlock", "semaphore", "rwlock", "critical_section",
    "synchronized",
})


def _is_sink_unreachable_clean(
    result: PrefilterResult,
    source: str,
    sloc: int,
) -> bool:
    """Skip sink-unreachable functions with no logic-class signals.

    Only skips when ALL of:
      - sink_unreachable is True (caller already checked)
      - no auth/authz keywords
      - no crypto API calls
      - no lock/mutex/atomic operations
      - no comparison to status-code-like constants
      - SLOC ≤ 30
      - no prefilter hits
    """
    if result.hits:
        return False

    if sloc > 30:
        return False

    source_lower = source.lower()

    if any(kw in source_lower for kw in _AUTH_KEYWORDS):
        return False

    if any(api in source_lower for api in _CRYPTO_APIS):
        return False

    if any(op in source_lower for op in _CONCURRENCY_OPS):
        return False

    if re.search(r"==\s*(0x[0-9a-fA-F]+|[4-5]\d{2})\b", source):
        return False

    return True


def _is_simple_accessor(source: str, lang: str) -> bool:
    """Check if a function is a trivial field accessor or constant return."""
    stripped = source.strip()
    lines = [ln.strip() for ln in stripped.splitlines() if ln.strip()]

    code_lines = [
        ln for ln in lines
        if not ln.startswith("//") and not ln.startswith("/*")
        and not ln.startswith("*") and not ln.startswith("#")
        and ln not in ("{", "}")
    ]

    if len(code_lines) > 3:
        return False

    body = " ".join(code_lines)

    if lang in ("c", "cpp"):
        if re.search(r"return\s+\w+->\w+\s*;$", body):
            return True
        if re.search(r"return\s+\w+\.\w+\s*;$", body):
            return True
        if re.search(r"return\s+\d+\s*;$", body):
            return True
        if re.search(r"return\s+NULL\s*;$", body):
            return True
    elif lang == "python":
        if re.search(r"return\s+self\.\w+$", body):
            return True
        m = re.search(r"return\s+(\w+)$", body)
        if m:
            returned = m.group(1).lower()
            if not any(s in returned for s in _SECURITY_SENSITIVE_NAMES):
                return True

    return False


def _check_c_patterns(
    result: PrefilterResult,
    source: str,
    line_start: int,
    callers: Optional[List[Dict[str, Any]]],
    callees: Optional[List[Dict[str, Any]]],
) -> None:
    """Check C/C++ source for known vulnerability patterns."""
    callee_names = set()
    if callees:
        callee_names = {c.get("name", "") for c in callees}

    result.has_dangerous_apis = bool(callee_names & _DANGEROUS_C_APIS)

    result.has_pointer_ops = bool(
        re.search(r'\*\s*\(.*\+', source)
        or re.search(r'->\s*\w+\s*\[', source)
        or re.search(r'\(\w+\s*\*\)\s*\w+', source)
    )

    result.has_array_access = bool(re.search(r'\w+\s*\[', source))

    for i, line in enumerate(source.splitlines(), start=line_start):
        stripped = line.strip()

        if re.search(r'\bstrcpy\s*\(', stripped):
            result.hits.append(PrefilterHit(
                rule_id="unbounded-strcpy",
                message="strcpy() has no length limit — use strncpy or strlcpy",
                line=i,
                severity="error",
            ))

        if re.search(r'\bsprintf\s*\(', stripped):
            result.hits.append(PrefilterHit(
                rule_id="unbounded-sprintf",
                message="sprintf() has no length limit — use snprintf",
                line=i,
                severity="error",
            ))

        if re.search(r'\bgets\s*\(', stripped):
            result.hits.append(PrefilterHit(
                rule_id="gets-usage",
                message="gets() is always exploitable — use fgets",
                line=i,
                severity="error",
            ))

        match = re.search(
            r'snprintf\s*\([^,]+,\s*sizeof\s*\([^)]+\)\s*,'
            r'\s*"[^"]*%s[^"]*"',
            stripped,
        )
        if match:
            result.hits.append(PrefilterHit(
                rule_id="format-string-concat",
                message=(
                    "snprintf with %s and user-controlled input may "
                    "enable format string or overflow if concatenated"
                ),
                line=i,
                severity="warning",
            ))

        if re.search(
            r"(SELECT|INSERT|UPDATE|DELETE)\b.*%s",
            stripped, re.IGNORECASE,
        ):
            result.hits.append(PrefilterHit(
                rule_id="sql-string-format",
                message="SQL query built with string formatting — SQL injection risk",
                line=i,
                severity="error",
            ))

        if re.search(r'\buint16_t\b.*\boffset\b|\buint16_t\b.*\blen\b', stripped):
            result.hits.append(PrefilterHit(
                rule_id="narrow-integer-size",
                message=(
                    "uint16_t used for offset/length — wraps at 65536, "
                    "may cause infinite loop or re-processing"
                ),
                line=i,
                severity="warning",
            ))

        if re.search(r'\batoi\s*\(|\batol\s*\(', stripped):
            if not re.search(r'if\s*\(', stripped):
                result.hits.append(PrefilterHit(
                    rule_id="atoi-unchecked",
                    message="atoi/atol does not report errors — use strtol with errno check",
                    line=i,
                    severity="warning",
                ))

        if re.search(r'\bmalloc\s*\([^)]*\*', stripped):
            result.hits.append(PrefilterHit(
                rule_id="malloc-multiply-overflow",
                message=(
                    "malloc with multiplication — integer overflow wraps "
                    "allocation size, leading to heap buffer overflow"
                ),
                line=i,
                severity="warning",
            ))

    _check_c_missing_bounds(result, source, line_start)
    _check_c_use_after_free(result, source, line_start)
    _check_c_toctou(result, source, line_start)
    _check_c_post_loop_oob(result, source, line_start)


def _check_c_missing_bounds(
    result: PrefilterResult,
    source: str,
    line_start: int,
) -> None:
    """Check for array access on function parameters without bounds checks."""
    lines = source.splitlines()

    params_with_index_access = set()
    for i, line in enumerate(lines, start=line_start):
        for m in re.finditer(r'(\w+)\s*\[(\w+)\]', line):
            index_var = m.group(2)
            if not index_var.isdigit():
                params_with_index_access.add((index_var, i))

    for var, access_line in params_with_index_access:
        has_check = False
        for line in lines:
            if re.search(
                rf'\b{re.escape(var)}\s*(?:[<>]=?)\s*\w+|'
                rf'\w+\s*(?:[<>]=?)\s*{re.escape(var)}|'
                rf'if\s*\(.*{re.escape(var)}',
                line,
            ):
                has_check = True
                break

        if not has_check:
            result.hits.append(PrefilterHit(
                rule_id="array-index-unchecked",
                message=(
                    f"variable '{var}' used as array index at line "
                    f"{access_line} without visible bounds check"
                ),
                line=access_line,
                severity="warning",
            ))


def _check_c_use_after_free(
    result: PrefilterResult,
    source: str,
    line_start: int,
) -> None:
    """Detect potential use-after-free and double-free within a function.

    Tracks which pointer variables are passed to free(), then checks
    whether they are dereferenced or freed again afterwards.
    """
    lines = source.splitlines()
    freed_vars: Dict[str, int] = {}

    for i, line in enumerate(lines, start=line_start):
        stripped = line.strip()

        free_match = re.search(r'\bfree\s*\(\s*(\w+)\s*\)', stripped)
        if free_match:
            var = free_match.group(1)
            if var in freed_vars:
                result.hits.append(PrefilterHit(
                    rule_id="double-free",
                    message=(
                        f"'{var}' freed at line {freed_vars[var]} "
                        f"and again at line {i}"
                    ),
                    line=i,
                    severity="error",
                ))
            freed_vars[var] = i
            continue

        for var, free_line in list(freed_vars.items()):
            if re.search(rf'\b{re.escape(var)}\s*->', stripped):
                result.hits.append(PrefilterHit(
                    rule_id="use-after-free",
                    message=(
                        f"'{var}' freed at line {free_line}, "
                        f"dereferenced at line {i}"
                    ),
                    line=i,
                    severity="error",
                ))
            elif re.search(rf'\*\s*{re.escape(var)}\b', stripped):
                result.hits.append(PrefilterHit(
                    rule_id="use-after-free",
                    message=(
                        f"'{var}' freed at line {free_line}, "
                        f"dereferenced at line {i}"
                    ),
                    line=i,
                    severity="error",
                ))

        for var in list(freed_vars):
            if re.search(rf'\b{re.escape(var)}\s*(?<!=)=(?!=)\s*', stripped):
                if not re.search(r'\bfree\s*\(', stripped):
                    del freed_vars[var]


def _check_c_toctou(
    result: PrefilterResult,
    source: str,
    line_start: int,
) -> None:
    """Detect time-of-check-to-time-of-use patterns.

    Looks for access()/stat() followed by open()/fopen() on similar
    paths — classic filesystem TOCTOU race.
    """
    lines = source.splitlines()
    check_line = None
    check_path_var = None

    for i, line in enumerate(lines, start=line_start):
        stripped = line.strip()

        check_match = re.search(
            r'\b(access|stat|lstat)\s*\(\s*(\w+)', stripped,
        )
        if check_match:
            check_line = i
            check_path_var = check_match.group(2)
            continue

        if check_line and check_path_var:
            use_match = re.search(
                r'\b(open|fopen|creat|unlink|rename|chmod|chown)\s*\(\s*'
                + re.escape(check_path_var),
                stripped,
            )
            if use_match:
                result.hits.append(PrefilterHit(
                    rule_id="toctou-filesystem",
                    message=(
                        f"check at line {check_line} "
                        f"({check_path_var}) followed by use at "
                        f"line {i} — filesystem TOCTOU race"
                    ),
                    line=i,
                    severity="warning",
                ))
                check_line = None
                check_path_var = None


def _check_c_post_loop_oob(
    result: PrefilterResult,
    source: str,
    line_start: int,
) -> None:
    """Detect post-loop out-of-bounds writes.

    Looks for loops with `index < capacity` guards where the index
    variable is used in a write after the loop body.  The index can
    equal the capacity when the loop exits, making `buf[index]` OOB.
    """
    lines = source.splitlines()
    loop_re = re.compile(
        r'\b(?:while|for)\b.*\b(\w+)\s*<\s*(\w+)\b'
        r'(?!\s*[-+*/])',
    )
    brace_depth = 0
    loop_index_var: Optional[str] = None
    loop_cap_var: Optional[str] = None
    loop_line: Optional[int] = None
    in_loop = False
    loop_brace_depth = 0
    braceless_body = False

    for i, line in enumerate(lines, start=line_start):
        stripped = line.strip()

        if braceless_body:
            braceless_body = False
            continue

        if not in_loop:
            m = loop_re.search(stripped)
            if m:
                loop_index_var = m.group(1)
                loop_cap_var = m.group(2)
                loop_line = i
                if '{' in stripped:
                    in_loop = True
                    loop_brace_depth = brace_depth + 1
                else:
                    braceless_body = True
                    continue
        if in_loop:
            brace_depth += stripped.count('{') - stripped.count('}')
            if brace_depth < loop_brace_depth:
                in_loop = False
                continue
            continue

        if loop_index_var and not in_loop:
            idx_esc = re.escape(loop_index_var)
            if re.search(
                rf'\bif\b.*\b{idx_esc}\b.*<|'
                rf'\bif\b.*\b{idx_esc}\b.*>|'
                rf'\bif\b.*<.*\b{idx_esc}\b',
                stripped,
            ):
                loop_index_var = None
                loop_cap_var = None
                loop_line = None
                continue

            write_re = re.compile(
                rf'\b\w+\s*\[\s*{idx_esc}\s*\]\s*=',
            )
            if write_re.search(stripped):
                result.hits.append(PrefilterHit(
                    rule_id="post-loop-oob-write",
                    message=(
                        f"write using loop index '{loop_index_var}' "
                        f"after loop at line {loop_line} — index can "
                        f"equal '{loop_cap_var}' at loop exit (off-by-one)"
                    ),
                    line=i,
                    severity="warning",
                ))
                loop_index_var = None
                loop_cap_var = None
                loop_line = None


def _check_python_patterns(
    result: PrefilterResult,
    source: str,
    line_start: int,
    callers: Optional[List[Dict[str, Any]]],
    callees: Optional[List[Dict[str, Any]]],
) -> None:
    """Check Python source for known vulnerability patterns."""
    callee_names = set()
    if callees:
        callee_names = {c.get("name", "") for c in callees}

    result.has_dangerous_apis = bool(callee_names & _DANGEROUS_PY_APIS)

    for i, line in enumerate(source.splitlines(), start=line_start):
        stripped = line.strip()

        if re.search(r'\bos\.path\.join\b', stripped):
            if not re.search(
                r'os\.path\.realpath|os\.path\.abspath|'
                r'\.startswith\(|resolve\(\)',
                source,
            ):
                result.hits.append(PrefilterHit(
                    rule_id="path-join-no-containment",
                    message=(
                        "os.path.join without path containment check "
                        "(realpath/startswith) — path traversal risk"
                    ),
                    line=i,
                    severity="warning",
                ))

        if re.search(r'\bopen\s*\(', stripped):
            if re.search(r'os\.path\.join|user|request|param|filename', source):
                if not re.search(
                    r'os\.path\.realpath|\.startswith\(|resolve\(\)',
                    source,
                ):
                    result.hits.append(PrefilterHit(
                        rule_id="open-user-controlled-path",
                        message=(
                            "open() with potentially user-controlled path "
                            "and no containment check"
                        ),
                        line=i,
                        severity="warning",
                    ))

        if re.search(r'\beval\s*\(|\bexec\s*\(', stripped):
            result.hits.append(PrefilterHit(
                rule_id="eval-exec",
                message="eval/exec with potentially untrusted input — code injection risk",
                line=i,
                severity="error",
            ))

        if re.search(r'\bsubprocess\.\w+\(.*shell\s*=\s*True', stripped):
            result.hits.append(PrefilterHit(
                rule_id="subprocess-shell-true",
                message="subprocess with shell=True — command injection risk",
                line=i,
                severity="error",
            ))

        if re.search(r'\bpickle\.loads?\s*\(', stripped):
            result.hits.append(PrefilterHit(
                rule_id="pickle-untrusted",
                message="pickle.load/loads can execute arbitrary code on untrusted data",
                line=i,
                severity="error",
            ))

        if re.search(r'\byaml\.load\s*\(', stripped):
            if not re.search(r'Loader\s*=\s*yaml\.SafeLoader', stripped):
                result.hits.append(PrefilterHit(
                    rule_id="yaml-unsafe-load",
                    message="yaml.load without SafeLoader can execute arbitrary code",
                    line=i,
                    severity="error",
                ))


def run_prefilter_batch(
    *,
    target_path: Path,
    functions: List[Dict[str, Any]],
) -> Dict[str, PrefilterResult]:
    """Run pre-filter on a batch of functions.

    Returns dict keyed by 'file:function'.
    """
    results = {}
    for func in functions:
        file_path = func.get("file", "")
        name = func.get("name", "")
        source = func.get("source", "")

        if not source:
            full = safe_join(target_path, file_path) if file_path else None
            if full is not None and full.exists():
                try:
                    all_lines = full.read_text(errors="replace").splitlines()
                    start = max(0, func.get("line_start", 1) - 1)
                    end = func.get("line_end") or (start + 50)
                    source = "\n".join(all_lines[start:end])
                except OSError:
                    source = ""

        result = run_prefilter(
            target_path=target_path,
            file_path=file_path,
            function_name=name,
            source=source,
            line_start=func.get("line_start", 0),
            line_end=func.get("line_end", 0),
            callers=func.get("callers"),
            callees=func.get("callees"),
            metadata=func.get("metadata"),
        )
        results[f"{file_path}:{name}"] = result

    return results
