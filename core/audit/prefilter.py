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
from typing import Any

from ._util import safe_join

logger = logging.getLogger(__name__)

# Universal libc/POSIX surface plus a marked kernel SEED core
# (kmalloc/kzalloc/kfree exemplars + the classic copy_from_user /
# copy_to_user boundary). The kernel API bulk (kv*/devm_* allocators,
# __copy_*_user / _copy_*_iter variants, ...) is served by the
# linux_kernel vocab pack through domain_vocab below — do not grow the
# kernel subset here; teach the study loop / pack instead.
_DANGEROUS_C_APIS = frozenset({
    "strcpy", "strcat", "sprintf", "gets", "scanf", "vsprintf",
    "memcpy", "memmove", "memset",
    "strncpy", "strncat", "snprintf",
    "malloc", "calloc", "realloc", "free",
    "kmalloc", "kzalloc", "kfree",
    "copy_from_user", "copy_to_user",
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

_DANGEROUS_GO_CALLEES = frozenset({
    "Command", "CommandContext",
    "Query", "QueryRow", "Exec",
    "Unmarshal", "Decode", "NewDecoder",
    "Open", "Create", "Remove", "ReadFile", "WriteFile",
    "OpenFile", "RemoveAll",
})

_DANGEROUS_RUST_CALLEES = frozenset({
    "transmute", "from_raw_parts", "from_raw_parts_mut",
    "as_ptr", "as_mut_ptr",
    "write_volatile", "read_volatile",
})

_DANGEROUS_PHP_CALLEES = frozenset({
    "eval", "exec", "system", "passthru", "shell_exec", "popen",
    "proc_open", "pcntl_exec",
    "include", "include_once", "require", "require_once",
    "unserialize", "preg_replace",
    "file_get_contents", "file_put_contents", "fopen", "fwrite",
    "readfile", "unlink", "rename", "copy", "mkdir", "rmdir",
    "extract", "parse_str", "assert",
    "mysql_query", "mysqli_query", "pg_query",
    "header", "setcookie",
})

_DANGEROUS_JAVA_CALLEES = frozenset({
    "exec", "getRuntime",
    "executeQuery", "executeUpdate", "prepareStatement",
    "readObject", "readUnshared", "readResolve",
    "forName", "newInstance", "getMethod", "invoke",
    "getConnection", "createStatement",
    "evaluate", "compile",
    "parse", "unmarshal",
    "delete", "renameTo", "createNewFile", "createTempFile",
    "getParameter", "getHeader", "getCookies",
    "sendRedirect", "forward", "include",
})

_DANGEROUS_JS_CALLEES = frozenset({
    "eval", "Function",
    "exec", "execSync", "spawn", "spawnSync", "execFile",
    "innerHTML", "outerHTML", "insertAdjacentHTML", "write", "writeln",
    "createElement",
    "query", "execute",
    "readFile", "readFileSync", "writeFile", "writeFileSync",
    "unlink", "unlinkSync", "rename", "renameSync",
    "createReadStream", "createWriteStream",
    "fetch", "request",
    "deserialize", "parse",
    "compile", "render",
})

_DANGEROUS_LUA_CALLEES = frozenset({
    "loadstring", "loadfile", "dofile", "load",
    "execute", "popen",
    "open", "remove", "rename", "tmpname",
    "rawset", "rawget", "rawequal", "rawlen",
    "setfenv", "getfenv",
    "setmetatable",
})

_DANGEROUS_PERL_CALLEES = frozenset({
    "eval", "exec", "system",
    "open", "sysopen", "unlink", "rename", "chmod", "chown",
    "readdir", "opendir",
    "require", "do",
})

_SECURITY_SENSITIVE_NAMES = frozenset({
    "password", "passwd", "secret", "token", "key", "apikey",
    "api_key", "credential", "credentials", "auth", "private_key",
    "session", "cookie", "nonce", "salt", "hash", "digest",
    "passphrase", "pin", "otp", "totp", "hmac",
})

_LANG_EXTENSIONS = {
    ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
    ".hpp": "cpp", ".hh": "cpp",
    ".py": "python", ".pyw": "python",
    ".java": "java",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".php": "php",
    ".lua": "lua",
    ".pl": "perl", ".pm": "perl",
    ".rb": "ruby",
    ".cs": "csharp",
}


@dataclass
class PrefilterHit:
    """A single mechanical finding from pre-filtering."""
    rule_id: str
    message: str
    line: int = 0
    severity: str = "warning"
    tool: str = "prefilter"


# ── Evidence↔hypothesis correlation ─────────────────────────────────
#
# A prefilter/SARIF hit only supports a hypothesis in the same
# vulnerability family: a strcpy hit says nothing about a SQL-injection
# claim.  Each rule id maps to a coarse CWE family; a hit whose family
# does not correlate with the hypothesis text (or stated CWE) may be
# shown as review context but must not stamp evidence_tool or drive
# suspicious→finding promotion.

PREFILTER_RULE_FAMILY: dict[str, str] = {
    # C / C++
    "unbounded-strcpy": "memory",
    "unbounded-sprintf": "memory",
    "gets-usage": "memory",
    "format-string-concat": "memory",
    "sql-string-format": "injection",
    "narrow-integer-size": "memory",
    "atoi-unchecked": "memory",
    "malloc-multiply-overflow": "memory",
    "assign-in-conditional": "other",
    "array-index-unchecked": "memory",
    "double-free": "memory",
    "use-after-free": "memory",
    "toctou-filesystem": "concurrency",
    "post-loop-oob-write": "memory",
    # Python
    "path-join-no-containment": "path",
    "open-user-controlled-path": "path",
    "eval-exec": "injection",
    "subprocess-shell-true": "injection",
    "pickle-untrusted": "injection",
    "yaml-unsafe-load": "injection",
    # Go
    "go-exec-command": "injection",
    "go-unsafe-usage": "memory",
    "go-sql-string-concat": "injection",
    "go-template-unescaped": "injection",
    "go-path-traversal": "path",
    "go-ssrf": "injection",
    "go-deserialize-interface": "injection",
    "go-gob-decode": "injection",
    "go-cgo-call": "memory",
    # Rust
    "rust-unsafe-block": "memory",
    "rust-command-exec": "injection",
    "rust-raw-pointer-cast": "memory",
    "rust-transmute": "memory",
    "rust-ffi-extern": "memory",
    "rust-no-mangle": "memory",
    "rust-from-raw-parts": "memory",
    "rust-sql-format": "injection",
    # PHP
    "php-eval-variable": "injection",
    "php-command-exec": "injection",
    "php-file-inclusion": "path",
    "php-unserialize": "injection",
    "php-preg-replace-e": "injection",
    "php-sql-injection": "injection",
    "php-xss": "injection",
    "php-extract-superglobal": "injection",
    "php-path-traversal": "path",
    "php-open-redirect": "other",
    # Java
    "java-runtime-exec": "injection",
    "java-process-builder": "injection",
    "java-deserialization": "injection",
    "java-sql-concat": "injection",
    "java-reflection": "injection",
    "java-path-traversal": "path",
    "java-xxe": "injection",
    "java-script-injection": "injection",
    "java-ldap-injection": "injection",
    # JavaScript / TypeScript
    "js-eval": "injection",
    "js-function-constructor": "injection",
    "js-command-exec": "injection",
    "js-xss-dom": "injection",
    "js-react-dangerous-html": "injection",
    "js-sql-injection": "injection",
    "js-path-traversal": "path",
    "js-unsafe-parse": "injection",
    "js-open-redirect": "other",
    "js-regex-injection": "injection",
    # Lua
    "lua-loadstring": "injection",
    "lua-file-exec": "injection",
    "lua-os-execute": "injection",
    "lua-io-popen": "injection",
    "lua-io-open": "path",
    "lua-setfenv": "other",
    "lua-metatable-abuse": "other",
    "lua-raw-access": "other",
    "lua-debug-library": "other",
    "lua-format-injection": "injection",
    # Perl
    "perl-eval": "injection",
    "perl-command-exec": "injection",
    "perl-backtick-injection": "injection",
    "perl-open-pipe": "injection",
    "perl-sql-injection": "injection",
    "perl-xss": "injection",
    "perl-regex-eval": "injection",
    "perl-require-variable": "injection",
    "perl-chmod-unsafe": "auth",
}

# Per-family hypothesis vocabulary.  Single-word keywords match on a
# word-prefix boundary (\bfree matches "freed"); multi-word keywords
# match as substrings.  "other" has no vocabulary: hits without a
# family never correlate and stay context-only.
_FAMILY_KEYWORDS: dict[str, frozenset] = {
    "memory": frozenset({
        "overflow", "underflow", "out-of-bounds", "out of bounds", "oob",
        "buffer", "bounds", "memcpy", "strcpy", "strcat", "sprintf",
        "gets", "use-after-free", "use after free", "uaf", "double free",
        "double-free", "dangling", "heap", "stack", "memory", "free",
        "alloc", "off-by-one", "off by one", "wraparound", "integer",
        "truncation", "format string", "uninitialized", "uninitialised",
        "null pointer", "null deref",
    }),
    "injection": frozenset({
        "injection", "inject", "sql", "command", "shell", "exec", "eval",
        "xss", "cross-site", "cross site", "script", "deserial",
        "unserialize", "pickle", "yaml", "template", "ssrf", "xxe",
        "ldap", "redos", "prototype pollution", "code execution",
    }),
    "crypto": frozenset({
        "crypto", "cipher", "encrypt", "decrypt", "hash", "hmac",
        "random", "nonce", "salt", "tls", "ssl", "signature",
        "certificate", "weak key", "key generation",
    }),
    "auth": frozenset({
        "auth", "authentication", "authorization", "authorisation",
        "permission", "privilege", "access control", "acl", "session",
        "credential", "bypass", "chmod", "setuid",
    }),
    "concurrency": frozenset({
        "race", "toctou", "time-of-check", "time of check", "concurrent",
        "lock", "deadlock", "atomic", "thread", "reentran",
        "signal handler",
    }),
    "path": frozenset({
        "path traversal", "traversal", "directory", "symlink", "path",
        "file inclusion", "lfi", "rfi", "containment", "..",
        "filename", "file name",
    }),
    "other": frozenset(),
}

# CWE number → family, for correlating via a stated vuln_type/cwe_class.
_CWE_FAMILY: dict[int, str] = {
    **dict.fromkeys(
        (119, 120, 121, 122, 124, 125, 126, 127, 131, 134, 190, 191,
         193, 401, 415, 416, 457, 476, 562, 590, 680, 787, 788, 824,
         825), "memory",
    ),
    **dict.fromkeys(
        (77, 78, 79, 88, 89, 90, 91, 94, 95, 96, 502, 611, 643, 652,
         917, 918, 1336), "injection",
    ),
    **dict.fromkeys((22, 23, 36, 59, 61, 73, 426, 427), "path"),
    **dict.fromkeys(
        (250, 269, 276, 287, 288, 306, 307, 522, 732, 798, 862, 863),
        "auth",
    ),
    **dict.fromkeys(
        (326, 327, 328, 330, 331, 335, 338, 347, 757, 916), "crypto",
    ),
    **dict.fromkeys((362, 364, 366, 367, 368, 421, 1223), "concurrency"),
}


def _keyword_in_text(kw: str, text: str) -> bool:
    if " " in kw or "-" in kw or kw == "..":
        return kw in text
    return re.search(r"\b" + re.escape(kw), text) is not None


def family_for_rule(rule_id: str) -> str:
    """Map a rule id (prefilter or SARIF) to a coarse CWE family.

    Prefilter ids resolve via PREFILTER_RULE_FAMILY; unknown ids (e.g.
    semgrep/CodeQL SARIF rules) fall back to keyword inference on the
    id text itself.  Unmatchable ids return "other".
    """
    if not rule_id:
        return "other"
    family = PREFILTER_RULE_FAMILY.get(rule_id)
    if family:
        return family
    text = re.sub(r"[._\-/]+", " ", rule_id.lower())
    for fam, keywords in _FAMILY_KEYWORDS.items():
        if fam == "other":
            continue
        if any(_keyword_in_text(kw, text) for kw in keywords):
            return fam
    return "other"


def evidence_matches_hypothesis(
    rule_family: str,
    hypothesis_text: str,
    vuln_type: str = "",
) -> bool:
    """True when evidence from *rule_family* speaks to the hypothesis.

    Correlates either by CWE number in *vuln_type* (or the hypothesis
    itself) or by family vocabulary in the combined text.  Family
    "other" never correlates — its hits are review context only.
    """
    keywords = _FAMILY_KEYWORDS.get(rule_family)
    if not keywords:
        return False
    text = f"{hypothesis_text} {vuln_type}".lower()
    m = re.search(r"cwe[-_ ]?(\d+)", text)
    if m and _CWE_FAMILY.get(int(m.group(1))) == rule_family:
        return True
    return any(_keyword_in_text(kw, text) for kw in keywords)


@dataclass
class PrefilterResult:
    """Result of running the pre-filter on one function."""
    file: str
    function: str
    skip_llm: bool = False
    skip_reason: str = ""
    hits: list[PrefilterHit] = field(default_factory=list)
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
            "BEFORE your review. These are structural pattern matches that "
            "fire on SYNTAX — they do NOT verify caller constraints, error "
            "handling context, or whether the condition is reachable. A "
            "pattern hit does NOT mean a vulnerability exists. You MUST "
            "verify each independently via code reading: check whether the "
            "flagged condition can actually occur given the function's "
            "callers, guards, and invariants. If you cannot demonstrate a "
            "concrete scenario where the flagged pattern leads to a defect, "
            "classify as clean."
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
    callers: list[dict[str, Any]] | None = None,
    callees: list[dict[str, Any]] | None = None,
    metadata: dict[str, Any] | None = None,
    sink_unreachable: bool = False,
    project_sinks: frozenset | None = None,
    domain_vocab: Any = None,
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

    extra_dangerous: frozenset = frozenset()
    extra_concurrency: frozenset = frozenset()
    if domain_vocab is not None:
        extra_dangerous = (
            getattr(domain_vocab, "allocators", frozenset())
            | getattr(domain_vocab, "deallocators", frozenset())
            | getattr(domain_vocab, "boundary_transfers", frozenset())
            | getattr(domain_vocab, "nullable_returns", frozenset())
            | getattr(domain_vocab, "refcount_gets", frozenset())
            | getattr(domain_vocab, "refcount_puts", frozenset())
        )
        extra_concurrency = (
            getattr(domain_vocab, "lock_acquires", frozenset())
            | getattr(domain_vocab, "lock_releases", frozenset())
        )

    result = PrefilterResult(
        file=file_path,
        function=function_name,
        language=lang,
        sloc=sloc,
    )

    if lang in ("c", "cpp"):
        _check_c_patterns(
            result, source, line_start, callers, callees,
            extra_dangerous=extra_dangerous,
        )
    elif lang == "python":
        _check_python_patterns(result, source, line_start, callers, callees)
    elif lang == "go":
        _check_go_patterns(result, source, line_start, callers, callees)
    elif lang == "rust":
        _check_rust_patterns(result, source, line_start, callers, callees)
    elif lang == "php":
        _check_php_patterns(result, source, line_start, callers, callees)
    elif lang == "java":
        _check_java_patterns(result, source, line_start, callers, callees)
    elif lang in ("javascript", "typescript"):
        _check_js_patterns(result, source, line_start, callers, callees)
    elif lang == "lua":
        _check_lua_patterns(result, source, line_start, callers, callees)
    elif lang == "perl":
        _check_perl_patterns(result, source, line_start, callers, callees)

    if _is_trivially_clean(
        result, source, callers, callees, metadata,
        extra_dangerous=extra_dangerous,
    ):
        result.skip_llm = True

    if not result.skip_llm:
        is_wrapper, wrapper_reason = _is_trivial_wrapper(
            source, result.language, callees,
            project_sinks=project_sinks,
            extra_dangerous=extra_dangerous,
        )
        if is_wrapper:
            result.skip_llm = True
            result.skip_reason = wrapper_reason

    if not result.skip_llm and sink_unreachable and _is_sink_unreachable_clean(
        result, source, sloc,
        extra_concurrency=extra_concurrency,
    ):
        result.skip_llm = True
        result.skip_reason = "no sink path + no logic-class signals"

    return result


def _is_trivially_clean(
    result: PrefilterResult,
    source: str,
    callers: list[dict[str, Any]] | None,
    callees: list[dict[str, Any]] | None,
    metadata: dict[str, Any] | None,
    *,
    extra_dangerous: frozenset = frozenset(),
) -> bool:
    """Determine if a function can be skipped without LLM review.

    Conservative: only skips functions that CANNOT contain vulnerabilities.
    A false skip_llm=True is a missed bug, so err toward sending to LLM.
    """
    if result.hits:
        return False

    if result.has_dangerous_apis or result.has_pointer_ops:
        return False

    if result.has_array_access or result.has_user_input:
        return False

    callees_list = callees or []
    if callees_list:
        callee_names = {c.get("name", "") for c in callees_list}
        if callee_names & (
            _DANGEROUS_C_APIS | _DANGEROUS_GO_CALLEES
            | _DANGEROUS_RUST_CALLEES | _DANGEROUS_PHP_CALLEES
            | _DANGEROUS_JAVA_CALLEES | _DANGEROUS_JS_CALLEES
            | _DANGEROUS_LUA_CALLEES | _DANGEROUS_PERL_CALLEES
            | _DANGEROUS_PY_APIS | extra_dangerous
        ):
            return False

    if result.sloc > 15:
        return False

    if any(macro in source for macro in _DANGEROUS_MACROS):
        return False

    if _is_simple_accessor(source, result.language):
        result.skip_reason = "simple accessor (return field/constant)"
        return True

    return False


_DANGEROUS_MACROS = frozenset({
    "BUG_ON", "WARN_ON", "BUILD_BUG_ON", "assert", "ASSERT",
    "panic", "BUG", "WARN", "CHECK", "DCHECK",
})


_WRAPPER_CALL_RE = re.compile(r'\b(\w+)\s*\(')
_WRAPPER_RETURN_CALL_RE = re.compile(r'return\s+(\w+)\s*\(')
_WRAPPER_PTR_ARITH_RE = re.compile(
    r'(?<!\w->)\w+\s*\+\s*\w|\w+\s*\[\s*[^]]+\]|'
    r'\(\s*\w+\s*\*\s*\)|'
    r'\(\s*(?:unsigned\s+)?(?:char|int|long|short|void)\s*\*\s*\)',
)


def _is_trivial_wrapper(
    source: str,
    lang: str,
    callees: list[dict[str, Any]] | None,
    *,
    project_sinks: frozenset | None = None,
    extra_dangerous: frozenset = frozenset(),
) -> tuple[bool, str]:
    """Detect thin wrapper functions that delegate entirely to one callee.

    Returns (True, reason) when the function is a trivial pass-through
    wrapper that cannot itself introduce a vulnerability.
    """
    if not source or not source.strip():
        return False, ""

    lines = source.strip().splitlines()
    code_lines = [
        ln.strip() for ln in lines
        if ln.strip()
        and not ln.strip().startswith("//")
        and not ln.strip().startswith("/*")
        and not ln.strip().startswith("*")
        and not ln.strip().startswith("#")
        and ln.strip() not in ("{", "}")
    ]

    if len(code_lines) > 5:
        return False, ""

    body = " ".join(code_lines)
    body_no_sig = body

    if lang in ("c", "cpp"):
        sig_end = body.find("{")
        if sig_end >= 0:
            body_no_sig = body[sig_end + 1:]
            closing = body_no_sig.rfind("}")
            if closing >= 0:
                body_no_sig = body_no_sig[:closing]
        body_no_sig = body_no_sig.strip()
    elif lang == "python":
        for i, ln in enumerate(code_lines):
            if ln.startswith(("def ", "async def ")):
                body_no_sig = " ".join(code_lines[i + 1:])
                break

    if not body_no_sig:
        return False, ""

    for macro in _DANGEROUS_MACROS:
        if re.search(rf'\b{re.escape(macro)}\s*\(', body_no_sig):
            return False, ""

    if _WRAPPER_PTR_ARITH_RE.search(body_no_sig):
        return False, ""

    calls = _WRAPPER_CALL_RE.findall(body_no_sig)
    real_calls = [
        c for c in calls
        if c not in ("if", "while", "for", "switch", "sizeof", "typeof",
                      "return", "else", "case", "offsetof", "container_of")
        and c not in _DANGEROUS_MACROS
    ]

    if len(real_calls) != 1:
        return False, ""

    callee_name = real_calls[0]

    if callee_name in (_DANGEROUS_C_APIS | _DANGEROUS_PY_APIS | extra_dangerous):
        return False, ""
    if any(api in callee_name.lower() for api in _CRYPTO_APIS):
        return False, ""
    if project_sinks and callee_name in project_sinks:
        return False, ""

    if lang in ("c", "cpp"):
        return_count = len(re.findall(r'\breturn\b', body_no_sig))
        if return_count > 1:
            return False, ""
        if not _WRAPPER_RETURN_CALL_RE.search(body_no_sig):
            if not re.search(rf'\b{re.escape(callee_name)}\s*\(', body_no_sig):
                return False, ""
            stmts = [s.strip() for s in body_no_sig.split(";") if s.strip()]
            if len(stmts) > 1:
                return False, ""
    elif lang == "python":
        return_count = len(re.findall(r'\breturn\b', body_no_sig))
        if return_count > 1:
            return False, ""
        if not re.search(r'\breturn\b', body_no_sig):
            stmts = [s.strip() for s in body_no_sig.split("\n") if s.strip()]
            if len(stmts) > 1:
                return False, ""

    return True, f"trivial wrapper delegating to {callee_name}()"


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


_LIFECYCLE_OPS = frozenset({
    "free", "kfree", "kfree_rcu", "vfree", "kvfree",
    "release", "destroy", "put_", "refcount", "kref",
})

_AUTH_RE = re.compile(r"\b(?:" + "|".join(re.escape(k) for k in _AUTH_KEYWORDS) + r")")
_CRYPTO_RE = re.compile(r"\b(?:" + "|".join(re.escape(k) for k in _CRYPTO_APIS) + r")")
_LIFECYCLE_RE = re.compile(r"\b(?:" + "|".join(re.escape(k) for k in _LIFECYCLE_OPS) + r")")

_INTEGER_ARITH_RE = re.compile(
    r"[\w)]\s*\+\s*[\w(]"
    r"|"
    r"[\w)]\s+-\s+[\w(]"
    r"|"
    r"[\w)]\s+\*\s+[\w(]"
    r"|"
    r"[\w)]\s*<<\s*[\w(]"
    r"|"
    r"[\w)]\s*>>\s*[\w(]",
)


def _has_integer_arithmetic(source: str) -> bool:
    """Detect arithmetic that could overflow (addition, multiplication, shifts)."""
    return bool(_INTEGER_ARITH_RE.search(source))


def _is_sink_unreachable_clean(
    result: PrefilterResult,
    source: str,
    sloc: int,
    *,
    extra_concurrency: frozenset = frozenset(),
) -> bool:
    """Skip sink-unreachable functions with no logic-class signals.

    Only skips when ALL of:
      - sink_unreachable is True (caller already checked)
      - no prefilter hits
      - no dangerous-API / pointer-ops / array-access / user-input flags
      - no auth/authz keywords
      - no crypto API calls
      - no lock/mutex/atomic operations
      - no memory lifecycle operations
      - no comparison to status-code-like constants
      - SLOC ≤ 30
    """
    if result.hits:
        return False

    if result.has_dangerous_apis or result.has_pointer_ops:
        return False

    if result.has_array_access or result.has_user_input:
        return False

    if sloc > 30:
        return False

    source_lower = source.lower()

    if _AUTH_RE.search(source_lower):
        return False

    if _CRYPTO_RE.search(source_lower):
        return False

    all_concurrency = _CONCURRENCY_OPS | extra_concurrency
    if any(re.search(rf"\b{re.escape(op)}", source_lower) for op in all_concurrency):
        return False

    if _LIFECYCLE_RE.search(source_lower):
        return False

    if re.search(r"==\s*(0x[0-9a-fA-F]+|[4-5]\d{2})\b", source):
        return False

    return not _has_integer_arithmetic(source)


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
    elif lang == "go":
        if re.search(r"return\s+\w+\.\w+$", body):
            return True
        if re.search(r"return\s+\w+\.\w+\s*,\s*nil$", body):
            return True
        if re.search(r"return\s+\d+$", body):
            return True
    elif lang == "rust":
        if re.search(r"\bself\.\w+\s*$", body):
            return True
        if re.search(r"\bself\.\w+\.clone\(\)\s*$", body):
            return True
        if re.search(r"return\s+self\.\w+\s*;?\s*$", body):
            return True
        if re.search(r"^\s*\d+\s*$", body):
            return True
    elif lang == "php":
        if re.search(r"return\s+\$this->\w+\s*;$", body):
            return True
        if re.search(r"return\s+self::\$?\w+\s*;$", body):
            return True
        if re.search(r"return\s+\d+\s*;$", body):
            return True
        if re.search(r"return\s+(true|false|null)\s*;$", body):
            return True
    elif lang == "java":
        if re.search(r"return\s+this\.\w+\s*;$", body):
            return True
        if re.search(r"return\s+\w+\s*;$", body):
            m = re.search(r"return\s+(\w+)\s*;$", body)
            if m:
                returned = m.group(1).lower()
                if not any(s in returned for s in _SECURITY_SENSITIVE_NAMES):
                    return True
    elif lang in ("javascript", "typescript"):
        if re.search(r"return\s+this\.\w+\s*;?$", body):
            return True
        if re.search(r"return\s+this\._\w+\s*;?$", body):
            return True
        if re.search(r"return\s+\d+\s*;?$", body):
            return True
    elif lang == "lua":
        if re.search(r"return\s+self\.\w+\s*$", body):
            return True
        if re.search(r"return\s+\d+\s*$", body):
            return True
    elif lang == "perl":
        if re.search(r"return\s+\$self->\{\s*\w+\s*\}\s*;$", body):
            return True
        if re.search(r"return\s+\$_\[\d+\]\s*;$", body):
            return True

    return False


def _check_c_patterns(
    result: PrefilterResult,
    source: str,
    line_start: int,
    callers: list[dict[str, Any]] | None,
    callees: list[dict[str, Any]] | None,
    *,
    extra_dangerous: frozenset = frozenset(),
) -> None:
    """Check C/C++ source for known vulnerability patterns."""
    callee_names = set()
    if callees:
        callee_names = {c.get("name", "") for c in callees}

    dangerous = _DANGEROUS_C_APIS | extra_dangerous
    result.has_dangerous_apis = bool(callee_names & dangerous)
    if not result.has_dangerous_apis and not callee_names:
        result.has_dangerous_apis = bool(
            re.search(
                r"\b(" + "|".join(re.escape(a) for a in dangerous) + r")\s*\(",
                source,
            )
        )

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

        if re.search(r'\batoi\s*\(|\batol\s*\(', stripped) and not re.search(
            r'if\s*\(', stripped,
        ):
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

    _check_c_assign_in_cond(result, source, line_start)
    _check_c_missing_bounds(result, source, line_start)
    _check_c_use_after_free(result, source, line_start)
    _check_c_toctou(result, source, line_start)
    _check_c_post_loop_oob(result, source, line_start)


_ASSIGN_IN_COND_RE = re.compile(
    r"\bif\s*\(\s*"
    r"(?!\s*\()"
    r"(\w+)\s*=\s*"
    r"(0|1|NULL|nil|None|false|true|-1)\s*\)",
    re.IGNORECASE,
)

_ASSIGN_IN_COND_INTENTIONAL_RE = re.compile(
    r"\bif\s*\(\s*\("
    r"|\bif\s*\(\s*\w+\s*=\s*\w+\s*\("
)


def _check_c_assign_in_cond(
    result: PrefilterResult,
    source: str,
    line_start: int,
) -> None:
    """Detect assignment-in-conditional with a constant (CWE-480/481)."""
    for i, line in enumerate(source.splitlines(), start=line_start):
        stripped = line.strip()
        if stripped.startswith(("//", "*")):
            continue
        if _ASSIGN_IN_COND_INTENTIONAL_RE.search(stripped):
            continue
        m = _ASSIGN_IN_COND_RE.search(stripped)
        if m:
            result.hits.append(PrefilterHit(
                rule_id="assign-in-conditional",
                message=(
                    f"assignment `{m.group(1)} = {m.group(2)}` inside "
                    f"if-condition — likely meant `==` (CWE-480)"
                ),
                line=i,
                severity="error",
            ))


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
    freed_vars: dict[str, int] = {}

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
            if re.search(rf'\b{re.escape(var)}\s*->', stripped) or re.search(rf'\*\s*{re.escape(var)}\b', stripped):
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
            # Reassignment only: `var = ...`. The old lookbehind
            # inspected the char before `=`, which for `var != x`,
            # `var <= x`, `var += x` is `!`/`<`/`+` — comparisons and
            # compound ops cleared the freed set and hid the
            # use-after-free / double-free that followed.
            if re.search(
                rf'\b{re.escape(var)}\s*(?<![!<>+\-*/&|^%=])=(?!=)\s*',
                stripped,
            ) and not re.search(r'\bfree\s*\(', stripped):
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
    loop_index_var: str | None = None
    loop_cap_var: str | None = None
    loop_line: int | None = None
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
    callers: list[dict[str, Any]] | None,
    callees: list[dict[str, Any]] | None,
) -> None:
    """Check Python source for known vulnerability patterns."""
    callee_names = set()
    if callees:
        callee_names = {c.get("name", "") for c in callees}

    result.has_dangerous_apis = bool(callee_names & _DANGEROUS_PY_APIS)

    for i, line in enumerate(source.splitlines(), start=line_start):
        stripped = line.strip()

        if re.search(r'\bos\.path\.join\b', stripped) and not re.search(
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

        if (re.search(r'\bopen\s*\(', stripped)
                and re.search(
                    r'os\.path\.join|user|request|param|filename', source,
                )
                and not re.search(
                    r'os\.path\.realpath|\.startswith\(|resolve\(\)',
                    source,
                )):
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

        if re.search(r'\byaml\.load\s*\(', stripped) and not re.search(
            r'Loader\s*=\s*yaml\.SafeLoader', stripped,
        ):
                result.hits.append(PrefilterHit(
                    rule_id="yaml-unsafe-load",
                    message="yaml.load without SafeLoader can execute arbitrary code",
                    line=i,
                    severity="error",
                ))


def _check_go_patterns(
    result: PrefilterResult,
    source: str,
    line_start: int,
    callers: list[dict[str, Any]] | None,
    callees: list[dict[str, Any]] | None,
) -> None:
    """Check Go source for known vulnerability patterns."""
    callee_names = set()
    if callees:
        callee_names = {c.get("name", "") for c in callees}

    result.has_dangerous_apis = bool(callee_names & _DANGEROUS_GO_CALLEES)
    result.has_array_access = bool(re.search(r'\w+\s*\[', source))
    result.has_pointer_ops = bool(
        re.search(r'\bunsafe\.Pointer\b', source)
        or re.search(r'\buintptr\b', source)
    )

    for i, line in enumerate(source.splitlines(), start=line_start):
        stripped = line.strip()

        if re.search(r'\bexec\.Command(?:Context)?\s*\(', stripped):
            result.hits.append(PrefilterHit(
                rule_id="go-exec-command",
                message=(
                    "exec.Command with potentially user-controlled "
                    "arguments — command injection risk"
                ),
                line=i,
                severity="error",
            ))

        if re.search(
            r'\bunsafe\.(Pointer|Slice|String|Sizeof|Alignof|Offsetof)\b',
            stripped,
        ):
            result.hits.append(PrefilterHit(
                rule_id="go-unsafe-usage",
                message="unsafe package usage — memory safety bypassed",
                line=i,
                severity="warning",
            ))

        if re.search(r'\bdb\.(Query|QueryRow|Exec)\s*\(', stripped) and (
            re.search(
                r'fmt\.Sprintf|"\s*\+\s*\w|\w\s*\+\s*"',
                stripped,
            ) or (
                re.search(
                    r'fmt\.Sprintf|"\s*\+\s*\w|\w\s*\+\s*"',
                    source,
                )
                and not re.search(r'\$\d+', source)
            )
        ):
                result.hits.append(PrefilterHit(
                    rule_id="go-sql-string-concat",
                    message=(
                        "SQL query with string concatenation — "
                        "use parameterised queries ($1, $2)"
                    ),
                    line=i,
                    severity="error",
                ))

        if re.search(
            r'\btemplate\.(HTML|JS|CSS|HTMLAttr|URL)\s*\(',
            stripped,
        ):
            result.hits.append(PrefilterHit(
                rule_id="go-template-unescaped",
                message=(
                    "template.HTML/JS/CSS bypasses auto-escaping "
                    "— XSS risk if input is user-controlled"
                ),
                line=i,
                severity="warning",
            ))

        if re.search(
            r'\bos\.(Open|Create|Remove|ReadFile|WriteFile|'
            r'OpenFile|RemoveAll|MkdirAll)\s*\(',
            stripped,
        ) and re.search(
            r'user|request|param|filename|r\.\w+|'
            r'c\.Param|c\.Query|chi\.|mux\.',
            source,
        ) and not re.search(
            r'filepath\.Clean|filepath\.Abs|'
            r'strings\.Contains.*\.\.|path\.Clean',
            source,
        ):
            result.hits.append(PrefilterHit(
                rule_id="go-path-traversal",
                message=(
                    "file operation with potentially "
                    "user-controlled path and no containment "
                    "check (filepath.Clean / strings.Contains)"
                ),
                line=i,
                severity="warning",
            ))

        if re.search(
            r'\bhttp\.(Get|Post|PostForm)\s*\(', stripped,
        ) and re.search(
            r'user|request|param|fmt\.Sprintf|"\s*\+',
            stripped,
        ):
                result.hits.append(PrefilterHit(
                    rule_id="go-ssrf",
                    message=(
                        "HTTP request with potentially user-controlled "
                        "URL — SSRF risk"
                    ),
                    line=i,
                    severity="warning",
                ))

        if re.search(
            r'\b(?:json|xml)\.(?:Unmarshal|NewDecoder)',
            stripped,
        ) and re.search(r'interface\s*\{\s*\}|any\b', source):
            result.hits.append(PrefilterHit(
                rule_id="go-deserialize-interface",
                message=(
                    "deserialisation into interface{}/any — "
                    "type confusion risk, prefer concrete types"
                ),
                line=i,
                severity="warning",
            ))

        if re.search(r'\bgob\.(NewDecoder|Decode)\b', stripped):
            result.hits.append(PrefilterHit(
                rule_id="go-gob-decode",
                message=(
                    "gob.Decode on untrusted input can instantiate "
                    "arbitrary registered types"
                ),
                line=i,
                severity="warning",
            ))

        if re.search(r'\breflect\.\w+\s*\(', stripped):
            result.has_dangerous_apis = True

        if re.search(r'\bC\.\w+\s*\(', stripped):
            result.hits.append(PrefilterHit(
                rule_id="go-cgo-call",
                message=(
                    "CGo call — crosses memory-safety boundary, "
                    "C code is not bounds-checked"
                ),
                line=i,
                severity="warning",
            ))


def _check_rust_patterns(
    result: PrefilterResult,
    source: str,
    line_start: int,
    callers: list[dict[str, Any]] | None,
    callees: list[dict[str, Any]] | None,
) -> None:
    """Check Rust source for known vulnerability patterns."""
    callee_names = set()
    if callees:
        callee_names = {c.get("name", "") for c in callees}

    result.has_dangerous_apis = bool(callee_names & _DANGEROUS_RUST_CALLEES)
    result.has_pointer_ops = bool(
        re.search(r'\*const\b|\*mut\b', source)
        or re.search(r'\bas\s+\*(?:const|mut)\b', source)
    )
    result.has_array_access = bool(re.search(r'\w+\s*\[', source))

    has_unsafe_block = bool(re.search(r'\bunsafe\s*\{', source))

    for i, line in enumerate(source.splitlines(), start=line_start):
        stripped = line.strip()

        if re.search(r'\bunsafe\s*\{', stripped):
            result.hits.append(PrefilterHit(
                rule_id="rust-unsafe-block",
                message="unsafe block — memory safety guarantees suspended",
                line=i,
                severity="warning",
            ))

        if re.search(
            r'\bCommand::new\s*\(|\bprocess::Command\b',
            stripped,
        ):
            result.hits.append(PrefilterHit(
                rule_id="rust-command-exec",
                message=(
                    "std::process::Command with potentially "
                    "user-controlled arguments — command injection risk"
                ),
                line=i,
                severity="error",
            ))

        if re.search(r'\bas\s+\*(?:const|mut)\b', stripped):
            result.hits.append(PrefilterHit(
                rule_id="rust-raw-pointer-cast",
                message="raw pointer cast — bypasses borrow checker",
                line=i,
                severity="warning",
            ))

        if re.search(r'\btransmute\s*[:<(]', stripped):
            result.hits.append(PrefilterHit(
                rule_id="rust-transmute",
                message=(
                    "std::mem::transmute reinterprets bits — "
                    "type confusion and UB risk"
                ),
                line=i,
                severity="error",
            ))

        if re.search(r'\bextern\s+"C"\s*\{', stripped):
            result.hits.append(PrefilterHit(
                rule_id="rust-ffi-extern",
                message=(
                    "extern \"C\" block — FFI boundary, called code "
                    "is not memory-safe"
                ),
                line=i,
                severity="warning",
            ))

        if re.search(r'#\[no_mangle\]', stripped):
            result.hits.append(PrefilterHit(
                rule_id="rust-no-mangle",
                message=(
                    "#[no_mangle] exports symbol across FFI boundary"
                ),
                line=i,
                severity="warning",
            ))

        if re.search(
            r'\bfrom_raw_parts(?:_mut)?\s*\(',
            stripped,
        ):
            result.hits.append(PrefilterHit(
                rule_id="rust-from-raw-parts",
                message=(
                    "slice::from_raw_parts — caller must guarantee "
                    "pointer validity and length correctness"
                ),
                line=i,
                severity="warning",
            ))

        if re.search(
            r'(?:format!|&format!)\s*\(\s*"[^"]*'
            r'(?:SELECT|INSERT|UPDATE|DELETE)',
            stripped, re.IGNORECASE,
        ):
            result.hits.append(PrefilterHit(
                rule_id="rust-sql-format",
                message=(
                    "SQL query built with format! — "
                    "use parameterised queries"
                ),
                line=i,
                severity="error",
            ))

    if has_unsafe_block:
        result.has_dangerous_apis = True


def _check_php_patterns(
    result: PrefilterResult,
    source: str,
    line_start: int,
    callers: list[dict[str, Any]] | None,
    callees: list[dict[str, Any]] | None,
) -> None:
    """Check PHP source for known vulnerability patterns."""
    callee_names = set()
    if callees:
        callee_names = {c.get("name", "") for c in callees}

    result.has_dangerous_apis = bool(callee_names & _DANGEROUS_PHP_CALLEES)
    result.has_array_access = bool(re.search(r'\$\w+\s*\[', source))

    for i, line in enumerate(source.splitlines(), start=line_start):
        stripped = line.strip()

        if re.search(
            r'\b(?:eval|assert)\s*\(\s*\$', stripped,
        ):
            result.hits.append(PrefilterHit(
                rule_id="php-eval-variable",
                message="eval/assert with variable input — code injection",
                line=i,
                severity="error",
            ))

        if re.search(
            r'\b(?:system|exec|passthru|shell_exec|popen|'
            r'proc_open|pcntl_exec)\s*\(',
            stripped,
        ):
            result.hits.append(PrefilterHit(
                rule_id="php-command-exec",
                message="command execution function — injection risk",
                line=i,
                severity="error",
            ))

        if re.search(
            r'\b(?:include|include_once|require|require_once)\s*\(\s*\$',
            stripped,
        ):
            result.hits.append(PrefilterHit(
                rule_id="php-file-inclusion",
                message=(
                    "file inclusion with variable path — "
                    "LFI/RFI risk"
                ),
                line=i,
                severity="error",
            ))

        if re.search(r'\bunserialize\s*\(', stripped):
            result.hits.append(PrefilterHit(
                rule_id="php-unserialize",
                message=(
                    "unserialize on untrusted input — "
                    "object injection risk"
                ),
                line=i,
                severity="error",
            ))

        if re.search(
            r'\bpreg_replace\s*\(\s*["\'].*?/e["\']',
            stripped,
        ):
            result.hits.append(PrefilterHit(
                rule_id="php-preg-replace-e",
                message="preg_replace with /e modifier — code execution",
                line=i,
                severity="error",
            ))

        if re.search(
            r'\b(?:mysql_query|mysqli_query|pg_query)\s*\(',
            stripped,
        ) and re.search(r'\$', stripped) and not re.search(
            r'prepare\s*\(|bind_param|pg_query_params', source,
        ):
            result.hits.append(PrefilterHit(
                rule_id="php-sql-injection",
                message=(
                    "SQL query with variable interpolation — "
                    "use prepared statements"
                ),
                line=i,
                severity="error",
            ))

        if re.search(r'\becho\b.*\$_(?:GET|POST|REQUEST|COOKIE)', stripped):
            result.hits.append(PrefilterHit(
                rule_id="php-xss",
                message=(
                    "echoing superglobal without escaping — "
                    "XSS risk (use htmlspecialchars)"
                ),
                line=i,
                severity="error",
            ))

        if re.search(r'\bextract\s*\(\s*\$_', stripped):
            result.hits.append(PrefilterHit(
                rule_id="php-extract-superglobal",
                message="extract() on superglobal — variable injection",
                line=i,
                severity="error",
            ))

        if re.search(
            r'\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\s*\[', stripped,
        ):
            result.has_user_input = True

        if re.search(
            r'\b(?:file_get_contents|file_put_contents|fopen|'
            r'readfile|unlink|rename)\s*\(\s*\$',
            stripped,
        ) and not re.search(
            r'realpath|basename|str_replace.*\.\.',
            source,
        ):
            result.hits.append(PrefilterHit(
                rule_id="php-path-traversal",
                message=(
                    "file operation with variable path — "
                    "path traversal risk"
                ),
                line=i,
                severity="warning",
            ))

        if re.search(r'\bheader\s*\(\s*["\']Location.*\$', stripped):
            result.hits.append(PrefilterHit(
                rule_id="php-open-redirect",
                message="redirect with user-controlled URL — open redirect",
                line=i,
                severity="warning",
            ))


def _check_java_patterns(
    result: PrefilterResult,
    source: str,
    line_start: int,
    callers: list[dict[str, Any]] | None,
    callees: list[dict[str, Any]] | None,
) -> None:
    """Check Java source for known vulnerability patterns."""
    callee_names = set()
    if callees:
        callee_names = {c.get("name", "") for c in callees}

    result.has_dangerous_apis = bool(callee_names & _DANGEROUS_JAVA_CALLEES)
    result.has_array_access = bool(re.search(r'\w+\s*\[', source))

    for i, line in enumerate(source.splitlines(), start=line_start):
        stripped = line.strip()

        if re.search(
            r'Runtime\.getRuntime\(\)\.exec\s*\(', stripped,
        ):
            result.hits.append(PrefilterHit(
                rule_id="java-runtime-exec",
                message="Runtime.exec — command injection risk",
                line=i,
                severity="error",
            ))

        if re.search(r'\bProcessBuilder\s*\(', stripped):
            result.hits.append(PrefilterHit(
                rule_id="java-process-builder",
                message="ProcessBuilder — command injection risk",
                line=i,
                severity="error",
            ))

        if re.search(r'\bObjectInputStream\b', stripped):
            result.hits.append(PrefilterHit(
                rule_id="java-deserialization",
                message=(
                    "ObjectInputStream — deserialisation of untrusted "
                    "data leads to RCE"
                ),
                line=i,
                severity="error",
            ))

        if re.search(
            r'\.(?:executeQuery|executeUpdate|execute)\s*\(',
            stripped,
        ) and re.search(r'"\s*\+\s*\w|\w\s*\+\s*"', stripped):
            result.hits.append(PrefilterHit(
                rule_id="java-sql-concat",
                message=(
                    "SQL query with string concatenation — "
                    "use PreparedStatement"
                ),
                line=i,
                severity="error",
            ))

        if re.search(
            r'Class\.forName\s*\(|\.newInstance\s*\(|'
            r'\.getMethod\s*\(.*\.invoke\s*\(',
            stripped,
        ):
            result.hits.append(PrefilterHit(
                rule_id="java-reflection",
                message=(
                    "reflection with potentially user-controlled "
                    "class/method — injection risk"
                ),
                line=i,
                severity="warning",
            ))

        if re.search(
            r'new\s+File\s*\(.*(?:request|param|input|getParameter)',
            stripped, re.IGNORECASE,
        ):
            result.hits.append(PrefilterHit(
                rule_id="java-path-traversal",
                message=(
                    "File constructor with user input — "
                    "path traversal risk"
                ),
                line=i,
                severity="warning",
            ))

        if re.search(
            r'\.getParameter\s*\(|\.getHeader\s*\(|'
            r'\.getCookies\s*\(',
            stripped,
        ):
            result.has_user_input = True

        if re.search(
            r'XMLInputFactory|SAXParser|DocumentBuilder',
            stripped,
        ) and not re.search(
            r'FEATURE_SECURE_PROCESSING|'
            r'disallow-doctype-decl|'
            r'setExpandEntityReferences.*false',
            source,
        ):
            result.hits.append(PrefilterHit(
                rule_id="java-xxe",
                message=(
                    "XML parser without entity expansion disabled — "
                    "XXE risk"
                ),
                line=i,
                severity="warning",
            ))

        if re.search(
            r'ScriptEngine|\.eval\s*\(.*(?:request|param|input)',
            stripped, re.IGNORECASE,
        ):
            result.hits.append(PrefilterHit(
                rule_id="java-script-injection",
                message="ScriptEngine.eval with user input — code injection",
                line=i,
                severity="error",
            ))

        if re.search(r'\bLDAP\b.*\+\s*(?:request|param|input)', stripped, re.IGNORECASE):
            result.hits.append(PrefilterHit(
                rule_id="java-ldap-injection",
                message="LDAP query with user input — injection risk",
                line=i,
                severity="warning",
            ))


def _check_js_patterns(
    result: PrefilterResult,
    source: str,
    line_start: int,
    callers: list[dict[str, Any]] | None,
    callees: list[dict[str, Any]] | None,
) -> None:
    """Check JavaScript/TypeScript source for known vulnerability patterns."""
    callee_names = set()
    if callees:
        callee_names = {c.get("name", "") for c in callees}

    result.has_dangerous_apis = bool(callee_names & _DANGEROUS_JS_CALLEES)
    result.has_array_access = bool(re.search(r'\w+\s*\[', source))

    for i, line in enumerate(source.splitlines(), start=line_start):
        stripped = line.strip()

        if re.search(r'\beval\s*\(', stripped):
            result.hits.append(PrefilterHit(
                rule_id="js-eval",
                message="eval() — code injection risk",
                line=i,
                severity="error",
            ))

        if re.search(r'\bnew\s+Function\s*\(', stripped):
            result.hits.append(PrefilterHit(
                rule_id="js-function-constructor",
                message="new Function() — code injection risk",
                line=i,
                severity="error",
            ))

        if re.search(
            r'child_process.*\b(?:exec|execSync|spawn|execFile)\s*\(',
            stripped,
        ) or re.search(
            r'\b(?:exec|execSync|spawn|spawnSync|execFile)\s*\(',
            stripped,
        ) and re.search(r'child_process|require.*child', source):
            result.hits.append(PrefilterHit(
                rule_id="js-command-exec",
                message="child_process execution — command injection risk",
                line=i,
                severity="error",
            ))

        if re.search(
            r'\.innerHTML\s*=|\.outerHTML\s*=|'
            r'insertAdjacentHTML\s*\(|'
            r'document\.write\s*\(',
            stripped,
        ):
            result.hits.append(PrefilterHit(
                rule_id="js-xss-dom",
                message="DOM manipulation with raw HTML — XSS risk",
                line=i,
                severity="error",
            ))

        if re.search(
            r'dangerouslySetInnerHTML\s*=',
            stripped,
        ):
            result.hits.append(PrefilterHit(
                rule_id="js-react-dangerous-html",
                message=(
                    "dangerouslySetInnerHTML — bypasses React's "
                    "XSS protection"
                ),
                line=i,
                severity="warning",
            ))

        if re.search(
            r'\.query\s*\(\s*[`"\']\s*(?:SELECT|INSERT|UPDATE|DELETE)',
            stripped, re.IGNORECASE,
        ) and re.search(r'\$\{|\+\s*\w|\w\s*\+', stripped):
            result.hits.append(PrefilterHit(
                rule_id="js-sql-injection",
                message=(
                    "SQL query with string interpolation — "
                    "use parameterised queries"
                ),
                line=i,
                severity="error",
            ))

        if re.search(
            r'\bfs\.(?:readFile|writeFile|unlink|rename|'
            r'readFileSync|writeFileSync|unlinkSync|renameSync|'
            r'createReadStream|createWriteStream)\s*\(',
            stripped,
        ) and re.search(
            r'req\.|params\.|query\.|body\.|headers\.',
            source,
        ) and not re.search(
            r'path\.(?:resolve|normalize|basename)|'
            r'sanitize|includes.*\.\.',
            source,
        ):
            result.hits.append(PrefilterHit(
                rule_id="js-path-traversal",
                message=(
                    "file operation with request-derived path — "
                    "path traversal risk"
                ),
                line=i,
                severity="warning",
            ))

        if re.search(
            r'req\.(?:body|params|query|headers|cookies)\b',
            stripped,
        ):
            result.has_user_input = True

        if re.search(
            r'(?:JSON|YAML|yaml)\.parse\s*\(',
            stripped,
        ) and re.search(r'req\.|body\.|params\.', source):
            result.hits.append(PrefilterHit(
                rule_id="js-unsafe-parse",
                message=(
                    "parsing user-supplied data — "
                    "prototype pollution / injection risk"
                ),
                line=i,
                severity="warning",
            ))

        if re.search(r'\.redirect\s*\(.*(?:req\.|params\.|query\.)', stripped):
            result.hits.append(PrefilterHit(
                rule_id="js-open-redirect",
                message="redirect with user-controlled URL — open redirect",
                line=i,
                severity="warning",
            ))

        if re.search(r'\bnew\s+RegExp\s*\(.*(?:req\.|params\.|input)', stripped):
            result.hits.append(PrefilterHit(
                rule_id="js-regex-injection",
                message="RegExp with user input — ReDoS risk",
                line=i,
                severity="warning",
            ))


def _check_lua_patterns(
    result: PrefilterResult,
    source: str,
    line_start: int,
    callers: list[dict[str, Any]] | None,
    callees: list[dict[str, Any]] | None,
) -> None:
    """Check Lua source for known vulnerability patterns."""
    callee_names = set()
    if callees:
        callee_names = {c.get("name", "") for c in callees}

    result.has_dangerous_apis = bool(callee_names & _DANGEROUS_LUA_CALLEES)
    result.has_array_access = bool(re.search(r'\w+\s*\[', source))

    for i, line in enumerate(source.splitlines(), start=line_start):
        stripped = line.strip()

        if re.search(r'\b(?:loadstring|load)\s*\(', stripped):
            result.hits.append(PrefilterHit(
                rule_id="lua-loadstring",
                message="loadstring/load — code injection risk",
                line=i,
                severity="error",
            ))

        if re.search(r'\b(?:dofile|loadfile)\s*\(', stripped):
            result.hits.append(PrefilterHit(
                rule_id="lua-file-exec",
                message="dofile/loadfile — arbitrary file execution",
                line=i,
                severity="error",
            ))

        if re.search(r'\bos\.execute\s*\(', stripped):
            result.hits.append(PrefilterHit(
                rule_id="lua-os-execute",
                message="os.execute — command injection risk",
                line=i,
                severity="error",
            ))

        if re.search(r'\bio\.popen\s*\(', stripped):
            result.hits.append(PrefilterHit(
                rule_id="lua-io-popen",
                message="io.popen — command injection risk",
                line=i,
                severity="error",
            ))

        if re.search(r'\bio\.open\s*\(', stripped):
            result.hits.append(PrefilterHit(
                rule_id="lua-io-open",
                message="io.open — file access, check path sanitisation",
                line=i,
                severity="warning",
            ))

        if re.search(r'\bsetfenv\s*\(', stripped):
            result.hits.append(PrefilterHit(
                rule_id="lua-setfenv",
                message=(
                    "setfenv — environment manipulation, "
                    "sandbox escape risk"
                ),
                line=i,
                severity="warning",
            ))

        if re.search(r'\bsetmetatable\s*\(', stripped) and re.search(
            r'__index|__newindex|__call|__gc', source,
        ):
                result.hits.append(PrefilterHit(
                    rule_id="lua-metatable-abuse",
                    message=(
                        "setmetatable with metamethods — "
                        "behaviour override risk"
                    ),
                    line=i,
                    severity="warning",
                ))

        if re.search(r'\b(?:rawset|rawget)\s*\(', stripped):
            result.hits.append(PrefilterHit(
                rule_id="lua-raw-access",
                message="rawset/rawget — bypasses metatable protections",
                line=i,
                severity="warning",
            ))

        if re.search(
            r'\bdebug\.(?:getinfo|sethook|getlocal|setlocal|'
            r'getupvalue|setupvalue|getregistry)\s*\(',
            stripped,
        ):
            result.hits.append(PrefilterHit(
                rule_id="lua-debug-library",
                message=(
                    "debug library usage — sandbox escape risk, "
                    "should be disabled in production"
                ),
                line=i,
                severity="warning",
            ))

        if re.search(r'\bstring\.format\s*\(', stripped) and re.search(
            r'%s.*user|%s.*input|%s.*req', stripped, re.IGNORECASE,
        ):
                result.hits.append(PrefilterHit(
                    rule_id="lua-format-injection",
                    message="string.format with user input — format string risk",
                    line=i,
                    severity="warning",
                ))


def _check_perl_patterns(
    result: PrefilterResult,
    source: str,
    line_start: int,
    callers: list[dict[str, Any]] | None,
    callees: list[dict[str, Any]] | None,
) -> None:
    """Check Perl source for known vulnerability patterns."""
    callee_names = set()
    if callees:
        callee_names = {c.get("name", "") for c in callees}

    result.has_dangerous_apis = bool(callee_names & _DANGEROUS_PERL_CALLEES)
    result.has_array_access = bool(re.search(r'\$\w+\s*\[', source))
    result.has_user_input = bool(re.search(
        r'param\s*\(|<STDIN>|\$ENV\{|\$cgi->',
        source,
    ))

    for i, line in enumerate(source.splitlines(), start=line_start):
        stripped = line.strip()

        if re.search(r'\beval\s*\(?\s*["\$]', stripped):
            result.hits.append(PrefilterHit(
                rule_id="perl-eval",
                message="eval with variable — code injection risk",
                line=i,
                severity="error",
            ))

        if re.search(r'\b(?:system|exec)\s*\(?\s*["\$]', stripped):
            result.hits.append(PrefilterHit(
                rule_id="perl-command-exec",
                message="system/exec — command injection risk",
                line=i,
                severity="error",
            ))

        if re.search(r'`[^`]*\$', stripped):
            result.hits.append(PrefilterHit(
                rule_id="perl-backtick-injection",
                message="backtick with variable — command injection",
                line=i,
                severity="error",
            ))

        if re.search(
            r'\bopen\s*\(?\s*\w+\s*,\s*["\$]', stripped,
        ) and re.search(r'\||\>', stripped):
                result.hits.append(PrefilterHit(
                    rule_id="perl-open-pipe",
                    message=(
                        "two-argument open with pipe/redirect — "
                        "command injection risk (use three-argument open)"
                    ),
                    line=i,
                    severity="error",
                ))

        if re.search(
            r'\bDBI\b.*\bdo\s*\(|\bprepare\s*\(.*\$',
            stripped,
        ) and re.search(r'"\s*\.\s*\$|\$\w+', stripped) and not re.search(
            r'\?|placeholder', stripped, re.IGNORECASE,
        ):
            result.hits.append(PrefilterHit(
                rule_id="perl-sql-injection",
                message=(
                    "SQL with variable interpolation — "
                    "use placeholders (?)"
                ),
                line=i,
                severity="error",
            ))

        if re.search(
            r'\bprint\b.*\$(?:query|param|input|cgi)', stripped, re.IGNORECASE,
        ) and not re.search(r'encode_entities|escapeHTML|CGI::escape', source):
                result.hits.append(PrefilterHit(
                    rule_id="perl-xss",
                    message="printing user input without escaping — XSS risk",
                    line=i,
                    severity="warning",
                ))

        if re.search(r'=~\s*s/.*\$.*?/.*?/e', stripped):
            result.hits.append(PrefilterHit(
                rule_id="perl-regex-eval",
                message="regex substitution with /e modifier — code execution",
                line=i,
                severity="error",
            ))

        if re.search(r'\brequire\s+["\$]', stripped):
            result.hits.append(PrefilterHit(
                rule_id="perl-require-variable",
                message="require with variable — arbitrary module loading",
                line=i,
                severity="warning",
            ))

        if re.search(
            r'\bchmod\s*\(?\s*0?777|\bchmod\b.*\$',
            stripped,
        ):
            result.hits.append(PrefilterHit(
                rule_id="perl-chmod-unsafe",
                message="chmod with unsafe permissions or variable",
                line=i,
                severity="warning",
            ))


def run_prefilter_batch(
    *,
    target_path: Path,
    functions: list[dict[str, Any]],
) -> dict[str, PrefilterResult]:
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
