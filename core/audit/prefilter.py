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

import ast
import bisect
import logging
import re
import textwrap
import threading
from dataclasses import dataclass, field, fields
from functools import cached_property
from pathlib import Path
from typing import Any, Callable

from core.audit.source_view import (
    SanitizedView,
    sanitized_view,
    sanitized_view_with_status,
)

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
        lines.extend(f"- **{hit.rule_id}** (line {hit.line}): {hit.message}" for hit in self.hits)
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

    # A standing hit is a live signal on the wrapper's own line(s)
    # (shell=True, unsafe deserialization, format string): the shape
    # being a one-line delegate does not discharge it, and resolving
    # it mechanically clean is the suppression direction — the hits
    # must reach review.
    if not result.skip_llm and not result.hits:
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
    _callers: list[dict[str, Any]] | None,
    callees: list[dict[str, Any]] | None,
    _metadata: dict[str, Any] | None,
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


# Captures the DOTTED callee form (subprocess.run, pickle.loads): a
# bare-word capture could never match the dotted _DANGEROUS_PY_APIS
# entries, so dangerous one-line delegates skipped as trivial.
# Bounded segment loop: every '.'-boundary in a dotted run is a \b,
# so an unanchored scan restarted at each segment and re-walked the
# rest of the chain — quadratic on a long synthetic chain with no
# paren. 32 segments sits far above real dotted callees (trade-off
# both directions: larger admits absurd chains, smaller drops them).
_WRAPPER_CALL_RE = re.compile(r'\b((?:\w+\.){0,32}\w+)\s*\(')

#: The js/ts slash context the lexer heuristic cannot decide (regex
#: vs division after `)` / `]`) — the wrapper skip refuses instead
#: of judging it; see the refusal site in _is_trivial_wrapper.
_JS_AMBIGUOUS_SLASH_RE = re.compile(r"[)\]]\s*/")

#: A backslash ANYWHERE after a division-read `/` on the same
#: ref-view line has no valid-JS reading (a backslash in code
#: position is a syntax error outside Unicode-escaped identifiers,
#: an obfuscation-tier spelling refused by policy) — but a would-be
#: regex body reads it fine, so its presence marks the reading the
#: lexer got wrong. Partial hardening, not a closure: a regex body
#: can hide a comment-opener with NO backslash (`a /[//]x/` — the
#: char-class spelling), see the refusal-site comment.
_JS_INVALID_SLASH_RE = re.compile(r"[)\]\"'`\w]\s*/[^\n\\]{0,1000}\\")
_WRAPPER_RETURN_CALL_RE = re.compile(r'return\s+(\w+)\s*\(')
# The subscript body is \S-headed ([^\]\s][^]]*): the naive
# ``\[\s*[^]]+\]`` overlapped the whitespace span and the body on
# whitespace — quadratic on a '['-opening expression ending in a
# whitespace run. The dropped corner is a whitespace-only subscript
# ('x[  ]'), not real C.
_WRAPPER_PTR_ARITH_RE = re.compile(
    r'(?<!\w->)\w\s*\+\s*\w|\b\w+\s*\[\s*[^\]\s][^]]{0,4000}\]|'
    r'\(\s*\w+\s*\*\s*\)|'
    r'\(\s*(?:unsigned\s+)?(?:char|int|long|short|void)\s*\*\s*\)',
)


_WRAPPER_DANGEROUS_CALLEES = frozenset(
    _DANGEROUS_C_APIS | _DANGEROUS_PY_APIS
    | _DANGEROUS_GO_CALLEES | _DANGEROUS_RUST_CALLEES
    | _DANGEROUS_PHP_CALLEES | _DANGEROUS_JAVA_CALLEES
    | _DANGEROUS_JS_CALLEES | _DANGEROUS_LUA_CALLEES
    | _DANGEROUS_PERL_CALLEES,
)

#: Bare tails of the dotted entries (subprocess.run -> run): the
#: wrapper capture sees the bare form when the API is imported
#: unqualified.
_WRAPPER_DANGEROUS_TAILS = frozenset(
    e.rsplit(".", 1)[-1] for e in _WRAPPER_DANGEROUS_CALLEES
)

#: getattr with a LITERAL attribute name: base object dotted path and
#: the quoted attribute, with no further arguments (a default-argument
#: form stays unresolved -> conservative no-skip).
_WRAPPER_GETATTR_LITERAL_RE = re.compile(
    r'\bgetattr\s*\(\s*([A-Za-z_]\w*(?:\.\w+)*)\s*,\s*'
    r'[\'"]([A-Za-z_]\w*)[\'"]\s*\)',
)

#: The standard indirection family: a one-line delegate through any of
#: these hides its real target from the dotted-callee exclusion.
#: Shapes with LITERAL arguments resolve mechanically and re-enter the
#: exclusion checks under the resolved name(s); a shape with no
#: resolvable literal (dynamic name) refuses the skip — an
#: unresolvable delegate must never be journalled mechanically clean.
_WRAPPER_INDIRECTION_TAILS = frozenset({
    "getattr", "__import__", "import_module",
    "attrgetter", "methodcaller", "partial",
    "vars", "globals", "dlsym",
})

#: Literal names an indirection shape resolves through: quoted string
#: literals (attrgetter("run"), dlsym(h, "system"), vars(m)["run"],
#: globals()["system"]) anywhere in the delegate body.
_WRAPPER_LITERAL_NAME_RE = re.compile(r'[\'"]([A-Za-z_][\w.]*)[\'"]')

#: Line terminators normalised to "\n" before any judged-view split,
#: derived from ``str.splitlines`` semantics (every character it
#: splits on, minus "\n" itself, plus the "\r\n" compound first so it
#: never yields a double newline). A member missing here let one
#: plantable byte inside a string literal desync the kept/blanked
#: view pair — the byte survives as string data in the strings-kept
#: view (splitlines gains a line) but blanks to a space in the ref
#: view, so every later line judges drop-eligibility against the
#: wrong blanked twin and a live sink line is swallowed from both
#: views. A closure test derives this tuple from splitlines itself
#: (test_wrapper_lexer.TestSplitlinesTerminatorUniverse). The judged
#: views additionally split on "\n" ONLY, so even a terminator this
#: tuple were to miss stays inside one line in BOTH views and cannot
#: desync them.
_LINE_TERMINATORS: tuple[str, ...] = (
    "\r\n", "\r", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e",
    "\x85", "\u2028", "\u2029",
)


def _normalize_line_terminators(src: str) -> str:
    """Rewrite every exotic ``str.splitlines`` terminator to ``\\n``."""
    for _term in _LINE_TERMINATORS:
        src = src.replace(_term, "\n")
    return src

#: functools.partial's wrapped callable: the first argument as a plain
#: (possibly dotted) identifier REFERENCE — `partial(sp.run)` never
#: emits a call to sp.run, so the reference is the resolvable name.
_WRAPPER_PARTIAL_ARG_RE = re.compile(
    r'\bpartial\s*\(\s*((?:\w+\.)*\w+)\s*[,)]',
)

#: A sink escaping as a VALUE: `pool.submit(os.system, cmd)`,
#: `map(os.system, args)`, `asyncio.to_thread(os.system, a)` — the
#: dangerous target appears as an identifier REFERENCE, never as a
#: call, so the captured-callee exclusion cannot see it. The executor
#: is deliberately NOT enumerated (submit/to_thread/map/filter/
#: starmap/apply/…): the class rule is "sink callable escapes as a
#: value", so EVERY non-call identifier reference in the delegate
#: body re-enters the exclusion checks.
_WRAPPER_REF_TOKEN_RE = re.compile(
    r"(?<![\w.])((?:[A-Za-z_]\w*\.)*[A-Za-z_]\w*)",
)

#: Object-protocol executor attributes: calling `x.__call__(...)`
#: (or the bound-method / decorator unwrap chains `.__func__` /
#: `.__wrapped__`) executes the underlying `x`. A trailing executor
#: segment hid the real dotted target from the exclusion checks —
#: `os.system.__call__` has tail `__call__`, which matched neither
#: the dotted dangerous entries nor their bare tails.
_WRAPPER_EXECUTOR_DUNDERS = frozenset({
    "__call__", "__func__", "__wrapped__",
})


def _strip_executor_dunders(name: str) -> str:
    """Strip trailing executor-dunder segments — the executed target
    is the remaining base object. Empty result = nothing left to
    judge (the caller refuses the skip)."""
    parts = name.split(".")
    while parts and parts[-1] in _WRAPPER_EXECUTOR_DUNDERS:
        parts.pop()
    return ".".join(parts)


# ── Wrapper escape analysis ────────────────────────────────────────
#
# The trivial-wrapper skip is only sound if NO sink value escapes the
# delegate body: a sink reference carried by value into a binding, an
# argument, a return, or a yield reaches code the skip never reviews.
# The analysis below computes, per bound name, the set of references
# its value can carry (whole-value view over the language's real
# binding grammar — not a per-shape pattern list), resolves alias
# chains to a fixpoint, and judges every carried reference against the
# dangerous-callee exclusion. Anything the grammar walk cannot account
# for is UNRESOLVED: an unresolved value refuses the skip when it is
# the delegate (an unresolvable delegate must never be journalled
# mechanically clean); in data positions (arguments, returns, binding
# values) unresolved-ness alone does not refuse — a value the body
# never spells (parameter data, elements of externally-populated
# containers) is introduced and reviewed at its own spelling site, and
# judging it here would re-open the measured legitimate-corpus flip
# the argument-position gate exists to prevent.

#: A binding's value: (references carried by value, fully-resolved?).
_WrapperValue = tuple[set[str], bool]

#: ast fields that introduce or receive name bindings. The collector
#: must explicitly handle (or deliberately no-op) every node type
#: carrying one of these fields; an unlisted type refuses the whole
#: analysis (conservative default), and the closure test enumerates
#: the installed grammar against the handled set so new binder node
#: types fail loudly instead of silently escaping.
_PY_BINDER_FIELDS = frozenset({
    "target", "targets", "name", "names", "optional_vars", "rest",
})

#: Node types the collector fully handles (binds, judges, or safely
#: ignores). Everything else with a binder-shaped field refuses.
_PY_HANDLED_BINDERS: tuple[type, ...] = (
    ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr,
    ast.Import, ast.ImportFrom, ast.FunctionDef, ast.AsyncFunctionDef,
    ast.ClassDef, ast.For, ast.AsyncFor, ast.With, ast.AsyncWith,
    ast.ExceptHandler, ast.Global, ast.Nonlocal,
    ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp,
    # Deliberate no-ops: Delete unbinds; withitem/alias/comprehension
    # are handled through their parent statements.
    ast.Delete, ast.withitem, ast.alias, ast.comprehension,
)


def _py_dotted(node: ast.expr) -> str | None:
    """Dotted spelling of a pure Name/Attribute chain, else None."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _py_all_refs(node: ast.AST) -> set[str]:
    """Every dotted reference spelled anywhere under ``node`` —
    the conservative carry-set for opaque callables (lambdas, nested
    defs) whose call-time behaviour the prefilter cannot model."""
    out: set[str] = set()
    for n in ast.walk(node):
        if isinstance(n, (ast.Name, ast.Attribute)):
            d = _py_dotted(n)
            if d is not None:
                out.add(d)
    return out


def _py_value_refs(node: ast.expr | None) -> _WrapperValue:
    """Whole-value view of an expression: the references whose VALUE
    the expression can yield or carry. Value-preserving constructs
    (conditionals, boolean folds, displays, starring, walrus, await)
    are walked; value-computing constructs (arithmetic, comparisons,
    f-strings) yield a fresh object that cannot BE a body-spelled
    reference. Comprehensions carry their element/key/value, iterator
    and guard references (their own loop targets excluded); call
    results carry nothing here because the collector judges the
    callee and every argument at the Call node itself. Remaining
    opaque positions (subscripted elements, unknown node types)
    conservatively CARRY every reference spelled under them,
    unresolved — the value may not be one of them, but a body-spelled
    sink reference must never drop out of judgment."""
    if node is None:
        return set(), True
    if isinstance(node, (ast.Name, ast.Attribute)):
        d = _py_dotted(node)
        if d is not None:
            return {d}, True
        if isinstance(node, ast.Attribute):
            refs, ok = _py_value_refs(node.value)
            return {f"{r}.{node.attr}" for r in refs}, ok
        return set(), False
    if isinstance(node, (ast.Constant, ast.JoinedStr, ast.FormattedValue)):
        return set(), True
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        refs: set[str] = set()  # type: ignore[no-redef]
        ok = True
        for e in node.elts:
            r, o = _py_value_refs(e)
            refs |= r
            ok = ok and o
        return refs, ok
    if isinstance(node, ast.Dict):
        refs = set()
        ok = True
        for k, v in zip(node.keys, node.values):
            if k is None:
                ok = False  # **spread: stored values are not spelled here
            else:
                r, o = _py_value_refs(k)
                refs |= r
                ok = ok and o
            r, o = _py_value_refs(v)
            refs |= r
            ok = ok and o
        return refs, ok
    if isinstance(node, (ast.Starred, ast.NamedExpr, ast.Await)):
        return _py_value_refs(node.value)
    if isinstance(node, ast.IfExp):
        b_refs, b_ok = _py_value_refs(node.body)
        o_refs, o_ok = _py_value_refs(node.orelse)
        return b_refs | o_refs, b_ok and o_ok
    if isinstance(node, ast.BoolOp):
        refs = set()
        ok = True
        for v in node.values:
            r, o = _py_value_refs(v)
            refs |= r
            ok = ok and o
        return refs, ok
    if isinstance(node, ast.Lambda):
        return _py_all_refs(node), False
    if isinstance(node, ast.Call):
        # A call RESULT is a value the body does not spell. Nothing
        # drops out of judgment here: the collector's walk judges the
        # callee and every argument/keyword at the Call node itself,
        # so this arm only keeps the result from re-carrying inner
        # construct binders (a comprehension's loop variable) into
        # the enclosing position.
        return set(), False
    if isinstance(
        node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp),
    ):
        # A comprehension's element/key/value escapes by value like a
        # display element; iterator and guard refs are carried too.
        # Comprehension-scoped target names are the construct's own
        # binders, not body values — dropping them keeps a loop
        # variable that merely tail-collides with a sink from
        # refusing a benign wrapper.
        refs = set()
        targets: set[str] = set()
        for comp in node.generators:
            r, _o = _py_value_refs(comp.iter)
            refs |= r
            for cond in comp.ifs:
                r, _o = _py_value_refs(cond)
                refs |= r
            for n in ast.walk(comp.target):
                if isinstance(n, ast.Name):
                    targets.add(n.id)
        parts = (
            (node.key, node.value) if isinstance(node, ast.DictComp)
            else (node.elt,)
        )
        for part in parts:
            r, _o = _py_value_refs(part)
            refs |= r
        return {
            x for x in refs if x.split(".", 1)[0] not in targets
        }, False
    if isinstance(node, (ast.BinOp, ast.UnaryOp, ast.Compare)):
        return set(), True  # computed value — a fresh object
    # Opaque/unknown expression positions (comprehension elements,
    # subscripted displays, call results, future grammar additions):
    # conservatively carry every reference spelled under the node,
    # unresolved. A body-spelled sink reference is then judged
    # wherever the value escapes; unresolvedness alone still never
    # refuses in data positions (a value the body does not spell is
    # reviewed at its own spelling site).
    return _py_all_refs(node), False


def _py_wrapper_escape(
    source: str,
) -> tuple[dict[str, _WrapperValue], list[_WrapperValue], set[str]] | None:
    """Collect (bindings, judged values, parameters) for a Python
    wrapper body.

    ``bindings`` maps every bound name to its whole-value carry set;
    ``judged`` holds the value view of every escape position: binding
    values (including stores into containers/attributes), signature
    defaults, call arguments, returns, and yields; ``params`` names
    the caller-data parameters (unbound ones — see the exemption in
    _wrapper_ref_hits_exclusion).

    Returns None when the analysis cannot account for the body —
    unparseable source, star imports, or a binder construct outside
    the handled set — and the caller refuses the skip.
    """
    try:
        tree = ast.parse(textwrap.dedent(source))
    except (SyntaxError, ValueError, RecursionError):
        return None

    bindings: dict[str, _WrapperValue] = {}
    judged: list[_WrapperValue] = []
    accounted: set[str] = set()
    params: set[str] = set()
    outer_defs = {
        id(n) for n in tree.body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }

    def bind(name: str, refs: set[str], ok: bool) -> None:
        if ok and refs == {name}:
            # A name grounding to itself (`import os` binds os->os)
            # is not an alias; recording it would read as a cycle.
            accounted.add(name)
            return
        cur = bindings.get(name)
        if cur is not None:
            bindings[name] = (cur[0] | refs, cur[1] and ok)
        else:
            bindings[name] = (set(refs), ok)

    def bind_target(
        t: ast.expr, value_node: ast.expr | None,
        refs: set[str], ok: bool,
    ) -> None:
        if isinstance(t, ast.Name):
            bind(t.id, refs, ok)
        elif isinstance(t, ast.Starred):
            bind_target(t.value, None, refs, False)
        elif isinstance(t, (ast.Tuple, ast.List)):
            elts = t.elts
            if (
                isinstance(value_node, (ast.Tuple, ast.List))
                and len(value_node.elts) == len(elts)
                and not any(isinstance(e, ast.Starred) for e in elts)
            ):
                for te, ve in zip(elts, value_node.elts):
                    r, o = _py_value_refs(ve)
                    bind_target(te, ve, r, o)
            else:
                for te in elts:
                    bind_target(te, None, refs, False)
        # Attribute/Subscript targets bind no local name; the stored
        # value's refs are judged through the assignment's entry.

    def bind_default(arg_name: str, default: ast.expr) -> None:
        r, o = _py_value_refs(default)
        judged.append((r, o))
        # A pure-literal default leaves the parameter as plain
        # caller data (the caller's argument usually replaces it);
        # a reference-carrying or unresolved default joins the
        # parameter's value domain and must resolve like any alias.
        if r or not o:
            bind(arg_name, r, o)

    def bind_defaults(a: ast.arguments, exempt: bool = False) -> None:
        pos = a.posonlyargs + a.args
        # Only the WRAPPER's own parameters are caller data. A
        # lambda / nested-def parameter shadows only inside its own
        # scope — outside it the same spelling is the module or
        # import — so exempting it would launder a bare sink call
        # (`g = lambda system: 0` then `return system(c)`) through
        # the root drop in _wrapper_ref_hits_exclusion. Those
        # parameters get no exemption and no outer binding; their
        # in-scope references are already carried conservatively by
        # the opaque value view.
        if exempt:
            params.update(arg_.arg for arg_ in pos + a.kwonlyargs)
            if a.vararg is not None:
                params.add(a.vararg.arg)
            if a.kwarg is not None:
                params.add(a.kwarg.arg)
        for arg_, default in zip(pos[len(pos) - len(a.defaults):], a.defaults):
            bind_default(arg_.arg, default)
        for arg_, kw_default in zip(a.kwonlyargs, a.kw_defaults):
            if kw_default is not None:
                bind_default(arg_.arg, kw_default)

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            r, o = _py_value_refs(node.value)
            judged.append((r, o))
            for tgt in node.targets:
                bind_target(tgt, node.value, r, o)
        elif isinstance(node, ast.AnnAssign):
            if node.value is not None:
                r, o = _py_value_refs(node.value)
                judged.append((r, o))
                bind_target(node.target, node.value, r, o)
            elif isinstance(node.target, ast.Name):
                accounted.add(node.target.id)  # bare annotation binds nothing
        elif isinstance(node, ast.AugAssign):
            r, o = _py_value_refs(node.value)
            judged.append((r, o))
            if isinstance(node.target, ast.Name):
                # accumulated value: prior carry judged at its own site
                bind(node.target.id, r, False)
        elif isinstance(node, ast.NamedExpr):
            r, o = _py_value_refs(node.value)
            judged.append((r, o))
            if isinstance(node.target, ast.Name):
                bind(node.target.id, r, o)
        elif isinstance(node, ast.Import):
            for al in node.names:
                if al.asname:
                    bind(al.asname, {al.name}, True)
                else:
                    root = al.name.split(".")[0]
                    bind(root, {root}, True)
        elif isinstance(node, ast.ImportFrom):
            for al in node.names:
                if al.name == "*":
                    return None  # star import: unanalyzable binding set
                # Relative imports are spelled delegates too: the
                # level dots drop and the module path joins the ref,
                # so its parts face the same tail judgment as any
                # project-local name.
                if node.module:
                    bind(al.asname or al.name,
                         {f"{node.module}.{al.name}"}, True)
                else:
                    bind(al.asname or al.name, {al.name}, True)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # A decorator reference is executed at definition time —
            # a bare `@os.system` runs the sink on the function
            # object. Judge decorator refs like any escape position
            # (call-shaped decorators are judged by the Call arm too).
            for dec in node.decorator_list:
                judged.append(_py_value_refs(dec))
            bind_defaults(node.args, exempt=id(node) in outer_defs)
            if id(node) not in outer_defs:
                bind(node.name, _py_all_refs(node), False)
        elif isinstance(node, ast.Lambda):
            bind_defaults(node.args)
        elif isinstance(node, ast.ClassDef):
            for dec in node.decorator_list:
                judged.append(_py_value_refs(dec))
            bind(node.name, _py_all_refs(node), False)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            r, _o = _py_value_refs(node.iter)
            judged.append((r, _o))
            bind_target(node.target, None, r, False)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    r, _o = _py_value_refs(item.context_expr)
                    bind_target(item.optional_vars, None, r, False)
        elif isinstance(node, ast.ExceptHandler):
            if node.name:
                bind(node.name, set(), False)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            for n in node.names:
                bind(n, set(), False)  # externally rebindable
        elif isinstance(
            node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp),
        ):
            for comp in node.generators:
                r, _o = _py_value_refs(comp.iter)
                judged.append((r, _o))
                for tgt_node in ast.walk(comp.target):
                    if isinstance(tgt_node, ast.Name):
                        accounted.add(tgt_node.id)  # comprehension-scoped
        elif isinstance(node, ast.Call):
            # The callee reference is judged too: the textual
            # single-call gate and the main callee check can miss a
            # call the AST sees (line-view divergence), and a
            # call-position reference is exactly the exclusion's
            # domain.
            judged.append(_py_value_refs(node.func))
            for a in node.args:
                judged.append(_py_value_refs(a))
            for kw in node.keywords:
                judged.append(_py_value_refs(kw.value))
        elif isinstance(node, ast.Return):
            judged.append(_py_value_refs(node.value))
        elif isinstance(node, (ast.Yield, ast.YieldFrom)):
            if node.value is not None:
                judged.append(_py_value_refs(node.value))
        elif isinstance(node, _PY_HANDLED_BINDERS):
            pass  # deliberate no-op binder carriers
        elif any(f in _PY_BINDER_FIELDS for f in getattr(node, "_fields", ())):
            return None  # binder construct outside the handled grammar

    # Completeness sweep: every stored Name must be accounted for.
    # This is the by-construction closure — a binding construct the
    # walk above missed (or a future grammar addition) refuses the
    # skip instead of silently carrying a value.
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            if node.id not in bindings and node.id not in accounted:
                return None

    # A parameter that is rebound (or carries a reference default)
    # loses the caller-data exemption — its binding resolves instead.
    params -= set(bindings)
    return bindings, judged, params


#: Function-pointer declarator: the declared name sits inside the
#: first `(*name)` group (`int (*fp)(int) = system`).
_C_FNPTR_TARGET_RE = re.compile(r"\(\s*\*+\s*([A-Za-z_]\w*)\s*\)")

_C_LITERAL_RE = re.compile(
    r"0[xXbB][0-9a-fA-F]+[uUlL]*|\d+(?:\.\d*)?[uUlLfF]*"
    r"|NULL|nullptr|true|false",
)

#: A cast prefix: `(type)`, `(struct foo *)`, `(unsigned long)` — word
#: sequences with pointer stars only, so a parenthesized EXPRESSION
#: (operators inside) never strips.
_C_CAST_PREFIX_RE = re.compile(
    r"^\(\s*[A-Za-z_]\w*(?:\s+[A-Za-z_]\w*)*[\s*]*\)\s*",
)

_C_PURE_REF_RE = re.compile(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*")


def _c_value_refs(rhs: str) -> set[str]:
    """Every identifier chain spelled in a C-family value expression
    (`->` pre-normalised to `.` by the caller)."""
    return {m.group(1) for m in _WRAPPER_REF_TOKEN_RE.finditer(rhs)}


def _c_value_pure(rhs: str) -> bool:
    """True when the value expression provably yields only what it
    spells: a lone identifier chain or literal, possibly behind
    unary operators / casts, or a ternary of pure arms. Everything
    else is unresolved. Brace-initializer values never reach this
    classifier — the caller's statement splitter consumes `{`/`}`
    before value classification, so brace-carried references are
    refused upstream (body-view truncation at the initializer's `}`
    plus the multi-statement tail gates), not judged here."""
    rhs = rhs.strip()
    if not rhs:
        return False
    if "?" in rhs:
        _cond, _, rest = rhs.partition("?")
        a, sep, b = rest.partition(":")
        return bool(sep) and _c_value_pure(a) and _c_value_pure(b)
    prev = None
    while rhs != prev:
        prev = rhs
        rhs = rhs.lstrip("&*+-!~ ").strip()
        m = _C_CAST_PREFIX_RE.match(rhs)
        if m is not None and m.end() < len(rhs):
            rhs = rhs[m.end():].strip()
    return bool(
        _C_PURE_REF_RE.fullmatch(rhs) or _C_LITERAL_RE.fullmatch(rhs)
    )


def _c_find_assign(stmt: str) -> tuple[int, int, bool] | None:
    """Locate the first assignment operator in a statement fragment.

    Returns (lhs_end, rhs_start, is_compound), skipping comparison
    spellings (`==`, `!=`, `<=`, `>=`); shift-compounds (`<<=`,
    `>>=`) and single-op compounds (`+=`, `|=`, …) are assignments
    whose stored value is computed, not spelled — compound."""
    i = -1
    while True:
        i = stmt.find("=", i + 1)
        if i < 0:
            return None
        nxt = stmt[i + 1] if i + 1 < len(stmt) else ""
        if nxt == "=":
            i += 1
            continue
        if nxt == ">":
            continue  # `=>` arrow — a value, not an assignment
        prev = stmt[i - 1] if i > 0 else ""
        if prev == "=":
            continue
        if prev in "<>!":
            if prev in "<>" and i >= 2 and stmt[i - 2] == prev:
                return i - 2, i + 1, True  # <<= / >>=
            continue  # comparison
        if prev in "+-*/%&|^":
            return i - 1, i + 1, True
        if prev == ":":
            return i - 1, i + 1, False  # := declaration-assignment
        return i, i + 1, False


def _text_wrapper_escape(
    ref_lines: list[str],
) -> tuple[dict[str, _WrapperValue], list[_WrapperValue]] | None:
    """Whole-value binding/escape scan for the languages without an
    AST leg. Statement-level grammar: declarations with initializers
    (including typedef'd/`auto`/function-pointer declarators), plain,
    chained, and compound assignments, `:=` declarations, ternary
    values, and return-position value escapes. Splitting on `{`/`}`
    destroys brace initializers before this scan — their refusal
    comes from the caller's body-view truncation and tail gates, not
    from value judgment here. An assignment whose target cannot be
    named refuses the analysis (None — the caller refuses the
    skip).

    ``ref_lines`` are REFERENCE-view lines: strings and comments
    already blanked by the caller (the shared ``sanitized_view``
    chokepoint) so prose can never bind or escape a value."""
    text = "\n".join(ref_lines)
    text = text.replace("->", ".")
    bindings: dict[str, _WrapperValue] = {}
    judged: list[_WrapperValue] = []

    def bind(name: str, refs: set[str], ok: bool) -> None:
        cur = bindings.get(name)
        if cur is not None:
            bindings[name] = (cur[0] | refs, cur[1] and ok)
        else:
            bindings[name] = (set(refs), ok)

    def process(stmt: str) -> tuple[set[str], bool] | None:
        """Handle one fragment; returns the fragment's value view
        (for chained assignments), or None when unaccountable."""
        pos = _c_find_assign(stmt)
        if pos is None:
            # Expression statement — no binding, but its references
            # are JUDGED value escapes. The `[;{}\n]` split turns a
            # JS/TS `${…}` template interpolation into exactly this
            # shape (`const t = \`$` + `x && execSync`): pre-fix the
            # fragment's refs were returned unjudged, so a dangerous
            # ref escaping as an interpolation VALUE journalled
            # mechanically clean even though both judged views showed
            # it (the one-element-outside-the-derivation member of
            # the escape rebase). Judging every expression fragment
            # is the file's stated doctrine — over-exclusion costs
            # one review; a hidden value escape mints a false clean.
            value = (_c_value_refs(stmt), True)
            judged.append(value)
            return value
        lhs_end, rhs_start, compound = pos
        lhs = stmt[:lhs_end].strip()
        rhs = stmt[rhs_start:].strip()
        if _c_find_assign(rhs) is not None:
            value = process(rhs)  # type: ignore[assignment]
            if value is None:
                return None
        else:
            value = (_c_value_refs(rhs), _c_value_pure(rhs))
        judged.append(value)
        if compound:
            value = (value[0], False)  # accumulated/computed store
        if lhs.startswith("*") or "[" in lhs or "." in lhs:
            # Store through a pointer / into a container or member:
            # no local name is bound; the value refs stay judged.
            return value
        fnptr = _C_FNPTR_TARGET_RE.search(lhs)
        if fnptr is not None:
            bind(fnptr.group(1), *value)
            return value
        idents = re.findall(r"[A-Za-z_]\w*", lhs)
        if not idents:
            return None  # assignment with an unnameable target
        bind(idents[-1], *value)
        return value

    for stmt in re.split(r"[;{}\n]", text):
        stmt = stmt.strip()
        if not stmt:
            continue
        if re.match(r"return\b", stmt):
            judged.append((_c_value_refs(stmt[6:]), True))
            continue
        if process(stmt) is None:
            return None
    return bindings, judged


def _resolve_wrapper_ref(
    ref: str, bindings: dict[str, _WrapperValue],
) -> _WrapperValue:
    """Fixpoint alias resolution: expand the reference's leading
    segment through the binding map until it no longer names a
    binding. Cycles and expansion past the bound (pathological
    self-referential bodies) resolve to unresolved."""
    out: set[str] = set()
    ok = True
    seen: set[str] = set()
    stack = [ref]
    steps = 0
    while stack:
        steps += 1
        if steps > 256:
            return out, False
        r = _strip_executor_dunders(stack.pop())
        if not r:
            ok = False  # pure executor-dunder chain: no base to judge
            continue
        if r in seen:
            ok = False  # alias cycle never grounds
            continue
        seen.add(r)
        head, _, rest = r.partition(".")
        bound = bindings.get(head)
        if bound is None:
            out.add(r)
            continue
        refs, resolved = bound
        if not resolved:
            ok = False
        for base in refs:
            stack.append(f"{base}.{rest}" if rest else base)
    return out, ok


def _wrapper_ref_hits_exclusion(
    ref: str,
    exclusion: frozenset,
    tails: frozenset,
    project_sinks: frozenset | None,
    params: frozenset[str] | set[str] = frozenset(),
) -> bool:
    """Judge one carried reference: every dotted prefix against the
    full dangerous entries, every segment against the bare tails.

    A reference ROOTED at a parameter name is caller data — the local
    binding shadows any module or import of the same spelling, so the
    root segment carries no sink identity of its own and is dropped
    before judgment (a bare parameter reference is exempt entirely).
    The attribute segments still name the API reached through the
    caller's object (`sp.run`) and stay judged — for the built-in
    sets via their bare tails, and a declared project sink keeps its
    ROOT too: the operator's dotted declaration names the module, so
    a parameter colliding with that root never drops it (dropping
    would launder `utilmod.launch` through a parameter named
    `utilmod`, and dotted project sinks derive no tail set)."""
    parts = ref.split(".")
    if parts and parts[0] in params:
        sink_roots = {s.split(".", 1)[0] for s in project_sinks or ()}
        if parts[0] not in sink_roots:
            parts = parts[1:]
            if not parts:
                return False
    prefixes = {".".join(parts[:i]) for i in range(1, len(parts) + 1)}
    if prefixes & exclusion or set(parts) & tails:
        return True
    return bool(project_sinks and prefixes & project_sinks)


def _judged_view_lines(
    source: str, lang: str,
) -> tuple[list[str], list[str]] | None:
    """Cut the two judged views every lexical prefilter tier shares.

    One derivation for every consumer (trivial-wrapper AND
    simple-accessor tiers): a tier with its own raw-text line
    filter re-minted the one-planted-line suppression class the
    shared views closed. Returns ``(code_lines, ref_lines)``, or
    ``None`` when the js/ts ambiguous-slash refusal applies (the
    shape must not be judged lexically at all)."""
    # Judged views, both cut by the shared sanitized_view chokepoint
    # (escape-aware, multi-line-aware, per-language string grammar —
    # raw strings, template literals, backticks, text blocks,
    # heredocs; see core/audit/source_view.py):
    #
    # - code_lines (comments-only view, strings KEPT): comment
    #   markers are recognised lexically in code position only, and
    #   every MODELED string form (single-line escapes, raw/template/
    #   backtick/text-block/heredoc/long-string, value-position regex
    #   literals) carries state across lines, so its data can never
    #   open or close comment state and swallow a sink line out of
    #   the judged view; constructs the scanner does not model keep
    #   their text in the view (over-inclusion, costs a review). The
    #   grammar hole the scanner cannot decide from tokens — a js/ts
    #   `/` read as division whose regex reading would hide a
    #   comment-opener — is PARTIALLY refused at the wrapper tier
    #   below (ambiguous `)`/`]` contexts; backslash-bearing
    #   division tails); the backslash-free char-class spelling
    #   remains a DECLARED OPEN residual there.
    # - ref_lines (strings AND comments blanked): the reference view
    #   the escape analysis and the argument-position scan judge, so
    #   prose can never flip a benign wrapper. Blanking is confined
    #   to lexically closed literals; a mis-opened literal can only
    #   weaken these AUXILIARY refusal layers, never hide a call
    #   from the code_lines gates above, which see the same bytes
    #   with strings kept.
    #
    # For python the plain line filter stays: `/*` is not a comment
    # there and the AST escape leg supplies the reference judgment.
    code_lines: list[str] = []
    ref_lines: list[str] = []
    if lang == "python":
        raw_lines = [ln.strip() for ln in source.strip().splitlines()]
        code_lines = [
            ln for ln in raw_lines
            if ln
            and not ln.startswith("//")
            and not ln.startswith("/*")
            and not ln.startswith("*")
            and not ln.startswith("#")
            and ln not in ("{", "}")
        ]
    elif lang in ("perl", "lua"):
        # No prefix-based line drops here. The scanner does not model
        # every perl quote construct (plain `"…"` spans lines, q//,
        # qq{}, heredocs), so neither the raw text nor the blanked
        # twin can DECIDE that a `#`-prefixed line is a comment: a
        # multi-line string's continuation line can start with `#`
        # (string data) and carry live code after the closing quote —
        # dropping it removed a `system(` call from every judged view
        # (the one-planted-line suppression class the C-family branch
        # closed by judging drops on its fully-modeled blanked twin).
        # Perl typeglob aliases (`*glob = \&system;`) start with `*`
        # and were dropped as block-comment continuations — live
        # sink-aliasing code. Lua comment lines (`--`) never matched
        # the old filter and have always been kept, so keeping
        # `#`-prefixed lines merely aligns perl with the branch's
        # existing lua behavior. Cost is refusal-direction only: a
        # genuine comment line counts toward the 5-line cap, and
        # comment prose spelling `name(…)` reads as a call and
        # refuses the skip — one LLM review, the documented safe
        # direction (over-inclusion costs a review).
        #
        # Exotic line terminators normalised before the two views
        # split (same rationale as the C-family branch below): a lone
        # \r \u2014 or ANY other str.splitlines terminator in string data \u2014
        # splits raw_lines but survives blanked-to-space in the ref
        # view, pairing ref lines with the wrong source line and
        # weakening the escape/argument refusal layers. The
        # normalisation set is the full splitlines universe
        # (_LINE_TERMINATORS), and both views then split on "\n" ONLY
        # so no residual byte can desync them.
        src = _normalize_line_terminators(source.strip())
        raw_lines = [ln.strip() for ln in src.split("\n")]  # line-model: _normalize_line_terminators rewrites \r to \n above
        kept = [
            idx for idx, ln in enumerate(raw_lines)
            if ln and ln not in ("{", "}")
        ]
        code_lines = [raw_lines[i] for i in kept]
        sview = sanitized_view(src, language=lang).split("\n")  # line-model: _normalize_line_terminators rewrites \r to \n above
        ref_lines = [
            sview[i].strip() if i < len(sview) else ""
            for i in kept
        ]
    else:
        # Exotic line terminators normalised first so the two views
        # split onto the SAME indices: a lone \r \u2014 or any other
        # str.splitlines terminator (\x0b, \x0c, \x1c-\x1e, \x85,
        # U+2028/9) \u2014 survives as string data in the comments-only
        # view but blanks to a space in the ref view, desynchronising
        # splitlines() and pairing ref lines with the wrong source
        # line (one plantable byte swallowed a live sink line from
        # both judged views). The normalisation set is derived from
        # splitlines itself (_LINE_TERMINATORS), and both views then
        # split on "\n" ONLY \u2014 sanitized_view preserves "\n" 1:1 and
        # blanks everything else to spaces, so the two views agree on
        # line indices BY CONSTRUCTION even for a terminator the
        # tuple were to miss.
        src = _normalize_line_terminators(source.strip())
        cview = sanitized_view(src, language=lang, keep_strings=True)
        rlines = sanitized_view(src, language=lang).split("\n")  # line-model: _normalize_line_terminators rewrites \r to \n above
        for idx, raw in enumerate(cview.split("\n")):  # line-model: _normalize_line_terminators rewrites \r to \n above
            ln = raw.strip()
            rl = rlines[idx].strip() if idx < len(rlines) else ""
            if not ln or ln in ("{", "}"):
                continue
            # Drop-eligibility is judged on the BLANKED twin, never
            # on the strings-kept text: in the comments-only view
            # string data is present BY DESIGN, so a prefix-textual
            # filter there re-swallowed whole lines when a multi-line
            # literal's continuation started with `//` or `#` and its
            # closing line carried live code — the same suppression
            # class the lexer adoption closed, reintroduced one line
            # below it. In the blanked view comments and string data
            # are spaces, so `#` can only open a real preprocessor
            # directive there, and `//` cannot start a line at all
            # (that arm served only the hostile case; removed).
            if rl.startswith("#"):
                continue
            code_lines.append(ln)
            ref_lines.append(rl)

    # Ambiguous-slash refusal (js/ts): a `/` right after `)` or `]`
    # is the one spelling the scanner's division-vs-regex heuristic
    # cannot decide from tokens alone (`if (x) /re/` vs `(a+b) / c`)
    # — and a mis-call there lets a regex interior mint comment state
    # in code position, the full one-planted-line suppression
    # primitive. The wrapper tier refuses the skip outright instead
    # of judging it: cost is one LLM review for division-bearing
    # delegates (refusal direction), and unambiguous division (after
    # an identifier/number) keeps its skip. Scanned on the REF view,
    # where string/comment/modeled-regex content is already spaces —
    # only real code can spell the trigger.
    # Beside it, the no-valid-reading spelling: a backslash after a
    # division-read `/` on the same line is not JS (only a would-be
    # regex body reads it), so refusing costs nothing on legitimate
    # code. The two gates are PARTIAL HARDENING, not a closure of
    # the division-vs-regex mint class: a regex body can hide a
    # comment-opener with no backslash at all (`a /[//]x/` — the
    # `//` sits in a char class, the division reading dies on the
    # unterminated `[` only on a LATER line, and everything after
    # the `//` blanks out of both views). That residual is a
    # declared open bound (suppression direction, js/ts wrapper
    # delegates only, pinned in the battery); closing it needs
    # parser-grade JS lexing, not another spelling rule.
    if lang in ("javascript", "typescript"):
        for rl in ref_lines:
            if (_JS_AMBIGUOUS_SLASH_RE.search(rl)
                    or _JS_INVALID_SLASH_RE.search(rl)):
                return None

    return code_lines, ref_lines


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

    # Call-graph veto: when the extraction pipeline already resolved
    # this function's callees, a dangerous resolved name refuses the
    # skip regardless of how the body spells the call (macro
    # indirection, token paste, an alias the textual analysis below
    # cannot see). Exact-name match, mirroring _is_trivially_clean's
    # callee check — tail matching here would flip wrappers delegating
    # to project functions that merely share a bare name with a sink.
    for c in callees or []:
        cname = c.get("name", "")
        if not cname:
            continue
        if cname in _WRAPPER_DANGEROUS_CALLEES or cname in extra_dangerous:
            return False, ""
        if project_sinks and cname in project_sinks:
            return False, ""

    views = _judged_view_lines(source, lang)
    if views is None:
        # js/ts ambiguous-slash refusal — the lexer cannot decide
        # the shape; never judged mechanically clean.
        return False, ""
    code_lines, ref_lines = views

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

    call_matches = [
        m for m in _WRAPPER_CALL_RE.finditer(body_no_sig)
        if m.group(1) not in (
            "if", "while", "for", "switch", "sizeof", "typeof",
            "return", "else", "case", "offsetof", "container_of")
        and m.group(1) not in _DANGEROUS_MACROS
    ]

    if len(call_matches) != 1:
        return False, ""

    callee_name = call_matches[0].group(1)

    # Self-capture guard: for the languages whose signature is not
    # stripped from the body view (everything but c/cpp/python), the
    # signature's own name matches the call regex (`func Wrap(`,
    # `fn wrap(`, `public String wrap(`). When the ONE captured call
    # is that self-capture — the shape a desynced view degrades to —
    # the delegate is signature-only and never mechanically clean;
    # the healthy reason string must also never name the wrapper
    # itself as its own delegate.
    if lang not in ("c", "cpp", "python"):
        start = call_matches[0].start(1)
        brace = body_no_sig.find("{")
        if brace >= 0 and start < brace:
            return False, ""
        if re.search(
            # Param window bounded: planted 'func (' heads inside an
            # unbounded [^)] span re-scan the tail per head —
            # quadratic on hostile source (4000 is far above real
            # parameter lists; longer ones stop matching).
            r"\b(?:func(?:tion)?|fn|sub)\s+(?:\([^)]{0,4000}\)\s*)?$",
            body_no_sig[:start],
        ):
            return False, ""

    # Indirection: `getattr(subprocess, "run")(...)`, `vars(m)["run"]
    # (...)`, `functools.partial(sp.run)(...)`, `dlsym(h, "system")` —
    # single-call delegates whose captured callee is the indirection
    # helper, so the dangerous-callee exclusion below never sees the
    # real target. Literal arguments resolve mechanically: getattr's
    # base+attr precisely; the rest through every quoted name in the
    # body (plus partial's first-argument reference). Each resolved
    # candidate re-enters the exclusion checks; a shape with NO
    # resolvable literal, or resolving to another indirection helper,
    # refuses the skip — an unresolvable delegate must never be
    # journalled mechanically clean.
    # One-hop local alias first: `f2 = subprocess.run` (or Go `:=`)
    # then `return f2(...)` captures the LOCAL name as the callee
    # while the real target sits surface-spelled on the assignment
    # line. Resolve through the body's simple assignments before the
    # family/exclusion checks. Known residual (documented, not
    # chased): a concatenated literal inside a family call
    # (`attrgetter("ru"+"n")`) is not folded — the wrapper skip is
    # prefilter-tier only, and the function still passes the triage,
    # Joern, and hit-scan evidence layers, which see the file's
    # surface spellings.
    # Every language's dangerous-callee set joins the exclusion here
    # (needed below for both the callee and the escape judgments).
    exclusion = _WRAPPER_DANGEROUS_CALLEES | extra_dangerous
    tails = _WRAPPER_DANGEROUS_TAILS | {
        e.rsplit(".", 1)[-1] for e in extra_dangerous
    }

    # Whole-value escape analysis over the language's real binding
    # grammar: bindings feed the callee/reference fixpoint resolution,
    # and every value-escape position (binding value, signature
    # default, call argument, return, yield, and bare expression
    # fragments — which is where the `[;{}\n]` split lands `${…}`
    # template-interpolation values) is judged against the exclusion.
    # An unaccountable body refuses the skip. Position coverage is
    # pinned, not claimed: TestTemplateInterpolationValueEscape holds
    # the interpolation/expression-fragment members.
    wrapper_params: set[str] = set()
    if lang == "python":
        escape = _py_wrapper_escape(source)
        if escape is None:
            return False, ""
        wrapper_bindings, judged_values, wrapper_params = escape
    else:
        text_escape = _text_wrapper_escape(ref_lines)
        if text_escape is None:
            return False, ""
        wrapper_bindings, judged_values = text_escape
    for refs, _resolved in judged_values:
        for r in refs:
            expanded, _ok = _resolve_wrapper_ref(r, wrapper_bindings)
            for er in expanded:
                if _wrapper_ref_hits_exclusion(
                    er, exclusion, tails, project_sinks, wrapper_params,
                ):
                    return False, ""

    # Executor-dunder chains resolve to their base object BEFORE the
    # alias walk (`f2.__call__` must alias-resolve as `f2`), and again
    # after it (the alias target can itself carry the chain).
    callee_name = _strip_executor_dunders(callee_name)
    if not callee_name:
        return False, ""
    if callee_name.split(".", 1)[0] in wrapper_bindings:
        resolved_set, resolved_ok = _resolve_wrapper_ref(
            callee_name, wrapper_bindings,
        )
        if not resolved_ok or not resolved_set:
            # An unresolvable delegate (or one whose value the
            # body never names — a literal, a container element)
            # must never be journalled mechanically clean.
            return False, ""
        stripped = {_strip_executor_dunders(r) for r in resolved_set}
        if "" in stripped:
            return False, ""
        if len(stripped) == 1:
            callee_name = next(iter(stripped))
        else:
            # Multi-valued delegate: judge every candidate; the
            # spelled local name stays in the reason/gates.
            multi = sorted(stripped)
            if any(
                c.rsplit(".", 1)[-1] in _WRAPPER_INDIRECTION_TAILS
                for c in multi
            ):
                return False, ""
            if re.search(r"\)\s*[([]", body_no_sig):
                return False, ""
            for name in multi:
                if any(
                    seg.startswith("__") and seg.endswith("__")
                    and seg != "__import__"
                    for seg in name.split(".")
                ):
                    return False, ""
                if _wrapper_ref_hits_exclusion(
                    name, exclusion, tails, project_sinks, wrapper_params,
                ):
                    return False, ""
                if any(api in name.lower() for api in _CRYPTO_APIS):
                    return False, ""
            return _wrapper_tail_gates(
                lang, body_no_sig, callee_name,
            )

    candidates = [callee_name]
    _tail = callee_name.rsplit(".", 1)[-1]
    if _tail in _WRAPPER_INDIRECTION_TAILS:
        if _tail == "getattr":
            m = _WRAPPER_GETATTR_LITERAL_RE.search(body_no_sig)
            if not m:
                return False, ""
            callee_name = f"{m.group(1)}.{m.group(2)}"
            candidates = [callee_name]
        else:
            resolved = _WRAPPER_LITERAL_NAME_RE.findall(body_no_sig)
            if _tail == "partial":
                pm = _WRAPPER_PARTIAL_ARG_RE.search(body_no_sig)
                if pm is None:
                    return False, ""
                resolved.append(pm.group(1))
            if not resolved:
                return False, ""
            if any(
                r.rsplit(".", 1)[-1] in _WRAPPER_INDIRECTION_TAILS
                for r in resolved
            ):
                return False, ""
            candidates = [callee_name, *resolved]
    elif re.search(r"\)\s*[([]", body_no_sig):
        # The captured call's RESULT is itself called or subscripted
        # (`make_fn()(arg)`): the executed target is unknown, and an
        # unknown delegate is never mechanically clean. Resolved
        # indirection shapes are handled above; this guards the
        # factories the family list does not name.
        return False, ""

    # Any remaining dunder segment routes the call through the object
    # protocol (`x.__class__(...)`, `x.__self__.run(...)`): the
    # executed target is not the spelled name, and an unresolvable
    # delegate must never be journalled mechanically clean.
    # (`__import__` is the indirection family's own member, resolved
    # above.)
    for name in candidates:
        if any(
            seg.startswith("__") and seg.endswith("__")
            and seg != "__import__"
            for seg in name.split(".")
        ):
            return False, ""

    # Every language's dangerous-callee set (a wrapper's language arm
    # only strips the signature; the exclusion must not be narrower
    # than _is_trivially_clean's), matched against EVERY dotted prefix
    # of the name AND every segment against the bare tails — `from
    # subprocess import run` delegates via the bare name, and an
    # attribute chain can bury the dangerous target mid-name
    # (`sp.run.retry(...)`). Over-exclusion only costs one review; a
    # missed exclusion journals a dangerous delegate mechanically
    # clean.
    for name in candidates:
        if _wrapper_ref_hits_exclusion(
            name, exclusion, tails, project_sinks, wrapper_params,
        ):
            return False, ""
        if any(api in name.lower() for api in _CRYPTO_APIS):
            return False, ""

    # A sink passed as an ARGUMENT to any call is non-clean: the
    # delegate never spells the target in call position
    # (`pool.submit(os.system, cmd)`, `map(os.system, args)`), so the
    # callee checks above cannot exclude it. For Python the AST
    # escape analysis above already judged every argument / return /
    # yield / binding value; the textual scan below serves the
    # languages without an AST leg. Judge every identifier reference
    # in argument position (inside a call's parentheses, not itself
    # called) against the same exclusion — dotted references over
    # every prefix + every segment tail, bare references against the
    # full entry names AND the bare tails (`pool.submit(system, cmd)`
    # after a bare import escapes via the bare name exactly like the
    # bare-callee case above). The position gate is load-bearing: a
    # name-blind scan flags keyword spellings (`assert x == f()`) and
    # plain data reads (`return request.param`) that share a tail
    # with a sink but cannot escape a callable — measured at
    # thousands of flipped legitimate rows; with the gate the flip
    # set is callable-shaped references only. Strings and comments
    # are cut from this view only. The crypto substring heuristic
    # stays call-position-only: matching it against every variable
    # NAME (`hash_val`, `signed_off`) would flip accessor-adjacent
    # wrappers wholesale without naming a sink. Over-exclusion costs
    # one review; the miss journals a dangerous delegate mechanically
    # clean.
    if lang != "python":
        ref_body = " ".join(ref_lines)
        if lang in ("c", "cpp"):
            cut = ref_body.find("{")
            if cut >= 0:
                ref_body = ref_body[cut + 1:]
                closing = ref_body.rfind("}")
                if closing >= 0:
                    ref_body = ref_body[:closing]
        # Local aliases (`f2 = os.system` then `pool.submit(f2,
        # cmd)`): the argument spells the LOCAL name while the sink
        # sits surface-spelled on the assignment line, outside any
        # argument list — resolve through the escape analysis'
        # binding fixpoint.
        for rm in _WRAPPER_REF_TOKEN_RE.finditer(ref_body):
            if ref_body[rm.end():].lstrip()[:1] == "(":
                continue  # call position — judged by the callee checks
            before = ref_body[:rm.start()]
            if before.count("(") <= before.count(")"):
                continue  # not inside any call's argument list
            ref = _strip_executor_dunders(rm.group(1))
            if not ref:
                continue
            expanded, _ok = _resolve_wrapper_ref(ref, wrapper_bindings)
            if any(
                _wrapper_ref_hits_exclusion(
                    er, exclusion, tails, project_sinks,
                )
                for er in expanded
            ):
                return False, ""

    return _wrapper_tail_gates(lang, body_no_sig, callee_name)


def _wrapper_tail_gates(
    lang: str, body_no_sig: str, callee_name: str,
) -> tuple[bool, str]:
    """Final shape gates: a trivial delegate has at most one return
    and, without one, at most a single statement."""
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
            stmts = [s.strip() for s in body_no_sig.split("\n") if s.strip()]  # line-model: statement count only; strip()-normalised
            if len(stmts) > 1:
                return False, ""

    return True, f"trivial wrapper delegating to {callee_name}()"


_AUTH_KEYWORDS = frozenset({
    "role", "permission", "session", "token", "auth", "authz",
    "authorize", "authenticate", "login", "logout", "privilege",
    "access_control", "acl", "rbac",
})

# All entries LOWERCASE: every consumer matches against a lowercased
# view (``callee_name.lower()``, ``source.lower()``), so an uppercase
# entry (the OpenSSL prefixes were spelled ``EVP_``/``SSL_``…) can
# never match — the exclusion silently died and SSL_/EVP_-touching
# functions were hard-suppressed pre-LLM as sink-unreachable clean.
_CRYPTO_APIS = frozenset({
    "encrypt", "decrypt", "hash", "hmac", "sign", "verify",
    "digest", "cipher", "aes", "rsa", "sha", "md5",
    "pbkdf2", "scrypt", "bcrypt", "argon2",
    "evp_", "rand_", "ssl_", "tls_",
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


def _py_simple_accessor(source: str) -> bool:
    """AST-shape membership for the python accessor arm.

    The function body must be EXACTLY one ``return`` (an optional
    docstring aside) of a ``self`` field, a gated bare name, or a
    numeric/boolean/None constant. Anything else — a second
    statement, a call, a subscript — refuses. The AST judgment
    replaces the old raw-line prefix filter + suffix-anchored regex,
    which let a side-effecting statement ride in front of the return
    and dropped ``#``-prefixed string-continuation lines carrying
    live code.
    """
    # Size cap first (the lexical counting the pre-AST arm used, kept
    # for parity so the rewrite never skips MORE than before): the
    # dropped comment/docstring-continuation lines can only
    # under-count, and honesty never rests on the count — the AST
    # shape check below is the verdict.
    stripped = [ln.strip() for ln in source.strip().splitlines()]
    counted = [
        ln for ln in stripped
        if ln
        and not ln.startswith(("//", "/*", "*", "#"))
        and ln not in ("{", "}")
    ]
    if len(counted) > 3:
        return False
    try:
        tree = ast.parse(textwrap.dedent(source))
    except (SyntaxError, ValueError):
        return False
    funcs = [
        n for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    if len(funcs) != 1:
        return False
    fn = funcs[0]
    # Def-time-executed expressions are live code the body-shape
    # check below never sees: a Call in a decorator, a default
    # argument, or an annotation (`@reg(os.system(c))`,
    # `n=(m := f(c))`, `-> f(c)`) runs when the def executes and
    # would ride an otherwise-trivial body into the skip. Plain
    # decorators (@property) and literal defaults/annotations keep
    # their skip.
    def_time: list[ast.expr] = list(fn.decorator_list)
    def_time.extend(fn.args.defaults)
    def_time.extend(d for d in fn.args.kw_defaults if d is not None)
    if fn.returns is not None:
        def_time.append(fn.returns)
    annotated = list(fn.args.args) + list(fn.args.posonlyargs) + list(
        fn.args.kwonlyargs,
    )
    if fn.args.vararg is not None:
        annotated.append(fn.args.vararg)
    if fn.args.kwarg is not None:
        annotated.append(fn.args.kwarg)
    def_time.extend(
        a.annotation for a in annotated if a.annotation is not None
    )
    for expr in def_time:
        for sub in ast.walk(expr):
            if isinstance(sub, (ast.Call, ast.NamedExpr, ast.Await)):
                return False
    body = list(fn.body)
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body = body[1:]
    if len(body) != 1 or not isinstance(body[0], ast.Return):
        return False
    val = body[0].value
    if (
        isinstance(val, ast.Attribute)
        and isinstance(val.value, ast.Name)
        and val.value.id == "self"
    ):
        return not _accessor_ref_refused(val.attr)
    if isinstance(val, ast.Name):
        return not _accessor_ref_refused(val.id)
    if isinstance(val, ast.Constant):
        # int/bool/None only — the parity set the pre-AST arm
        # accepted (strings and floats always went to review).
        return isinstance(val.value, (bool, int)) or val.value is None
    return False


def _accessor_ref_refused(returned: str) -> bool:
    """Gate a returned name/field against the dangerous + sensitive sets.

    The principle the lua arm documented, applied to every arm:
    ``return os.execute`` hands the sink back as a VALUE — the
    wrapper path's escape analysis exists to refuse that, and an
    accessor arm must not bypass it. Security-sensitive field names
    (password, token, ...) also refuse: over-inclusion costs one
    review, the documented safe direction.
    """
    if not returned:
        return False
    ref = re.sub(
        r"[^\w.]", "", returned.replace("->", ".").replace("::", "."),
    ).strip(".")
    if not ref or ref.replace(".", "").isdigit():
        return False
    if _wrapper_ref_hits_exclusion(
        ref, _WRAPPER_DANGEROUS_CALLEES, _WRAPPER_DANGEROUS_TAILS, None,
    ):
        return True
    low = ref.lower()
    return any(s in low for s in _SECURITY_SENSITIVE_NAMES)


#: A bare signature line (K&R `{`-on-next-line form): the parameter
#: list closes the line, no statement follows.
_ACCESSOR_SIG_LINE_RE = re.compile(r"^[^=;{}]*\([^;{}]*\)\s*$")

#: A return-type-only line (the BSD/kernel `int\nname(...)` split
#: signature): qualifier/type identifiers and pointer stars only —
#: no punctuation a statement would carry.
_ACCESSOR_TYPE_LINE_RE = re.compile(
    r"^(?:[A-Za-z_]\w*\s+)*[A-Za-z_]\w*(?:\s*\*+)?\s*$"
)

#: Whole-body accessor arms, matched with fullmatch over the
#: signature-stripped body — a suffix anchor let any side-effecting
#: statement ride in front of the accessor return.
_ACCESSOR_ARMS: dict[str, re.Pattern[str]] = {
    "c": re.compile(
        r"return\s+(?:(\w+(?:->|\.)\w+)|\d+|NULL)\s*;",
    ),
    "go": re.compile(
        r"return\s+(?:(\w+\.\w+)(?:\s*,\s*nil)?|\d+)",
    ),
    "lua": re.compile(
        r"return\s+(?:(\w+\.\w+)|\d+)",
    ),
    "rust": re.compile(
        r"(?:return\s+)?(?:(self\.\w+(?:\.clone\(\))?)|\d+)\s*;?",
    ),
    "php": re.compile(
        r"return\s+(?:(\$this->\w+|self::\$?\w+)"
        r"|\d+|true|false|null)\s*;",
    ),
    "java": re.compile(
        r"return\s+(?:this\.(\w+)|(\w+))\s*;",
    ),
    "javascript": re.compile(
        r"return\s+(?:this\.(_?\w+)|\d+)\s*;?",
    ),
    "perl": re.compile(
        r"return\s+(?:\$self->\{\s*(\w+)\s*\}|\$_\[\d+\])\s*;",
    ),
}
_ACCESSOR_ARMS["cpp"] = _ACCESSOR_ARMS["c"]
_ACCESSOR_ARMS["typescript"] = _ACCESSOR_ARMS["javascript"]


def _is_simple_accessor(source: str, lang: str) -> bool:
    """True only when the WHOLE body is a single accessor return.

    Judged semantically, never on raw prefix-dropped lines or a
    suffix-anchored arm: python parses to an AST whose body must be
    exactly one ``return`` of a self-field/name/constant; every other
    language judges the shared sanitized-view line pair
    (``_judged_view_lines`` — the wrapper tier's chokepoint, so a
    string-continuation line can never be dropped as a comment) and
    anchors its arm over the ENTIRE signature-stripped body, so a
    side-effecting statement (deref-store, refcount op, sink call)
    can never ride in front of the return. The returned name is
    gated against the dangerous callee sets in every arm.
    """
    if lang == "python":
        return _py_simple_accessor(source)

    views = _judged_view_lines(source, lang)
    if views is None:
        return False
    code_lines, _ref_lines = views
    if not code_lines or len(code_lines) > 3:
        return False

    body = " ".join(code_lines)
    if lang == "lua":
        body_no_sig = re.sub(
            r"^\s*(?:local\s+)?function\b[^)]*\)\s*", "", body)
        # No leading ``\s*``: it re-scanned a hostile whitespace run
        # from every position (quadratic) and the trailing .strip()
        # already removes whatever whitespace precedes the cut.
        body_no_sig = re.sub(r"\bend\s*$", "", body_no_sig).strip()
    else:
        sig_end = body.find("{")
        if sig_end >= 0:
            body_no_sig = body[sig_end + 1:].strip()
            # Trailing close-brace only: rfind would cut at an
            # INTERIOR brace (perl `$self->{name}`) when the
            # function's own closing brace sits on a dropped
            # brace-only line.
            if body_no_sig.endswith("}"):
                body_no_sig = body_no_sig[:-1].strip()
        elif (
            len(code_lines) >= 2
            and "return" not in code_lines[0]
            and _ACCESSOR_SIG_LINE_RE.match(code_lines[0])
        ):
            # Brace-only lines are dropped from the judged views, so
            # a K&R-style `{` on its own line leaves a braceless
            # body: strip the leading line only when it is
            # unambiguously a bare signature (ends at its parameter
            # list). Anything else refuses — never guess at a body.
            body_no_sig = " ".join(code_lines[1:]).strip()
        elif (
            len(code_lines) >= 3
            and code_lines[0].split()[0] != "return"
            and _ACCESSOR_TYPE_LINE_RE.match(code_lines[0])
            and "return" not in code_lines[1]
            and _ACCESSOR_SIG_LINE_RE.match(code_lines[1])
        ):
            # The BSD/kernel split-signature idiom — the return type
            # on its OWN line above the name (`int\ndiskmapopen(...)
            # \n{`). Without this join the dominant kernel style lost
            # its accessor skip wholesale (refusal-direction cost);
            # honesty still rests entirely on the whole-body arm
            # below.
            body_no_sig = " ".join(code_lines[2:]).strip()
        else:
            return False
    if not body_no_sig:
        return False

    arm = _ACCESSOR_ARMS.get(lang)
    if arm is None:
        return False
    m = arm.fullmatch(body_no_sig)
    if m is None:
        return False
    returned = next((g for g in m.groups() if g), "")
    return not _accessor_ref_refused(returned)


# ── Suppressor-guard views ───────────────────────────────────────────
#
# A guard that switches a rule OFF ("a sanitizer is visible, so no
# hit") is a suppression receipt and must be earned against code: a
# comment, a trailing comment or a string literal that merely NAMES the
# sanitizer ("// TODO: basename") would otherwise silence the rule.
# Suppressor guards therefore read the shared view through
# ``sanitized_view_with_status`` (comments and strings blanked) and
# CANNOT VOUCH when it reports ``ambiguous`` (the lexer had to guess:
# an unterminated multi-line literal, a PHP 7 ``#[`` comment, ...) —
# the hit is kept.  Sink matching and the positive context checks that
# KEEP a hit stay on raw text.
#
# Some sanitizer evidence is string data by nature — a ``".."``
# needle of a containment check, a ``$1`` placeholder in a query, an
# XML feature URI.  Those guards (_LiteralGuard) look at one argument
# POSITION of the sanitizing call on the code view — the needle /
# query / feature-name argument — and accept it only when that
# argument is a CONSTANT expression (string literals joined by
# ``+``/``.``, PHP arrays of literals) whose literal text, read from
# the comments-only view (``keep_strings=True``), is the evidence
# itself (a named separator constant may join a needle literal).  A
# path-traversal needle must be that literal, in the call.  Only a Go
# query variable and a Java feature-name constant may stand in for the
# literal, under the single-assignment rule (_SingleAssignment): the
# function writes the NAME exactly once (a preceding zero declaration
# aside), with a plain constant, in its body directly or through
# unconditional blocks (try / finally / synchronized / bare), before
# the call — any other write shape or position cannot vouch.  A log message spelling the token is not the
# call, and a path literal such as ``'../uploads/' . $f`` flowing into
# some other argument is data, not a sanitizer (_literal_guard_holds).
#
# Perl guards stay on raw text: the hash-comment scanner does not
# model perl quote constructs (``qr/#/`` would blank a live sanitizer
# later on the line), see the source_view module docstring.

class _GuardViews:
    """Lazily built suppressor-guard views of one function's source.

    ``code`` blanks comments and strings, ``keep`` blanks comments only
    (both from the shared ``sanitized_view_with_status``, called with
    the file path and the prefilter's language id); ``code_lines``
    aligns ``code`` with the per-line loops; ``vouch`` is False when
    the lexer reported ambiguity, and every guard then keeps the hit
    (``sees``/``line_sees``/``feeds`` return False).  Built on first
    use, so a function with no candidate sink pays nothing.
    """

    def __init__(self, result: PrefilterResult, source: str) -> None:
        self._result = result
        self._source = source
        self._feeds: dict[str, bool] = {}

    def _view(self, keep_strings: bool) -> SanitizedView:
        return sanitized_view_with_status(
            self._source, self._result.file,
            language=self._result.language or None,
            keep_strings=keep_strings,
        )

    @cached_property
    def _code(self) -> SanitizedView:
        return self._view(False)

    @cached_property
    def _keep(self) -> SanitizedView:
        return self._view(True)

    @property
    def code(self) -> str:
        return self._code.text

    @property
    def keep(self) -> str:
        return self._keep.text

    @property
    def vouch(self) -> bool:
        """False when the lexer had to guess (``ambiguous``): a guard on
        this view cannot vouch for a sanitizer and must keep the hit."""
        return not self._code.ambiguous

    def sees(self, pattern: str) -> bool:
        """A vouched code-view match of *pattern* anywhere in the function."""
        return self.vouch and re.search(pattern, self.code) is not None

    def line_sees(self, pattern: str, k: int) -> bool:
        """A vouched code-view match of *pattern* on source line *k*."""
        return self.vouch and re.search(pattern, self.code_lines[k]) is not None

    @cached_property
    def code_lines(self) -> list[str]:
        return _guard_view_lines(self._source, self.code)

    def feeds(self, guard: _LiteralGuard) -> bool:
        """Memoised :func:`_literal_guard_holds` over this function."""
        if guard.name not in self._feeds:
            self._feeds[guard.name] = (
                self.vouch and not self._keep.ambiguous
                and _literal_guard_holds(self.code, self.keep, guard)
            )
        return self._feeds[guard.name]


class _NoVouchViews:
    """Guard views that never vouch: the fallback after a view failure.

    Same interface as :class:`_GuardViews`, built from the raw source
    with plain string operations only (no lexer): ``vouch`` is False and
    ``sees``/``line_sees``/``feeds`` return False, so no view-based guard can
    suppress and every rule falls back to main's raw-text decision.
    ``code``/``keep`` are the raw source and ``code_lines`` its stripped
    lines (the per-line loops' model), for consumers that read them as
    an input to a vouch-gated test.
    """

    vouch = False

    def __init__(self, source: str) -> None:
        self._source = source

    @property
    def code(self) -> str:
        return self._source

    @property
    def keep(self) -> str:
        return self._source

    def sees(self, pattern: str) -> bool:
        return False

    def line_sees(self, pattern: str, k: int) -> bool:
        return False

    def feeds(self, guard: _LiteralGuard) -> bool:
        return False

    @cached_property
    def code_lines(self) -> list[str]:
        return [
            seg.splitlines()[0].strip()
            for seg in self._source.splitlines(keepends=True)  # line-model: same per-line model as _guard_view_lines
        ]


# Recoveries made by _with_guard_views: one count per checker run whose
# first attempt raised and whose never-vouching re-run returned (read
# with guard_view_failure_count), and one warning per process.
_guard_view_failures = 0
_guard_view_warned = False
_guard_view_lock = threading.Lock()


def guard_view_failure_count() -> int:
    """How many checker runs RECOVERED in this process: the attempt with
    guard views raised and the re-run without view-based suppression
    returned.  A recovery does not prove the failure came from a view (a
    non-view failure that does not repeat is counted too); a failure the
    re-run repeats propagates and is not counted."""
    return _guard_view_failures


def _note_guard_view_failure(exc: Exception) -> None:
    """Count a recovered checker run and warn once (exception type only,
    never source text).  Best-effort: a failure here is swallowed, so
    reporting can never cost the recovered result."""
    global _guard_view_failures, _guard_view_warned
    try:
        with _guard_view_lock:
            _guard_view_failures += 1
            warn = not _guard_view_warned
            _guard_view_warned = True
        if warn:
            logger.warning(
                "prefilter: a checker attempt with guard views failed "
                "(%s); its rules re-ran without view-based suppression "
                "and that run returned, so main's hits are kept (further "
                "recoveries are counted, not logged)", type(exc).__name__,
            )
        logger.debug("prefilter guard-view attempt failed",
                     exc_info=(type(exc), exc, exc.__traceback__))
    except Exception:  # noqa: BLE001 — reporting must not cost the hits
        pass


_RESULT_STATE_FIELDS = tuple(
    f.name for f in fields(PrefilterResult) if f.name != "hits")


def _with_guard_views(
    result: PrefilterResult, source: str,
    body: Callable[[Any], None],
) -> None:
    """Run a checker *body* with lexer-backed guard views; if anything in
    that attempt raises (the view build, a guard helper, an index into
    the views, or a view failure the PHP prepare pointer held and
    re-raised), roll the attempt back and re-run *body* with
    :class:`_NoVouchViews`.  Only when the re-run returns is the
    recovery counted and warned (:func:`_note_guard_view_failure`); a
    failure in the re-run propagates uncounted, as main's own raw-text
    code would.  KeyboardInterrupt and SystemExit are not caught.

    Rollback restores exactly the tail of ``result.hits`` appended by the
    attempt and the ``_RESULT_STATE_FIELDS`` (shallow).  It does not
    undo in-place changes to pre-existing hits or external counters:
    php-sql-injection's additions-failure counter counts every attempt in
    which the additions themselves raised (a view failure does not reach it).

    The boundary costs stack depth: near the recursion limit the re-run
    raises 1 to 3 frames earlier than main on the measured checkers
    (CPython 3.14).
    """
    mark = len(result.hits)
    state = {name: getattr(result, name) for name in _RESULT_STATE_FIELDS}
    try:
        body(_GuardViews(result, source))
        return
    except Exception as exc:  # noqa: BLE001 — never cost main's hits
        first = exc
        del result.hits[mark:]
        for name, value in state.items():
            setattr(result, name, value)
    body(_NoVouchViews(source))
    _note_guard_view_failure(first)


def _guard_view_lines(source: str, view: str) -> list[str]:
    """Slices of *view* aligned 1:1 with ``line.strip()`` per source line.

    Aligned by character offset over ``source.splitlines`` (the line
    model every per-line loop here iterates), so a terminator that
    splitlines honours but the view blanks as string data (``\\x0c``,
    ``\\r``) cannot shift the guard onto another line.
    """
    out: list[str] = []
    off = 0
    for seg in source.splitlines(keepends=True):  # line-model: offset walk pairing the view with the per-line loops' splitlines model
        line = seg.splitlines()[0]
        lead = len(line) - len(line.lstrip())
        out.append(view[off + lead:off + lead + len(line.strip())])
        off += len(seg)
    return out


@dataclass(frozen=True)
class _LiteralGuard:
    """A sanitizer whose evidence is a constant string argument.

    ``call_re`` matches the call up to and including ``(``;
    ``positions`` are the 0-based argument indexes that carry the
    evidence; ``evidence`` judges the literal texts of a constant
    argument; ``fixed`` pins other arguments to one of a set of literal
    code texts (``setFeature(F, true)`` — ``false`` re-enables the
    feature).  ``bind`` is empty when the evidence must be a literal in
    the call; otherwise (``"go"``/``"java"``) a bare NAME may stand for
    it under the single-assignment rule (_SingleAssignment).  ``php``
    admits the PHP ``array(...)`` construct (any case) in a constant.
    """

    name: str
    call_re: re.Pattern[str]
    positions: tuple[int, ...]
    evidence: Callable[[list[str]], bool]
    fixed: tuple[tuple[int, frozenset[str]], ...] = ()
    bind: str = ""
    php: bool = False


_GUARD_OPEN = "([{"
_GUARD_CLOSE = ")]}"
# A string literal on the code view: contents are blanked (a CR inside
# one becomes a space, a newline stays), the quotes stay.  A Java text
# block reads as `""` + `"<text>"` + `""` — the same literal text.
_GUARD_LIT_RE = re.compile(r'(["\'`])[ \t\r\n\f\v]*\1')
# What may remain of a constant argument once its literals (and named
# separator constants) are cut; CR/FF/VT included for CRLF sources.
_GUARD_CONST_RE = re.compile(r'[ \t\r\n\f\v+.,()\[\]]*')
# PHP only: the `array(...)` construct — the keyword (any case) directly
# followed, after optional blanks, by `(`.
_GUARD_CONST_PHP_RE = re.compile(
    r'(?:[ \t\r\n\f\v+.,()\[\]]|\b(?i:array)\b(?=[ \t\r\n\f\v]*\())*')
_GUARD_ARRAY_CALL_RE = re.compile(r'[ \t\r\n\f\v]*\(')
_GUARD_WORD_RE = re.compile(r'[\w$]+')
_GUARD_NAME_ONLY_RE = re.compile(r'\$?[A-Za-z_]\w*')
# A platform path-separator constant joined to a needle literal
# (`'..' . DIRECTORY_SEPARATOR`, `".." + string(os.PathSeparator)`,
# `'..' + path.sep`): a known one-character separator, so it adds
# nothing a literal separator would not.
_GUARD_SEP_RE = re.compile(
    r'string\s*\(\s*(?:os\.PathSeparator|filepath\.Separator)\s*\)'
    r'|(?:DIRECTORY_SEPARATOR|os\.PathSeparator|filepath\.Separator'
    r'|path\.sep)\b'
)


def _guard_bracket_pairs(code: str) -> dict[int, int]:
    """Opening index -> matching closing index for ``()[]{}`` on *code*."""
    pairs: dict[int, int] = {}
    stack: list[int] = []
    for m in re.finditer(r'[()\[\]{}]', code):
        if m.group() in _GUARD_OPEN:
            stack.append(m.start())
        elif stack:
            pairs[stack.pop()] = m.start()
    return pairs


def _guard_call_args(
    code: str, pairs: dict[int, int], open_idx: int, upto: int,
) -> tuple[list[tuple[int, int]], int]:
    """``[start, end)`` of arguments 0..*upto* of the call opened at *open_idx*.

    Splits on top-level commas, jumping over nested brackets, so the
    cost is the top-level length of the argument list (bounded at 4000
    chars when the call is unbalanced).  Also returns the chars scanned.
    """
    stop = pairs.get(open_idx, min(len(code), open_idx + 4001))
    args: list[tuple[int, int]] = []
    k = start = open_idx + 1
    while k < stop and len(args) <= upto:
        c = code[k]
        if c in _GUARD_OPEN and k in pairs:
            k = pairs[k] + 1
            continue
        if c == ",":
            args.append((start, k))
            start = k + 1
        k += 1
    if len(args) <= upto:
        args.append((start, min(k, stop)))
    return args, k - open_idx


def _guard_constant_literals(
    code: str, keep: str, start: int, end: int, php: bool = False,
) -> tuple[list[str] | None, int]:
    """Literal texts of a constant expression ``code[start:end]``, else None.

    Constant: string literals joined by ``+``/``.``, optionally in a
    PHP ``array(...)``/``[...]`` (*php*: the ``array`` keyword, any case,
    counts only when ``(`` follows it; in other languages ``array`` is
    an ordinary identifier), plus named separator constants
    (_GUARD_SEP_RE); any other identifier, call or interpolation (a JS
    ``${...}`` stays code) disqualifies it.  Also returns the chars
    scanned (charged to the caller's budget).
    """
    cuts: list[tuple[int, int]] = []
    skip = start
    # Early exit on the first word that is neither the PHP ``array(``
    # construct nor part of a separator constant: string contents are
    # blanked, so any word here is code (a nested call is rejected
    # without a full scan).
    for w in _GUARD_WORD_RE.finditer(code, start, end):
        if w.start() < skip:
            continue
        if php and w.group().lower() == "array" and (
            _GUARD_ARRAY_CALL_RE.match(code, w.end(), end) is not None
        ):
            continue
        sep = _GUARD_SEP_RE.match(code, w.start(), end)
        if sep is None:
            return None, w.end() - start
        cuts.append((sep.start(), sep.end()))
        skip = sep.end()
    if cuts:
        text = "".join(
            code[a:b] for a, b in zip(
                [start] + [cb for _, cb in cuts], [ca for ca, _ in cuts] + [end])
        )
    else:
        text = code[start:end]
    # literals are one quote + blanks + the same quote (contents are
    # blanked), so cutting them is one C-level substitution
    if not (_GUARD_CONST_PHP_RE if php else _GUARD_CONST_RE).fullmatch(
            _GUARD_LIT_RE.sub("", text)):
        return None, end - start
    lits = [
        keep[m.start() + 1:m.end() - 1]
        for m in _GUARD_LIT_RE.finditer(code, start, end)
    ]
    return (lits or None), end - start


def _guard_rhs_end(code: str, pairs: dict[int, int], start: int) -> int:
    """End of the expression starting at *start* (an assignment's RHS).

    Stops at a top-level ``;``, ``,`` or closer, or at a top-level
    newline unless the expression continues with ``+``/``.`` across it;
    literals (which may span lines) and nested brackets are skipped.
    Bounded at 4000 chars.
    """
    stop = min(len(code), start + 4000)
    k = start
    while k < stop:
        c = code[k]
        if c in _GUARD_OPEN and k in pairs:
            k = pairs[k] + 1
            continue
        if c in "\"'`":
            m = _GUARD_LIT_RE.match(code, k)
            if m:
                k = m.end()
                continue
        if c in ";," or c in _GUARD_CLOSE:
            return k
        if c == "\n":
            before = code[start:k].rstrip()
            after = code[k:stop].lstrip()
            if not (before.endswith(("+", ".")) or after.startswith(("+", "."))):
                return k
        k += 1
    return stop


# Single-assignment rule (_SingleAssignment) — write shapes on the code
# view.  An assignment operator after the NAME: plain `=`/`:=` (group
# empty) or any compound form; never `==`, `=>`, `!=`, `<=`, `>=`.  Go
# keeps the operator on the NAME's line (a newline ends a Go
# statement); Java may wrap before it.
# Both are only ever `.match`ed right after a NAME; the leading
# lookbehind pins the run start so a scanning use cannot restart inside
# a whitespace run (ReDoS scan-restart census).
_GUARD_ASSIGN_OP_RE = re.compile(
    r'(?<![ \t])[ \t]*((?:[-+*/%.&|^]|\?\?|\|\||&&|<<|>>>?|\*\*)?):?=(?![=>])')
_GUARD_ASSIGN_OP_NL_RE = re.compile(
    r'(?<![ \t\r\n])[ \t\r\n]*((?:[-+*/%.&|^]|\?\?|\|\||&&|<<|>>>?|\*\*)?)'
    r':?=(?![=>])')
_GUARD_INCDEC_AFTER_RE = re.compile(r'[ \t]*(?:\+\+|--)')
# foreach/for binding after the NAME: Java `T NAME : xs`, JS `NAME of`,
# `NAME in`; a Go `case NAME:` / label reads the same way (write).
_GUARD_FOR_AFTER_RE = re.compile(r'[ \t]*(?::(?![:=])|(?:of|in)\b)')
# Maximal runs of left-hand-side material: names, member dots,
# brackets, (blanked) literal quotes, and commas that may end their
# line (a Go LHS wraps after a comma).  Built once per window; a NAME
# whose run ends at an assignment operator and continues with `,` or a
# closer is in a destructuring / multi-assign left-hand side.
_GUARD_LHS_RUN_RE = re.compile(
    r'(?:[\w$ \t.\[\](){}"\'`]|,[ \t]*(?:\r?\n[ \t]*)?)+')
_GUARD_LHS_START_RE = re.compile(r'[ \t]*[,\])}]')
_GUARD_LHS_ASSIGN_RE = re.compile(r':?=(?![=>])')
_GUARD_LHS_PLAIN_RE = re.compile(
    r'(?:[ \t]*,[ \t]*(?:\r?\n[ \t]*)?[\w$]+)*[ \t]*')
_GUARD_DECL_BEFORE_RE = re.compile(r'(?:^|[^\w$])(?:var|const)[ \t]+$')
_GUARD_DECL_TAIL_RE = re.compile(r'(?:[ \t]+[\w.\[\]*]+)?[ \t]*=(?![=>])')
# Zero declarations (no initializer, or null / zero / empty): Go
# `var NAME TYPE` [`= nil|0|""`], Java `[final] String NAME` [`= null|0|""`].
_GUARD_GO_ZERO_TAIL_RE = re.compile(
    r'[ \t]+[\w.\[\]*]+[ \t]*(?:=[ \t]*(?:nil|0|"")[ \t]*)?(?:;|\r?\n|$)')
_GUARD_JAVA_DECL_BEFORE_RE = re.compile(
    r'(?:^|[^\w$.])(?:final[ \t\r\n]+)?String[ \t\r\n]+$')
_GUARD_JAVA_ZERO_TAIL_RE = re.compile(
    r'[ \t\r\n]*(?:=[ \t\r\n]*(?:null|0|"")[ \t\r\n]*)?;')
# what may precede the vouching write on its statement: declaration
# words, then (multi-assign) earlier names of the list.
_GUARD_STMT_PREFIX_RE = re.compile(
    r'[ \t\r\n\f\v]*(?:(?:var|const|final|static|private|public|protected'
    r'|String)[ \t\r\n\f\v]+)*((?:[\w$]+[ \t]*,[ \t]*(?:\r?\n[ \t]*)?)*)')
_GUARD_MAX_OCCURRENCES = 512
# Tests switch this on: _in_catch then verifies its ancestry
# precondition with a parent walk (not part of the production cost).
_GUARD_DEBUG_ANCESTRY = False
_GUARD_WORD_AT_RE = re.compile(r'[A-Za-z_]\w*')
_GUARD_THROWS_TAIL = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.,<> \t\r\n")
_GUARD_JAVA_NAME_RE = re.compile(r'(\bnew[ \t\r\n]+)?\b([A-Za-z_]\w*)[ \t\r\n]*$')
_GUARD_JAVA_KEYWORDS = frozenset({
    "if", "for", "while", "switch", "catch", "synchronized", "return",
    "else", "do", "try", "finally",
})


def _guard_match_close(code: str, i: int, stop: int) -> int:
    """Index of the bracket closing ``code[i]`` before *stop*, else -1."""
    opener = code[i]
    closer = {"(": ")", "[": "]", "{": "}"}[opener]
    depth = 0
    for k in range(i, stop):
        c = code[k]
        if c == opener:
            depth += 1
        elif c == closer:
            depth -= 1
            if depth == 0:
                return k
    return -1


def _guard_go_named_header(code: str, i: int, brace: int) -> bool:
    """``code[i:brace]`` (just after ``func``) is a named declaration.

    ``[(receiver)] Name [[type params]] (params) [results]``, any of it
    wrapped over lines; results may hold ``(...)``, ``[...]``, ``*``,
    ``.``, ``<-`` and ``interface{…}``/``struct{…}``.  A ``func(`` literal
    has no name after its parameter list.
    """
    def skip(k: int) -> int:
        while k < brace and code[k] in " \t\r\n":
            k += 1
        return k

    k = skip(i)
    if k < brace and code[k] == "(":
        j = _guard_match_close(code, k, brace)
        if j < 0:
            return False
        k = skip(j + 1)
    m = _GUARD_WORD_AT_RE.match(code, k, brace)
    if m is None:
        return False
    k = skip(m.end())
    if k < brace and code[k] == "[":
        j = _guard_match_close(code, k, brace)
        if j < 0:
            return False
        k = skip(j + 1)
    if k >= brace or code[k] != "(":
        return False
    j = _guard_match_close(code, k, brace)
    if j < 0:
        return False
    k = j + 1
    while k < brace:
        c = code[k]
        if c in " \t\r\n*.,<-":
            k += 1
        elif c in "([":
            j = _guard_match_close(code, k, brace)
            if j < 0:
                return False
            k = j + 1
        else:
            m = _GUARD_WORD_AT_RE.match(code, k, brace)
            if m is None:
                return False
            k = m.end()
            if m.group() in ("interface", "struct"):
                k = skip(k)
                if k < brace and code[k] == "{":
                    j = _guard_match_close(code, k, brace)
                    if j < 0:
                        return False
                    k = j + 1
    return k == brace


class _SingleAssignment:
    """Canonical binding rule: a NAME vouches only through ONE write.

    A bare NAME argument stands for a constant only when the function
    window contains exactly one write to it — any operator (`=`, `:=`,
    `+=`, `.=`, `??=`, `||=`, `&&=`, ...; Java may wrap before the
    operator), an increment, a destructuring or multi-assign position
    (the left-hand side may wrap after a comma), a for/foreach binding,
    `&NAME` (by-reference / address taken), a `var`/`const`
    declaration, or any occurrence before that write (a parameter, an
    earlier use) — and that write is a plain `NAME = <constant>` (also
    `:=`, `var|const NAME [TYPE] =`, Java `[final] String NAME =`, or
    an element of `a, NAME := x, <constant>`) that precedes the call
    and starts its own statement (no `if (c)`, `case:`, `&&`, `->`
    before it).  A zero declaration that precedes it (Go `var NAME T`
    [`= nil|0|""`], Java `[final] String NAME` [`= null|0|""`]) is not a
    second write.  The write sits in a named function or method body,
    directly or through UNCONDITIONAL blocks only (Java `try`,
    try-with-resources, `finally`, `synchronized`, a bare `{}` block;
    a Go bare block); a branch, loop, switch, `catch`, lambda,
    anonymous class or closure on the way disqualifies it.  The call
    follows the write inside that function body and not inside a
    `catch` block.  Member accesses (`obj.NAME`, `$this->NAME`) are
    other variables.  Everything else cannot vouch.  Cost: names,
    braces, statement terminators and LHS runs are indexed once per
    window, classification stops at the second write, RHS element
    lists of a multi-assign are split once, and the two brace walks
    (write -> function body, call -> nearest catch) are memoised for
    every brace they pass, so each brace is classified at most once
    per walk kind: O(B + Q) walk steps for B braces and Q queries
    (``ops`` counts them; the tests bound it).
    """

    def __init__(
        self, code: str, pairs: dict[int, int], names: set[str],
        lang: str, calls: list[int],
    ) -> None:
        self._code = code
        self._pairs = pairs
        self._lang = lang
        self._assign_op = (
            _GUARD_ASSIGN_OP_RE if lang == "go" else _GUARD_ASSIGN_OP_NL_RE)
        self._term = ";{}\n" if lang == "go" else ";{}"
        self._terms_list: list[int] | None = None
        self._runs: tuple[list[int], list[int]] | None = None
        self._occ: dict[str, list[int]] = {n: [] for n in names}
        names_re = re.compile(
            r'(?<![\w$])(?:'
            + "|".join(re.escape(n) for n in sorted(names, key=len, reverse=True))
            + r')(?![\w$])')
        for m in names_re.finditer(code):
            rows = self._occ[m.group()]
            if len(rows) > _GUARD_MAX_OCCURRENCES:
                continue
            a = m.start()
            before = code[max(0, a - 2):a]
            if before.endswith(".") or before == "->" or before == "::":
                continue
            rows.append(a)
        self._brace_close: dict[int, int] = {}
        self._brace_parent: dict[int, int] = {}
        self._enclosing = self._enclosing_braces(sorted(
            {p for rows in self._occ.values() for p in rows} | set(calls)))
        self._rhs_lists: dict[int, list[tuple[int, int]]] = {}
        self._writes: dict[str, tuple[int, int, int, int] | None] = {}
        # memoised brace walks (path compression; the brace tree, the
        # code and the language never change after __init__)
        self._body_memo: dict[int, int | None] = {}
        self._catch_memo: dict[int, int] = {}
        # operation counts: parent edges walked, classifier calls, memo
        # stores (tests bound them; the debug ancestry check is excluded)
        self.ops = {"edges": 0, "classify": 0, "stores": 0}
        self.cost = 0

    def _enclosing_braces(self, positions: list[int]) -> dict[int, int]:
        """Position -> index of its innermost enclosing ``{`` (-1 none).

        ``{}`` are paired on their own stack, so a stray ``(`` or ``[``
        left visible by the lexer cannot unbalance the block structure.
        Also records every ``{``'s close and parent.
        """
        out: dict[int, int] = {}
        stack: list[int] = []
        it = iter(positions)
        nxt = next(it, None)
        for m in re.finditer(r'[{}]', self._code):
            while nxt is not None and nxt < m.start():
                out[nxt] = stack[-1] if stack else -1
                nxt = next(it, None)
            if m.group() == "{":
                self._brace_parent[m.start()] = stack[-1] if stack else -1
                stack.append(m.start())
            elif stack:
                self._brace_close[stack.pop()] = m.start()
        while nxt is not None:
            out[nxt] = stack[-1] if stack else -1
            nxt = next(it, None)
        return out

    def _java_head(self, brace: int) -> tuple[str, str]:
        """(head text before *brace*, keyword/name before its ``(…)``)."""
        self.ops["classify"] += 1
        head = self._code[max(0, brace - 400):brace].rstrip()
        t = head.rfind("throws")
        if (
            t > 0 and not (head[t - 1].isalnum() or head[t - 1] == "_")
            and head[t + 6:t + 7] in (" ", "\t", "\r", "\n")
            and all(c in _GUARD_THROWS_TAIL for c in head[t + 6:])
        ):
            head = head[:t].rstrip()
        if not head.endswith(")"):
            return head, ""
        depth, k = 0, len(head) - 1
        while k >= 0:
            if head[k] == ")":
                depth += 1
            elif head[k] == "(":
                depth -= 1
                if depth == 0:
                    break
            k -= 1
        if k <= 0:
            return head, ""
        m = _GUARD_JAVA_NAME_RE.search(head, 0, k)
        if m is None:
            return head, ""
        return head, ("new " if m.group(1) else "") + m.group(2)

    def _is_function_body(self, brace: int) -> bool:
        """``{`` at *brace* opens a named function/method body.

        Go: the nearest line-start ``func`` before it heads a named
        declaration ending exactly at *brace* (receiver, type parameters
        and wrapped lines allowed; a ``func(`` literal is a closure).
        Java: it follows ``Name(...)`` [``throws …``] where Name is not a
        control keyword and not ``new X(...)`` (an anonymous class);
        ``-> {`` is a lambda.
        """
        code = self._code
        self.ops["classify"] += 1
        if self._lang == "go":
            lo = max(0, brace - 4000)
            k = brace
            for _ in range(64):
                f = code.rfind("func", lo, k)
                if f < 0:
                    return False
                k = f
                after = code[f + 4:f + 5]
                if f > 0 and (code[f - 1].isalnum() or code[f - 1] in "_$"):
                    continue
                if not (after.isspace() or after == "("):
                    continue
                if code[code.rfind("\n", 0, f) + 1:f].strip():
                    continue
                return _guard_go_named_header(code, f + 4, brace)
            return False
        head, name = self._java_head(brace)
        return bool(
            head.endswith(")") and name
            and name not in _GUARD_JAVA_KEYWORDS and not name.startswith("new ")
        )

    def _is_unconditional(self, brace: int) -> bool:
        """``{`` at *brace* opens a block that always runs to its end
        once entered from the enclosing block: Java `try`, `try (…)`,
        `finally`, `synchronized (…)` or a bare block; a Go bare block
        (``{`` first on its line)."""
        code = self._code
        self.ops["classify"] += 1
        if self._lang == "go":
            return not code[code.rfind("\n", 0, brace) + 1:brace].strip()
        head, name = self._java_head(brace)
        if not head or head[-1] in ";{}":
            return True
        word = re.search(r'\b(try|finally)$', head)
        if word:
            return True
        return head.endswith(")") and name in ("synchronized", "try")

    @property
    def _terms(self) -> list[int]:
        """Statement-terminator offsets, built once on first use."""
        if self._terms_list is None:
            self._terms_list = [
                m.start() for m in
                re.finditer("[" + re.escape(self._term) + "]", self._code)]
        return self._terms_list

    def _lhs_write(self, b: int) -> tuple[bool, int] | None:
        """NAME ending at *b* in a destructuring / multi-assign LHS."""
        if self._runs is None:
            runs = list(_GUARD_LHS_RUN_RE.finditer(self._code))
            self._runs = ([m.start() for m in runs], [m.end() for m in runs])
        starts, ends = self._runs
        i = bisect.bisect_right(starts, b) - 1
        if i < 0 or ends[i] <= b:
            return None
        e = ends[i]
        m = _GUARD_LHS_ASSIGN_RE.match(self._code, e)
        if m is None or not _GUARD_LHS_START_RE.match(self._code, b, e):
            return None
        plain = _GUARD_LHS_PLAIN_RE.fullmatch(self._code, b, e)
        return (True, m.end()) if plain else (False, -1)

    def _classify(self, a: int, name: str) -> object:
        """None for a read; "zero" for a zero declaration; else
        (vouching shape, RHS start or -1)."""
        code = self._code
        b = a + len(name)
        prev = code[max(0, a - 3):a]
        if prev.endswith(("++", "--")) or (
            prev.endswith("&") and not prev.endswith("&&")
        ):
            return False, -1
        if self._lang == "go":
            if _GUARD_DECL_BEFORE_RE.search(code, max(0, a - 16), a):
                if (
                    code[max(0, a - 16):a].rstrip().endswith("var")
                    and _GUARD_GO_ZERO_TAIL_RE.match(code, b)
                ):
                    return "zero"
                m = _GUARD_DECL_TAIL_RE.match(code, b)
                return (True, m.end()) if m else (False, -1)
        elif _GUARD_JAVA_DECL_BEFORE_RE.search(code, max(0, a - 24), a) and (
            _GUARD_JAVA_ZERO_TAIL_RE.match(code, b)
        ):
            return "zero"
        m = self._assign_op.match(code, b)
        if m:
            return (True, m.end()) if not m.group(1) else (False, -1)
        if _GUARD_INCDEC_AFTER_RE.match(code, b):
            return False, -1
        lhs = self._lhs_write(b)
        if lhs is not None:
            return lhs
        if _GUARD_FOR_AFTER_RE.match(code, b):
            return False, -1
        pre = code[max(0, a - 8):a]
        if re.search(r'(?:\bas|=>)[ \t]*$', pre):
            return False, -1
        return None

    def _statement_index(self, a: int) -> int | None:
        """Index of NAME in its statement's LHS list (0 for a plain
        write); None when anything but declaration words / earlier list
        names precedes it on the statement."""
        code = self._code
        i = bisect.bisect_left(self._terms, a) - 1
        # a Go newline after a trailing comma continues the statement
        # (a wrapped multi-assign left-hand side)
        for _ in range(64):
            if i < 0 or code[self._terms[i]] != "\n":
                break
            k = self._terms[i] - 1
            while k >= 0 and code[k] in " \t\r":
                k -= 1
            if k < 0 or code[k] != ",":
                break
            i -= 1
        start = self._terms[i] + 1 if i >= 0 else 0
        m = _GUARD_STMT_PREFIX_RE.fullmatch(code, start, a)
        if m is None:
            return None
        return m.group(1).count(",")

    def _rhs_element(self, rhs: int, index: int) -> tuple[int, int] | None:
        spans = self._rhs_lists.get(rhs)
        if spans is None:
            spans = []
            k = rhs
            while True:
                end = _guard_rhs_end(self._code, self._pairs, k)
                self.cost += end - k + 1
                spans.append((k, end))
                if end >= len(self._code) or self._code[end] != ",":
                    break
                k = end + 1
            self._rhs_lists[rhs] = spans
        return spans[index] if index < len(spans) else None

    def _body_of(self, brace: int) -> int | None:
        """The function body reached from *brace* through unconditional
        blocks only, else None.

        Every brace on one walk reaches the same answer (each step's
        tests depend only on that brace, and the parent map is fixed),
        so the answer is stored for all of them: each brace is
        classified at most once per instance.
        """
        memo = self._body_memo
        path: list[int] = []
        result: int | None = None
        while brace >= 0:
            if brace in memo:
                result = memo[brace]
                break
            path.append(brace)
            if self._is_function_body(brace):
                result = brace
                break
            if not self._is_unconditional(brace):
                result = None
                break
            brace = self._brace_parent.get(brace, -1)
            self.ops["edges"] += 1
        for b in path:
            memo[b] = result
        self.ops["stores"] += len(path)
        return result

    def _nearest_catch(self, brace: int) -> int:
        """The innermost ``catch`` block brace enclosing *brace* (itself
        included), else -1; memoised for every brace on the walk."""
        memo = self._catch_memo
        path: list[int] = []
        result = -1
        while brace >= 0:
            if brace in memo:
                result = memo[brace]
                break
            path.append(brace)
            if self._java_head(brace)[1] == "catch":
                result = brace
                break
            brace = self._brace_parent.get(brace, -1)
            self.ops["edges"] += 1
        for b in path:
            memo[b] = result
        self.ops["stores"] += len(path)
        return result

    def _is_ancestor(self, outer: int, brace: int) -> bool:
        """*outer* is *brace* or encloses it (debug check only)."""
        while brace >= 0:
            if brace == outer:
                return True
            brace = self._brace_parent.get(brace, -1)
        return False

    def _single_write(self, name: str) -> tuple[int, int, int, int] | None:
        """(write offset, function body brace, RHS span) of NAME's single
        vouching write, independent of the call; memoised."""
        if name in self._writes:
            return self._writes[name]
        found = None
        rows = self._occ.get(name) or []
        if len(rows) > _GUARD_MAX_OCCURRENCES:
            # a constant used this often is not a reviewable binding;
            # classifying every use would cost a scan per occurrence
            self._writes[name] = None
            return None
        writes = []
        zeros = []
        for a in rows:
            kind = self._classify(a, name)
            if kind == "zero":
                zeros.append(a)
            elif kind is not None:
                writes.append((a, kind))
                if len(writes) > 1:
                    break
        if len(writes) == 1:
            a, (vouching, rhs) = writes[0]
            first = next((r for r in rows if r not in zeros), -1)
            brace = self._enclosing.get(a, -1)
            if (
                vouching and first == a and brace >= 0
                and all(z < a for z in zeros)
            ):
                index = self._statement_index(a)
                body = self._body_of(brace) if index is not None else None
                if body is not None:
                    span = self._rhs_element(rhs, index)
                    if span is not None:
                        found = (a, body, span[0], span[1])
        self._writes[name] = found
        return found

    def _in_catch(self, call: int, body: int) -> bool:
        """A ``catch`` block lies strictly between *call* and *body*.

        Precondition (established by constant_rhs): *body* encloses the
        call's innermost brace — body < write < call < close(body), and
        _enclosing/_brace_close come from the same ``{}`` stack, so body
        is open at the call.  Enclosing braces are totally ordered by
        nesting and an inner one opens later, so a catch lies strictly
        inside *body* on that chain exactly when the innermost enclosing
        catch opens after *body*.
        """
        if self._lang != "java":
            return False
        brace = self._enclosing.get(call, -1)
        if _GUARD_DEBUG_ANCESTRY and not self._is_ancestor(body, brace):
            raise AssertionError(f"body {body} does not enclose call {call}")
        return self._nearest_catch(brace) > body

    def constant_rhs(self, name: str, call: int) -> tuple[int, int] | None:
        """RHS span of NAME's single vouching write reaching *call*."""
        w = self._single_write(name)
        if w is None:
            return None
        a, body, ra, rb = w
        if not a < call < self._brace_close.get(body, len(self._code)):
            return None
        if self._in_catch(call, body):
            return None
        return ra, rb


def _literal_guard_holds(code: str, keep: str, guard: _LiteralGuard) -> bool:
    """True when a *guard* call's evidence argument is constant evidence.

    *code* is the comments+strings blanked view, *keep* the
    comments-only view of the same text (equal length).  The argument
    at one of ``guard.positions`` must be a constant expression whose
    literal texts satisfy ``guard.evidence``; for a guard with ``bind``
    it may also be a bare NAME whose single vouching write
    (_SingleAssignment) assigns such a constant.  Linear in the text:
    brackets are paired once, nested calls are jumped over, names are
    indexed in one pass, and every argument/RHS scan is charged to a
    2N+8000 budget whose exhaustion keeps the hit.  The binding brace
    walks take O(B + Q) steps (B braces, Q bare-NAME queries); each
    step classifies one brace from a bounded look-back (400 chars,
    4000 for a Go header), so the whole is linear in the text with
    that constant.
    """
    if not guard.call_re.search(code):
        return False
    pairs = _guard_bracket_pairs(code)
    upto = max(guard.positions + tuple(i for i, _ in guard.fixed))
    budget = 2 * len(code) + 8000
    pending: list[tuple[int, str]] = []  # (call offset, bare NAME)
    for m in guard.call_re.finditer(code):
        args, scanned = _guard_call_args(code, pairs, m.end() - 1, upto)
        budget -= scanned
        if budget < 0:
            return False
        if any(
            i >= len(args) or code[args[i][0]:args[i][1]].strip() not in allowed
            for i, allowed in guard.fixed
        ):
            continue
        for pos in guard.positions:
            if pos >= len(args):
                continue
            a, b = args[pos]
            lits, scanned = _guard_constant_literals(
                code, keep, a, b, guard.php)
            budget -= scanned
            if budget < 0:
                return False
            if lits is not None:
                if guard.evidence(lits):
                    return True
                continue
            name = code[a:b].strip()
            if guard.bind and _GUARD_NAME_ONLY_RE.fullmatch(name):
                pending.append((m.start(), name))
    if not pending:
        return False
    single = _SingleAssignment(
        code, pairs, {n for _, n in pending}, guard.bind,
        [c for c, _ in pending])
    for call, name in pending:
        span = single.constant_rhs(name, call)
        budget -= single.cost
        single.cost = 0
        if budget < 0:
            return False
        if span is None:
            continue
        lits, scanned = _guard_constant_literals(code, keep, *span, guard.php)
        budget -= scanned
        if lits is not None and guard.evidence(lits):
            return True
    return False


# The literal IS the sanitizer evidence: a bare traversal needle
# (`..`, `../`, `..\`) for containment/strip checks — a literal in the
# call, never a variable; a `$N` placeholder in one literal of the
# query text (never assembled from pieces like `"$" + "1"`); the XML
# feature name (which may be split across a constant concatenation,
# even mid-token).
_GUARD_TRAVERSAL_RE = re.compile(r'(?:/|\\{1,2})?\.\.(?:/|\\{1,2})?')
_GUARD_PLACEHOLDER_RE = re.compile(r'\$\d')


def _is_traversal_needle(lits: list[str]) -> bool:
    return any(_GUARD_TRAVERSAL_RE.fullmatch(t) for t in lits)


def _has_placeholder(lits: list[str]) -> bool:
    return any(_GUARD_PLACEHOLDER_RE.search(t) for t in lits)


_PHP_STR_REPLACE_GUARD = _LiteralGuard(
    "php-str_replace", re.compile(r'\bstr_replace\s*\('), (0,),
    _is_traversal_needle, php=True,
)
_GO_CONTAINS_GUARD = _LiteralGuard(
    "go-strings.Contains", re.compile(r'\bstrings\.Contains\w*\s*\('), (1,),
    _is_traversal_needle,
)
_JS_INCLUDES_GUARD = _LiteralGuard(
    "js-includes", re.compile(r'\bincludes\s*\('), (0,),
    _is_traversal_needle,
)
# Query text is argument 0 (Query/Exec/Prepare) or 1 (the *Context
# variants after ctx, sqlx Get/Select after dest); a query variable may
# vouch under the single-assignment rule (Go statements end at `;`,
# braces and newlines; the body is a named `func`).
_GO_SQL_GUARD = _LiteralGuard(
    "go-sql-placeholder",
    re.compile(r'\.(?:Query|QueryRow|Exec|Prepare|Get|Select)\w*\s*\('),
    (0, 1), _has_placeholder, bind="go",
)
# A feature-name constant may vouch under the single-assignment rule
# (Java statements end at `;` and braces, not newlines).
_JAVA_SET_FEATURE_GUARD = _LiteralGuard(
    "java-setFeature", re.compile(r'\bsetFeature\s*\('), (0,),
    lambda lits: "disallow-doctype-decl" in "".join(lits),
    fixed=((1, frozenset({"true", "Boolean.TRUE"})),), bind="java",
)


# Convention for the per-language pattern checks below: same-line
# co-occurrence gaps are bounded (``.{0,200}``/``.{0,1000}`` by
# shape, delimiter spans ``[^)]{0,4000}``) instead of unbounded
# ``.*``/``[^)]*``.  The
# scanned source is hostile, and an unbounded gap lets a crafted line
# re-scan its whole tail from every occurrence of the head token —
# quadratic in the line length.  The bounds sit far above real code
# lines (short of generated/minified bundles); a longer gap simply
# stops matching, which costs at most one heuristic hit on inputs no
# human wrote.
def _check_c_patterns(
    result: PrefilterResult,
    source: str,
    line_start: int,
    _callers: list[dict[str, Any]] | None,
    callees: list[dict[str, Any]] | None,
    *,
    extra_dangerous: frozenset = frozenset(),
    views: _GuardViews | _NoVouchViews | None = None,
) -> None:
    """Check C/C++ source for known vulnerability patterns."""
    if views is None:
        _with_guard_views(result, source, lambda v: _check_c_patterns(
            result, source, line_start, _callers, callees,
            extra_dangerous=extra_dangerous, views=v))
        return
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
        re.search(r'\*\s*\(.{0,1000}\+', source)
        or re.search(r'->\s*\w+\s*\[', source)
        or re.search(r'\(\w+\s*\*\)\s*\w+', source)
    )

    result.has_array_access = bool(re.search(r'\b\w+\s*\[', source))

    for k, line in enumerate(source.splitlines()):
        i = line_start + k
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
            r'snprintf\s*\([^,]{1,4000},\s*sizeof\s*\([^)]{1,4000}\)\s*,'
            r'\s*"[^"]{0,1000}%s[^"]{0,1000}"',
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
            r"(SELECT|INSERT|UPDATE|DELETE)\b.{0,1000}%s",
            stripped, re.IGNORECASE,
        ):
            result.hits.append(PrefilterHit(
                rule_id="sql-string-format",
                message="SQL query built with string formatting — SQL injection risk",
                line=i,
                severity="error",
            ))

        if re.search(
            r'\buint16_t\b.{0,1000}\boffset\b'
            r'|\buint16_t\b.{0,1000}\blen\b',
            stripped,
        ):
            result.hits.append(PrefilterHit(
                rule_id="narrow-integer-size",
                message=(
                    "uint16_t used for offset/length — wraps at 65536, "
                    "may cause infinite loop or re-processing"
                ),
                line=i,
                severity="warning",
            ))

        if re.search(r'\batoi\s*\(|\batol\s*\(', stripped) and not (
            views.line_sees(r'if\s*\(', k)
            and re.search(r'if\s*\(', stripped)  # baseline guard, verbatim (main)
        ):
                result.hits.append(PrefilterHit(
                    rule_id="atoi-unchecked",
                    message="atoi/atol does not report errors — use strtol with errno check",
                    line=i,
                    severity="warning",
                ))

        if re.search(r'\bmalloc\s*\([^)]{0,4000}\*', stripped):
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
    _check_c_missing_bounds(result, source, line_start, views)
    _check_c_use_after_free(result, source, line_start, views)
    _check_c_toctou(result, source, line_start)
    _check_c_post_loop_oob(result, source, line_start, views)


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
    views: _GuardViews | _NoVouchViews,
) -> None:
    """Check for array access on function parameters without bounds checks.

    The bounds-check search (the suppressor) reads the comment/string-
    blanked view: ``/* caller ensures i < len */`` is not a check.
    """
    lines = source.splitlines()

    params_with_index_access = set()
    for i, line in enumerate(lines, start=line_start):
        for m in re.finditer(r'\b(\w+)\s*\[(\w+)\]', line):
            index_var = m.group(2)
            if not index_var.isdigit():
                params_with_index_access.add((index_var, i))

    for var, access_line in params_with_index_access:
        check_re = (
            rf'\b{re.escape(var)}\s*(?:[<>]=?)\s*\w+|'
            rf'\b\w+\s*(?:[<>]=?)\s*{re.escape(var)}|'
            rf'if\s*\(.{{0,1000}}{re.escape(var)}'
        )
        # baseline guard, verbatim (main): any raw line of the window
        base_check = any(re.search(check_re, line) for line in lines)
        has_check = False
        # an ambiguous view cannot vouch for a check: keep the hit; and
        # the view never sees a check the baseline does not (monotone)
        if base_check and views.vouch:
            for line in views.code.splitlines():  # line-model: any-line search, line identity unused
                if re.search(check_re, line):
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
    views: _GuardViews | _NoVouchViews,
) -> None:
    """Detect potential use-after-free and double-free within a function.

    Tracks which pointer variables are passed to free(), then checks
    whether they are dereferenced or freed again afterwards.  The
    reassignment that clears a freed pointer (a suppressor) is judged
    on the blanked view's line: ``// p = NULL`` clears nothing.
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
            code_line = views.code_lines[i - line_start]
            clear_re = rf'\b{re.escape(var)}\s*(?<![!<>+\-*/&|^%=])=(?!=)\s*'
            if views.vouch and re.search(
                clear_re, code_line,
            ) and not re.search(r'\bfree\s*\(', code_line) and re.search(
                clear_re, stripped,
            ) and not re.search(r'\bfree\s*\(', stripped):  # baseline guard, verbatim (main)
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
    views: _GuardViews | _NoVouchViews,
) -> None:
    """Detect post-loop out-of-bounds writes.

    Looks for loops with `index < capacity` guards where the index
    variable is used in a write after the loop body.  The index can
    equal the capacity when the loop exits, making `buf[index]` OOB.
    The post-loop bounds check that clears the index (a suppressor) is
    judged on the blanked view's line.
    """
    lines = source.splitlines()
    loop_re = re.compile(
        r'\b(?:while|for)\b.{0,200}\b(\w+)\s*<\s*(\w+)\b'
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
            reset_re = (
                rf'\bif\b(?:(?!\b{idx_esc}\b).){{0,64}}'
                rf'\b{idx_esc}\b.{{0,200}}<|'
                rf'\bif\b(?:(?!\b{idx_esc}\b).){{0,64}}'
                rf'\b{idx_esc}\b.{{0,200}}>|'
                rf'\bif\b[^<\n]{{0,64}}<.{{0,200}}\b{idx_esc}\b'
            )
            if views.vouch and re.search(
                reset_re, views.code_lines[i - line_start],
            ) and re.search(reset_re, stripped):  # baseline guard, verbatim (main)
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
    _callers: list[dict[str, Any]] | None,
    callees: list[dict[str, Any]] | None,
    *,
    views: _GuardViews | _NoVouchViews | None = None,
) -> None:
    """Check Python source for known vulnerability patterns."""
    if views is None:
        _with_guard_views(result, source, lambda v: _check_python_patterns(
            result, source, line_start, _callers, callees, views=v))
        return
    callee_names = set()
    if callees:
        callee_names = {c.get("name", "") for c in callees}

    result.has_dangerous_apis = bool(callee_names & _DANGEROUS_PY_APIS)

    for k, line in enumerate(source.splitlines()):
        i = line_start + k
        stripped = line.strip()

        if re.search(r'\bos\.path\.join\b', stripped) and not (
            views.sees(
                r'os\.path\.realpath|os\.path\.abspath|'
                r'\.startswith\(|resolve\(\)',
            ) and re.search(  # baseline guard, verbatim (main)
                r'os\.path\.realpath|os\.path\.abspath|'
                r'\.startswith\(|resolve\(\)',
                source,
            )
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
                and not (
                    views.sees(
                        r'os\.path\.realpath|\.startswith\(|resolve\(\)',
                    ) and re.search(  # baseline guard, verbatim (main)
                        r'os\.path\.realpath|\.startswith\(|resolve\(\)',
                        source,
                    )
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

        if re.search(
            r'\bsubprocess\.\w+\(.{0,1000}shell\s*=\s*True', stripped,
        ):
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

        if re.search(r'\byaml\.load\s*\(', stripped) and not (
            views.line_sees(r'Loader\s*=\s*yaml\.SafeLoader', k)
            and re.search(  # baseline guard, verbatim (main)
                r'Loader\s*=\s*yaml\.SafeLoader', stripped,
            )
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
    _callers: list[dict[str, Any]] | None,
    callees: list[dict[str, Any]] | None,
    *,
    views: _GuardViews | _NoVouchViews | None = None,
) -> None:
    """Check Go source for known vulnerability patterns."""
    if views is None:
        _with_guard_views(result, source, lambda v: _check_go_patterns(
            result, source, line_start, _callers, callees, views=v))
        return
    callee_names = set()
    if callees:
        callee_names = {c.get("name", "") for c in callees}

    result.has_dangerous_apis = bool(callee_names & _DANGEROUS_GO_CALLEES)
    result.has_array_access = bool(re.search(r'\b\w+\s*\[', source))
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
                and not (
                    views.feeds(_GO_SQL_GUARD)
                    and re.search(r'\$\d+', source)  # baseline guard, verbatim (main)
                )
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
        ) and not (
            (
                views.sees(r'filepath\.Clean|filepath\.Abs|path\.Clean')
                or views.feeds(_GO_CONTAINS_GUARD)
            ) and re.search(  # baseline guard, verbatim (main)
                r'filepath\.Clean|filepath\.Abs|'
                r'strings\.Contains.{0,1000}\.\.|path\.Clean',
                source,
            )
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
    _callers: list[dict[str, Any]] | None,
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
    result.has_array_access = bool(re.search(r'\b\w+\s*\[', source))

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


# php-sql-injection: monotonic over the historical rule.
#
# Every hit the historical rule produces (a mysql_query / mysqli_query /
# pg_query call and a variable on a line, unless the function anywhere
# holds prepare( / bind_param / pg_query_params) is always reported:
# nothing here can withhold it, so a lexing disagreement with PHP can
# only lose an ADDITIONAL hit.  Sanitised procedural calls the
# historical rule flags stay flagged (its false positives are unchanged).
#
# Additions, from one lexed pass over the function, judged per sink:
# - method/static sinks ($pdo->query, $mysqli->real_query, $db->exec,
#   DB::select ...): their SQL argument (the first) holds an SQL-shaped
#   literal and a variable reaches it (code, "..." interpolation, a
#   backtick operand, or an argument list cut by a statement bound);
# - procedural sinks the historical rule misses (other executors such as
#   mysqli_real_query / pg_send_query / sqlsrv_query / oci_parse, any
#   case, a variable only on a continuation line), and sinks its
#   function-wide guard silenced but whose own statement holds no guard:
#   a variable anywhere in the call.
# A sink in a statement holding a prepare( / bind_param( /
# pg_query_params( call adds nothing (call-shaped tokens, a subset of
# main's; the narrower scope only ever makes the rule fire more than the
# historical function-wide guard).  Main's own hits never pass through
# this guard.
#
# Additions are dropped as false positives only on proof: a complete
# argument list; for procedural executors a plain-variable connection
# argument and variable-free extra arguments (sqlsrv bind parameters
# excepted), for method and static sinks only the first argument is
# read; no sink nested in the call; and a `.`-concatenated SQL argument
# whose every operand is a variable-free literal, an ASCII PHP number, a
# named constant (CONST, \\Ns\\CONST, self::X, Cls::X), an
# intval/floatval/boolval call (unless the source declares or imports
# one of those names), an (int)/(float)/(bool) cast (see
# _php_sql_cast_operand for exactly what it inspects and the accepted
# residuals), or $x->quote(...) on the sink's own
# receiver when no literal piece holds a quote character or a
# backslash.  Escape functions (*_escape_string, addslashes) never
# prove.  Names match case-insensitively on ASCII only.
#
# SQL shape: a literal that STARTS with an SQL verb (select, insert,
# update, delete, replace, truncate; drop/alter/create/show/describe/
# explain/call/with only with their SQL object), or a WHERE comparison
# / ORDER BY / GROUP BY fragment.
#
# Bounded gaps (additions only): a method sink fed by a variable built
# elsewhere (`$pdo->query($sql)`), sprintf-built SQL without an
# SQL-shaped literal, ->prepare("... $x") (not a sink), dynamic or
# callback executor calls, and code a lexing disagreement hides.  The
# lexer follows PHP for `?>`, `{$...}` interpolation and heredoc labels;
# a `#[...]` attribute is read as PHP 8 code only when the rest of its
# line has balanced quotes, otherwise as a PHP 7 `#` comment, which can
# hide a method sink PHP 8 runs (an FN in the additions only).
_PHP_SQL_SINK_RE = re.compile(
    r'(?P<proc>\b(?:mysqli_(?:real_|multi_)?query'
    r'|mysql_(?:unbuffered_|db_)?query|pg_(?:send_)?query|sqlsrv_query'
    r'|db2_exec|oci_parse))\s*\('
    r'|->\s*(?P<meth>query|exec|multi_query|real_query)\s*\('
    r'|\bDB::(?P<stat>raw|select|insert|update|delete|statement'
    r'|unprepared)\s*\(',
    re.IGNORECASE | re.ASCII,
)
# The historical rule (pre-change main), kept verbatim: a line with one of
# these calls and a variable is a hit unless the function anywhere holds
# a guard token.  Its hits are always reported.
_PHP_SQL_BASE_SINK_RE = re.compile(
    r'\b(?:mysql_query|mysqli_query|pg_query)\s*\(',
)
_PHP_SQL_BASE_GUARD_RE = re.compile(r'prepare\s*\(|bind_param|pg_query_params')
# PHP numeric literals (ASCII only; `١` or `²` are constant names to PHP)
_PHP_SQL_NUMBER_RE = re.compile(
    r'0[xX][0-9a-fA-F]+(?:_[0-9a-fA-F]+)*|0[bB][01]+(?:_[01]+)*'
    r'|0[oO][0-7]+(?:_[0-7]+)*'
    r'|[0-9]+(?:_[0-9]+)*(?:\.[0-9]+(?:_[0-9]+)*)?'
    r'(?:[eE][+-]?[0-9]+(?:_[0-9]+)*)?',
)
_PHP_SQL_PREPARED_RE = re.compile(
    r'\b(?:mysqli_|pg_|oci_)?prepare\s*\(|bind_param\s*\('
    r'|\bpg_query_params\s*\(',
)
_PHP_SQL_SHAPE_RE = re.compile(
    r'[\s(]*(?:(?:select|insert|update|delete|replace|truncate)\b'
    r'|drop\s+(?:temporary\s+)?(?:table|database|schema|index|view'
    r'|procedure|function|trigger|event|user)\b'
    r'|alter\s+(?:table|database|schema|view|user)\b'
    r'|create\s+(?:or\s+replace\s+)?(?:temporary\s+)?(?:table|index'
    r'|unique|view|database|schema|procedure|function|trigger|event)\b'
    r'|show\s+(?:full\s+)?(?:tables|columns|fields|databases|schemas'
    r'|index|indexes|keys|create|grants|processlist|status|variables'
    r'|triggers|table|warnings|errors)\b'
    r'|call\s+[\w.]+\s*\('
    r'|with\s+(?:recursive\s+)?\w+\s+as\s*\('
    r'|describe\s+[\w`.]'
    r'|explain\s+(?:select|insert|update|delete)\b)',
    re.IGNORECASE,
)
_PHP_SQL_CLAUSE_RE = re.compile(
    r'\bwhere\s+[\w.`"\[\]]+\s*(?:[=<>!]|like\b|in\b|is\b|between\b)'
    r'|\b(?:order|group)\s+by\b',
    re.IGNORECASE,
)
_PHP_SQL_INTERP_RE = re.compile(r'(?<!\\)\$(?:[A-Za-z_]|\{)|\{\$')
# Names are matched case-insensitively on ASCII only: no Unicode case
# folding (`ıntval`, `myſql_query` are other functions to PHP).
_PHP_SQL_SANITISER_HEAD_RE = re.compile(
    r'(?:(?P<recv>\$\w+(?:->\w+)*)->quote|(?:intval|floatval|boolval)\b)'
    r'\s*\(',
    re.IGNORECASE | re.ASCII,
)
_PHP_SQL_CAST_RE = re.compile(
    r'\(\s*(?:int|integer|float|double|bool|boolean)\s*\)\s*',
    re.IGNORECASE | re.ASCII,
)
# what a numeric cast may apply to: variables, properties, indexes,
# class constants and arithmetic — no call, no `?:`/`??`, no assignment
_PHP_SQL_CAST_OPERAND_RE = re.compile(r'[A-Za-z0-9_\s$\[\]"+*/%:>-]+')
# inside a cast of a call expression: anything that may itself execute
# SQL (besides _PHP_SQL_SINK_RE) refuses the proof
_PHP_SQL_CAST_UNSAFE_RE = re.compile(
    r'->\s*prepare\s*\(|[)\]"]\s*\(|\$\w+\s*\(|(?:->|::)\s*[{$]|\bnew\b'
    r'|\b(?:call_user_func(?:_array)?|forward_static_call(?:_array)?'
    r'|array_map|array_walk(?:_recursive)?|array_filter|array_reduce'
    r'|usort|uasort|uksort|iterator_apply|fromcallable)\s*\(',
    re.IGNORECASE | re.ASCII,
)
# a PHP constant: CONST, \Ns\CONST, self::X, static::X, Cls::X (never
# `Cls::$prop`, never a call)
_PHP_SQL_CONSTANT_RE = re.compile(
    r'(?:\\?[A-Za-z_][A-Za-z0-9_]*(?:\\[A-Za-z_][A-Za-z0-9_]*)*::'
    r'|\\?(?:[A-Za-z_][A-Za-z0-9_]*\\)*)[A-Z_][A-Z0-9_]*',
)
_PHP_SQL_PLAIN_VAR_RE = re.compile(r'\$\w+(?:->\w+)*', re.ASCII)
# a declaration or import of an allowlisted helper name: unqualified
# intval(...) may then be a user function (namespace X; use function).
# Read on the raw text and on the comment-blanked code view.
_PHP_SQL_SHADOW_FUNC_RE = re.compile(
    r'\bfunction[\s&]*(?:intval|floatval|boolval)\s*\(',
    re.IGNORECASE | re.ASCII,
)
_PHP_SQL_USE_FUNCTION_RE = re.compile(
    r'\buse\s+function\b', re.IGNORECASE | re.ASCII,
)
_PHP_SQL_HELPER_NAME_RE = re.compile(
    r'\b(?:intval|floatval|boolval)\b', re.IGNORECASE | re.ASCII,
)
_PHP_SQL_HEREDOC_RE = re.compile(
    r'<<<[ \t]*(["\']?)([A-Za-z_\x80-\U0010ffff][\w\x80-\U0010ffff]*)\1'
    r'[ \t]*\r?\n',
)
_PHP_SQL_NONNL_RE = re.compile(r'[^\r\n]')
_PHP_SQL_NL_RE = re.compile(r'[\r\n]')
_PHP_SQL_STMT_END_RE = re.compile(r'[;{}]')
_PHP_SQL_LEX_JUMP_RE = re.compile(r'["\'`/#<?]')
_PHP_SQL_LINE_COMMENT_END_RE = re.compile(r'[\r\n]|\?>')
_PHP_SQL_ATTRIBUTE_RE = re.compile(r'#\[[^\]\r\n]*\]')
_PHP_SQL_OPEN_TAG_RE = re.compile(r'<\?(?:php|=)?', re.IGNORECASE)
_PHP_SQL_DQ_STOP_RE = {q: re.compile(r'[%s\\{$]' % q) for q in '"`'}
_PHP_SQL_EXPR_STOP_RE = re.compile(r'[{}\'"`]')
# literal bodies after the opening quote, up to (not incl.) the closer
_PHP_SQL_BODY_RE = {
    q: re.compile(r'[^%s\\]*(?:\\[\s\S][^%s\\]*)*' % (q, q))
    for q in '"\'`'
}
_PHP_SQL_MAX_PAREN_DEPTH = 16

# literal start -> (end, kind, content_start, content_end); kind is the
# quote character, "h" (heredoc) or "n" (nowdoc).
_PhpSqlLiterals = dict[int, tuple[int, str, int, int]]


def _php_sql_label_char(ch: str) -> bool:
    """PHP label character (heredoc identifiers): [A-Za-z0-9_\\x80-\\xff]."""
    return ch == '_' or ch.isalnum() or ord(ch) >= 0x80


def _php_sql_body_end(source: str, i: int, quote: str) -> int:
    """Index of the quote closing a `"`/backtick literal whose body starts
    at ``i`` (``len(source)`` if unclosed).

    ``{$...}`` / ``${...}`` interpolation is PHP code: its braces, and the
    literals nested inside it, are skipped as code, so a quote inside
    the expression does not end the outer literal.  Explicit stack, one
    pass.
    """
    n = len(source)
    stack = [quote]      # open literal quotes and '{' expression levels
    braces: list[int] = []
    while i < n:
        top = stack[-1]
        if top == "'":
            k = _PHP_SQL_BODY_RE["'"].match(source, i).end()
            if k >= n:
                return n
            stack.pop()
            i = k + 1
            continue
        if top != '{':
            m = _PHP_SQL_DQ_STOP_RE[top].search(source, i)
            if not m:
                return n
            k = m.start()
            c = source[k]
            if c == '\\':
                i = k + 2
            elif c == top:
                stack.pop()
                if not stack:
                    return k
                i = k + 1
            elif source.startswith('{$', k) or source.startswith('${', k):
                stack.append('{')
                braces.append(1)
                i = k + 2
            else:
                i = k + 1
            continue
        m = _PHP_SQL_EXPR_STOP_RE.search(source, i)
        if not m:
            return n
        k = m.start()
        c = source[k]
        if c == '{':
            braces[-1] += 1
        elif c == '}':
            braces[-1] -= 1
            if braces[-1] == 0:
                braces.pop()
                stack.pop()
        else:
            stack.append(c)
        i = k + 1
    return n


def _php_sql_lex(source: str) -> tuple[str, _PhpSqlLiterals]:
    """Code view of ``source`` (same length) plus its string literals.

    In the code view each literal becomes `"` followed by blanks, each
    comment becomes blanks, and each `?>` inline-HTML block becomes `;`
    followed by blanks (line breaks kept), so offsets map 1:1 to
    ``source``.  `//` and `#` comments end at a line break or `?>`, as
    in PHP; a `#[...]` attribute is blanked like a comment.  Single pass; an unterminated literal, comment or HTML block
    runs to the end of the text.
    """
    n = len(source)
    out: list[str] = []
    lits: _PhpSqlLiterals = {}
    i = 0
    flat = 0  # start of the pending verbatim run
    # line-comment end and quote counts after the last attribute, reused
    # while lexing resumes inside the same line (keeps `#[A] #[A] ...`
    # linear)
    stop_at = -1
    attr_at = -1
    attr_line_end = -1
    attr_counts = (0, 0, 0)
    while i < n:
        jump = _PHP_SQL_LEX_JUMP_RE.search(source, i)
        if not jump:
            break
        i = jump.start()
        ch = source[i]
        end = -1
        lead = ' '
        lit: tuple[str, int, int] | None = None
        if ch == "'":
            j = _PHP_SQL_BODY_RE["'"].match(source, i + 1).end()
            end = min(j + 1, n)
            lit = (ch, i + 1, min(j, n))
        elif ch in '"`':
            j = _php_sql_body_end(source, i + 1, ch)
            end = min(j + 1, n)
            lit = (ch, i + 1, min(j, n))
        elif source.startswith('<<<', i):
            m = _PHP_SQL_HEREDOC_RE.match(source, i)
            if m:
                ident = m.group(2)
                k = m.end()
                end = n
                cend = n
                while k < n:
                    stripped = k
                    while stripped < n and source[stripped] in ' \t':
                        stripped += 1
                    after = stripped + len(ident)
                    if source.startswith(ident, stripped) and (
                        after >= n or not _php_sql_label_char(source[after])
                    ):
                        end, cend = after, k
                        break
                    nl = _PHP_SQL_NL_RE.search(source, k)
                    if not nl:
                        break
                    k = nl.end()
                lit = ('n' if m.group(1) == "'" else 'h', m.end(), cend)
        elif source.startswith('/*', i):
            close = source.find('*/', i + 2)
            end = n if close < 0 else close + 2
        elif source.startswith('//', i) or ch == '#':
            if i >= stop_at:
                stop = _PHP_SQL_LINE_COMMENT_END_RE.search(source, i)
                stop_at = n if not stop else stop.start()
            end = stop_at
            attr = _PHP_SQL_ATTRIBUTE_RE.match(source, i, end)
            if attr:
                if attr_line_end != end or attr_at > attr.end():
                    attr_counts = tuple(
                        source.count(q, attr.end(), end) for q in '"\'`'
                    )
                else:
                    attr_counts = tuple(
                        c - source.count(q, attr_at, attr.end())
                        for c, q in zip(attr_counts, '"\'`')
                    )
                attr_at, attr_line_end = attr.end(), end
                if all(c % 2 == 0 for c in attr_counts):
                    # PHP 8 attribute.  With an unbalanced quote after it
                    # the line is read as a PHP 7 `#` comment instead,
                    # which can hide a method sink PHP 8 runs (an FN in
                    # the additions only; main's hits are unaffected)
                    end = attr.end()
        elif source.startswith('?>', i):
            tag = _PHP_SQL_OPEN_TAG_RE.search(source, i + 2)
            end = n if not tag else tag.end()
            lead = ';'
        if end >= 0:
            out.append(source[flat:i])
            blank = _PHP_SQL_NONNL_RE.sub(' ', source[i:end])
            if lit is not None:
                lits[i] = (end, lit[0], lit[1], lit[2])
                lead = '"'
            if blank:
                blank = (lead if blank[0] == ' ' else blank[0]) + blank[1:]
            out.append(blank)
            i = flat = end
            continue
        i += 1
    out.append(source[flat:])
    return "".join(out), lits


def _php_sql_close(code: str, start: int, stop: int) -> int:
    """Index of the ``)`` closing the ``(`` just before ``start``; -1 if
    it is not closed before ``stop``."""
    depth = 1
    for k in range(start, stop):
        c = code[k]
        if c == '(':
            depth += 1
        elif c == ')':
            depth -= 1
            if depth == 0:
                return k
    return -1


def _php_sql_split(code: str, start: int, stop: int, sep: str):
    """Split ``code[start:stop]`` at depth-0 ``sep``; stripped spans."""
    spans = []
    depth = 0
    piece = start
    for k in range(start, stop):
        c = code[k]
        if c in '([':
            depth += 1
        elif c in ')]':
            depth -= 1
        elif c == sep and depth == 0:
            if sep == '.' and (
                0 < k < stop - 1
                and code[k - 1].isdigit() and code[k + 1].isdigit()
            ):
                continue
            spans.append((piece, k))
            piece = k + 1
    spans.append((piece, stop))
    out = []
    for a, b in spans:
        while a < b and code[a].isspace():
            a += 1
        while b > a and code[b - 1].isspace():
            b -= 1
        out.append((a, b))
    return out


def _php_sql_cast_operand(code: str, a: int, b: int) -> bool:
    """``code[a:b]`` is what a numeric cast may safely apply to.

    The cast yields a number whatever its operand is.  Two paths:
    - fast path: the code view of the operand is only variables,
      properties, indexes, constants, string literals and arithmetic
      (``_PHP_SQL_CAST_OPERAND_RE``).  It is accepted without the scans
      below, so string-literal bodies (blank in the code view) and
      paren-less keywords are not inspected: a sink inside `{$...}` or a
      heredoc within the cast, and `(int) new Q + $a`, are accepted.
      These are accepted residuals of the additions' filter (0 in the
      real-world PHP corpus that was measured) — main's hits are never
      filtered.
    - call path: an operand holding calls is accepted only if it is one
      expression (no top-level `?:`, `??` or assignment, which would take
      the whole SQL) and its code view holds no sink-family call, no
      `->prepare(`, no dynamic or computed callee, no callback taker and
      no `new`.  An unknown user executor in that position is accepted
      (a deliberate trade-off; main never flags such executors).
      String-literal bodies are not inspected here either:
      `(int)f("{$db->query(...)}")` is accepted (same class as the
      fast-path residual).
    """
    while a < b and code[a].isspace():
        a += 1
    while b > a and code[b - 1].isspace():
        b -= 1
    if a < b and code[a] == '(' and _php_sql_close(code, a + 1, b) == b - 1:
        a, b = a + 1, b - 1
    if a >= b:
        return False
    if _PHP_SQL_CAST_OPERAND_RE.fullmatch(code, a, b) is not None:
        return True
    if (
        _PHP_SQL_SINK_RE.search(code, a, b) is not None
        or _PHP_SQL_CAST_UNSAFE_RE.search(code, a, b) is not None
    ):
        return False
    depth = 0
    for k in range(a, b):
        c = code[k]
        if c in '([':
            depth += 1
        elif c in ')]':
            depth -= 1
            if depth < 0:
                return False
        elif depth == 0 and _PHP_SQL_CAST_OPERAND_RE.fullmatch(c) is None:
            return False
    return depth == 0


def _php_sql_helper_shadowed(text: str) -> bool:
    """``text`` declares or imports intval/floatval/boolval."""
    if _PHP_SQL_SHADOW_FUNC_RE.search(text):
        return True
    pos = 0
    while True:
        m = _PHP_SQL_USE_FUNCTION_RE.search(text, pos)
        if not m:
            return False
        end = text.find(';', m.end())
        end = len(text) if end < 0 else end
        if _PHP_SQL_HELPER_NAME_RE.search(text, m.end(), end):
            return True
        pos = end + 1


def _php_sql_receiver(code: str, end: int, start: int) -> str | None:
    """The plain receiver chain (`$db`, `$this->db`) ending at ``end``
    (just before `->`), trailing whitespace dropped; None if the chain
    holds inner whitespace or is not a plain chain."""
    k = end
    while k > start and code[k - 1].isspace():
        k -= 1
    j = k
    while j > start and (code[j - 1].isalnum() or code[j - 1] in '_$->'):
        j -= 1
    m = _PHP_SQL_PLAIN_VAR_RE.match(code, j, k)
    if m is None or m.end() != k:
        return None
    return code[j:k]


def _php_sql_terms_safe(
    code: str, lits: _PhpSqlLiterals, source: str, a: int, b: int,
    receiver: str | None, helpers: bool, depth: int = 0,
) -> tuple[bool, bool] | None:
    """Check every operand of the concatenation ``code[a:b]``.

    None when an operand is not provably safe; otherwise ``(quoted,
    quote_chars)``: whether a ->quote() operand was used, and whether
    any literal piece holds a quote character.
    """
    if depth > _PHP_SQL_MAX_PAREN_DEPTH or a >= b:
        return None
    quoted = quote_chars = False
    for ta, tb in _php_sql_split(code, a, b, '.'):
        if ta >= tb:
            return None
        # a literal's body is blank in the code view, so a term that is
        # exactly one literal strips down to its opening `"`
        lit = lits.get(ta)
        if lit is not None and tb == ta + 1:
            body = source[lit[2]:lit[3]]
            if lit[1] == '`' or '$' in body:
                return None
            # a backslash may spell a quote (\x27, \047, \u{27})
            quote_chars = quote_chars or any(q in body for q in '\'"`\\')
            continue
        if _PHP_SQL_NUMBER_RE.fullmatch(code, ta, tb):
            continue
        if _PHP_SQL_CONSTANT_RE.fullmatch(code, ta, tb):
            # a named constant cannot carry request data (one define()d
            # from it is out of scope, like a table prefix)
            continue
        m = _PHP_SQL_SANITISER_HEAD_RE.match(code, ta, tb)
        if m and _php_sql_close(code, m.end(), tb) == tb - 1:
            recv = m.group('recv')
            if recv is not None:
                # PDO::quote() is safe for its own connection's driver
                # only: the receiver must be the sink's receiver
                if receiver is None or "".join(recv.split()) != receiver:
                    return None
                quoted = True
            elif not helpers:
                return None  # intval & co. may be shadowed here
            continue
        m = _PHP_SQL_CAST_RE.match(code, ta, tb)
        if m and _php_sql_cast_operand(code, m.end(), tb):
            continue
        if code[ta] == '(' and _php_sql_close(code, ta + 1, tb) == tb - 1:
            inner = _php_sql_terms_safe(code, lits, source, ta + 1, tb - 1,
                                        receiver, helpers, depth + 1)
            if inner is not None:
                quoted = quoted or inner[0]
                quote_chars = quote_chars or inner[1]
                continue
        return None
    return quoted, quote_chars


def _php_sql_proved(
    source: str, code: str, lits: _PhpSqlLiterals, a: int, b: int,
    receiver: str | None = None, helpers: bool = True,
) -> bool:
    """Every operand of the concatenation ``code[a:b]`` is safe.

    Escape functions never prove (their safety depends on the server's
    dialect, modes and charset).  A ->quote() result is a complete
    quoted literal, so it proves only when no literal piece holds a
    quote character — then it cannot land inside an open SQL string.
    """
    checked = _php_sql_terms_safe(code, lits, source, a, b, receiver,
                                  helpers)
    return checked is not None and not (checked[0] and checked[1])


# Procedural SQL executors: accepted argument shapes, by role.  "conn" is
# a plain variable; "sql" is the statement; "opt" holds no variable;
# "id" is a plain variable or variable-free; "bind" is bound parameters
# (any content).  A call matching no shape is unparsed (keeps its hit).
_PHP_SQL_PROCEDURAL_ARGS: dict[str, tuple[tuple[str, ...], ...]] = {
    'mysqli_query': (('conn', 'sql'), ('conn', 'sql', 'opt')),
    'mysqli_real_query': (('conn', 'sql'),),
    'mysqli_multi_query': (('conn', 'sql'),),
    'pg_query': (('sql',), ('conn', 'sql')),
    'pg_send_query': (('conn', 'sql'),),
    'mysql_query': (('sql',), ('sql', 'conn')),
    'mysql_unbuffered_query': (('sql',), ('sql', 'conn')),
    'mysql_db_query': (('id', 'sql'), ('id', 'sql', 'conn')),
    'sqlsrv_query': (('conn', 'sql'), ('conn', 'sql', 'bind'),
                     ('conn', 'sql', 'bind', 'opt')),
    'db2_exec': (('conn', 'sql'), ('conn', 'sql', 'opt')),
    'oci_parse': (('conn', 'sql'),),
}


def _php_sql_procedural_sql_arg(
    name: str, code: str, source: str, args: list[tuple[int, int]],
) -> tuple[int, int] | None:
    """The SQL argument of a procedural call whose other arguments fit
    one of its accepted shapes; else None."""
    for roles in _PHP_SQL_PROCEDURAL_ARGS.get(name.lower(), ()):
        if len(roles) != len(args):
            continue
        sql = None
        for role, (x, y) in zip(roles, args):
            plain = _PHP_SQL_PLAIN_VAR_RE.match(code, x, y)
            is_plain = plain is not None and plain.end() == y
            if role == 'sql':
                sql = (x, y)
            elif role == 'conn' and not is_plain:
                break
            elif role == 'opt' and '$' in source[x:y]:
                break
            elif role == 'id' and not (is_plain or '$' not in source[x:y]):
                break
        else:
            return sql
    return None


# Failures of the additions, contained by _php_sql_injection_lines: an
# aggregate count (read with php_sql_additions_failure_count) and one
# warning per process.
_php_sql_additions_failures = 0
_php_sql_additions_warned = False
_php_sql_additions_lock = threading.Lock()


def php_sql_additions_failure_count() -> int:
    """How many times the php-sql-injection additions raised and were
    skipped (main's hits kept) in this process."""
    return _php_sql_additions_failures


def _php_sql_main_rule_lines(source: str, line_start: int) -> set[int]:
    """The historical rule (pre-change main), verbatim: a line with one of
    its three calls and a variable, unless the function anywhere holds a
    guard token."""
    hits: set[int] = set()
    if not _PHP_SQL_BASE_GUARD_RE.search(source):
        for idx, text in enumerate(source.splitlines(keepends=True)):
            stripped = text.strip()
            if _PHP_SQL_BASE_SINK_RE.search(stripped) and '$' in stripped:
                hits.add(line_start + idx)
    return hits


def _php_sql_injection_lines(
    source: str, line_start: int, *,
    guard_view: Callable[[], str | None] = lambda: None,
) -> set[int]:
    """Line numbers (``line_start``-based) with a php-sql-injection hit.

    Monotonic over the historical rule: every line it flags is flagged
    here too, unconditionally.  The lexer and the proofs only decide
    which ADDITIONAL hits (method/static sinks, other executors, sinks
    the function-wide guard silenced, multi-line calls) to report.  If
    the additions raise (``guard_view`` included), main's result is
    returned unchanged.

    The per-statement prepared-statement guard only withholds an
    ADDITION, and it is a suppressor of it: ``prepare(`` must be code in
    this rule's blanked view AND in ``guard_view()`` (the shared
    sanitized view, same offsets, which also blanks inline HTML; called
    lazily), which returns None when that view is ambiguous — the guard
    then cannot vouch and the addition stands.  The historical rule's
    own function-wide guard above stays verbatim on raw text.  The
    default (no shared view) never vouches, so the guard can only make
    the rule fire more.
    """
    global _php_sql_additions_failures, _php_sql_additions_warned
    hits = _php_sql_main_rule_lines(source, line_start)
    try:
        added = _php_sql_additions(source, line_start, guard_view=guard_view)
    except Exception as exc:  # noqa: BLE001 — never cost main's hits
        with _php_sql_additions_lock:
            _php_sql_additions_failures += 1
            warn = not _php_sql_additions_warned
            _php_sql_additions_warned = True
        # The count above is always exact; the logging is best-effort, so
        # a failure while logging (e.g. RecursionError near the stack
        # limit) never costs main's hits.  The warning is retried until a
        # call returns: the failure that reserved it releases the
        # reservation if logger.warning raises.  A logger that emits and
        # then raises can therefore warn twice; failures arriving while
        # the reservation is held skip the warning; and if no failure
        # follows a failed warning, no warning is given.
        if warn:
            try:
                # no source text: the exception type only
                logger.warning(
                    "php-sql-injection: additional sinks skipped after %s; "
                    "the historical rule's hits are kept (further failures "
                    "are counted, not logged)", type(exc).__name__,
                )
            except BaseException as log_exc:  # noqa: BLE001 — re-raised below
                # release so a later failure retries; interrupts propagate
                with _php_sql_additions_lock:
                    _php_sql_additions_warned = False
                if not isinstance(log_exc, Exception):
                    raise
        try:
            logger.debug("php-sql-injection additions failed", exc_info=exc)
        except Exception:  # noqa: BLE001 — logging must not cost main's hits
            pass
        return hits
    return hits | added


def _php_sql_additions(
    source: str, line_start: int, *,
    guard_view: Callable[[], str | None] = lambda: None,
) -> set[int]:
    """Lines the lexer-based rule adds (method/static sinks, other
    executors, sinks main's function-wide guard silenced, multi-line
    calls).  Not guarded: _php_sql_injection_lines contains failures,
    including any raised by ``guard_view`` (the prepare pointer's
    shared view, called lazily from here)."""
    lines = source.splitlines(keepends=True)
    hits: set[int] = set()
    starts = []
    off = 0
    for ln in lines:
        starts.append(off)
        off += len(ln)

    def line_of(pos: int) -> int:
        return line_start + bisect.bisect_right(starts, pos) - 1

    code, lits = _php_sql_lex(source)
    lit_starts = sorted(lits)
    # intval & co. prove nothing where the source may shadow them
    helpers = not (
        _php_sql_helper_shadowed(source) or _php_sql_helper_shadowed(code)
    )

    def literals_in(a: int, b: int):
        lo = bisect.bisect_left(lit_starts, a)
        hi = bisect.bisect_left(lit_starts, b)
        return [lits[s] for s in lit_starts[lo:hi]]

    def reaches(a: int, b: int) -> bool:
        if '$' in code[a:b]:
            return True
        return any(
            kind == '`' or (
                kind in '"h'
                and _PHP_SQL_INTERP_RE.search(source, ca, cb) is not None
            )
            for _end, kind, ca, cb in literals_in(a, b)
        )

    def shaped(a: int, b: int) -> bool:
        return any(
            kind != '`' and (
                _PHP_SQL_SHAPE_RE.match(source, ca, cb) is not None
                or _PHP_SQL_CLAUSE_RE.search(source, ca, cb) is not None
            )
            for _end, kind, ca, cb in literals_in(a, b)
        )

    stmt = 0
    bounds = [m.start() for m in _PHP_SQL_STMT_END_RE.finditer(code)]
    bounds.append(len(code))
    for stop in bounds:
        s, e = stmt, stop
        stmt = stop + 1
        # per top-level sink: [line, match, close, covered, nested]
        outer: list | None = None
        records: list[list] = []
        guarded: bool | None = None
        for m in _PHP_SQL_SINK_RE.finditer(code, s, e):
            if outer is not None and m.start() < outer[3]:
                # a sink inside an earlier sink's arguments: the outer
                # call is never proved
                outer[4] = True
                continue
            if guarded is None:
                # once per statement: a prepare/bind_param/pg_query_params
                # call in the sink's own statement means no addition
                view = (
                    guard_view()
                    if _PHP_SQL_PREPARED_RE.search(code, s, e) else None
                )
                guarded = view is not None and (
                    _PHP_SQL_PREPARED_RE.search(view, s, e) is not None
                    # the additions' raw statement guard, verbatim:
                    # never withhold an addition it makes (monotone)
                    and _PHP_SQL_PREPARED_RE.search(source, s, e) is not None
                )
            if guarded:
                break
            close = _php_sql_close(code, m.end(), e)
            covered = close + 1 if close >= 0 else e
            outer = [line_of(m.start()), m, close, covered, False]
            records.append(outer)
        if guarded:
            continue
        for line, m, close, covered, nested in records:
            args = (
                _php_sql_split(code, m.end(), close, ',')
                if close >= 0 else None
            )
            if m.group('proc') is not None:
                sql = (
                    _php_sql_procedural_sql_arg(m.group('proc'), code,
                                                source, args)
                    if args else None
                )
                proved = not nested and sql is not None and _php_sql_proved(
                    source, code, lits, sql[0], sql[1], helpers=helpers,
                )
                if not proved and '$' in source[m.start():covered]:
                    hits.add(line)
                continue
            receiver = (
                _php_sql_receiver(code, m.start(), s)
                if m.group('meth') else None
            )
            proved = not nested and bool(args) and _php_sql_proved(
                source, code, lits, *args[0], receiver=receiver,
                helpers=helpers,
            )
            a, b = args[0] if args else (m.end(), covered)
            # an argument list not closed inside the statement (a
            # closure or match block follows) counts as reaching
            if not proved and shaped(a, b) and (
                args is None or nested or reaches(a, b)
            ):
                hits.add(line)
    return hits


def _check_php_patterns(
    result: PrefilterResult,
    source: str,
    line_start: int,
    _callers: list[dict[str, Any]] | None,
    callees: list[dict[str, Any]] | None,
    *,
    views: _GuardViews | _NoVouchViews | None = None,
) -> None:
    """Check PHP source for known vulnerability patterns."""
    if views is None:
        _with_guard_views(result, source, lambda v: _check_php_patterns(
            result, source, line_start, _callers, callees, views=v))
        return
    callee_names = set()
    if callees:
        callee_names = {c.get("name", "") for c in callees}

    result.has_dangerous_apis = bool(callee_names & _DANGEROUS_PHP_CALLEES)
    result.has_array_access = bool(re.search(r'\$\w+\s*\[', source))
    # The prepare pointer asks for the shared view inside the
    # php-sql-injection fail-safe; a view failure there would only
    # drop the additions.
    # It is held instead (a fresh holder per attempt) and re-raised as
    # soon as php-sql returns, so it reaches _with_guard_views, whose
    # never-vouching re-run keeps the additions.
    view_error: list[Exception] = []

    def guard_view() -> str | None:
        try:
            return views.code if views.vouch else None
        except Exception as exc:  # noqa: BLE001 — re-raised below
            view_error.append(exc)
            return None

    sql_injection_lines = _php_sql_injection_lines(
        source, line_start, guard_view=guard_view,
    )
    if view_error:
        raise view_error[0]
    for k, line in enumerate(source.splitlines()):
        i = line_start + k
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
            r'\bpreg_replace\s*\(\s*["\'].{0,1000}?/e["\']',
            stripped,
        ):
            result.hits.append(PrefilterHit(
                rule_id="php-preg-replace-e",
                message="preg_replace with /e modifier — code execution",
                line=i,
                severity="error",
            ))

        if i in sql_injection_lines:
            result.hits.append(PrefilterHit(
                rule_id="php-sql-injection",
                message=(
                    "SQL query with variable interpolation — "
                    "use prepared statements"
                ),
                line=i,
                severity="error",
            ))

        if re.search(
            r'\becho\b.{0,1000}\$_(?:GET|POST|REQUEST|COOKIE)', stripped,
        ):
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
        ) and not (
            (
                views.sees(r'realpath|basename')
                or views.feeds(_PHP_STR_REPLACE_GUARD)
            ) and re.search(  # baseline guard, verbatim (main)
                r'realpath|basename|str_replace.{0,1000}\.\.',
                source,
            )
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

        if re.search(
            r'\bheader\s*\(\s*["\']Location.{0,1000}\$', stripped,
        ):
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
    _callers: list[dict[str, Any]] | None,
    callees: list[dict[str, Any]] | None,
    *,
    views: _GuardViews | _NoVouchViews | None = None,
) -> None:
    """Check Java source for known vulnerability patterns."""
    if views is None:
        _with_guard_views(result, source, lambda v: _check_java_patterns(
            result, source, line_start, _callers, callees, views=v))
        return
    callee_names = set()
    if callees:
        callee_names = {c.get("name", "") for c in callees}

    result.has_dangerous_apis = bool(callee_names & _DANGEROUS_JAVA_CALLEES)
    result.has_array_access = bool(re.search(r'\b\w+\s*\[', source))

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
            r'\.getMethod\s*\(.{0,1000}\.invoke\s*\(',
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
            r'new\s+File\s*\(.{0,200}'
            r'(?:request|param|input|getParameter)',
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
        ) and not (
            (
                views.sees(
                    r'FEATURE_SECURE_PROCESSING|'
                    r'setExpandEntityReferences.{0,1000}false',
                )
                or views.feeds(_JAVA_SET_FEATURE_GUARD)
            ) and re.search(  # baseline guard, verbatim (main)
                r'FEATURE_SECURE_PROCESSING|'
                r'disallow-doctype-decl|'
                r'setExpandEntityReferences.{0,1000}false',
                source,
            )
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
            r'ScriptEngine|\.eval\s*\(.{0,200}(?:request|param|input)',
            stripped, re.IGNORECASE,
        ):
            result.hits.append(PrefilterHit(
                rule_id="java-script-injection",
                message="ScriptEngine.eval with user input — code injection",
                line=i,
                severity="error",
            ))

        if re.search(
            r'\bLDAP\b.{0,1000}\+\s*(?:request|param|input)',
            stripped, re.IGNORECASE,
        ):
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
    _callers: list[dict[str, Any]] | None,
    callees: list[dict[str, Any]] | None,
    *,
    views: _GuardViews | _NoVouchViews | None = None,
) -> None:
    """Check JavaScript/TypeScript source for known vulnerability patterns."""
    if views is None:
        _with_guard_views(result, source, lambda v: _check_js_patterns(
            result, source, line_start, _callers, callees, views=v))
        return
    callee_names = set()
    if callees:
        callee_names = {c.get("name", "") for c in callees}

    result.has_dangerous_apis = bool(callee_names & _DANGEROUS_JS_CALLEES)
    result.has_array_access = bool(re.search(r'\b\w+\s*\[', source))

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
            r'child_process.{0,1000}'
            r'\b(?:exec|execSync|spawn|execFile)\s*\(',
            stripped,
        ) or (re.search(
            r'\b(?:exec|execSync|spawn|spawnSync|execFile)\s*\(',
            stripped,
        ) and re.search(r'child_process|require.{0,1000}child', source)):
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
        ) and not (
            (
                views.sees(r'path\.(?:resolve|normalize|basename)|sanitize')
                or views.feeds(_JS_INCLUDES_GUARD)
            ) and re.search(  # baseline guard, verbatim (main)
                r'path\.(?:resolve|normalize|basename)|'
                r'sanitize|includes.{0,1000}\.\.',
                source,
            )
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

        if re.search(r'\.redirect\s*\(.{0,200}(?:req\.|params\.|query\.)', stripped):
            result.hits.append(PrefilterHit(
                rule_id="js-open-redirect",
                message="redirect with user-controlled URL — open redirect",
                line=i,
                severity="warning",
            ))

        if re.search(
            r'\bnew\s+RegExp\s*\(.{0,1000}(?:req\.|params\.|input)',
            stripped,
        ):
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
    _callers: list[dict[str, Any]] | None,
    callees: list[dict[str, Any]] | None,
) -> None:
    """Check Lua source for known vulnerability patterns."""
    callee_names = set()
    if callees:
        callee_names = {c.get("name", "") for c in callees}

    result.has_dangerous_apis = bool(callee_names & _DANGEROUS_LUA_CALLEES)
    result.has_array_access = bool(re.search(r'\b\w+\s*\[', source))

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
            r'%s.{0,200}user|%s.{0,200}input|%s.{0,200}req',
            stripped, re.IGNORECASE,
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
    _callers: list[dict[str, Any]] | None,
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

        # gated optional paren (the \(?\s* pair was quadratic)
        if re.search(r'\beval\s*(?:\(\s*)?["\$]', stripped):
            result.hits.append(PrefilterHit(
                rule_id="perl-eval",
                message="eval with variable — code injection risk",
                line=i,
                severity="error",
            ))

        if re.search(r'\b(?:system|exec)\s*(?:\(\s*)?["\$]', stripped):
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
            r'\bopen\s*(?:\(\s*)?\w+\s*,\s*["\$]', stripped,
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
            r'\bDBI\b.{0,200}\bdo\s*\(|\bprepare\s*\(.{0,200}\$',
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
            r'\bprint\b.{0,1000}\$(?:query|param|input|cgi)',
            stripped, re.IGNORECASE,
        ) and not re.search(r'encode_entities|escapeHTML|CGI::escape', source):
                result.hits.append(PrefilterHit(
                    rule_id="perl-xss",
                    message="printing user input without escaping — XSS risk",
                    line=i,
                    severity="warning",
                ))

        if re.search(
            # The pattern body BEFORE the interpolation excludes bare '$':
            # it stops at the first unescaped '$' deterministically —
            # with '$' inside the class, a '$'-storm line made every
            # split of the run explorable, quadratic per line.  Escaped
            # dollars still ride the escape branch; a match exists for
            # exactly the same lines (first-$ vs any-$ anchoring), and
            # the consumer is a boolean hit.
            r'=~\s*s/(?:\\.|[^/\\\n$])*\$(?:\\.|[^/\\\n])*'
            r'/(?:\\.|[^/\\\n])*/e',
            stripped,
        ):
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
            r'\bchmod\s*(?:\(\s*)?0?777|\bchmod\b.{0,1000}\$',
            stripped,
        ):
            result.hits.append(PrefilterHit(
                rule_id="perl-chmod-unsafe",
                message="chmod with unsafe permissions or variable",
                line=i,
                severity="warning",
            ))
