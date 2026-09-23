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
import logging
import re
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.audit.source_view import sanitized_view

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
_WRAPPER_CALL_RE = re.compile(r'\b((?:\w+\.)*\w+)\s*\(')

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
_JS_INVALID_SLASH_RE = re.compile(r"[)\]\"'`\w]\s*/[^\n\\]*\\")
_WRAPPER_RETURN_CALL_RE = re.compile(r'return\s+(\w+)\s*\(')
_WRAPPER_PTR_ARITH_RE = re.compile(
    r'(?<!\w->)\w+\s*\+\s*\w|\w+\s*\[\s*[^]]+\]|'
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
        refs: set[str] = set()
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
        for arg_, default in zip(a.kwonlyargs, a.kw_defaults):
            if default is not None:
                bind_default(arg_.arg, default)

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
                for n in ast.walk(comp.target):
                    if isinstance(n, ast.Name):
                        accounted.add(n.id)  # comprehension-scoped
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
            return set(), True  # expression statement — no binding
        lhs_end, rhs_start, compound = pos
        lhs = stmt[:lhs_end].strip()
        rhs = stmt[rhs_start:].strip()
        if _c_find_assign(rhs) is not None:
            value = process(rhs)  # chained: bind inner target first
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
        raw_lines = [ln.strip() for ln in src.split("\n")]
        kept = [
            idx for idx, ln in enumerate(raw_lines)
            if ln and ln not in ("{", "}")
        ]
        code_lines = [raw_lines[i] for i in kept]
        sview = sanitized_view(src, language=lang).split("\n")
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
        rlines = sanitized_view(src, language=lang).split("\n")
        for idx, raw in enumerate(cview.split("\n")):
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
                return False, ""

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
            r"\b(?:func(?:tion)?|fn|sub)\s+(?:\([^)]*\)\s*)?$",
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
    # default, call argument, return, yield) is judged against the
    # exclusion. An unaccountable body refuses the skip.
    wrapper_params: set[str] = set()
    if lang == "python":
        escape = _py_wrapper_escape(source)
        if escape is None:
            return False, ""
        wrapper_bindings, judged_values, wrapper_params = escape
    else:
        escape = _text_wrapper_escape(ref_lines)
        if escape is None:
            return False, ""
        wrapper_bindings, judged_values = escape
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
            stmts = [s.strip() for s in body_no_sig.split("\n") if s.strip()]
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
    elif lang == "lua":
        # Field / constant return only (`return self.value` … `end`).
        # Pre-fix these skipped by ACCIDENT: the signature's own
        # `function get_value(` was the wrapper gate's "one call"
        # (the self-capture the wrapper path now refuses), so the
        # honest accessor arm takes over the legitimate shape — with
        # the returned NAME gated against the dangerous sets:
        # `return os.execute` hands the sink back as a VALUE, which
        # the wrapper path's escape analysis exists to refuse, and an
        # accessor arm must not bypass it.
        m = re.search(r"return\s+(\w+\.\w+|\d+)\s*(?:end\s*)?$", body)
        if m and not _wrapper_ref_hits_exclusion(
            m.group(1), _WRAPPER_DANGEROUS_CALLEES,
            _WRAPPER_DANGEROUS_TAILS, None,
        ):
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
    _callers: list[dict[str, Any]] | None,
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
    _callers: list[dict[str, Any]] | None,
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
    _callers: list[dict[str, Any]] | None,
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
    _callers: list[dict[str, Any]] | None,
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
    _callers: list[dict[str, Any]] | None,
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
    _callers: list[dict[str, Any]] | None,
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
        ) or (re.search(
            r'\b(?:exec|execSync|spawn|spawnSync|execFile)\s*\(',
            stripped,
        ) and re.search(r'child_process|require.*child', source)):
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
    _callers: list[dict[str, Any]] | None,
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
