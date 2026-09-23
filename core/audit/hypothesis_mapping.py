"""Map hypotheses to mechanical tool actions.

Given a natural-language hypothesis string from the LLM's review,
select the appropriate Semgrep rule, SMT solver verb, or Coccinelle
consistency-check.  Pure functions — no orchestrator state.
"""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path

# P10 web families — unsafe-shape patterns shared across their keyword
# aliases. Each family has a guarded fixture under
# engine/negative_controls/ that the pattern must NOT match (safe
# usage: json/yaml.safe_load, fixed-URL fetches, defusedxml / NONET
# parsing, allowlist-derived redirect targets). A pattern that matched
# its fixture would be a presence detector and the sweep caps it at
# inconclusive.
_DESERIALIZATION_PATTERN = (
    "pickle\\.loads?\\s*\\(|yaml\\.load\\s*\\(|unserialize\\s*\\(|"
    "Marshal\\.load|ObjectInputStream|marshal\\.loads?\\s*\\("
)
_SSRF_PATTERN = (
    # request call whose URL argument is an f-string, a concatenation,
    # or a request-derived attribute — a bare identifier (allowlist
    # lookup result) does not match.
    # \x27 is the apostrophe: the rendered rule embeds this pattern in
    # a single-quoted YAML scalar, so a literal quote char would
    # truncate the rule text.
    "urlopen\\s*\\(\\s*(?:f[\\x27\"]|[^),]*\\+)|"
    "requests\\.\\w+\\s*\\(\\s*(?:f[\\x27\"]|[^),]*\\+)|"
    "(?:urlopen|requests\\.\\w+)\\s*\\(\\s*(?:request|req)\\.|"
    "curl_easy_setopt\\s*\\([^;]*CURLOPT_URL[^;]*(?:\\+|argv|buf|input)|"
    "curl_exec.*\\$_(?:GET|POST|REQUEST)"
)
_XXE_PATTERN = (
    "resolve_entities\\s*=\\s*True|load_dtd\\s*=\\s*True|"
    "etree\\.parse\\s*\\(|minidom\\.parse|"
    "simplexml_load_string|libxml_disable_entity_loader\\s*\\(\\s*false|"
    "XML_PARSE_NOENT|xmlSubstituteEntitiesDefault\\s*\\(\\s*1"
)
_OPEN_REDIRECT_PATTERN = (
    "redirect\\s*\\(\\s*(?:request\\.|req\\.|params|"
    "\\$_(?:GET|POST|REQUEST)|url|target|next|dest)|"
    "sendRedirect\\s*\\(\\s*request|"
    "header\\s*\\(\\s*[\\x27\"]Location:?[\\x27\"]?\\s*\\."
)
# Terminal escape injection (CWE-150): printf-family emitting a %s
# whose corresponding argument is a bare variable/member (no wrapping
# call) straight to stdout/stderr. Presence-style: the canonical safe
# idiom (strnvis into a buffer, then print the buffer) is textually
# identical at the print site, so the guarded fixture matches and the
# sweep caps this rule at inconclusive — confirmation-grade evidence
# for the family comes from the joern taint leg (cwe_dispatch
# CWE-150 sinks). The \b anchors keep fmprintf/snprintf (filtered /
# non-terminal) from matching.
_ESCAPE_INJECTION_PATTERN = (
    "\\bprintf\\s*\\(\\s*\"[^\"]*%s[^\"]*\"\\s*,\\s*"
    "[\\w.>\\[\\]-]+\\s*[,)]|"
    "\\bv?fprintf\\s*\\(\\s*std(?:out|err)\\s*,\\s*\"[^\"]*%s[^\"]*\""
    "\\s*,\\s*[\\w.>\\[\\]-]+\\s*[,)]"
)

_HYPOTHESIS_SEMGREP_PATTERNS: dict[str, str] = {
    "buffer overflow": "strcpy|sprintf|gets\\s*\\(|strcat",
    "sql injection": "SELECT.*%|INSERT.*%|UPDATE.*%|DELETE.*%",
    "command injection": "system\\s*\\(|popen\\s*\\(|exec[lv]p?e?\\s*\\(",
    "path traversal": "os\\.path\\.join|open\\s*\\(",
    "format string": "%s.*printf|printf\\s*\\(\\s*[a-zA-Z_]",
    "use after free": "free\\s*\\(",
    "double free": "free\\s*\\(",
    "xss": "(snprintf|sprintf)\\s*\\([^)]*\"%s|write\\s*\\(.*\\+|response\\.write|res\\.send",
    "reflected": "(snprintf|sprintf)\\s*\\([^)]*\"%s|write\\s*\\(.*\\+|response\\.write|res\\.send",
    "cross-site": "(snprintf|sprintf)\\s*\\([^)]*\"%s|write\\s*\\(.*\\+|response\\.write|res\\.send",
    "deserialization": _DESERIALIZATION_PATTERN,
    "deserialisation": _DESERIALIZATION_PATTERN,
    "unpickle": _DESERIALIZATION_PATTERN,
    "ssrf": _SSRF_PATTERN,
    "server-side request": _SSRF_PATTERN,
    "xxe": _XXE_PATTERN,
    "xml external entit": _XXE_PATTERN,
    "open redirect": _OPEN_REDIRECT_PATTERN,
    "unvalidated redirect": _OPEN_REDIRECT_PATTERN,
    "terminal escape": _ESCAPE_INJECTION_PATTERN,
    "escape sequence": _ESCAPE_INJECTION_PATTERN,
    "escape-sequence": _ESCAPE_INJECTION_PATTERN,
}


# Target extension → semgrep language key for the dynamic
# per-hypothesis rules. Every pattern in
# ``_HYPOTHESIS_SEMGREP_PATTERNS`` is a ``pattern-regex``, so the
# language key's only job is FILE SELECTION — a wrong key means the
# rule never even scans its own target file. Pre-fix everything
# unmapped defaulted to ``c``: for PHP/Ruby/C#/Kotlin/Swift/Lua/Scala
# targets the per-hypothesis rule could never match, silently
# disabling /audit's only dynamic verification channel there.
# Unknown extensions fall back to ``generic`` (regex over any file)
# rather than a language guess.
_SEMGREP_LANG_BY_EXT: dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rs": "rust",
    ".php": "php",
    # .phtml is in semgrep's own target selection for language:php —
    # without this row the CWE-dispatch semgrep leg dropped on
    # templating trees. The other legacy suffixes (.php5/.php4/.php3)
    # are deliberately ABSENT: semgrep skips them for php-language
    # rules (paths.scanned stays empty), so mapping them here would
    # (a) regress the dynamic per-hypothesis rules, whose generic key
    # DOES scan those files today, and (b) record a semgrep dispatch
    # for a scan that examined nothing — which the pre-existing
    # CWE-88/327 coverage rows would convert to clean-when-silent.
    # A live test pins semgrep's actual selection; re-add a suffix
    # only when that pin shows the engine scanning it.
    ".phtml": "php",
    ".rb": "ruby",
    ".cs": "csharp",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".swift": "swift",
    ".scala": "scala",
    ".lua": "lua",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".hxx": "cpp",
}


def semgrep_language_for(file_path: str) -> str:
    """Semgrep language key for a dynamic pattern-regex rule targeting
    ``file_path``. ``generic`` for unmapped extensions."""
    ext = Path(file_path).suffix.lower()
    return _SEMGREP_LANG_BY_EXT.get(ext, "generic")


# Every semgrep language key the extension table can emit — the
# universe a content-probed language hint may resolve into.
_SEMGREP_PROBEABLE_LANGS = frozenset(_SEMGREP_LANG_BY_EXT.values())


def semgrep_probed_language(
    file_path: str, language: str | None,
) -> str | None:
    """Semgrep language key licensed by an inventory content probe for
    a file whose extension the table cannot map, or None.

    ``language`` is the inventory's recorded language for the file —
    content-probed when the extension says nothing (PHP plugin
    "module" files lead with their open tag, extensionless scripts
    carry a shebang). The probe only speaks for files the extension
    table does NOT map: for mapped extensions the table stays
    authoritative, so behaviour on ordinary targets cannot change.
    Languages outside the table's value set (perl, shell, asm, ...)
    yield None — there is no semgrep language key to scan them as.

    Consumers pair a non-None answer with semgrep's
    ``--scan-unknown-extensions`` flag: without it the engine's own
    extension-based target selection silently SKIPS such a file
    (``paths.scanned`` stays empty), so a language-keyed rule could
    never produce a scanned-target witness there in either direction.
    """
    if not language:
        return None
    if Path(file_path).suffix.lower() in _SEMGREP_LANG_BY_EXT:
        return None
    lang = language.lower()
    return lang if lang in _SEMGREP_PROBEABLE_LANGS else None


def hypothesis_to_semgrep_rule(hypothesis: str, file_path: str) -> str | None:
    """Generate a Semgrep YAML rule from a hypothesis string.

    Returns a path to a temp YAML file, or None if no rule can be derived.
    """
    keyed = hypothesis_to_semgrep_rule_keyed(hypothesis, file_path)
    return keyed[0] if keyed else None


def hypothesis_to_semgrep_rule_keyed(
    hypothesis: str, file_path: str,
) -> tuple[str, str] | None:
    """Like hypothesis_to_semgrep_rule, but also returns the keyword.

    Returns ``(rule_yaml_path, keyword)`` where *keyword* is the
    ``_HYPOTHESIS_SEMGREP_PATTERNS`` key that selected the pattern.
    The keyword lets the sweep engine look up the matching negative
    control fixture (engine/negative_controls/) so a presence-detector
    rule cannot return "confirmed".
    """
    hyp_lower = hypothesis.lower()

    pattern = None
    matched_keyword = ""
    rule_id = "hypothesis-check"
    for keyword, regex in _HYPOTHESIS_SEMGREP_PATTERNS.items():
        if keyword in hyp_lower:
            if keyword == "format string" and file_path.endswith(".go"):
                continue
            if regex is _ESCAPE_INJECTION_PATTERN and (
                semgrep_language_for(file_path) not in ("c", "cpp")
            ):
                # C-idiom pattern (printf-family %s): on other
                # languages a zero-match would be a false refutation
                # of e.g. SQL/regex escape-sequence hypotheses (the
                # format-string/.go precedent).
                continue
            pattern = regex
            matched_keyword = keyword
            rule_id = keyword.replace(" ", "-")
            break

    if not pattern:
        return None

    lang = semgrep_language_for(file_path)

    rule_yaml = (
        f"rules:\n"
        f"  - id: audit-sweep-{rule_id}\n"
        f"    pattern-regex: '{pattern}'\n"
        f"    message: 'Hypothesis validation: {rule_id}'\n"
        f"    languages: [{lang}]\n"
        f"    severity: WARNING\n"
    )

    try:
        fd, tmp_name = tempfile.mkstemp(
            prefix="audit_sweep_", suffix=".yaml", text=True,
        )
        with os.fdopen(fd, "w") as fh:
            fh.write(rule_yaml)
        return tmp_name, matched_keyword
    except OSError:
        return None


_SMT_HYPOTHESIS_VERBS = [
    ("integer overflow leading to", "check-overflow-to-oob"),
    ("overflow to oob", "check-overflow-to-oob"),
    ("negative value", "check-negative-bypass"),
    ("bypass the size check", "check-negative-bypass"),
    ("bypass the resource limit", "check-negative-bypass"),
    ("out of bounds", "check-oob"),
    ("out-of-bounds", "check-oob"),
    ("buffer overflow", "check-oob"),
    ("integer underflow", "check-overflow"),
    ("integer overflow", "check-overflow"),
    ("arithmetic overflow", "check-overflow"),
    ("multiplication overflow", "check-overflow"),
    ("addition overflow", "check-overflow"),
    ("truncation overflow", "check-overflow"),
    ("arithmetic underflow", "check-overflow"),
    ("permission bypass", "check-auth-bypass"),
    ("capability bypass", "check-auth-bypass"),
    ("auth bypass", "check-auth-bypass"),
    ("access control bypass", "check-auth-bypass"),
    ("privilege escalation", "check-auth-bypass"),
    ("early return bypass", "check-auth-bypass"),
    ("capability check", "check-auth-bypass"),
    ("permission check bypass", "check-auth-bypass"),
    ("lock imbalance", "check-lock-discipline"),
    ("missing unlock", "check-lock-discipline"),
    ("lock not released", "check-lock-discipline"),
    ("lock held on return", "check-lock-discipline"),
    ("lock held on error", "check-lock-discipline"),
    ("spinlock held", "check-lock-discipline"),
    ("mutex held", "check-lock-discipline"),
    ("deadlock", "check-lock-discipline"),
    ("lock discipline", "check-lock-discipline"),
    ("without unlocking", "check-lock-discipline"),
    ("resource leak", "check-resource-leak"),
    ("memory leak", "check-resource-leak"),
    ("leak on error", "check-resource-leak"),
    ("not freed", "check-resource-leak"),
    ("missing free", "check-resource-leak"),
    ("missing kfree", "check-resource-leak"),
    ("leaked on error path", "check-resource-leak"),
    ("allocated but not freed", "check-resource-leak"),
    ("leak in error handling", "check-resource-leak"),
    ("null pointer dereference", "check-null-propagation"),
    ("null dereference", "check-null-propagation"),
    ("null propagation", "check-null-propagation"),
    ("unchecked null", "check-null-propagation"),
    ("missing null check", "check-null-propagation"),
    ("null pointer", "check-null-propagation"),
    ("dereference without check", "check-null-propagation"),
    ("use without null check", "check-null-propagation"),
    ("integer narrowing", "check-integer-narrowing"),
    ("integer widening", "check-integer-narrowing"),
    ("truncation", "check-integer-narrowing"),
    ("narrowing conversion", "check-integer-narrowing"),
    ("implicit cast", "check-integer-narrowing"),
    ("type truncation", "check-integer-narrowing"),
    ("loss of data", "check-integer-narrowing"),
    ("size_t to int", "check-integer-narrowing"),
]


def hypothesis_to_smt_verb(hypothesis: str) -> str | None:
    """Map a hypothesis to an SMT solver verb."""
    hyp_lower = hypothesis.lower()
    for keyword, verb in _SMT_HYPOTHESIS_VERBS:
        if keyword in hyp_lower:
            return verb
    # Keyword-pair gaps here (and in the cocci mapping below) are
    # bounded ({0,200}): an unbounded `.*` gap makes every occurrence
    # of the first keyword re-scan the rest of the hypothesis text
    # for the second — quadratic on hostile-shaped text. Real
    # hypothesis prose keeps the pair within a phrase; beyond the
    # bound the mapping simply does not attach.
    if re.search(
        r"negative.{0,200}bypass|bypass.{0,200}negative|"
        r"signed.{0,200}unsigned",
        hyp_lower,
    ):
        return "check-negative-bypass"
    return None


_COCCI_RULES_DIR = Path(__file__).resolve().parents[2] / "engine" / "coccinelle" / "rules"


def hypothesis_to_cocci_check(hypothesis: str) -> str | None:
    """Map a hypothesis to a Coccinelle consistency-check rule.

    Returns the path to a .cocci rule file, or None.
    """
    if not _COCCI_RULES_DIR.is_dir():
        return None

    hyp_lower = hypothesis.lower()

    if "unchecked return" in hyp_lower or "return value" in hyp_lower:
        rule = _COCCI_RULES_DIR / "unchecked_return.cocci"
        if rule.exists():
            return str(rule)

    if "missing null check" in hyp_lower or "null check" in hyp_lower:
        rule = _COCCI_RULES_DIR / "missing_null_check.cocci"
        if rule.exists():
            return str(rule)

    if any(kw in hyp_lower for kw in (
        "rcu_dereference", "rcu_read_lock", "rcu lock",
        "rcu grace period", "rcu protection",
    )):
        rule = _COCCI_RULES_DIR / "rcu_dereference_outside_rcu.cocci"
        if rule.exists():
            return str(rule)
        rule = _COCCI_RULES_DIR / "rcu_no_lock.cocci"
        if rule.exists():
            return str(rule)

    if any(kw in hyp_lower for kw in (
        "lock scope", "lock gap", "accessed after unlock",
        "outside lock", "unprotected access",
    )):
        rule = _COCCI_RULES_DIR / "lock_scope_gap.cocci"
        if rule.exists():
            return str(rule)

    if any(kw in hyp_lower for kw in (
        "lock ordering", "deadlock", "abba",
        "lock order", "lock inversion",
    )):
        rule = _COCCI_RULES_DIR / "lock_order_violation.cocci"
        if rule.exists():
            return str(rule)

    if any(kw in hyp_lower for kw in (
        "lock held", "lock imbalance", "without unlock",
        "missing lock", "lock not released",
    )):
        rule = _COCCI_RULES_DIR / "lock_imbalance.cocci"
        if rule.exists():
            return str(rule)

    if any(kw in hyp_lower for kw in (
        "copy_to_user", "info leak", "kernel memory to userspace",
        "not fully initialized", "leak uninitialized kernel memory",
        "padding", "copied to userspace",
    )):
        rule = _COCCI_RULES_DIR / "copy_to_user_uninit.cocci"
        if rule.exists():
            return str(rule)

    if any(kw in hyp_lower for kw in (
        "uninitialized", "not initialized", "uninitialised",
        "indeterminate value",
    )):
        rule = _COCCI_RULES_DIR / "uninitialized_return.cocci"
        if rule.exists():
            return str(rule)

    if any(kw in hyp_lower for kw in (
        "bounds check", "out of bounds", "out-of-bounds",
        "array index", "without validation",
    )):
        rule = _COCCI_RULES_DIR / "missing_bounds_check.cocci"
        if rule.exists():
            return str(rule)

    if any(kw in hyp_lower for kw in (
        "double fetch", "read from user", "copy_from_user",
    )):
        rule = _COCCI_RULES_DIR / "double_fetch.cocci"
        if rule.exists():
            return str(rule)

    if any(kw in hyp_lower for kw in (
        "toctou", "time-of-check", "time of check",
        "check-then-use", "check-use",
    )) or re.search(r"check.{0,200}then.{0,200}use", hyp_lower):
        rule = _COCCI_RULES_DIR / "toctou_check_use.cocci"
        if rule.exists():
            return str(rule)

    if any(kw in hyp_lower for kw in (
        "list_del", "list corruption", "list_for_each",
        "unsafe list", "linked list",
    )):
        rule = _COCCI_RULES_DIR / "unsafe_list_del.cocci"
        if rule.exists():
            return str(rule)

    if any(kw in hyp_lower for kw in (
        "uid truncat", "gid truncat", "truncating conversion",
        "narrowing", "__old_uid", "__old_gid",
    )):
        rule = _COCCI_RULES_DIR / "uid_truncation.cocci"
        if rule.exists():
            return str(rule)

    if any(kw in hyp_lower for kw in (
        "resource leak", "memory leak", "not freed",
        "missing free", "leak on error",
    )):
        rule = _COCCI_RULES_DIR / "resource_leak_err.cocci"
        if rule.exists():
            return str(rule)

    if any(kw in hyp_lower for kw in (
        "memory barrier", "smp_wmb",
        "smp_rmb", "smp_mb", "write ordering",
        "missing barrier", "reorder",
    )) or re.search(r"store.{0,200}load", hyp_lower):
        rule = _COCCI_RULES_DIR / "missing_memory_barrier.cocci"
        if rule.exists():
            return str(rule)

    if re.search(r"atomic.{0,200}race|check.{0,200}then.{0,200}act|atomic_read", hyp_lower):
        rule = _COCCI_RULES_DIR / "atomic_check_then_act.cocci"
        if rule.exists():
            return str(rule)

    if any(kw in hyp_lower for kw in (
        "race condition", "use-after-free", "use after free",
        "after unlock", "freed while",
        "concurrent", "non-atomic",
    )) or re.search(r"after.{0,200}lock.{0,200}released", hyp_lower):
        rule = _COCCI_RULES_DIR / "use_after_unlock.cocci"
        if rule.exists():
            return str(rule)

    return None
