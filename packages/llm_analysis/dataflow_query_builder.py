"""Mechanical CodeQL query construction for IRIS dataflow validation.

Three tiers, ordered by reliability:

  Tier 1 — `build_prebuilt_query`: for known (language, CWE) pairs,
    wraps a CodeQL pre-built Flow module (e.g. CommandInjectionFlow).
    The LLM is not involved in QL generation; the wrapper imports the
    professionally-written, pack-maintained config and reports paths.
    Handles 70-80% of real Semgrep findings (CWE-78 / 79 / 89 / 22 etc.).

  Tier 2 — `build_template_query`: for unknown CWEs, assembles a full
    query from a per-language template with placeholders. The LLM fills
    only the `isSource` and `isSink` predicate bodies — small surface,
    much smaller compile-error risk than full-query generation.

  Tier 3 (in dataflow_validation.py): compile-error retry feeding the
    error back to the LLM. Last resort when Tier 2's template fill-in
    still doesn't compile (e.g. wrong AST node names).

The mechanical layers (1+2) reduce the LLM's QL surface from "write a
complete CodeQL query, including imports / metadata / module structure
/ PathGraph / select clause / source / sink" down to "write the body of
two predicates" or, when a CWE is known, nothing at all.

Empirical motivation: real-LLM E2E runs showed Gemini-2.5-pro hallucinated
import paths (`semmle.python.security.dataflow.*` no longer exists),
used the legacy `Configuration` class API, and got AST class names wrong
(`IndexExpr` instead of `Subscript`). Constraining the LLM to predicate
bodies — for which CodeQL's standard library exposes high-level helpers
like `RemoteFlowSource` — sidesteps most of these failure modes.
"""

import re
from typing import Dict, Optional, Tuple


# Tier 1 ----------------------------------------------------------------------

# Pre-built Flow modules from CodeQL's standard library packs.
# Each entry maps (language, CWE) → (Customizations.qll path,
# Flow module name). The path is what we `import`, the module name is
# what we use for PathGraph / PathNode.
#
# These cover the most common CWEs flagged by Semgrep. Adding entries is
# a one-line change — just confirm the pack actually ships the module
# (look under `~/.codeql/packages/codeql/<lang>-all/*/semmle/<lang>/security/dataflow/`).
_PREBUILT_FLOWS: Dict[Tuple[str, str], Tuple[str, str]] = {
    # ---- Python (verified against installed codeql/python-all pack) ----
    ("python", "CWE-78"):  ("semmle.python.security.dataflow.CommandInjectionQuery",       "CommandInjectionFlow"),
    ("python", "CWE-77"):  ("semmle.python.security.dataflow.UnsafeShellCommandConstructionQuery", "UnsafeShellCommandConstructionFlow"),
    ("python", "CWE-89"):  ("semmle.python.security.dataflow.SqlInjectionQuery",           "SqlInjectionFlow"),
    ("python", "CWE-90"):  ("semmle.python.security.dataflow.LdapInjectionQuery",          "LdapInjectionFlow"),
    ("python", "CWE-94"):  ("semmle.python.security.dataflow.CodeInjectionQuery",          "CodeInjectionFlow"),
    ("python", "CWE-22"):  ("semmle.python.security.dataflow.PathInjectionQuery",          "PathInjectionFlow"),
    ("python", "CWE-79"):  ("semmle.python.security.dataflow.ReflectedXssQuery",           "ReflectedXssFlow"),
    ("python", "CWE-93"):  ("semmle.python.security.dataflow.HttpHeaderInjectionQuery",    "HttpHeaderInjectionFlow"),
    ("python", "CWE-117"): ("semmle.python.security.dataflow.LogInjectionQuery",           "LogInjectionFlow"),
    ("python", "CWE-209"): ("semmle.python.security.dataflow.StackTraceExposureQuery",     "StackTraceExposureFlow"),
    ("python", "CWE-312"): ("semmle.python.security.dataflow.CleartextLoggingQuery",       "CleartextLoggingFlow"),
    ("python", "CWE-313"): ("semmle.python.security.dataflow.CleartextStorageQuery",       "CleartextStorageFlow"),
    ("python", "CWE-327"): ("semmle.python.security.dataflow.WeakSensitiveDataHashingQuery", "WeakSensitiveDataHashingFlow"),
    ("python", "CWE-501"): ("semmle.python.security.dataflow.UrlRedirectQuery",            "UrlRedirectFlow"),
    ("python", "CWE-502"): ("semmle.python.security.dataflow.UnsafeDeserializationQuery",  "UnsafeDeserializationFlow"),
    ("python", "CWE-601"): ("semmle.python.security.dataflow.UrlRedirectQuery",            "UrlRedirectFlow"),
    ("python", "CWE-611"): ("semmle.python.security.dataflow.XxeQuery",                    "XxeFlow"),
    ("python", "CWE-643"): ("semmle.python.security.dataflow.XpathInjectionQuery",         "XpathInjectionFlow"),
    ("python", "CWE-776"): ("semmle.python.security.dataflow.XmlBombQuery",                "XmlBombFlow"),
    ("python", "CWE-918"): ("semmle.python.security.dataflow.ServerSideRequestForgeryQuery", "ServerSideRequestForgeryFlow"),
    ("python", "CWE-943"): ("semmle.python.security.dataflow.NoSqlInjectionQuery",         "NoSqlInjectionFlow"),
    ("python", "CWE-1004"): ("semmle.python.security.dataflow.CookieInjectionQuery",       "CookieInjectionFlow"),
    ("python", "CWE-1333"): ("semmle.python.security.dataflow.PolynomialReDoSQuery",       "PolynomialReDoSFlow"),
    ("python", "CWE-1336"): ("semmle.python.security.dataflow.TemplateInjectionQuery",     "TemplateInjectionFlow"),

    # ---- Java ----
    ("java", "CWE-78"):  ("semmle.code.java.security.CommandLineQuery",     "RemoteUserInputToArgumentToExecFlow"),
    ("java", "CWE-89"):  ("semmle.code.java.security.SqlInjectionQuery",    "QueryInjectionFlow"),
    ("java", "CWE-22"):  ("semmle.code.java.security.PathCreation",         "TaintedPathFlow"),
    ("java", "CWE-79"):  ("semmle.code.java.security.XSS",                  "XssFlow"),
    ("java", "CWE-502"): ("semmle.code.java.security.UnsafeDeserializationQuery", "UnsafeDeserializationFlow"),

    # ---- C / C++ ----
    ("cpp", "CWE-78"):  ("semmle.code.cpp.security.CommandExecution",   "CommandExecutionFlow"),
    ("cpp", "CWE-22"):  ("semmle.code.cpp.security.TaintedPath",        "TaintedPathFlow"),
    ("cpp", "CWE-120"): ("semmle.code.cpp.security.BufferAccess",       "BufferAccessFlow"),

    # ---- JavaScript / TypeScript ----
    ("javascript", "CWE-79"):  ("semmle.javascript.security.dataflow.DomBasedXssQuery",     "DomBasedXss"),
    ("javascript", "CWE-78"):  ("semmle.javascript.security.dataflow.CommandInjectionQuery", "CommandInjection"),
    ("javascript", "CWE-89"):  ("semmle.javascript.security.dataflow.SqlInjectionQuery",     "SqlInjection"),
    ("javascript", "CWE-22"):  ("semmle.javascript.security.dataflow.TaintedPathQuery",      "TaintedPath"),

    # ---- Go ----
    ("go", "CWE-78"):  ("semmle.go.security.CommandInjectionQuery",   "CommandInjection"),
    ("go", "CWE-89"):  ("semmle.go.security.SqlInjectionQuery",       "SqlInjection"),
}


def lookup_prebuilt_flow(language: str, cwe: str) -> Optional[Tuple[str, str]]:
    """Return (import_path, flow_module_name) for known (language, CWE) pairs.

    Both args are normalised to lowercase / uppercase respectively. Returns
    None when the combination has no prebuilt mapping — caller falls back
    to Tier 2 (template) or Tier 3 (LLM-generated free-form).
    """
    if not language or not cwe:
        return None
    key = (language.lower().strip(), cwe.upper().strip())
    return _PREBUILT_FLOWS.get(key)


def build_prebuilt_query(
    *,
    language: str,
    flow_import: str,
    flow_module: str,
    query_id: str = "raptor/iris-validation",
) -> str:
    """Assemble a tiny wrapper query that uses a prebuilt Flow module.

    The wrapper is purely mechanical — no LLM-generated content. All
    the dataflow logic (sources, sinks, sanitizers, taint propagation
    rules) lives inside the imported Flow module. We just import it
    and ask for path results.

    Returns the .ql text. Caller writes to a file inside a qlpack and
    runs `codeql database analyze`.
    """
    lang_import = _LANGUAGE_HEADER.get(language.lower())
    if lang_import is None:
        raise ValueError(f"unsupported language for prebuilt query: {language}")

    # Path-problem queries require @severity. Use 'error' since we're
    # validating an existing finding's reachability — match found ⇒
    # finding stands.
    return f"""\
/**
 * @name IRIS validation: {query_id}
 * @kind path-problem
 * @id {query_id}
 * @problem.severity error
 */
{lang_import}
import {flow_import}
import {flow_module}::PathGraph

from {flow_module}::PathNode source, {flow_module}::PathNode sink
where {flow_module}::flowPath(source, sink)
select sink.getNode(), source, sink, "IRIS-validated dataflow path"
"""


# Tier 2 ----------------------------------------------------------------------

# Per-language taint-tracking templates. The LLM fills in two strings:
# `source_predicate_body` and `sink_predicate_body`. Everything else
# (imports, module structure, PathGraph wiring, select clause) is
# mechanical.
#
# These match the modern ConfigSig + TaintTracking::Global<> API found
# in current python-all / java-all / cpp-all / javascript-all packs.
_TAINT_TEMPLATES: Dict[str, str] = {
    "python": """\
/**
 * @name IRIS validation: {query_id}
 * @kind path-problem
 * @id {query_id}
 * @problem.severity error
 */
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources

module IrisConfig implements DataFlow::ConfigSig {{
  predicate isSource(DataFlow::Node n) {{
    {source_predicate_body}
  }}
  predicate isSink(DataFlow::Node n) {{
    {sink_predicate_body}
  }}
}}

module IrisFlow = TaintTracking::Global<IrisConfig>;
import IrisFlow::PathGraph

from IrisFlow::PathNode source, IrisFlow::PathNode sink
where IrisFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "IRIS dataflow path"
""",
    "java": """\
/**
 * @name IRIS validation: {query_id}
 * @kind path-problem
 * @id {query_id}
 * @problem.severity error
 */
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources

module IrisConfig implements DataFlow::ConfigSig {{
  predicate isSource(DataFlow::Node n) {{
    {source_predicate_body}
  }}
  predicate isSink(DataFlow::Node n) {{
    {sink_predicate_body}
  }}
}}

module IrisFlow = TaintTracking::Global<IrisConfig>;
import IrisFlow::PathGraph

from IrisFlow::PathNode source, IrisFlow::PathNode sink
where IrisFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "IRIS dataflow path"
""",
    "cpp": """\
/**
 * @name IRIS validation: {query_id}
 * @kind path-problem
 * @id {query_id}
 * @problem.severity error
 */
import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.dataflow.new.TaintTracking
import semmle.code.cpp.security.FlowSources

module IrisConfig implements DataFlow::ConfigSig {{
  predicate isSource(DataFlow::Node n) {{
    {source_predicate_body}
  }}
  predicate isSink(DataFlow::Node n) {{
    {sink_predicate_body}
  }}
}}

module IrisFlow = TaintTracking::Global<IrisConfig>;
import IrisFlow::PathGraph

from IrisFlow::PathNode source, IrisFlow::PathNode sink
where IrisFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "IRIS dataflow path"
""",
    "javascript": """\
/**
 * @name IRIS validation: {query_id}
 * @kind path-problem
 * @id {query_id}
 * @problem.severity error
 */
import javascript
import DataFlow::PathGraph

module IrisConfig implements DataFlow::ConfigSig {{
  predicate isSource(DataFlow::Node n) {{
    {source_predicate_body}
  }}
  predicate isSink(DataFlow::Node n) {{
    {sink_predicate_body}
  }}
}}

module IrisFlow = TaintTracking::Global<IrisConfig>;

from IrisFlow::PathNode source, IrisFlow::PathNode sink
where IrisFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "IRIS dataflow path"
""",
    "go": """\
/**
 * @name IRIS validation: {query_id}
 * @kind path-problem
 * @id {query_id}
 * @problem.severity error
 */
import go
import semmle.go.dataflow.DataFlow
import semmle.go.dataflow.TaintTracking

module IrisConfig implements DataFlow::ConfigSig {{
  predicate isSource(DataFlow::Node n) {{
    {source_predicate_body}
  }}
  predicate isSink(DataFlow::Node n) {{
    {sink_predicate_body}
  }}
}}

module IrisFlow = TaintTracking::Global<IrisConfig>;
import IrisFlow::PathGraph

from IrisFlow::PathNode source, IrisFlow::PathNode sink
where IrisFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "IRIS dataflow path"
""",
}


# Imports for the per-language top-level. Used by both Tier 1 wrapper and
# anywhere we need just the `import <lang>` line.
_LANGUAGE_HEADER: Dict[str, str] = {
    "python":     "import python",
    "java":       "import java",
    "cpp":        "import cpp",
    "javascript": "import javascript",
    "go":         "import go",
}


def supported_languages_for_template() -> set:
    """Languages with a Tier 2 template available."""
    return set(_TAINT_TEMPLATES.keys())


def build_template_query(
    *,
    language: str,
    source_predicate_body: str,
    sink_predicate_body: str,
    query_id: str = "raptor/iris-validation",
) -> Optional[str]:
    """Assemble a Tier 2 query from the template + LLM-supplied predicates.

    Args:
        language: Normalised language tag ("python", "java", etc.).
        source_predicate_body: QL fragment forming the body of
            `predicate isSource(DataFlow::Node n) { ... }`. Trailing
            semicolons / surrounding braces are NOT included.
        sink_predicate_body: same shape, for `isSink`.
        query_id: Stable identifier embedded in the query metadata.

    Returns:
        Full .ql text, or None when the language has no template.
    """
    template = _TAINT_TEMPLATES.get(language.lower())
    if template is None:
        return None
    if not source_predicate_body or not source_predicate_body.strip():
        return None
    if not sink_predicate_body or not sink_predicate_body.strip():
        return None

    return template.format(
        source_predicate_body=source_predicate_body.strip(),
        sink_predicate_body=sink_predicate_body.strip(),
        query_id=query_id,
    )


# Tier 1+2 schema for LLM ----------------------------------------------------


# Schema for the structured response when we ask the LLM for predicates only.
# Used by the dataflow_validation runner when Tier 1 doesn't apply and we
# fall through to Tier 2.
TEMPLATE_PREDICATE_SCHEMA = {
    "source_predicate_body": (
        "string — body of the isSource(DataFlow::Node n) predicate. "
        "Just the body content (without surrounding braces or the "
        "predicate signature). Example: "
        "'n instanceof RemoteFlowSource' for a remote source."
    ),
    "sink_predicate_body": (
        "string — body of the isSink(DataFlow::Node n) predicate. "
        "Same shape: just the body. Example: "
        "'exists(Call c | c.getFunc().(...) ... and n.asExpr() = c.getArg(0))'."
    ),
    "expected_evidence": (
        "string — what kind of match would confirm the hypothesis."
    ),
    "reasoning": (
        "string — why these predicates test the dataflow_summary's claim."
    ),
}


# CWE inference --------------------------------------------------------------

# Maps regex patterns over Semgrep rule IDs / rule_ids to CWE numbers.
# Used when the finding's `cwe_id` field is empty — many Semgrep rules
# don't tag CWE explicitly but their rule names are descriptive. Without
# inference we lose the CWE → prebuilt query mapping for these findings.
#
# Order matters: more specific patterns first. The first match wins.
_RULE_ID_TO_CWE: list = [
    # Command injection — variants seen in real rule sets:
    # "command-injection", "os-command-injection", "command_injection",
    # "subprocess-shell-true", "shell-true", "subprocess.shell",
    # "command-shell" (raptor's variant), "exec-shell", etc.
    (re.compile(
        r"command[-_]?injection"
        r"|os[-_]?command"
        r"|subprocess[-_.].*shell"
        r"|shell[-_]?true"
        r"|command[-_]shell"
        r"|exec[-_]?shell",
        re.IGNORECASE,
    ), "CWE-78"),
    # SQL injection
    (re.compile(r"sql[-_]?injection|sqli\b", re.IGNORECASE), "CWE-89"),
    # NoSQL injection
    (re.compile(r"nosql[-_]?injection|mongo[-_].*injection", re.IGNORECASE), "CWE-943"),
    # Path traversal
    (re.compile(r"path[-_]?traversal|tainted[-_]?path|directory[-_]?traversal",
                re.IGNORECASE), "CWE-22"),
    # XSS — DOM-based and reflected both map to CWE-79
    (re.compile(r"\bxss\b|cross[-_]?site[-_]?scripting", re.IGNORECASE), "CWE-79"),
    # Code injection / eval
    (re.compile(r"code[-_]?injection|\beval\b.*injection", re.IGNORECASE), "CWE-94"),
    # XXE / XML external entity
    (re.compile(r"\bxxe\b|xml[-_]?external[-_]?entit", re.IGNORECASE), "CWE-611"),
    # SSRF
    (re.compile(r"\bssrf\b|server[-_]?side[-_]?request[-_]?forger",
                re.IGNORECASE), "CWE-918"),
    # LDAP injection
    (re.compile(r"ldap[-_]?injection", re.IGNORECASE), "CWE-90"),
    # XPath injection
    (re.compile(r"xpath[-_]?injection", re.IGNORECASE), "CWE-643"),
    # Open redirect
    (re.compile(r"open[-_]?redirect|url[-_]?redirect", re.IGNORECASE), "CWE-601"),
    # Template injection / SSTI
    (re.compile(r"template[-_]?injection|\bssti\b", re.IGNORECASE), "CWE-1336"),
    # Deserialization
    (re.compile(r"deserialization|insecure[-_]?deserial|unsafe[-_]?deserial",
                re.IGNORECASE), "CWE-502"),
    # Log injection
    (re.compile(r"log[-_]?injection|log[-_]?forging", re.IGNORECASE), "CWE-117"),
    # Hardcoded credentials
    (re.compile(r"hardcoded[-_]?(?:credential|secret|password|key|token)",
                re.IGNORECASE), "CWE-798"),
    # Weak crypto / hash
    (re.compile(r"weak[-_]?(?:hash|crypto|cipher|digest)|broken[-_]?(?:hash|crypto)",
                re.IGNORECASE), "CWE-327"),
    # ReDoS
    (re.compile(r"\bredos\b|catastrophic[-_]?backtrack|polynomial[-_]?redos",
                re.IGNORECASE), "CWE-1333"),
    # Cleartext logging
    (re.compile(r"cleartext[-_]?(?:log|stor)|sensitive[-_]?in[-_]?log",
                re.IGNORECASE), "CWE-312"),
    # Stack trace exposure
    (re.compile(r"stack[-_]?trace|exception[-_]?message[-_]?disclos",
                re.IGNORECASE), "CWE-209"),
]


def infer_cwe_from_rule_id(rule_id: str) -> Optional[str]:
    """Infer a CWE tag from a Semgrep rule_id when the finding lacks one.

    Many Semgrep rules don't set the `cwe_id` field explicitly but have
    descriptive rule names like "raptor.injection.command-shell" or
    "python.lang.security.deserialization.pickle". Inferring from the
    rule_id lets Tier 1's CWE → Flow map kick in for findings that
    would otherwise fall through to Tier 2.

    Returns the first matching CWE-NNN string, or None when no pattern
    matches. Patterns are ordered from most specific to most general
    so e.g. "subprocess-shell-true" hits the command-injection pattern
    rather than a hypothetical generic "subprocess" one.
    """
    if not rule_id:
        return None
    for pattern, cwe in _RULE_ID_TO_CWE:
        if pattern.search(rule_id):
            return cwe
    return None


__all__ = [
    "lookup_prebuilt_flow",
    "build_prebuilt_query",
    "build_template_query",
    "supported_languages_for_template",
    "TEMPLATE_PREDICATE_SCHEMA",
    "infer_cwe_from_rule_id",
]
