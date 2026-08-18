"""LLM prompt templates and response parsers for dark verification.

Prompt templates are keyed by language. Response parsers use a
config table to avoid per-language if-chains.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from ._types import DarkWitnessSpec, language_for_file

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Prompt templates — one per language (C/C++ share one)
# ---------------------------------------------------------------------------

# The finding's file / function arrive as untrusted slots and the
# hypothesis / detail as untrusted envelope blocks in the user
# message; the template text below stays interpolation-free and
# forms the system prompt.
_FINDING_HEADER = """\
## Finding

The finding's file and function are given in the `file` and
`function` slots.  Its hypothesis and detail arrive as untrusted
blocks (kinds `finding-hypothesis` and `finding-detail`).

## Task
"""

_PROMPT_FOOTER = """
Return ONLY the JSON object. No markdown fencing, no explanation outside the JSON.
"""

_TEMPLATES: dict[str, str] = {
    "python": """\
You are verifying a suspected vulnerability in a Python codebase.

""" + _FINDING_HEADER + """
Provide a concrete witness: specific arguments to call the function named in the `function` slot with
that would demonstrate the bug. You must provide STRUCTURED DATA, not code.

## Output format

Return a JSON object with these fields:
- "module_path": the Python import path (e.g. "core.audit.gate")
- "function": the function name to call
- "args": list of positional arguments (JSON-serialisable)
- "kwargs": dict of keyword arguments (JSON-serialisable)
- "expected_return": the expected return value if the bug is real (null if expecting an exception)
- "expected_exception": the exception class name if the bug should raise (empty string if expecting a return)
- "rationale": one sentence explaining why these inputs trigger the bug
""" + _PROMPT_FOOTER,

    "c": """\
You are verifying a suspected vulnerability in a C/C++ codebase.

""" + _FINDING_HEADER + """
Provide structured data for a witness: the arguments to call the function named in the `function` slot
with that would trigger the bug. The harness compiles with
-fsanitize=address,undefined — an ASan/UBSan report is a confirmed bug.

## Output format

Return a JSON object with these fields:
- "function": the function name
- "arg_expressions": list of C literal expressions for each argument (strings, e.g. ["NULL", "buf", "256"])
- "param_types": list of C parameter type declarations (e.g. ["char *", "char *", "int"])
- "return_type": the C return type (e.g. "int", "void", "char *")
- "includes": list of system headers needed (e.g. ["string.h"])
- "setup_lines": list of variable declaration lines (e.g. ["char buf[10] = \\"AAAA\\";"]). NO function calls, NO control flow.
- "expected_crash": true if you expect ASan/crash, false for return-value check
- "expected_sanitizer": ASan error type if known (e.g. "heap-buffer-overflow"), empty string otherwise
- "expected_return": expected return value as a string (null if expecting a crash)
- "rationale": one sentence explaining why these inputs trigger the bug
""" + _PROMPT_FOOTER,

    "go": """\
You are verifying a suspected vulnerability in a Go codebase.

""" + _FINDING_HEADER + """
Provide structured data for a witness: the arguments to call the function named in the `function` slot
with that would trigger the bug. A panic is a confirmed bug.

## Output format

Return a JSON object with these fields:
- "function": the function name
- "package": the Go package name (e.g. "main", "auth")
- "import_path": the full import path if not main (e.g. "github.com/example/auth")
- "arg_expressions": list of Go literal expressions for each argument (e.g. ["nil", "\\"test\\"", "0"])
- "return_type": the Go return type (empty string for void/no return)
- "expected_return": expected return value as a string (null if expecting a panic)
- "expected_exception": "panic" if you expect a panic, empty string otherwise
- "rationale": one sentence explaining why these inputs trigger the bug
""" + _PROMPT_FOOTER,

    "javascript": """\
You are verifying a suspected vulnerability in a JavaScript codebase.

""" + _FINDING_HEADER + """
Provide structured data for a witness: the arguments to call the function named in the `function` slot
with that would trigger the bug.

## Output format

Return a JSON object with these fields:
- "function": the function name
- "require_path": the require() path relative to the project root (e.g. "./src/auth")
- "args": list of argument values (JSON-serialisable)
- "expected_return": expected return value (null if expecting an error)
- "expected_exception": the Error class name if you expect a throw (e.g. "TypeError"), empty string otherwise
- "rationale": one sentence explaining why these inputs trigger the bug
""" + _PROMPT_FOOTER,

    "typescript": """\
You are verifying a suspected vulnerability in a TypeScript codebase.

""" + _FINDING_HEADER + """
Provide structured data for a witness: the arguments to call the function named in the `function` slot
with that would trigger the bug.

## Output format

Return a JSON object with these fields:
- "function": the function name
- "require_path": the require() path relative to the project root (e.g. "./src/auth")
- "args": list of argument values (JSON-serialisable)
- "expected_return": expected return value (null if expecting an error)
- "expected_exception": the Error class name if you expect a throw (e.g. "TypeError"), empty string otherwise
- "rationale": one sentence explaining why these inputs trigger the bug
""" + _PROMPT_FOOTER,

    "ruby": """\
You are verifying a suspected vulnerability in a Ruby codebase.

""" + _FINDING_HEADER + """
Provide structured data for a witness: the arguments to call the function named in the `function` slot
with that would trigger the bug.

## Output format

Return a JSON object with these fields:
- "function": the function name (top-level method or Class.method)
- "require_path": the require path relative to the project root (e.g. "lib/auth")
- "args": list of argument values (JSON-serialisable)
- "expected_return": expected return value (null if expecting an exception)
- "expected_exception": the exception class name if you expect a raise (e.g. "ArgumentError"), empty string otherwise
- "rationale": one sentence explaining why these inputs trigger the bug
""" + _PROMPT_FOOTER,

    "php": """\
You are verifying a suspected vulnerability in a PHP codebase.

""" + _FINDING_HEADER + """
Provide structured data for a witness: the arguments to call the function named in the `function` slot
with that would trigger the bug.

## Output format

Return a JSON object with these fields:
- "function": the function name
- "require_path": the require_once path relative to the project root (e.g. "src/auth.php")
- "args": list of argument values (JSON-serialisable)
- "expected_return": expected return value (null if expecting an exception)
- "expected_exception": the exception class name if you expect a throw (e.g. "InvalidArgumentException"), empty string otherwise
- "rationale": one sentence explaining why these inputs trigger the bug
""" + _PROMPT_FOOTER,

    "rust": """\
You are verifying a suspected vulnerability in a Rust codebase.

""" + _FINDING_HEADER + """
Provide structured data for a witness: the arguments to call the function named in the `function` slot
with that would trigger the bug. The harness compiles with ASan when
available — a sanitizer report or panic is a confirmed bug.

## Output format

Return a JSON object with these fields:
- "function": the function name
- "use_path": the `use` path if needed (e.g. "target::auth::check"), empty string for items in scope
- "arg_expressions": list of Rust literal expressions for each argument (e.g. ["\\"test\\".to_string()", "None", "0usize"])
- "return_type": the Rust return type (empty string for unit type)
- "setup_lines": list of variable declaration lines (e.g. ["let mut buf = vec![0u8; 10];"]). NO unsafe blocks, NO std::process.
- "expected_crash": true if you expect a panic/abort, false for return-value check
- "expected_sanitizer": sanitizer error type if known, empty string otherwise
- "expected_return": expected return value as a string (null if expecting a crash)
- "rationale": one sentence explaining why these inputs trigger the bug
""" + _PROMPT_FOOTER,

    "java": """\
You are verifying a suspected vulnerability in a Java codebase.

""" + _FINDING_HEADER + """
Provide structured data for a witness: the arguments to call the function named in the `function` slot
with that would trigger the bug.

## Output format

Return a JSON object with these fields:
- "function": the method name
- "class_name": the class containing the method (e.g. "AuthUtils")
- "imports": list of import statements needed (e.g. ["java.util.HashMap"])
- "arg_expressions": list of Java literal expressions for each argument (e.g. ["null", "\\"admin\\"", "0"])
- "return_type": the Java return type (e.g. "String", "void", "int")
- "is_static": true if the method is static, false if it needs an instance
- "expected_return": expected return value as a string (null if expecting an exception)
- "expected_exception": the exception class name if you expect a throw (e.g. "NullPointerException"), empty string otherwise
- "rationale": one sentence explaining why these inputs trigger the bug
""" + _PROMPT_FOOTER,

    "lua": """\
You are verifying a suspected vulnerability in a Lua codebase.

""" + _FINDING_HEADER + """
Provide structured data for a witness: the arguments to call the function named in the `function` slot
with that would trigger the bug.

## Output format

Return a JSON object with these fields:
- "function": the function name
- "require_path": the Lua require path (dot-separated, e.g. "lib.auth")
- "args": list of argument values (JSON-serialisable; use null for nil)
- "expected_return": expected return value (null if expecting an error)
- "expected_exception": error message substring if you expect an error, empty string otherwise
- "rationale": one sentence explaining why these inputs trigger the bug
""" + _PROMPT_FOOTER,

    "perl": """\
You are verifying a suspected vulnerability in a Perl codebase.

""" + _FINDING_HEADER + """
Provide structured data for a witness: the arguments to call the function named in the `function` slot
with that would trigger the bug.

## Output format

Return a JSON object with these fields:
- "function": the function name (e.g. "MyModule::check" or just "check")
- "use_module": the Perl module name (e.g. "MyModule" or "Lib::Auth")
- "args": list of argument values (JSON-serialisable; use null for undef)
- "expected_return": expected return value (null if expecting a die)
- "expected_exception": error message substring if you expect die/croak, empty string otherwise
- "rationale": one sentence explaining why these inputs trigger the bug
""" + _PROMPT_FOOTER,
}

_TEMPLATES["cpp"] = _TEMPLATES["c"]


def build_witness_prompt(
    file: str,
    function: str,
    hypothesis: str,
    body: str,
    *,
    language: str = "",
    model_id: str = "",
) -> tuple[str, str]:
    """Build the enveloped LLM prompt for witness generation.

    The language template (task + output format, interpolation-free)
    becomes the system prompt; the finding's hypothesis / detail go
    into untrusted blocks and its file / function into slots.
    Returns ``(user, system)``.
    """
    from core.security.prompt_envelope import TaintedString, UntrustedBlock
    from core.security.prompt_framing import with_audit_framing

    from .._util import envelope_prompt

    lang = language or language_for_file(file) or "python"
    # Audit-purpose framing: witness generation is the most
    # exploit-shaped auxiliary ask — carry the same defensive-audit
    # context the review class carries (see core.security.
    # prompt_framing; the witness is executed in the run's sandbox to
    # confirm or refute the finding, never against a live system).
    template = with_audit_framing(_TEMPLATES.get(lang, _TEMPLATES["python"]))
    key = f"{file}:{function}"
    blocks = (
        UntrustedBlock(
            content=hypothesis or "(no hypothesis)",
            kind="finding-hypothesis",
            origin=key,
        ),
        UntrustedBlock(
            content=body[:2000],
            kind="finding-detail",
            origin=key,
        ),
    )
    slots = {
        "file": TaintedString(value=file, trust="untrusted"),
        "function": TaintedString(value=function, trust="untrusted"),
    }
    return envelope_prompt(template, blocks, slots, model_id=model_id)


# ---------------------------------------------------------------------------
# Response parsing — config-driven to avoid per-language if-chains
# ---------------------------------------------------------------------------

# Each parser config defines how to extract lang_config from the LLM's JSON.
# "shape" determines the extraction strategy:
#   "python"     — needs module_path (required), args, kwargs
#   "native"     — C/C++/Rust: arg_expressions, param_types, expected_crash
#   "go"         — package, import_path, arg_expressions
#   "require"    — JS/TS/Ruby/PHP/Lua: args + require_path
#   "perl"       — args + use_module
#   "java"       — class_name, imports, arg_expressions, is_static


def _extract_json(text: str) -> dict[str, Any] | None:
    """Extract a JSON object from potentially messy LLM output."""
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        start = 1
        end = len(lines)
        for i in range(1, len(lines)):
            if lines[i].strip() == "```":
                end = i
                break
        text = "\n".join(lines[start:end]).strip()

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        brace = text.find("{")
        if brace >= 0:
            depth = 0
            end = -1
            in_string = False
            escape = False
            for i in range(brace, len(text)):
                ch = text[i]
                if escape:
                    escape = False
                    continue
                if ch == "\\":
                    escape = True
                    continue
                if ch == '"':
                    in_string = not in_string
                    continue
                if in_string:
                    continue
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        end = i + 1
                        break
            if end < 0:
                logger.debug("failed to parse witness response: %s", text[:200])
                return None
            try:
                data = json.loads(text[brace:end])
            except json.JSONDecodeError:
                logger.debug("failed to parse witness response: %s", text[:200])
                return None
        else:
            return None

    if not isinstance(data, dict):
        return None
    return data


def parse_witness_response(
    response: str,
    finding_key: str,
    file: str,
    function: str,
    *,
    language: str = "",
) -> DarkWitnessSpec | None:
    """Parse the LLM's witness response into a DarkWitnessSpec."""
    lang = language or language_for_file(file) or "python"

    data = _extract_json(response)
    if data is None:
        return None

    func_name = data.get("function", function)

    if lang == "python":
        module_path = data.get("module_path", "")
        if not module_path:
            return None
        return DarkWitnessSpec(
            finding_key=finding_key, file=file, function=func_name,
            language=lang, module_path=module_path,
            args=data.get("args", []),
            kwargs=data.get("kwargs", {}),
            expected_return=data.get("expected_return"),
            expected_exception=data.get("expected_exception", ""),
            rationale=data.get("rationale", ""),
        )

    if lang in ("c", "cpp"):
        return DarkWitnessSpec(
            finding_key=finding_key, file=file, function=func_name,
            language=lang,
            expected_crash=bool(data.get("expected_crash", False)),
            expected_sanitizer=data.get("expected_sanitizer", ""),
            expected_return=data.get("expected_return"),
            rationale=data.get("rationale", ""),
            lang_config={
                "arg_expressions": data.get("arg_expressions", []),
                "param_types": data.get("param_types", []),
                "return_type": data.get("return_type", "int"),
                "includes": data.get("includes", []),
                "setup_lines": data.get("setup_lines", []),
            },
        )

    if lang == "go":
        return DarkWitnessSpec(
            finding_key=finding_key, file=file, function=func_name,
            language=lang,
            expected_return=data.get("expected_return"),
            expected_exception=data.get("expected_exception", ""),
            rationale=data.get("rationale", ""),
            lang_config={
                "package": data.get("package", "main"),
                "import_path": data.get("import_path", ""),
                "import_alias": "target",
                "arg_expressions": data.get("arg_expressions", []),
                "return_type": data.get("return_type", ""),
            },
        )

    if lang in ("javascript", "typescript", "ruby", "php", "lua"):
        return DarkWitnessSpec(
            finding_key=finding_key, file=file, function=func_name,
            language=lang,
            args=data.get("args", []),
            expected_return=data.get("expected_return"),
            expected_exception=data.get("expected_exception", ""),
            rationale=data.get("rationale", ""),
            lang_config={
                "require_path": data.get("require_path", ""),
            },
        )

    if lang == "perl":
        return DarkWitnessSpec(
            finding_key=finding_key, file=file, function=func_name,
            language=lang,
            args=data.get("args", []),
            expected_return=data.get("expected_return"),
            expected_exception=data.get("expected_exception", ""),
            rationale=data.get("rationale", ""),
            lang_config={
                "use_module": data.get("use_module", ""),
            },
        )

    if lang == "rust":
        return DarkWitnessSpec(
            finding_key=finding_key, file=file, function=func_name,
            language=lang,
            expected_crash=bool(data.get("expected_crash", False)),
            expected_sanitizer=data.get("expected_sanitizer", ""),
            expected_return=data.get("expected_return"),
            rationale=data.get("rationale", ""),
            lang_config={
                "arg_expressions": data.get("arg_expressions", []),
                "return_type": data.get("return_type", ""),
                "use_path": data.get("use_path", ""),
                "setup_lines": data.get("setup_lines", []),
            },
        )

    if lang == "java":
        return DarkWitnessSpec(
            finding_key=finding_key, file=file, function=func_name,
            language=lang,
            expected_return=data.get("expected_return"),
            expected_exception=data.get("expected_exception", ""),
            rationale=data.get("rationale", ""),
            lang_config={
                "class_name": data.get("class_name", ""),
                "imports": data.get("imports", []),
                "arg_expressions": data.get("arg_expressions", []),
                "return_type": data.get("return_type", "Object"),
                "is_static": data.get("is_static", True),
            },
        )

    return None
