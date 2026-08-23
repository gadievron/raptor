"""Executor dispatch and per-language execution logic.

Uses a dispatch table instead of if-chains. Each language registers
an executor function; execute_witness() looks it up and calls it.
"""

from __future__ import annotations

import ast
import contextlib
import contextvars
import json
import logging
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath

from core.paths import confine
from core.run.scratch import scratch_dir
from core.run.workdir import exec_workdir

from ._harness import (
    _CALL_MARKER_PREFIX,
    generate_c_harness,
    generate_go_harness,
    generate_java_harness,
    generate_js_harness,
    generate_lua_harness,
    generate_perl_harness,
    generate_php_harness,
    generate_ruby_harness,
    generate_rust_harness,
    generate_ts_harness,
    generate_witness_script,
    validate_import_path,
)
from ._types import (
    _SUPPORTED_LANGS,
    DarkVerifyResult,
    DarkWitnessSpec,
    language_for_file,
)
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)

_WITNESS_TIMEOUT_S = 10
_COMPILE_TIMEOUT_S = 30
_MAX_OUTPUT_BYTES = 8192

# Persistent destination for sandbox --audit evidence, set by
# execute_witness() around executor dispatch. Every witness step
# (compile AND run) routes stdout/stderr capture through a throwaway
# scratch dir passed as the sandbox's ``output=`` — under the CLI
# ``--audit`` flag that scratch dir satisfies the audit-target
# requirement, so the tracer writes its evidence into
# ``<scratch>/.audit/`` and the sweep destroys it with the scratch.
# Threading the run's persistent output dir as ``audit_run_dir=``
# (audit-signal routing only, no Landlock impact) keeps the operator's
# audit trail. A contextvar rather than a parameter on every executor:
# the executor dispatch table has a fixed uniform signature, and the
# value is pure ambient plumbing the executors never read.
_AUDIT_RUN_DIR: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "dark_verify_audit_run_dir", default=None,
)


_IDENTIFIER_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")
_QUALIFIED_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_.:/]*$")

_DANGEROUS_INTERP_FUNCS = frozenset({
    "system", "exec", "eval", "open", "spawn",
    "popen", "fork", "kill", "unlink", "remove", "rmdir",
    "rename", "chmod", "chown", "chdir",
    "require", "load", "import",
    "__import__", "compile", "globals", "locals",
    "getattr", "setattr", "delattr",
    "passthru", "shell_exec", "proc_open", "pcntl_exec",
    "backtick", "send", "__send__",
})

_TYPE_RE = re.compile(
    r"^[a-zA-Z_][a-zA-Z0-9_*&\[\]<>, .:]*$"
)

# require_path is pasted into JS/TS require(), Ruby require, PHP
# require_once and Lua require — a load path rooted at the target tree.
# Keep it to plain path characters: anything outside this set (quotes,
# backslashes, $, #, backticks, whitespace) has no business in a module
# path and only shows up in injection attempts.
_REQUIRE_PATH_RE = re.compile(r"^[a-zA-Z0-9_@./-]+$")


def _module_ref_error(
    field: str,
    value: str,
    target_root: Path | None,
) -> str | None:
    """Traversal/containment check for spec fields that become load paths.

    require_path (JS/TS/Ruby/PHP/Lua), use_path (Rust), use_module
    (Perl) and import_path (Go) all feed module resolution rooted at
    the target tree; an absolute value or a ``..`` walks the load
    outside it. The fields are separator-joined names, so a plain
    ``..`` substring test covers every separator convention (``/``,
    ``.``, ``::``) at once — legitimate module references never contain
    consecutive dots. With a *target_root* the joined path must also
    resolve inside the root (:func:`core.paths.confine`), which catches
    a repo-planted symlink pointing out of the tree.
    """
    if value.startswith(("/", "\\")):
        return f"{field} must be relative: {value!r}"
    if ".." in value:
        return f"{field} must not contain '..': {value!r}"
    if target_root is not None and confine(target_root, value) is None:
        return f"{field} escapes target root: {value!r}"
    return None

# arg_expressions are target-language literal expressions that the harness
# generators paste verbatim into compiled/interpreted source (C: "NULL",
# "buf", "256"; Go: "nil"; Rust: "0usize", '"x".to_string()'; Java: "null",
# '"admin"').  A substring blocklist over them is trivially bypassed by
# string concatenation ('__import__("o"+"s")'), so validation is an
# ALLOWLIST: each expression must parse (as Python, mode="eval") into the
# small literal grammar in _ALLOWED_EXPR_NODES — constants, bare
# identifiers, dotted names, literal containers, +/-/* arithmetic over
# those, and the one call shape the LLM corpus actually produces
# (zero-argument method on a string/bytes literal, Rust's
# '"x".to_string()').  Typed numeric literals Python cannot parse
# ("0usize", "100L", "1.5f") are matched by _SUFFIXED_NUMBER_RE instead.
# Everything else — general calls, subscripts, lambdas, f-strings,
# statement separators (fail the parse), comments, newlines — is a
# validation error.
_SUFFIXED_NUMBER_RE = re.compile(r"^-?\d+(?:\.\d+)?[a-zA-Z_][a-zA-Z0-9_]*$")

# Return-value comparison is exact EXCEPT for cross-language boolean/nil
# spellings (Python "True" vs Go/Ruby "true", "None" vs "nil"/"null"),
# where only the casing differs by language convention. A blanket
# case-insensitive compare would flip refuted to confirmed for any
# case-differing string pair ("admin" vs "ADMIN").
_BOOLEAN_SPELLINGS = frozenset({"true", "false", "nil", "none", "null"})

_ALLOWED_EXPR_NODES = (
    ast.Expression, ast.Constant,
    ast.Tuple, ast.List, ast.Dict, ast.Set,
    ast.Name, ast.Load,
    ast.UnaryOp, ast.USub, ast.UAdd,
    ast.BinOp, ast.Add, ast.Sub, ast.Mult,
    ast.Attribute, ast.Call,
)


def _arg_expression_error(expr_s: str) -> str | None:
    """Allowlist check for a single arg_expression.

    Returns a short reason string when the expression falls outside the
    literal grammar, None when it is acceptable.
    """
    if "\n" in expr_s or "\r" in expr_s:
        return "newline"
    if "#" in expr_s:
        # A trailing Python comment would let arbitrary text past the
        # parser while still being pasted verbatim into the harness.
        return "comment character"
    # Rust borrows: a leading `&` / `&mut` is an inert prefix token (no
    # call or statement-separator power) over an otherwise-allowed
    # literal — strip it so witness args like `&[1, 2]` validate.
    if expr_s.startswith("&"):
        expr_s = expr_s[1:].lstrip()
        if expr_s.startswith("mut "):
            expr_s = expr_s[4:].lstrip()
    if _SUFFIXED_NUMBER_RE.match(expr_s):
        return None  # target-language typed numeric literal (0usize, 100L)
    try:
        tree = ast.parse(expr_s, mode="eval")
    except (SyntaxError, ValueError):
        return "not a parseable literal expression"
    for node in ast.walk(tree):
        if not isinstance(node, _ALLOWED_EXPR_NODES):
            return f"disallowed construct: {type(node).__name__}"
        if isinstance(node, ast.Attribute) and node.attr.startswith("__"):
            return "dunder attribute access"
        if isinstance(node, ast.Call):
            # Only call shape allowed: zero-argument method on a
            # string/bytes literal ('"x".to_string()').  General calls
            # stay rejected — Runtime.getRuntime().exec(...), getattr,
            # __import__ over concatenated strings, etc.
            func = node.func
            if (
                not isinstance(func, ast.Attribute)
                or not isinstance(func.value, ast.Constant)
                or node.args or node.keywords
            ):
                return "function call not allowed"
    return None


# ---------------------------------------------------------------------------
# setup_lines: declaration-only grammar (C/C++/Rust)
# ---------------------------------------------------------------------------
#
# setup_lines are pasted verbatim into the compiled harness main().
# The prompt contract says "variable declaration lines ... NO function
# calls, NO control flow" — but validation used to be a substring
# blocklist, which this file's own arg_expressions doctrine (above)
# concedes is trivially bypassed. The LLM controls both the prediction
# (expected_crash / expected_sanitizer / expected_return) and, through
# free-form setup code, the observation: `raise(SIGSEGV)`, a null
# write, a forged ASan stderr line, or a printf of the harness's JSON
# shape each minted verdict="confirmed" against provably benign
# targets. So setup_lines get the same ALLOWLIST treatment as
# arg_expressions: each line must parse as a single variable
# declaration with a literal initializer. Everything else — calls,
# casts, derefs, control flow, preprocessor, multiple statements — is
# a validation error (fail closed: the witness is dropped, never run).

_C_STRING_LIT_RE = re.compile(r'"(?:\\.|[^"\\])*"')
_C_CHAR_LIT_RE = re.compile(r"'(?:\\.|[^'\\])'")

# declarator: one-or-more type words, optional pointer stars, the
# variable name, optional array dims. No parens (kills function
# declarators, casts and __attribute__), no commas (one variable per
# line keeps the grammar honest). The dims group spells "optional
# digits" as `(?:[0-9]+\s*)?` rather than `[0-9]*` so the two
# whitespace runs around the digits can never both claim the same
# spaces — with `[0-9]*` allowed to match empty, `\s*[0-9]*\s*` has
# quadratically many partitions of one whitespace run and an
# unclosed `[` made the validator a backtracking sink on
# LLM-authored input.
_C_DECL_LHS_RE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*"            # first type word
    r"(?:\s+[A-Za-z_][A-Za-z0-9_]*)*"     # further type words / name
    r"(?:\s*\*+\s*[A-Za-z_][A-Za-z0-9_]*)?"  # pointer declarator + name
    r"(?:\s*\[\s*(?:[0-9]+\s*)?\])*"      # array dims
    r"\s*$"
)

# initializer after string/char literals were replaced by the inert
# token `_S_`: numbers (incl. hex/suffixed), identifiers (NULL, other
# setup vars), brace init-lists, commas, unary +/-, address-of.
_C_INIT_RHS_RE = re.compile(r"^[A-Za-z0-9_+\-&,.{}\s]*$")


def _c_setup_line_error(line: str) -> str | None:
    """Declaration-only allowlist for one C/C++ setup line."""
    stripped = line.strip()
    if not stripped:
        return None
    # Neutralise string/char literal CONTENT first so data bytes can't
    # trip (or dodge) the structural checks below.
    neutral = _C_STRING_LIT_RE.sub("_S_", stripped)
    neutral = _C_CHAR_LIT_RE.sub("_S_", neutral)
    if '"' in neutral or "'" in neutral:
        return "unbalanced string/char literal"
    if not neutral.endswith(";") or neutral.count(";") != 1:
        return "must be a single declaration ending in ';'"
    body = neutral[:-1].strip()
    for ch, what in (("(", "function call / cast"), (")", "function call / cast"),
                     ("#", "preprocessor"), ("/", "comment or division"),
                     ("\\", "line continuation"), ("?", "conditional"),
                     ("%", "operator"), ("!", "operator"), ("^", "operator"),
                     ("|", "operator"), ("~", "operator"), ("<", "operator"),
                     (">", "operator")):
        if ch in body:
            return f"disallowed construct ({what}): {ch!r}"
    lhs, eq, rhs = body.partition("=")
    if eq and ("=" in rhs):
        return "multiple assignment"
    if not _C_DECL_LHS_RE.match(lhs.strip()):
        return "not a variable declaration"
    if eq and not _C_INIT_RHS_RE.match(rhs.strip()):
        return "initializer outside the literal grammar"
    if "*" in rhs:
        return "initializer outside the literal grammar"
    return None


# The type annotation is spelled as non-space chunks separated by
# `\s+` instead of one class with `\s` inside: a class that can eat
# whitespace next to the `\s*=` that follows gives the engine
# quadratically many ways to split the run before `=`, and an
# annotation with no `=` after it made the validator a backtracking
# sink on LLM-authored input. Chunking keeps the accepted language
# identical (any interleaving of type chars and whitespace) while
# every space belongs to exactly one quantifier.
_RUST_LET_RE = re.compile(
    r"^let\s+(?:mut\s+)?[A-Za-z_][A-Za-z0-9_]*"
    r"(?:\s*:\s*[A-Za-z_][A-Za-z0-9_:<>\[\]&',]*"
    r"(?:\s+[A-Za-z0-9_:<>\[\]&',]+)*)?"
    r"\s*=\s*(?P<rhs>.+)$"
)

# Rust initializer character set (after string/char literals are
# masked): identifier paths (`::`, `.`), calls, refs, containers,
# numeric literals. Notably ABSENT: `{`/`}` (blocks, closures with
# captures, struct-init escape), `|` (closures), `=` `<` `>` (no
# turbofish, no comparisons), `*` `/` `%` (no arithmetic-deref
# smuggling), `#` (attributes), `?` (early return), `\\`.
_RUST_EXPR_CHARSET_RE = re.compile(r"^[A-Za-z0-9_:.,&!;()\[\]\s+-]*$")

_RUST_MACRO_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*!")

# Prompt contract for Rust setup_lines: "NO unsafe blocks, NO
# std::process". `unsafe` has no legitimate spelling in a literal /
# constructor initializer; `process` covers std::process spellings.
_RUST_FORBIDDEN_TOKENS = ("unsafe", "process")


def _rust_expr_error(expr: str) -> str | None:
    """Allowlist for one Rust initializer EXPRESSION.

    Wider than the shared arg_expression grammar: plain function /
    constructor / method calls over identifier paths and literals are
    allowed (`bytes::Bytes::from_static(&[0x40u8])` is the bread and
    butter of real Rust witnesses). This stays sound because setup
    lines execute BEFORE the harness's pre-call sentinel: a setup
    expression that crashes does so pre-sentinel (classified as a
    setup-phase failure, never a confirmation), and the verdict
    channel itself is authenticated (JSON token + post-sentinel
    sanitizer ordering). Statements, blocks, closures, non-vec!
    macros, comparisons and arithmetic-deref shapes stay rejected —
    the field remains a single expression, not code.

    NOTE the asymmetry with arg_expressions: call arguments evaluate
    AFTER the sentinel (a panicking argument would read as the target
    crashing), so args keep the strict literal grammar.
    """
    masked = _C_STRING_LIT_RE.sub("_S_", expr.strip())
    masked = _C_CHAR_LIT_RE.sub("_S_", masked)
    if not masked:
        return "empty initializer"
    if '"' in masked:
        return "unbalanced string literal"
    # Residual single quotes (unbalanced char literal, lifetimes) are
    # caught by the charset check below — `'` is not in the set.
    for tok in _RUST_FORBIDDEN_TOKENS:
        if tok in masked:
            return f"disallowed construct: {tok}"
    if not _RUST_EXPR_CHARSET_RE.match(masked):
        return "disallowed character"
    for m in _RUST_MACRO_RE.finditer(masked):
        if m.group(1) != "vec":
            return f"macro not allowed: {m.group(1)}!"
    # Bracket balance + `;` and `,` only inside brackets (array
    # `[elem; count]`, argument lists). A top-level `;` is a second
    # statement.
    depth = 0
    for ch in masked:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
            if depth < 0:
                return "unbalanced brackets"
        elif ch == ";" and depth == 0:
            return "multiple statements"
    if depth != 0:
        return "unbalanced brackets"
    return None


def _rust_setup_line_error(line: str) -> str | None:
    """let-binding-only allowlist for one Rust setup line."""
    stripped = line.strip()
    if not stripped:
        return None
    if not stripped.endswith(";"):
        return "must be a single let-binding ending in ';'"
    body = stripped[:-1].strip()
    m = _RUST_LET_RE.match(body)
    if not m:
        return "not a let-binding declaration"
    return _rust_expr_error(m.group("rhs"))


_SETUP_VALIDATORS = {
    "c": _c_setup_line_error,
    "cpp": _c_setup_line_error,
    "rust": _rust_setup_line_error,
}


# Java imports are pasted (semicolon-stripped) into `import <x>;` at
# the top of the harness — an embedded newline used to survive the
# strip and open a top-level injection point. Allowlist: a dotted
# identifier path with an optional `static` prefix and `.*` suffix.
_JAVA_IMPORT_RE = re.compile(
    r"^(?:static\s+)?[A-Za-z_$][A-Za-z0-9_$]*"
    r"(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*(?:\.\*)?$"
)


def validate_spec(
    spec: DarkWitnessSpec,
    target_root: Path | None = None,
) -> str | None:
    """Pre-execution validation of LLM-generated spec fields.

    Returns an error string if the spec contains dangerous patterns,
    None if it passes validation. Defense-in-depth layer — the sandbox
    is the primary defense, this catches obvious injection attempts
    before code generation. When *target_root* is given, the load-path
    fields must also resolve inside it.
    """
    if not _IDENTIFIER_RE.match(spec.function):
        return f"invalid function name: {spec.function!r}"
    # Derive the language the same way execute_witness dispatches — a
    # spec with language unset must not skip the interpreter check.
    lang = spec.language or language_for_file(spec.file) or ""
    if lang in ("python", "ruby", "php", "perl", "javascript", "typescript",
                "lua") and spec.function.lower() in _DANGEROUS_INTERP_FUNCS:
        return f"dangerous builtin as function name: {spec.function!r}"

    lc = spec.lang_config
    for expr in lc.get("arg_expressions", []):
        expr_s = str(expr)
        reason = _arg_expression_error(expr_s)
        if reason:
            return (
                f"code injection risk in arg_expression "
                f"({reason}): {expr_s[:60]!r}"
            )

    # Compiled-language harness generators fall back to raw spec.args
    # when arg_expressions is absent — those values are then pasted as
    # target-language EXPRESSIONS, so they get the same allowlist at
    # the use-site (interpreted languages render args as quoted DATA
    # and are exempt).
    if lang in ("c", "cpp", "rust", "go", "java") and (
            "arg_expressions" not in lc):
        for arg in spec.args:
            arg_s = str(arg)
            reason = _arg_expression_error(arg_s)
            if reason:
                return (
                    f"code injection risk in args used as expression "
                    f"({reason}): {arg_s[:60]!r}"
                )

    rt = lc.get("return_type", "")
    if rt and not _TYPE_RE.match(rt):
        return f"invalid return_type: {rt!r}"

    # param_types are pasted verbatim into the C extern declaration —
    # unvalidated, `int); __attribute__((constructor)) ...` compiled
    # and crashed before main. Each element must be a plain type
    # spelling (same grammar as return_type).
    for pt in lc.get("param_types", []):
        pt_s = str(pt)
        if not _TYPE_RE.match(pt_s):
            return f"invalid param_type: {pt_s[:60]!r}"

    # setup_lines (C/C++/Rust): declaration-only grammar. Checked here
    # (the shared pre-execution chokepoint) as well as in the native
    # executors so no dispatch path can skip it.
    if lang in _SETUP_VALIDATORS:
        setup_err = _validate_setup(lc.get("setup_lines", []), lang)
        if setup_err:
            return setup_err

    cn = lc.get("class_name", "")
    if cn and not _QUALIFIED_RE.match(cn):
        return f"invalid class_name: {cn!r}"

    if lang == "java":
        # imports are pasted into `import <x>;` lines — allowlist to a
        # dotted identifier path (an embedded newline used to survive
        # the generator's ';' strip and inject top-level Java code).
        for imp in lc.get("imports", []):
            imp_s = str(imp).strip()
            if imp_s and not _JAVA_IMPORT_RE.match(imp_s):
                return f"invalid java import: {imp_s[:60]!r}"
        # Bind the harness to the finding's FILE: the compile classpath
        # spans the whole target tree, so an unbound class_name reaches
        # any class in the repo — a lookalike method on another class
        # would mint a verdict for this finding. Java's public-class
        # rule ties the file stem to the class; nested classes keep the
        # stem as their outer prefix.
        if cn:
            stem = PurePosixPath(spec.file.replace("\\", "/")).stem
            if cn != stem and not cn.startswith(stem + "."):
                return (
                    f"class_name {cn!r} not bound to the finding's file "
                    f"({spec.file!r} implies {stem!r})"
                )

    up = lc.get("use_path", "")
    if up:
        if not _QUALIFIED_RE.match(up):
            return f"invalid use_path: {up!r}"
        err = _module_ref_error("use_path", up, target_root)
        if err:
            return err

    um = lc.get("use_module", "")
    if um:
        if not _QUALIFIED_RE.match(um):
            return f"invalid use_module: {um!r}"
        err = _module_ref_error("use_module", um, target_root)
        if err:
            return err

    ip = lc.get("import_path", "")
    if ip:
        if not re.match(r"^[a-zA-Z0-9_./-]+$", ip):
            return f"invalid import_path: {ip!r}"
        err = _module_ref_error("import_path", ip, target_root)
        if err:
            return err

    rp = lc.get("require_path", "")
    if rp:
        if not _REQUIRE_PATH_RE.match(rp):
            return f"invalid require_path: {rp!r}"
        err = _module_ref_error("require_path", rp, target_root)
        if err:
            return err

    return None


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def execute_witness(
    spec: DarkWitnessSpec,
    target_root: Path,
    *,
    timeout_s: int = _WITNESS_TIMEOUT_S,
    audit_run_dir: str | Path | None = None,
) -> DarkVerifyResult:
    """Execute a witness and compare output to expectations.

    Dispatches to the appropriate language executor based on the spec's
    language field (auto-detected from file extension if not set).

    ``audit_run_dir``: the run's persistent output directory. Under the
    sandbox CLI ``--audit`` flag it becomes the tracer's evidence
    destination for every witness step — without it the evidence lands
    in the step's throwaway scratch dir and is destroyed on sweep.
    Ignored (with a debug note) when the directory does not exist: the
    sandbox raises ValueError for a missing audit_run_dir, and a lost
    audit trail must not cost the witness verdict.
    """
    lang = spec.language or language_for_file(spec.file) or ""
    if lang not in _SUPPORTED_LANGS:
        return DarkVerifyResult(
            finding_key=spec.finding_key,
            verdict="error",
            language=lang,
            match_detail=f"unsupported language: {lang or '(unknown)'}",
        )

    # spec.file is documented as repo-relative; a traversal value
    # ("../../...") would make the host-side source reads below (Go and
    # Rust executors read the file unsandboxed and splice it into the
    # compiled witness) pull in arbitrary operator files.
    source_file = target_root / spec.file
    try:
        contained = source_file.resolve().is_relative_to(
            Path(target_root).resolve())
    except OSError:
        contained = False
    if not contained:
        return DarkVerifyResult(
            finding_key=spec.finding_key,
            verdict="error",
            language=lang,
            match_detail=f"source path escapes target root: {spec.file}",
        )
    if not source_file.is_file():
        return DarkVerifyResult(
            finding_key=spec.finding_key,
            verdict="error",
            language=lang,
            match_detail=f"source file not found: {spec.file}",
        )

    spec_err = validate_spec(spec, target_root)
    if spec_err:
        return DarkVerifyResult(
            finding_key=spec.finding_key, verdict="error", language=lang,
            match_detail=f"spec validation failed: {spec_err}",
        )

    executor = _EXECUTORS.get(lang)
    if not executor:
        return DarkVerifyResult(
            finding_key=spec.finding_key, verdict="error", language=lang,
            match_detail=f"no executor for language: {lang}",
        )
    evidence_dir: str | None = None
    if audit_run_dir:
        # Mirror the sandbox's own audit-target validation (exists AND
        # writable) — either failure raises ValueError there, and a
        # lost audit trail must degrade to the scratch-dir behaviour,
        # never cost the verdict.
        if Path(audit_run_dir).is_dir() and os.access(
            audit_run_dir, os.W_OK | os.X_OK,
        ):
            evidence_dir = str(audit_run_dir)
        else:
            logger.debug(
                "audit_run_dir %s missing or not writable — compile/run "
                "audit evidence for this witness stays in the scratch "
                "dir",
                audit_run_dir,
            )
    token = _AUDIT_RUN_DIR.set(evidence_dir)
    try:
        return executor(spec, target_root, timeout_s)
    finally:
        _AUDIT_RUN_DIR.reset(token)


# ---------------------------------------------------------------------------
# Shared JSON output classifier
# ---------------------------------------------------------------------------


def _classify_json_output(
    spec: DarkWitnessSpec,
    stdout: str,
    language: str,
    *,
    expected_token: str = "",
) -> DarkVerifyResult:
    """Classify JSON-formatted output from any language harness.

    When *expected_token* is set, the JSON must echo it back in its
    ``token`` field. The harness template embeds the token (generated
    in-process AFTER the LLM response was parsed — neither the witness
    LLM nor the scanned repo can know it), so a status line printed by
    anything other than the harness's own epilogue — a forged
    ``{"status":"returned",...}`` from pasted code or from the target
    itself — fails authentication and classifies as inconclusive.
    """
    stdout = stdout.strip()
    if not stdout:
        return DarkVerifyResult(
            finding_key=spec.finding_key, verdict="inconclusive",
            language=language,
            match_detail="no output from witness",
        )

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return DarkVerifyResult(
            finding_key=spec.finding_key, verdict="inconclusive",
            language=language,
            match_detail=f"unparseable output: {stdout[:200]}",
        )

    if expected_token and data.get("token") != expected_token:
        return DarkVerifyResult(
            finding_key=spec.finding_key, verdict="inconclusive",
            language=language,
            match_detail=(
                "witness output missing the harness token — not emitted "
                "by the harness epilogue; not accepted"
            ),
        )

    status = data.get("status", "")

    if status == "import_error":
        return DarkVerifyResult(
            finding_key=spec.finding_key, verdict="error", language=language,
            match_detail=f"import failed: {data.get('message', '')}",
        )

    expected_exc = spec.expected_exception

    if status == "exception":
        exc_type = data.get("type", "")
        exc_msg = data.get("message", "")
        if expected_exc:
            if exc_type == expected_exc:
                return DarkVerifyResult(
                    finding_key=spec.finding_key, verdict="confirmed",
                    language=language,
                    actual_exception=f"{exc_type}: {exc_msg}",
                    match_detail="exception type matches prediction",
                )
            return DarkVerifyResult(
                finding_key=spec.finding_key, verdict="refuted",
                language=language,
                actual_exception=f"{exc_type}: {exc_msg}",
                match_detail=f"expected {expected_exc}, got {exc_type}",
            )
        # No exception was predicted: an unexpected exception proves
        # the witness (arguments, import path, harness) is wrong about
        # the mechanism, not that the hypothesis is right — a TypeError
        # from a mis-guessed signature must never read as a bug.
        return DarkVerifyResult(
            finding_key=spec.finding_key, verdict="error",
            language=language,
            actual_exception=f"{exc_type}: {exc_msg}",
            match_detail=(
                "unexpected exception — witness stated no exception "
                "expectation; not accepted as confirmation"
            ),
        )

    if status == "returned":
        actual_repr = data.get("value", "")
        if expected_exc:
            return DarkVerifyResult(
                finding_key=spec.finding_key, verdict="refuted",
                language=language, actual_return=actual_repr,
                match_detail=(
                    f"expected {expected_exc} exception, "
                    f"but function returned normally"
                ),
            )
        # A return-value match may only confirm when the witness's
        # stated expectation IS a return-value check. A spec that
        # predicted a crash/sanitizer signal and returned normally is
        # refuted regardless of what the value happens to be.
        if spec.expected_crash or spec.expected_sanitizer:
            return DarkVerifyResult(
                finding_key=spec.finding_key, verdict="refuted",
                language=language, actual_return=actual_repr,
                match_detail=(
                    "expected crash/sanitizer signal, but function "
                    "returned normally"
                ),
            )
        if spec.expected_return is not None:
            if language == "python":
                # Python harness uses repr(), which includes quotes for strings
                expected_repr = repr(spec.expected_return)
            else:
                expected_repr = str(spec.expected_return)
                # Strip surrounding quotes from actual output for non-Python
                # languages — harnesses may quote the value in JSON
                if (
                    len(actual_repr) >= 2
                    and actual_repr[0] in ('"', "'")
                    and actual_repr[-1] == actual_repr[0]
                ):
                    actual_repr = actual_repr[1:-1]
            folded = actual_repr.lower()
            matches = actual_repr == expected_repr or (
                folded == expected_repr.lower()
                and folded in _BOOLEAN_SPELLINGS
            )
            if matches:
                return DarkVerifyResult(
                    finding_key=spec.finding_key, verdict="confirmed",
                    language=language, actual_return=actual_repr,
                    match_detail="return value matches prediction",
                )
            return DarkVerifyResult(
                finding_key=spec.finding_key, verdict="refuted",
                language=language, actual_return=actual_repr,
                match_detail=f"expected {expected_repr}, got {actual_repr}",
            )
        return DarkVerifyResult(
            finding_key=spec.finding_key, verdict="inconclusive",
            language=language, actual_return=actual_repr,
            match_detail="no expected value to compare against",
        )

    return DarkVerifyResult(
        finding_key=spec.finding_key, verdict="inconclusive",
        language=language,
        match_detail=f"unknown status: {status}",
    )


_classify_output = _classify_json_output


# ---------------------------------------------------------------------------
# Shared: sandbox access — FAIL CLOSED when the sandbox is unavailable
# ---------------------------------------------------------------------------

_SANDBOX_REFUSAL = "sandbox unavailable — refusing to execute target-derived code"


def _import_sandbox_run() -> Callable | None:
    """Import the sandbox entry point, or None when core.sandbox is missing.

    Callers FAIL CLOSED: every witness step executes target-derived code —
    the run steps obviously, but the compile steps too (javac discovers
    annotation processors on the compile classpath; C/Rust compiles honour
    #embed/.incbin/include_str! reads of any operator-readable file and
    embed the bytes into the produced binary).  "No sandbox" therefore
    means "no execution", never a plain subprocess.run fallback.  Mirrors
    _run_autobuild_sandboxed in core/dataflow/cvefix_walk.py.
    """
    try:
        from core.sandbox.context import run as sandbox_run
    except ImportError:
        return None
    return sandbox_run


def _sandbox_refusal_result(
    spec: DarkWitnessSpec, language: str,
) -> DarkVerifyResult:
    """Error verdict for a witness step refused because core.sandbox is absent."""
    return DarkVerifyResult(
        finding_key=spec.finding_key, verdict="error", language=language,
        match_detail=_SANDBOX_REFUSAL,
    )


_SYSTEM_TOOLCHAIN_PREFIXES = ("/usr/", "/lib/", "/lib64/", "/etc/", "/bin/", "/sbin/")


# Parent-side capture bound. The executors used capture_output=True
# and sliced proc.stdout[:_MAX_OUTPUT_BYTES] only AFTER the child
# exited — a hostile witness looping print() for its timeout window
# fed an unbounded pipe accumulation buffer into the auditor process
# (RLIMIT_FSIZE bounds files, not pipes; the child-side memory rlimit
# does not bound the parent's buffer). Streams are redirected to
# tmpfiles and read back capped instead: head-only for stdout
# (matching the existing head-slice truncation semantics), head+tail
# for stderr — PLUS marker-anchored windows (see ``anchors`` below):
# positional head/tail capture alone let attacker-controlled padding
# evict the harness sentinel and the sanitizer report from the window
# classification sees, flipping genuine crashes to inconclusive from
# stderr content alone.
_CAPTURE_CAP_BYTES = 64 * 1024
_TRUNCATION_MARKER = "\n...[output truncated]...\n"

# Marker-anchored retention: the FULL stream is scanned with a
# bounded incremental matcher and a context window around each marker
# hit is retained for classification, in stream order, alongside the
# positional head/tail diagnostics. Bounded memory: the scan carries
# only max(len(marker))-1 bytes between chunks and records at most
# the first/last _ANCHOR_HITS_KEPT hit offsets per marker (a hostile
# stream spamming a marker cannot grow the offset lists — and the
# harness sentinel carries the run's secret token, so it cannot be
# spammed at all).
_ANCHOR_PRE_CONTEXT = 256
_ANCHOR_POST_CONTEXT = 4096
_ANCHOR_HITS_KEPT = 4
_ANCHOR_SCAN_CHUNK = 1 << 20

# Sanitizer-report anchor: every family observe.py classifies spells
# its name "...Sanitizer" (AddressSanitizer, UndefinedBehaviorSanitizer,
# MemorySanitizer, ThreadSanitizer), and the post-sentinel ordering
# check in _classify_native_output greps the same token.
_SANITIZER_ANCHOR = b"Sanitizer"


def _scan_anchor_offsets(
    path: Path, anchors: tuple[bytes, ...],
) -> list[int]:
    """Offsets of anchor-marker hits across the FULL stream.

    Incremental chunked scan (bounded memory); per marker only the
    first and last ``_ANCHOR_HITS_KEPT`` hits are recorded so a stream
    spamming a marker cannot balloon the result.
    """
    from collections import deque

    firsts: dict[bytes, list[int]] = {m: [] for m in anchors}
    lasts: dict[bytes, deque] = {
        m: deque(maxlen=_ANCHOR_HITS_KEPT) for m in anchors
    }
    overlap = max(len(m) for m in anchors) - 1
    carry = b""
    pos = 0  # absolute offset of the next unread byte
    with open(path, "rb") as f:
        while True:
            block = f.read(_ANCHOR_SCAN_CHUNK)
            if not block:
                break
            buf = carry + block
            base = pos - len(carry)
            for m in anchors:
                start = 0
                while True:
                    i = buf.find(m, start)
                    if i < 0:
                        break
                    # A match ending inside the carry region was fully
                    # visible last round — skip the double-count.
                    if i + len(m) > len(carry):
                        off = base + i
                        if len(firsts[m]) < _ANCHOR_HITS_KEPT:
                            firsts[m].append(off)
                        lasts[m].append(off)
                    start = i + 1
            pos += len(block)
            carry = buf[-overlap:] if overlap > 0 else b""
    offsets: set[int] = set()
    for m in anchors:
        for off in firsts[m]:
            offsets.add(off)
        for off in lasts[m]:
            offsets.add(off)
    return sorted(offsets)


def _read_capped(
    path: Path,
    *,
    keep_tail: bool,
    anchors: tuple[bytes, ...] = (),
) -> tuple[str, bool]:
    """Read a bounded view of *path*: ``(text, truncated)``.

    Retains the head (+ tail when ``keep_tail``) plus, when *anchors*
    are given, a context window around each anchor-marker hit found by
    scanning the FULL stream — all in stream order, gaps replaced by
    ``_TRUNCATION_MARKER``. ``truncated`` is True when any byte of the
    stream was dropped.
    """
    try:
        size = path.stat().st_size
        with open(path, "rb") as f:
            if size <= 2 * _CAPTURE_CAP_BYTES:
                text = f.read(2 * _CAPTURE_CAP_BYTES).decode(
                    "utf-8", errors="replace",
                )
                return text, False
        intervals: list[tuple[int, int]] = [(0, _CAPTURE_CAP_BYTES)]
        if keep_tail:
            intervals.append((size - _CAPTURE_CAP_BYTES, size))
        if anchors:
            for off in _scan_anchor_offsets(path, anchors):
                lo = max(0, off - _ANCHOR_PRE_CONTEXT)
                hi = min(size, off + _ANCHOR_POST_CONTEXT)
                intervals.append((lo, hi))
        intervals.sort()
        merged: list[list[int]] = []
        for lo, hi in intervals:
            if merged and lo <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], hi)
            else:
                merged.append([lo, hi])
        pieces: list[str] = []
        covered = 0
        with open(path, "rb") as f:
            prev_end = 0
            for lo, hi in merged:
                if lo > prev_end:
                    pieces.append(_TRUNCATION_MARKER)
                f.seek(lo)
                pieces.append(
                    f.read(hi - lo).decode("utf-8", errors="replace"),
                )
                covered += hi - lo
                prev_end = hi
            if prev_end < size:
                pieces.append(_TRUNCATION_MARKER)
        return "".join(pieces), covered < size
    except OSError:
        return "", False


def _merge_capped_stderr_classification(proc, label: str) -> None:
    """Re-derive stderr-based sandbox classification on capped text.

    The sandbox's own post-run classification (sanitizer detection in
    ``sandbox_info``) reads ``result.stderr``, which file redirection
    leaves unset — re-run the same observe helper over the capped
    stderr and merge the stderr-derived keys. Enforcement-pattern
    detection (``blocked``) is not re-derived; witness verdicts never
    confirm from it.
    """
    stderr_text = proc.stderr or ""
    if not stderr_text:
        return
    try:
        from core.sandbox.observe import _interpret_result
    except ImportError:
        return
    clone = subprocess.CompletedProcess(
        getattr(proc, "args", []), proc.returncode, None, stderr_text,
    )
    try:
        _interpret_result(clone, label)
    except Exception:
        logger.debug(
            "capped stderr re-classification failed", exc_info=True,
        )
        return
    derived = getattr(clone, "sandbox_info", None) or {}
    info = getattr(proc, "sandbox_info", None)
    if info is None:
        proc.sandbox_info = derived
        return
    if derived.get("sanitizer") and not info.get("sanitizer"):
        info["sanitizer"] = derived["sanitizer"]
        if derived.get("crashed"):
            info["crashed"] = True
        extra = derived.get("evidence")
        if extra:
            existing = info.get("evidence") or ""
            info["evidence"] = (
                f"{existing} — {extra}" if existing else extra
            )


_CAP_STDOUT_NAME = "raptor-cap-stdout"
_CAP_STDERR_NAME = "raptor-cap-stderr"


def _sandbox_run_capped(
    sandbox_run: Callable,
    cmd: list[str],
    *,
    cap_dir: Path,
    stderr_anchors: tuple[bytes, ...] = (),
    **kwargs,
) -> subprocess.CompletedProcess:
    """sandbox_run with bounded on-disk capture instead of pipes.

    Replaces ``sandbox_run(cmd, capture_output=True, text=True, ...)``.
    The sandbox facade does not plumb ``stdout=``/``stderr=`` file
    handles, so the redirection happens INSIDE the child command line:
    ``/bin/sh -c 'exec "$@" > out 2> err'`` — ``exec`` replaces the
    shell with the target, so exit codes and crash signals reach the
    parent (and the sandbox's rc-based classification) unchanged.

    *cap_dir* must be a directory that is writable inside the sandbox
    and visible to the parent afterwards — the caller's ``output=``
    dir (the sandbox's designated writable channel). Returns the
    CompletedProcess with ``stdout``/``stderr`` set to the CAPPED text
    and the stderr-derived ``sandbox_info`` keys re-merged.
    *stderr_anchors* are marker byte-strings whose surrounding context
    must survive the cap (harness sentinel, sanitizer reports); the
    full on-disk stream is scanned for them parent-side before the
    capped read. ``proc.stderr_truncated`` records whether any stderr
    byte was dropped so classification can refuse to conclude from a
    truncated stream. A runner that captured inline anyway
    (stub/injected runner) keeps its own already-in-memory text.
    Exceptions (TimeoutExpired etc.) propagate exactly as before.
    """
    import shlex

    out_path = Path(cap_dir) / _CAP_STDOUT_NAME
    err_path = Path(cap_dir) / _CAP_STDERR_NAME
    script = (
        'exec "$@" > ' + shlex.quote(str(out_path))
        + " 2> " + shlex.quote(str(err_path))
    )
    wrapped = ["/bin/sh", "-c", script, cmd[0], *cmd]
    # Under the sandbox CLI --audit flag, the throwaway cap_dir passed
    # as output= would become the tracer's evidence destination — swept
    # with the scratch when the step completes. Route audit evidence to
    # the run's persistent output dir instead (audit-signal only, no
    # Landlock impact). Ambient via execute_witness(); every witness
    # step (compile and run) funnels through here.
    audit_run_dir = _AUDIT_RUN_DIR.get()
    if audit_run_dir and "audit_run_dir" not in kwargs:
        kwargs["audit_run_dir"] = audit_run_dir
    try:
        proc = sandbox_run(wrapped, **kwargs)
        if proc.stdout is None:
            proc.stdout, _ = _read_capped(out_path, keep_tail=False)
        if proc.stderr is None:
            proc.stderr, stderr_truncated = _read_capped(
                err_path, keep_tail=True, anchors=stderr_anchors,
            )
            proc.stderr_truncated = stderr_truncated
            _merge_capped_stderr_classification(
                proc,
                str(kwargs.get("caller_label") or "audit-dark-verify"),
            )
        return proc
    finally:
        for leftover in (out_path, err_path):
            with contextlib.suppress(OSError):
                leftover.unlink()


def _toolchain_read_paths(binary: str | None) -> list[str]:
    """Read-allowance roots for a toolchain binary under restrict_reads.

    Every witness step runs with ``restrict_reads=True`` — on
    Landlock-only hosts (no mount namespace) that flag is the only
    thing keeping ``$HOME`` credentials out of reach of the untrusted
    code, and witness stdout is echoed into match_detail and persisted,
    so an unrestricted read is a straight exfil channel.  The
    restricted allowlist covers the system prefixes (/usr, /lib, /etc,
    ...) but not user-local toolchain installs (rustup, nvm, sdkman,
    venvs).  For the running Python interpreter the canonical helper
    knows the prefix layout; for anything else grant the resolved
    binary's bin dir plus its parent (the runtime root holding the
    sibling lib/ tree).  ``$HOME`` itself — or any ancestor of it — is
    never granted: that would reopen the exact channel restrict_reads
    closes.
    """
    if not binary:
        return []
    resolved = os.path.realpath(shutil.which(binary) or binary)
    if resolved == os.path.realpath(sys.executable):
        try:
            from core.sandbox.python_paths import python_runtime_tool_paths
        except ImportError:
            return []
        return python_runtime_tool_paths()
    paths: list[str] = []
    home = os.path.realpath(os.path.expanduser("~"))
    bin_dir = os.path.dirname(resolved)
    for cand in (bin_dir, os.path.dirname(bin_dir)):
        if not cand or not os.path.isdir(cand):
            continue
        if any(cand == p.rstrip("/") or cand.startswith(p)
               for p in _SYSTEM_TOOLCHAIN_PREFIXES):
            continue
        if cand in ("/", home) or home.startswith(cand + "/"):
            continue
        if cand not in paths:
            paths.append(cand)
    return paths


def _sandboxed_compile(
    sandbox_run: Callable,
    compile_cmd: list[str],
    *,
    target_root: Path,
    work_dir: Path,
    caller_label: str,
    env: dict | None = None,
) -> subprocess.CompletedProcess:
    """Run a compile step in the same sandbox shape as the run steps.

    Network blocked, env sanitised (get_safe_env by default; a caller env
    is stripped of DANGEROUS_ENV_VARS via strict_env), reads/writes
    confined by the same policy as the run steps: toolchain + target_root
    + the throwaway work_dir.  restrict_reads=True keeps $HOME unreadable
    even on Landlock-only hosts where the mount namespace is unavailable
    — the compile executes target-derived code, so it gets the read
    restriction too.

    work_dir is passed as ``output`` — the sandbox's designated writable
    channel — because the compiler writes into it (object files, rustc
    rmeta scratch, javac .class files, GOPATH/GOCACHE). ``tool_paths``
    is a READ-ONLY grant: under mount-namespace isolation it becomes a
    read-only bind, and a compile writing through it fails with EROFS
    ("couldn't create a temp dir: Read-only file system"). That write
    used to sneak through only because the read-only remount of a
    /tmp-resident bind failed EPERM (clearing the host mount's locked
    nosuid/nodev flags) and fell back to Landlock, whose baseline allows
    /tmp — a hole closed when read-only remounts started preserving
    locked flags. work_dir stays in ``tool_paths`` as well: under
    restrict_reads the Landlock read allowlist is built from
    target + readable_paths + tool_paths (``output`` grants writes, not
    reads), and the mount layer skips the read-only stacking for paths
    equal to target/output, so the pair yields exactly read+write on
    work_dir and read-only everywhere else.
    """
    kwargs: dict = {}
    if env is not None:
        kwargs["env"] = env
        kwargs["strict_env"] = True
    return _sandbox_run_capped(
        sandbox_run,
        compile_cmd,
        # work_dir doubles as the capture dir — it is the compile's
        # output= channel (writable inside the sandbox, parent-visible).
        cap_dir=work_dir,
        block_network=True,
        restrict_reads=True,
        target=str(target_root),
        output=str(work_dir),
        timeout=_COMPILE_TIMEOUT_S,
        caller_label=caller_label,
        tool_paths=[str(work_dir), *_toolchain_read_paths(compile_cmd[0])],
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Shared: interpreted-language script runner
# ---------------------------------------------------------------------------


def _run_script_witness(
    spec: DarkWitnessSpec,
    script: str,
    *,
    suffix: str,
    cmd_prefix: list[str],
    target_root: Path,
    timeout_s: int,
    language: str,
    expected_token: str = "",
) -> DarkVerifyResult:
    """Write a script to disk, run it in the sandbox, classify output.

    The script lives in its OWN temp directory, not as a bare file in
    /tmp: under mount-namespace isolation the sandbox shadows /tmp with
    a private tmpfs, and a ``tool_paths`` entry of /tmp itself is not
    bind-mounted wholesale — the interpreter then cannot see its script
    at all ("no output from witness" on every mount-ns host, while
    Landlock-only hosts worked). A dedicated subdirectory IS
    bind-mounted read-only into the sandbox view.
    """
    script_dir = None
    try:
        script_dir = Path(
            tempfile.mkdtemp(prefix="raptor_dark_", dir=exec_workdir()))
        script_file = script_dir / f"witness{suffix}"
        script_file.write_text(script, encoding="utf-8")

        sandbox_run = _import_sandbox_run()
        if sandbox_run is None:
            return _sandbox_refusal_result(spec, language)
        cap_dir = Path(tempfile.mkdtemp(
            prefix="raptor_dark_cap_", dir=exec_workdir()))
        try:
            proc = _sandbox_run_capped(
                sandbox_run,
                cmd_prefix + [str(script_file)],
                cap_dir=cap_dir,
                block_network=True,
                restrict_reads=True,
                target=str(target_root),
                # The capture dir is the run's writable channel — the
                # sandbox binds output= read-write and parent-visible.
                output=str(cap_dir),
                timeout=timeout_s,
                caller_label=f"audit-dark-verify-{language}",
                tool_paths=[str(script_dir),
                            *_toolchain_read_paths(cmd_prefix[0])],
            )
        finally:
            shutil.rmtree(cap_dir, ignore_errors=True)

        stdout = (proc.stdout or "")[:_MAX_OUTPUT_BYTES]
        return _classify_json_output(
            spec, stdout, language, expected_token=expected_token)

    except subprocess.TimeoutExpired:
        return DarkVerifyResult(
            finding_key=spec.finding_key, verdict="inconclusive",
            language=language,
            match_detail=f"witness timed out after {timeout_s}s",
        )
    except Exception as exc:
        logger.debug("%s witness failed: %s", language, exc, exc_info=True)
        return DarkVerifyResult(
            finding_key=spec.finding_key, verdict="error", language=language,
            match_detail=f"execution failed: {type(exc).__name__}: {exc}",
        )
    finally:
        if script_dir is not None:
            shutil.rmtree(script_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Shared: interpreted language via external binary
# ---------------------------------------------------------------------------


def _make_interpreted_executor(
    lang: str,
    *,
    binary_names: list[str],
    suffix: str,
    harness_fn: Callable,
    not_found_msg: str,
) -> Callable:
    """Factory for interpreted-language executors (Ruby, PHP, Lua, Perl)."""

    def executor(
        spec: DarkWitnessSpec,
        target_root: Path,
        timeout_s: int,
    ) -> DarkVerifyResult:
        interp = None
        for name in binary_names:
            interp = shutil.which(name)
            if interp:
                break
        if not interp:
            return DarkVerifyResult(
                finding_key=spec.finding_key, verdict="error", language=lang,
                match_detail=not_found_msg,
            )

        token = secrets.token_hex(8)
        harness_src = harness_fn(spec, target_root, witness_token=token)
        return _run_script_witness(
            spec, harness_src, suffix=suffix,
            cmd_prefix=[interp],
            target_root=target_root, timeout_s=timeout_s,
            language=lang, expected_token=token,
        )

    return executor


# ---------------------------------------------------------------------------
# Shared: native binary runner + classifier
# ---------------------------------------------------------------------------


def _run_native_binary(
    spec: DarkWitnessSpec,
    binary: Path,
    target_root: Path,
    timeout_s: int,
    lang: str,
    *,
    expected_token: str = "",
) -> DarkVerifyResult:
    """Run a compiled binary and classify the result."""
    from core.config import RaptorConfig
    env = RaptorConfig.get_safe_env()
    env["ASAN_OPTIONS"] = "detect_leaks=0"
    sandbox_run = _import_sandbox_run()
    if sandbox_run is None:
        return _sandbox_refusal_result(spec, lang)
    # Anchored capture: the harness sentinel (token-bearing — cannot be
    # forged or spammed by the target) and the sanitizer-report family
    # marker must survive the stderr cap regardless of how much padding
    # the target prints around them; the eviction of either flipped
    # genuine crashes to inconclusive from stderr content alone.
    anchors: list[bytes] = [_SANITIZER_ANCHOR]
    if expected_token:
        anchors.insert(
            0, (_CALL_MARKER_PREFIX + expected_token).encode(),
        )
    cap_dir = Path(tempfile.mkdtemp(
        prefix="raptor_dark_cap_", dir=exec_workdir()))
    try:
        proc = _sandbox_run_capped(
            sandbox_run,
            [str(binary)],
            cap_dir=cap_dir,
            stderr_anchors=tuple(anchors),
            block_network=True,
            restrict_reads=True,
            target=str(target_root),
            output=str(cap_dir),
            timeout=timeout_s,
            caller_label="audit-dark-verify-native",
            tool_paths=[str(binary.parent)],
            env=env,
            strict_env=True,
        )
    finally:
        shutil.rmtree(cap_dir, ignore_errors=True)

    sandbox_info = getattr(proc, "sandbox_info", None)
    return _classify_native_output(
        spec, proc, sandbox_info, lang, expected_token=expected_token)


# One sanitizer report line: the bug-type-and-context tail of an
# `ERROR:`/`WARNING:`/`SUMMARY:` sanitizer header (ASAN
# "heap-buffer-overflow on address 0x...", TSAN "data race (pid=...)").
# Full-line capture, not `(\S+)`: multi-word bug types must stay
# matchable by substring.
_SANITIZER_REPORT_RE = re.compile(
    r"(?:ERROR|WARNING|SUMMARY): \w*Sanitizer:? ([^\n]+)"
)

def _window_sanitizer_reports(window_text: str) -> list[str]:
    """Sanitizer report lines (lowercased, deduplicated, order kept)
    inside a verified stderr window.

    No extraction cap: the window text is already bounded by the
    capture machinery, so the result is inherently bounded — a fixed
    cap N would hand report-line spam a new suppression lever (N
    forged lines push the genuine report, typically LAST because the
    sanitizer aborts at the fault, out of the match set)."""
    return list(dict.fromkeys(
        m.group(1).lower()
        for m in _SANITIZER_REPORT_RE.finditer(window_text)
    ))


def _sanitizer_matches(
    expected: str,
    detail: dict,
    window_reports: list[str] | None = None,
) -> bool:
    """True when the observed sanitizer report matches the witness's
    stated expectation.

    ``expected`` is the LLM-predicted error type (e.g.
    ``"heap-buffer-overflow"``) or a sanitizer family name
    (``"asan"``). The sandbox classifier reports the family in
    ``detail["sanitizer"]`` and the report's bug type inside
    ``detail["evidence"]`` (``"AddressSanitizer: heap-buffer-overflow"``).

    ``window_reports``: when the pre-call sentinel is verified, the
    report lines extracted from the POST-sentinel stderr window. They
    are authoritative for type matching — the whole-stream evidence
    string is first-match-derived, so a decoy `ERROR:
    AddressSanitizer: <wrong-type>` line printed before the real
    report would rename a genuine crash's bug type (flipping confirmed
    to inconclusive), and a forged expected-type line planted BEFORE
    the sentinel would match a report the target call never produced.
    An EMPTY list is still authoritative: a verified window whose
    "Sanitizer" text carries no report-shaped line (bare mentions
    only) fails the type match rather than falling back to the
    whole-stream evidence — the fallback would hand pre-sentinel
    forgeries the match back. Only ``None`` (no verified window at
    all: legacy token-less callers) uses the evidence substring check.
    """
    exp = (expected or "").strip().lower()
    if not exp:
        return False
    family = str(detail.get("sanitizer", "")).strip().lower()
    if exp == family:
        return True
    if window_reports is not None:
        return any(exp in report for report in window_reports)
    evidence = str(detail.get("evidence", "")).lower()
    return bool(evidence) and exp in evidence


def _classify_native_output(
    spec: DarkWitnessSpec,
    proc: subprocess.CompletedProcess,
    sandbox_info: dict | None,
    lang: str,
    *,
    expected_token: str = "",
) -> DarkVerifyResult:
    """Classify output from a native binary execution.

    Confirmation is bound to the witness's stated expectation: a
    sanitizer report must match ``expected_sanitizer`` when one was
    predicted, and a crash only confirms when the witness predicted a
    crash. An unpredicted crash/report proves the *witness* is wrong
    about the mechanism, not that the hypothesis is right — it never
    confirms (a harness bug, a bad argument expression, or an
    unrelated defect all crash too).

    When *expected_token* is set, a crash/sanitizer signal additionally
    only confirms if the harness's pre-call sentinel
    (``__raptor_witness_start__:<token>``) reached stderr first — the
    signal must come from the target call, not from anything that ran
    before it (setup code, constructors, initializers).
    """
    from core.witness.sandbox_outcome import outcome_from_sandbox_info
    from core.witness.types import WitnessOutcome

    outcome, detail = outcome_from_sandbox_info(sandbox_info, proc.returncode)

    stderr_full = proc.stderr or ""
    stderr_truncated = bool(getattr(proc, "stderr_truncated", False)) or (
        _TRUNCATION_MARKER in stderr_full
    )

    call_reached = True
    sanitizer_after_call = True
    window_reports: list[str] | None = None
    if expected_token:
        stderr_text = proc.stderr or ""
        marker = _CALL_MARKER_PREFIX + expected_token
        marker_at = stderr_text.find(marker)
        call_reached = marker_at >= 0
        if call_reached and outcome == WitnessOutcome.SANITIZER_REPORT:
            # The report must come from the target call, not from
            # anything that ran before the sentinel: setup expressions
            # execute pre-sentinel and may write to stderr, so a
            # forged sanitizer line planted there must not match. A
            # real sanitizer aborts at the faulting instruction —
            # inside the target call, after the sentinel.
            post = stderr_text[marker_at + len(marker):]
            sanitizer_after_call = "Sanitizer" in post
            # Anchor bug-type matching to the verified window too:
            # the sandbox classifier's evidence string is first-match
            # over the WHOLE stream, so a decoy line before the real
            # report (or before the sentinel) steers it. The window's
            # report lines are authoritative — including when EMPTY
            # (a real post-sentinel sanitizer always prints a
            # report-shaped header line; bare "Sanitizer" mentions
            # with the only report-shaped text pre-sentinel are a
            # forgery, not a crash).
            window_reports = _window_sanitizer_reports(post)

    if stderr_truncated:
        # A truncated stream may only classify when the markers the
        # verdict hangs on demonstrably survived the cap. When the
        # sentinel (or the predicted sanitizer report) was NOT found
        # in the retained stream, its absence proves nothing — the
        # marker may sit in the dropped bytes — so the answer is
        # ``error`` (re-run with a larger capture cap), never a
        # silent inconclusive/clean/refuted.
        sentinel_lost = bool(expected_token) and not call_reached
        sanitizer_lost = (
            bool(spec.expected_sanitizer)
            and outcome != WitnessOutcome.SANITIZER_REPORT
            and "Sanitizer" not in stderr_full
        )
        if sentinel_lost or sanitizer_lost:
            return DarkVerifyResult(
                finding_key=spec.finding_key, verdict="error",
                language=lang,
                match_detail=(
                    "stderr exceeded the capture cap and the "
                    + ("harness sentinel" if sentinel_lost
                       else "predicted sanitizer report")
                    + " was not found in the retained stream — "
                    "truncated output must not classify; re-run "
                    "with a larger capture cap"
                ),
            )

    if outcome in (
        WitnessOutcome.SANITIZER_REPORT, WitnessOutcome.EXIT_SIGNAL,
    ) and not call_reached:
        return DarkVerifyResult(
            finding_key=spec.finding_key, verdict="inconclusive",
            language=lang,
            match_detail=(
                "crash/sanitizer signal observed BEFORE the target call "
                "(pre-call sentinel absent) — setup-phase failure, not "
                "accepted as confirmation"
            ),
        )

    if outcome == WitnessOutcome.SANITIZER_REPORT and not sanitizer_after_call:
        return DarkVerifyResult(
            finding_key=spec.finding_key, verdict="inconclusive",
            language=lang,
            match_detail=(
                "sanitizer text observed only BEFORE the pre-call "
                "sentinel — not produced by the target call; not "
                "accepted as confirmation"
            ),
        )

    if outcome == WitnessOutcome.SANITIZER_REPORT:
        sanitizer_type = detail.get("sanitizer", "")
        if spec.expected_sanitizer:
            if _sanitizer_matches(
                spec.expected_sanitizer, detail, window_reports,
            ):
                return DarkVerifyResult(
                    finding_key=spec.finding_key,
                    verdict="confirmed",
                    language=lang,
                    actual_exception=f"sanitizer: {sanitizer_type}",
                    match_detail=(
                        f"sanitizer report matches prediction "
                        f"({spec.expected_sanitizer})"
                    ),
                )
            return DarkVerifyResult(
                finding_key=spec.finding_key,
                verdict="inconclusive",
                language=lang,
                actual_exception=f"sanitizer: {sanitizer_type}",
                match_detail=(
                    f"sanitizer fired ({sanitizer_type}) but does not "
                    f"match expected {spec.expected_sanitizer}"
                ),
            )
        if spec.expected_crash:
            return DarkVerifyResult(
                finding_key=spec.finding_key,
                verdict="confirmed",
                language=lang,
                actual_exception=f"sanitizer: {sanitizer_type}",
                match_detail=f"ASan/UBSan fired: {sanitizer_type}",
            )
        return DarkVerifyResult(
            finding_key=spec.finding_key,
            verdict="inconclusive",
            language=lang,
            actual_exception=f"sanitizer: {sanitizer_type}",
            match_detail=(
                f"unexpected sanitizer report ({sanitizer_type}) — "
                f"witness predicted no crash; not accepted as "
                f"confirmation"
            ),
        )

    if outcome == WitnessOutcome.EXIT_SIGNAL:
        signal = detail.get("signal", "unknown")
        if detail.get("resource_exceeded") or detail.get("seccomp_killed"):
            return DarkVerifyResult(
                finding_key=spec.finding_key, verdict="inconclusive",
                language=lang,
                actual_exception=f"signal: {signal}",
                match_detail=(
                    f"process killed by {signal} (resource limit / "
                    f"seccomp), not a target crash"
                ),
            )
        if spec.expected_crash:
            return DarkVerifyResult(
                finding_key=spec.finding_key, verdict="confirmed",
                language=lang,
                actual_exception=f"signal: {signal}",
                match_detail=f"crash signal {signal} matches prediction",
            )
        return DarkVerifyResult(
            finding_key=spec.finding_key, verdict="inconclusive",
            language=lang,
            actual_exception=f"signal: {signal}",
            match_detail=(
                f"unexpected crash ({signal}) — witness predicted "
                f"normal completion; not accepted as confirmation"
            ),
        )

    stdout = (proc.stdout or "")[:_MAX_OUTPUT_BYTES]
    if spec.expected_crash:
        return DarkVerifyResult(
            finding_key=spec.finding_key, verdict="refuted",
            language=lang,
            actual_return=stdout[:200],
            match_detail="expected crash but process exited normally",
        )
    return _classify_json_output(
        spec, stdout, lang, expected_token=expected_token)


# ---------------------------------------------------------------------------
# Validate setup lines (C/C++/Rust)
# ---------------------------------------------------------------------------


# One variable declaration with a literal initializer fits in far
# less; the cap only exists so a hostile line can't feed the grammar
# regexes unbounded input.
_MAX_SETUP_LINE_CHARS = 4096


def _validate_setup(lines: list[str], lang: str = "c") -> str | None:
    """Declaration-only allowlist over setup lines (see the grammar
    block above ``validate_spec``). Returns a reason string on the
    first offending line, None when every line is acceptable."""
    checker = _SETUP_VALIDATORS.get(lang, _c_setup_line_error)
    for i, line in enumerate(lines):
        if len(str(line)) > _MAX_SETUP_LINE_CHARS:
            return (
                f"setup line {i} outside the declaration grammar "
                f"(line exceeds {_MAX_SETUP_LINE_CHARS} chars): "
                f"{str(line)[:60]}"
            )
        reason = checker(str(line))
        if reason:
            return (
                f"setup line {i} outside the declaration grammar "
                f"({reason}): {str(line)[:60]}"
            )
    return None


# ---------------------------------------------------------------------------
# Per-language executors
# ---------------------------------------------------------------------------


def _execute_python(
    spec: DarkWitnessSpec,
    target_root: Path,
    timeout_s: int,
) -> DarkVerifyResult:
    validation_error = validate_import_path(spec, target_root)
    if validation_error:
        return DarkVerifyResult(
            finding_key=spec.finding_key, verdict="error", language="python",
            match_detail=f"validation failed: {validation_error}",
        )
    token = secrets.token_hex(8)
    script = generate_witness_script(spec, target_root, witness_token=token)
    return _run_script_witness(
        spec, script, suffix=".py",
        cmd_prefix=[sys.executable],
        target_root=target_root, timeout_s=timeout_s,
        language="python", expected_token=token,
    )


def _execute_native(
    spec: DarkWitnessSpec,
    target_root: Path,
    timeout_s: int,
    *,
    lang: str = "c",
) -> DarkVerifyResult:
    setup_err = _validate_setup(spec.lang_config.get("setup_lines", []), lang)
    if setup_err:
        return DarkVerifyResult(
            finding_key=spec.finding_key, verdict="error", language=lang,
            match_detail=setup_err,
        )

    cc = "cc" if lang == "c" else "c++"
    if not shutil.which(cc):
        return DarkVerifyResult(
            finding_key=spec.finding_key, verdict="error", language=lang,
            match_detail=f"compiler not found: {cc}",
        )

    token = secrets.token_hex(8)
    harness_src = generate_c_harness(spec, target_root, witness_token=token)
    try:
        with scratch_dir("raptor_dark_c_", dir=exec_workdir()) as work_dir:
            ext = ".c" if lang == "c" else ".cpp"
            harness_file = work_dir / f"harness{ext}"
            harness_file.write_text(harness_src, encoding="utf-8")
            binary = work_dir / "harness_bin"

            source_file = target_root / spec.file
            compile_cmd = [
                cc, "-fsanitize=address,undefined", "-g", "-O0",
                "-o", str(binary),
                str(harness_file), str(source_file),
                "-lm",
            ]

            # The compile itself executes target-derived code paths
            # (#embed / .incbin can read any operator-readable file into
            # the binary), so it gets the same sandbox as the run step —
            # and fails closed.
            sandbox_run = _import_sandbox_run()
            if sandbox_run is None:
                return _sandbox_refusal_result(spec, lang)
            comp = _sandboxed_compile(
                sandbox_run, compile_cmd,
                target_root=target_root, work_dir=work_dir,
                caller_label=f"audit-dark-verify-{lang}-compile",
            )
            if comp.returncode != 0:
                return DarkVerifyResult(
                    finding_key=spec.finding_key, verdict="error",
                    language=lang,
                    match_detail=(
                        f"compilation failed: {(comp.stderr or '')[:300]}"
                    ),
                )

            return _run_native_binary(
                spec, binary, target_root, timeout_s, lang,
                expected_token=token)

    except subprocess.TimeoutExpired:
        return DarkVerifyResult(
            finding_key=spec.finding_key, verdict="inconclusive", language=lang,
            match_detail="compilation or execution timed out",
        )
    except Exception as exc:
        logger.debug("native witness failed: %s", exc, exc_info=True)
        return DarkVerifyResult(
            finding_key=spec.finding_key, verdict="error", language=lang,
            match_detail=f"execution failed: {type(exc).__name__}: {exc}",
        )


def _execute_c(spec: DarkWitnessSpec, target_root: Path, timeout_s: int) -> DarkVerifyResult:
    return _execute_native(spec, target_root, timeout_s, lang="c")


def _execute_cpp(spec: DarkWitnessSpec, target_root: Path, timeout_s: int) -> DarkVerifyResult:
    return _execute_native(spec, target_root, timeout_s, lang="cpp")


def _execute_go(
    spec: DarkWitnessSpec,
    target_root: Path,
    timeout_s: int,
) -> DarkVerifyResult:
    go_bin = shutil.which("go")
    if not go_bin:
        return DarkVerifyResult(
            finding_key=spec.finding_key, verdict="error", language="go",
            match_detail="go compiler not found",
        )

    token = secrets.token_hex(8)
    harness_src = generate_go_harness(spec, target_root, witness_token=token)
    try:
        with scratch_dir("raptor_dark_go_", dir=exec_workdir()) as work_dir:
            harness_file = work_dir / "harness_main.go"
            harness_file.write_text(harness_src, encoding="utf-8")

            go_package = spec.lang_config.get("package", "main")
            build_files = [str(harness_file)]
            if go_package == "main":
                source_file = target_root / spec.file
                src_text = source_file.read_text(encoding="utf-8")
                src_text = re.sub(
                    r'(?m)^func\s+main\s*\(\s*\)\s*\{',
                    'func _original_main() {',
                    src_text,
                )
                target_copy = work_dir / "target_source.go"
                target_copy.write_text(src_text, encoding="utf-8")
                build_files.append(str(target_copy))

            from core.config import RaptorConfig
            safe_env = RaptorConfig.get_safe_env()
            safe_env["GOPATH"] = str(work_dir / "gopath")
            safe_env["GOCACHE"] = str(work_dir / "gocache")

            binary = work_dir / "harness_bin"
            build_cmd = [go_bin, "build", "-o", str(binary)] + build_files
            # `go build` can execute target-derived code (cgo,
            # //go:generate tooling in odd setups) — sandbox it like the
            # run step, fail closed without one.  GOPATH/GOCACHE stay
            # redirected into the work area; strict_env strips
            # DANGEROUS_ENV_VARS on the way in.
            sandbox_run = _import_sandbox_run()
            if sandbox_run is None:
                return _sandbox_refusal_result(spec, "go")
            comp = _sandboxed_compile(
                sandbox_run, build_cmd,
                target_root=target_root, work_dir=work_dir,
                caller_label="audit-dark-verify-go-compile",
                env=safe_env,
            )
            if comp.returncode != 0:
                stderr = (comp.stderr or "")[:300]
                return DarkVerifyResult(
                    finding_key=spec.finding_key, verdict="error",
                    language="go",
                    match_detail=f"go build failed: {stderr}",
                )

            return _run_native_binary(
                spec, binary, target_root, timeout_s, "go",
                expected_token=token)

    except subprocess.TimeoutExpired:
        return DarkVerifyResult(
            finding_key=spec.finding_key, verdict="inconclusive", language="go",
            match_detail="go execution timed out",
        )
    except Exception as exc:
        logger.debug("Go witness failed: %s", exc, exc_info=True)
        return DarkVerifyResult(
            finding_key=spec.finding_key, verdict="error", language="go",
            match_detail=f"execution failed: {type(exc).__name__}: {exc}",
        )


def _execute_js(
    spec: DarkWitnessSpec,
    target_root: Path,
    timeout_s: int,
) -> DarkVerifyResult:
    node_bin = shutil.which("node")
    if not node_bin:
        return DarkVerifyResult(
            finding_key=spec.finding_key, verdict="error", language="javascript",
            match_detail="node not found",
        )
    token = secrets.token_hex(8)
    harness_src = generate_js_harness(spec, target_root, witness_token=token)
    return _run_script_witness(
        spec, harness_src, suffix=".js",
        cmd_prefix=[node_bin],
        target_root=target_root, timeout_s=timeout_s,
        language="javascript", expected_token=token,
    )


def _execute_ts(
    spec: DarkWitnessSpec,
    target_root: Path,
    timeout_s: int,
) -> DarkVerifyResult:
    ts_runner = shutil.which("tsx") or shutil.which("ts-node")
    if ts_runner:
        cmd_prefix = [ts_runner]
    else:
        npx = shutil.which("npx")
        if npx:
            cmd_prefix = [npx, "tsx"]
        else:
            return DarkVerifyResult(
                finding_key=spec.finding_key, verdict="error",
                language="typescript",
                match_detail="tsx/ts-node/npx not found",
            )
    token = secrets.token_hex(8)
    harness_src = generate_ts_harness(spec, target_root, witness_token=token)
    return _run_script_witness(
        spec, harness_src, suffix=".ts",
        cmd_prefix=cmd_prefix,
        target_root=target_root, timeout_s=timeout_s,
        language="typescript", expected_token=token,
    )


# Bound on proxy hops in _resolve_rustc: which() result -> wrapper ->
# rustup proxy -> toolchain compiler is 3; one spare for exotic stacks.
_RUSTC_RESOLVE_MAX_HOPS = 4


def _resolve_rustc() -> str | None:
    """Resolve the real rustc binary, seeing through proxy layers.

    rustup installs ``rustc`` as a proxy (a hardlink of the multi-call
    ``rustup`` binary): at run time it reads the ``$RUSTUP_HOME``
    (default ``~/.rustup``) settings and re-execs the selected
    toolchain's compiler from ``toolchains/<tc>/bin/rustc``. The
    witness compile runs under ``restrict_reads`` with only the
    *invoked* binary's own directories granted
    (:func:`_toolchain_read_paths`), so the proxy's settings read and
    toolchain exec are denied and every Rust witness collapses to
    ``verdict="error"`` ("compilation failed") on rustup-managed hosts
    — while system installs under /usr keep working. Ask the proxy
    for its sysroot on the host (the operator's own toolchain — the
    same trust as ``shutil.which``) and invoke the real compiler
    directly; the sysroot then IS the granted read root, covering the
    sibling lib/ tree the compile needs.

    Resolution must reach a fixed point, not stop after one hop:
    wrapper shims can layer (a site-local rustc wrapper dispatching to
    a rustup-managed install), and then ``<sysroot>/bin/rustc`` from
    the first probe is itself a proxy whose settings read the sandbox
    denies. A candidate is the real compiler only when it lives inside
    the sysroot it reports — a proxy always reports a sysroot
    elsewhere — so keep probing until a candidate passes that check
    (bounded by ``_RUSTC_RESOLVE_MAX_HOPS``).
    """
    rustc = shutil.which("rustc")
    if not rustc:
        return None
    for _ in range(_RUSTC_RESOLVE_MAX_HOPS):
        # System installs (/usr/bin/rustc etc.) are no rustup proxies
        # and live inside the sandbox's default read allowlist — even a
        # distro proxy under /usr can read its own settings there. Only
        # probe when rustc resolves OUTSIDE the system prefixes
        # (rustup's ~/.cargo/bin layout), keeping the host-side probe
        # off the common path.
        resolved = os.path.realpath(rustc)
        if any(resolved.startswith(p) for p in _SYSTEM_TOOLCHAIN_PREFIXES):
            return rustc
        try:
            proc = subprocess.run(
                [rustc, "--print", "sysroot"],
                capture_output=True, text=True, timeout=_COMPILE_TIMEOUT_S,
            )
        except (OSError, subprocess.SubprocessError):
            return rustc
        sysroot = (proc.stdout or "").strip()
        if proc.returncode != 0 or not sysroot:
            return rustc
        real = Path(sysroot) / "bin" / "rustc"
        if not real.is_file():
            return rustc
        # Real compiler: lives inside the sysroot it reports (rustup's
        # toolchains/<tc>/bin/rustc under toolchains/<tc>). A proxy
        # resolves elsewhere (~/.cargo/bin) — probe IT next.
        if os.path.realpath(real).startswith(
                os.path.realpath(sysroot) + os.sep):
            return str(real)
        if str(real) == rustc:
            return rustc  # self-reporting proxy: no progress possible
        rustc = str(real)
    return rustc


def _execute_rust(
    spec: DarkWitnessSpec,
    target_root: Path,
    timeout_s: int,
) -> DarkVerifyResult:
    # Fail closed BEFORE the host-side sysroot probe: with no sandbox
    # nothing may execute — not even the trusted-toolchain probe.
    sandbox_run = _import_sandbox_run()
    if sandbox_run is None:
        return _sandbox_refusal_result(spec, "rust")

    rustc = _resolve_rustc()
    if not rustc:
        return DarkVerifyResult(
            finding_key=spec.finding_key, verdict="error", language="rust",
            match_detail="rustc not found",
        )

    setup_err = _validate_setup(
        spec.lang_config.get("setup_lines", []), "rust")
    if setup_err:
        return DarkVerifyResult(
            finding_key=spec.finding_key, verdict="error", language="rust",
            match_detail=setup_err,
        )

    token = secrets.token_hex(8)
    harness_src = generate_rust_harness(spec, target_root, witness_token=token)
    try:
        with scratch_dir("raptor_dark_rs_", dir=exec_workdir()) as work_dir:
            harness_file = work_dir / "harness.rs"
            harness_file.write_text(harness_src, encoding="utf-8")
            binary = work_dir / "harness_bin"

            # rustc accepts exactly one crate root, so the harness pulls
            # the target in via include!("target_source.rs") — copy the
            # source next to the harness under that fixed name (contract
            # with generate_rust_harness). Copying into work_dir also
            # keeps the compile read-set minimal. Rename any target fn
            # main so it cannot collide with the harness main once
            # spliced into the same crate (same idiom as the Go
            # executor).
            source_file = target_root / spec.file
            source_copy = work_dir / "target_source.rs"
            src_content = source_file.read_text(encoding="utf-8")
            src_content = re.sub(
                r'(?m)^fn\s+main\s*\(\s*\)',
                'fn _original_main()',
                src_content,
            )
            source_copy.write_text(src_content, encoding="utf-8")
            # -C panic=abort: a panicking witness must register as a
            # crash. Default unwind exits with code 101 (no signal),
            # which the shared classifier reads as a normal exit — abort
            # raises SIGABRT and flows through the existing EXIT_SIGNAL
            # path.
            compile_cmd = [
                rustc, "--edition", "2021",
                "-C", "panic=abort",
                "-Z", "sanitizer=address",
                "-g", "-o", str(binary),
                str(harness_file),
            ]

            # rustc executes target-derived code paths at compile time
            # (include_str!/include_bytes! read any operator-readable
            # file into the binary) — sandbox the compile like the run
            # step; the fail-closed check already ran up top.
            comp = _sandboxed_compile(
                sandbox_run, compile_cmd,
                target_root=target_root, work_dir=work_dir,
                caller_label="audit-dark-verify-rust-compile",
            )

            if comp.returncode != 0:
                compile_cmd_simple = [
                    rustc, "--edition", "2021",
                    "-C", "panic=abort",
                    "-g", "-o", str(binary),
                    str(harness_file),
                ]
                comp = _sandboxed_compile(
                    sandbox_run, compile_cmd_simple,
                    target_root=target_root, work_dir=work_dir,
                    caller_label="audit-dark-verify-rust-compile",
                )
                if comp.returncode != 0:
                    return DarkVerifyResult(
                        finding_key=spec.finding_key, verdict="error",
                        language="rust",
                        match_detail=(
                            f"compilation failed: {(comp.stderr or '')[:300]}"
                        ),
                    )

            return _run_native_binary(
                spec, binary, target_root, timeout_s, "rust",
                expected_token=token)

    except subprocess.TimeoutExpired:
        return DarkVerifyResult(
            finding_key=spec.finding_key, verdict="inconclusive",
            language="rust",
            match_detail="compilation or execution timed out",
        )
    except Exception as exc:
        logger.debug("Rust witness failed: %s", exc, exc_info=True)
        return DarkVerifyResult(
            finding_key=spec.finding_key, verdict="error", language="rust",
            match_detail=f"execution failed: {type(exc).__name__}: {exc}",
        )


def _execute_java(
    spec: DarkWitnessSpec,
    target_root: Path,
    timeout_s: int,
) -> DarkVerifyResult:
    javac = shutil.which("javac")
    java_bin = shutil.which("java")
    if not javac or not java_bin:
        return DarkVerifyResult(
            finding_key=spec.finding_key, verdict="error", language="java",
            match_detail="javac/java not found",
        )

    token = secrets.token_hex(8)
    harness_src = generate_java_harness(spec, target_root, witness_token=token)
    try:
        with scratch_dir("raptor_dark_java_", dir=exec_workdir()) as work_dir:
            harness_file = work_dir / "DarkWitnessHarness.java"
            harness_file.write_text(harness_src, encoding="utf-8")

            source_file = target_root / spec.file

            # -proc:none: javac auto-discovers annotation processors from
            # the compile classpath — which includes target_root — and
            # RUNS them at compile time.  Disabling processing means
            # target classes never execute inside javac, even in the
            # sandbox (belt and braces, and faster).
            #
            # -d work_dir: without it javac writes each .class next to
            # its source — including the TARGET's class into the
            # read-only target tree, failing "error while writing ...:
            # Read-only file system" (that write only ever succeeded
            # through the /tmp-resident read-only-bind remount hole,
            # see _sandboxed_compile). work_dir is the compile step's
            # writable surface and already leads the run classpath.
            compile_cmd = [
                javac, "-proc:none", "-d", str(work_dir), "-cp",
                f"{work_dir}:{source_file.parent}:{target_root}",
                str(harness_file), str(source_file),
            ]

            sandbox_run = _import_sandbox_run()
            if sandbox_run is None:
                return _sandbox_refusal_result(spec, "java")
            comp = _sandboxed_compile(
                sandbox_run, compile_cmd,
                target_root=target_root, work_dir=work_dir,
                caller_label="audit-dark-verify-java-compile",
            )
            if comp.returncode != 0:
                return DarkVerifyResult(
                    finding_key=spec.finding_key, verdict="error",
                    language="java",
                    match_detail=(
                        f"compilation failed: {(comp.stderr or '')[:300]}"
                    ),
                )

            run_cmd = [
                java_bin, "-cp",
                f"{work_dir}:{source_file.parent}:{target_root}",
                "DarkWitnessHarness",
            ]

            cap_dir = Path(tempfile.mkdtemp(
                prefix="raptor_dark_cap_", dir=exec_workdir()))
            try:
                proc = _sandbox_run_capped(
                    sandbox_run,
                    run_cmd,
                    cap_dir=cap_dir,
                    block_network=True,
                    restrict_reads=True,
                    target=str(target_root),
                    output=str(cap_dir),
                    timeout=timeout_s,
                    caller_label="audit-dark-verify-java",
                    tool_paths=[str(work_dir),
                                *_toolchain_read_paths(java_bin)],
                )
            finally:
                shutil.rmtree(cap_dir, ignore_errors=True)

            stdout = (proc.stdout or "")[:_MAX_OUTPUT_BYTES]
            return _classify_json_output(
                spec, stdout, "java", expected_token=token)

    except subprocess.TimeoutExpired:
        return DarkVerifyResult(
            finding_key=spec.finding_key, verdict="inconclusive",
            language="java",
            match_detail="compilation or execution timed out",
        )
    except Exception as exc:
        logger.debug("Java witness failed: %s", exc, exc_info=True)
        return DarkVerifyResult(
            finding_key=spec.finding_key, verdict="error", language="java",
            match_detail=f"execution failed: {type(exc).__name__}: {exc}",
        )


# ---------------------------------------------------------------------------
# Dispatch table — factory-generated interpreted executors
# ---------------------------------------------------------------------------

_execute_ruby = _make_interpreted_executor(
    "ruby", binary_names=["ruby"], suffix=".rb",
    harness_fn=generate_ruby_harness, not_found_msg="ruby not found",
)

_execute_php = _make_interpreted_executor(
    "php", binary_names=["php"], suffix=".php",
    harness_fn=generate_php_harness, not_found_msg="php not found",
)

_execute_lua = _make_interpreted_executor(
    "lua", binary_names=["lua", "lua5.4", "lua5.3", "luajit"], suffix=".lua",
    harness_fn=generate_lua_harness, not_found_msg="lua not found",
)

_execute_perl = _make_interpreted_executor(
    "perl", binary_names=["perl"], suffix=".pl",
    harness_fn=generate_perl_harness, not_found_msg="perl not found",
)


# ---------------------------------------------------------------------------
# Master dispatch table
# ---------------------------------------------------------------------------

_EXECUTORS: dict[str, Callable[..., DarkVerifyResult]] = {
    "python": _execute_python,
    "c": _execute_c,
    "cpp": _execute_cpp,
    "go": _execute_go,
    "javascript": _execute_js,
    "typescript": _execute_ts,
    "ruby": _execute_ruby,
    "php": _execute_php,
    "rust": _execute_rust,
    "java": _execute_java,
    "lua": _execute_lua,
    "perl": _execute_perl,
}
