"""Executor dispatch and per-language execution logic.

Uses a dispatch table instead of if-chains. Each language registers
an executor function; execute_witness() looks it up and calls it.
"""

from __future__ import annotations

import ast
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

from core.paths import confine
from core.run.scratch import scratch_dir

from ._harness import (
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

logger = logging.getLogger(__name__)

_WITNESS_TIMEOUT_S = 10
_COMPILE_TIMEOUT_S = 30
_MAX_OUTPUT_BYTES = 8192

_UNSAFE_SETUP_RE = re.compile(
    r"(?:system\s*\(|popen\s*\(|exec[lv]p?e?\s*\(|fork\s*\("
    r"|__asm__|asm\s*\(|#\s*include\s*[<\"])"
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

    rt = lc.get("return_type", "")
    if rt and not _TYPE_RE.match(rt):
        return f"invalid return_type: {rt!r}"

    cn = lc.get("class_name", "")
    if cn and not _QUALIFIED_RE.match(cn):
        return f"invalid class_name: {cn!r}"

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
) -> DarkVerifyResult:
    """Execute a witness and compare output to expectations.

    Dispatches to the appropriate language executor based on the spec's
    language field (auto-detected from file extension if not set).
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
    return executor(spec, target_root, timeout_s)


# ---------------------------------------------------------------------------
# Shared JSON output classifier
# ---------------------------------------------------------------------------


def _classify_json_output(
    spec: DarkWitnessSpec,
    stdout: str,
    language: str,
) -> DarkVerifyResult:
    """Classify JSON-formatted output from any language harness."""
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
    """
    kwargs: dict = {}
    if env is not None:
        kwargs["env"] = env
        kwargs["strict_env"] = True
    return sandbox_run(
        compile_cmd,
        block_network=True,
        restrict_reads=True,
        target=str(target_root),
        capture_output=True, text=True,
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
        script_dir = Path(tempfile.mkdtemp(prefix="raptor_dark_"))
        script_file = script_dir / f"witness{suffix}"
        script_file.write_text(script, encoding="utf-8")

        sandbox_run = _import_sandbox_run()
        if sandbox_run is None:
            return _sandbox_refusal_result(spec, language)
        proc = sandbox_run(
            cmd_prefix + [str(script_file)],
            block_network=True,
            restrict_reads=True,
            target=str(target_root),
            capture_output=True, text=True,
            timeout=timeout_s,
            caller_label=f"audit-dark-verify-{language}",
            tool_paths=[str(script_dir),
                        *_toolchain_read_paths(cmd_prefix[0])],
        )

        stdout = (proc.stdout or "")[:_MAX_OUTPUT_BYTES]
        return _classify_json_output(spec, stdout, language)

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

        harness_src = harness_fn(spec, target_root)
        return _run_script_witness(
            spec, harness_src, suffix=suffix,
            cmd_prefix=[interp],
            target_root=target_root, timeout_s=timeout_s,
            language=lang,
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
) -> DarkVerifyResult:
    """Run a compiled binary and classify the result."""
    from core.config import RaptorConfig
    env = RaptorConfig.get_safe_env()
    env["ASAN_OPTIONS"] = "detect_leaks=0"
    sandbox_run = _import_sandbox_run()
    if sandbox_run is None:
        return _sandbox_refusal_result(spec, lang)
    proc = sandbox_run(
        [str(binary)],
        block_network=True,
        restrict_reads=True,
        target=str(target_root),
        capture_output=True, text=True,
        timeout=timeout_s,
        caller_label="audit-dark-verify-native",
        tool_paths=[str(binary.parent)],
        env=env,
        strict_env=True,
    )

    sandbox_info = getattr(proc, "sandbox_info", None)
    return _classify_native_output(spec, proc, sandbox_info, lang)


def _sanitizer_matches(expected: str, detail: dict) -> bool:
    """True when the observed sanitizer report matches the witness's
    stated expectation.

    ``expected`` is the LLM-predicted error type (e.g.
    ``"heap-buffer-overflow"``) or a sanitizer family name
    (``"asan"``). The sandbox classifier reports the family in
    ``detail["sanitizer"]`` and the report's bug type inside
    ``detail["evidence"]`` (``"AddressSanitizer: heap-buffer-overflow"``).
    """
    exp = (expected or "").strip().lower()
    if not exp:
        return False
    family = str(detail.get("sanitizer", "")).strip().lower()
    if exp == family:
        return True
    evidence = str(detail.get("evidence", "")).lower()
    return bool(evidence) and exp in evidence


def _classify_native_output(
    spec: DarkWitnessSpec,
    proc: subprocess.CompletedProcess,
    sandbox_info: dict | None,
    lang: str,
) -> DarkVerifyResult:
    """Classify output from a native binary execution.

    Confirmation is bound to the witness's stated expectation: a
    sanitizer report must match ``expected_sanitizer`` when one was
    predicted, and a crash only confirms when the witness predicted a
    crash. An unpredicted crash/report proves the *witness* is wrong
    about the mechanism, not that the hypothesis is right — it never
    confirms (a harness bug, a bad argument expression, or an
    unrelated defect all crash too).
    """
    from core.witness.sandbox_outcome import outcome_from_sandbox_info
    from core.witness.types import WitnessOutcome

    outcome, detail = outcome_from_sandbox_info(sandbox_info, proc.returncode)

    if outcome == WitnessOutcome.SANITIZER_REPORT:
        sanitizer_type = detail.get("sanitizer", "")
        if spec.expected_sanitizer:
            if _sanitizer_matches(spec.expected_sanitizer, detail):
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
    return _classify_json_output(spec, stdout, lang)


# ---------------------------------------------------------------------------
# Validate setup lines (C/C++/Rust)
# ---------------------------------------------------------------------------


def _validate_setup(lines: list[str]) -> str | None:
    """Reject setup lines containing dangerous patterns."""
    for i, line in enumerate(lines):
        if _UNSAFE_SETUP_RE.search(line):
            return f"unsafe pattern in setup line {i}: {line[:60]}"
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
    script = generate_witness_script(spec, target_root)
    return _run_script_witness(
        spec, script, suffix=".py",
        cmd_prefix=[sys.executable],
        target_root=target_root, timeout_s=timeout_s,
        language="python",
    )


def _execute_native(
    spec: DarkWitnessSpec,
    target_root: Path,
    timeout_s: int,
    *,
    lang: str = "c",
) -> DarkVerifyResult:
    setup_err = _validate_setup(spec.lang_config.get("setup_lines", []))
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

    harness_src = generate_c_harness(spec, target_root)
    try:
        with scratch_dir("raptor_dark_c_") as work_dir:
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
                spec, binary, target_root, timeout_s, lang)

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

    harness_src = generate_go_harness(spec, target_root)
    try:
        with scratch_dir("raptor_dark_go_") as work_dir:
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
                spec, binary, target_root, timeout_s, "go")

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
    harness_src = generate_js_harness(spec, target_root)
    return _run_script_witness(
        spec, harness_src, suffix=".js",
        cmd_prefix=[node_bin],
        target_root=target_root, timeout_s=timeout_s,
        language="javascript",
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
    harness_src = generate_ts_harness(spec, target_root)
    return _run_script_witness(
        spec, harness_src, suffix=".ts",
        cmd_prefix=cmd_prefix,
        target_root=target_root, timeout_s=timeout_s,
        language="typescript",
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

    setup_err = _validate_setup(spec.lang_config.get("setup_lines", []))
    if setup_err:
        return DarkVerifyResult(
            finding_key=spec.finding_key, verdict="error", language="rust",
            match_detail=setup_err,
        )

    harness_src = generate_rust_harness(spec, target_root)
    try:
        with scratch_dir("raptor_dark_rs_") as work_dir:
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
                spec, binary, target_root, timeout_s, "rust")

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

    harness_src = generate_java_harness(spec, target_root)
    try:
        with scratch_dir("raptor_dark_java_") as work_dir:
            harness_file = work_dir / "DarkWitnessHarness.java"
            harness_file.write_text(harness_src, encoding="utf-8")

            source_file = target_root / spec.file

            # -proc:none: javac auto-discovers annotation processors from
            # the compile classpath — which includes target_root — and
            # RUNS them at compile time.  Disabling processing means
            # target classes never execute inside javac, even in the
            # sandbox (belt and braces, and faster).
            compile_cmd = [
                javac, "-proc:none", "-cp",
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

            proc = sandbox_run(
                run_cmd,
                block_network=True,
                restrict_reads=True,
                target=str(target_root),
                capture_output=True, text=True,
                timeout=timeout_s,
                caller_label="audit-dark-verify-java",
                tool_paths=[str(work_dir),
                            *_toolchain_read_paths(java_bin)],
            )

            stdout = (proc.stdout or "")[:_MAX_OUTPUT_BYTES]
            return _classify_json_output(spec, stdout, "java")

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
