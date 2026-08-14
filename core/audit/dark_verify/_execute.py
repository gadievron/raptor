"""Executor dispatch and per-language execution logic.

Uses a dispatch table instead of if-chains. Each language registers
an executor function; execute_witness() looks it up and calls it.
"""

from __future__ import annotations

import contextlib
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

from ._types import DarkVerifyResult, DarkWitnessSpec, _SUPPORTED_LANGS, language_for_file
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

_CODE_INJECTION_RE = re.compile(
    r"[;`]"
    r"|system\s*\(|popen\s*\(|exec\s*\("
    r"|eval\s*\(|spawn\s*\("
    r"|\$\(|%x\{|%x\(|%x\["
    r"|Runtime\s*\.\s*getRuntime"
    r"|ProcessBuilder"
    r"|os\s*\.\s*system|os\s*\.\s*popen"
    r"|subprocess"
)

_TYPE_RE = re.compile(
    r"^[a-zA-Z_][a-zA-Z0-9_*&\[\]<>, .:]*$"
)


def validate_spec(spec: DarkWitnessSpec) -> str | None:
    """Pre-execution validation of LLM-generated spec fields.

    Returns an error string if the spec contains dangerous patterns,
    None if it passes validation. Defense-in-depth layer — the sandbox
    is the primary defense, this catches obvious injection attempts
    before code generation.
    """
    if not _IDENTIFIER_RE.match(spec.function):
        return f"invalid function name: {spec.function!r}"
    if spec.language in ("python", "ruby", "php", "perl", "javascript", "typescript",
                         "lua") and spec.function.lower() in _DANGEROUS_INTERP_FUNCS:
        return f"dangerous builtin as function name: {spec.function!r}"

    lc = spec.lang_config
    for expr in lc.get("arg_expressions", []):
        expr_s = str(expr)
        if _CODE_INJECTION_RE.search(expr_s):
            return f"code injection in arg_expression: {expr_s[:60]!r}"

    rt = lc.get("return_type", "")
    if rt and not _TYPE_RE.match(rt):
        return f"invalid return_type: {rt!r}"

    cn = lc.get("class_name", "")
    if cn and not _QUALIFIED_RE.match(cn):
        return f"invalid class_name: {cn!r}"

    up = lc.get("use_path", "")
    if up and not _QUALIFIED_RE.match(up):
        return f"invalid use_path: {up!r}"

    um = lc.get("use_module", "")
    if um and not _QUALIFIED_RE.match(um):
        return f"invalid use_module: {um!r}"

    ip = lc.get("import_path", "")
    if ip and not re.match(r"^[a-zA-Z0-9_./-]+$", ip):
        return f"invalid import_path: {ip!r}"

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

    source_file = target_root / spec.file
    if not source_file.is_file():
        return DarkVerifyResult(
            finding_key=spec.finding_key,
            verdict="error",
            language=lang,
            match_detail=f"source file not found: {spec.file}",
        )

    spec_err = validate_spec(spec)
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
        return DarkVerifyResult(
            finding_key=spec.finding_key, verdict="confirmed",
            language=language,
            actual_exception=f"{exc_type}: {exc_msg}",
            match_detail="unexpected exception confirms bug",
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
            if actual_repr.lower() == expected_repr.lower():
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
    """Write a script to disk, run it in the sandbox, classify output."""
    script_file = None
    try:
        fd, script_path = tempfile.mkstemp(suffix=suffix, prefix="raptor_dark_")
        os.close(fd)
        script_file = Path(script_path)
        script_file.write_text(script, encoding="utf-8")

        try:
            from core.sandbox.context import run as sandbox_run
            proc = sandbox_run(
                cmd_prefix + [str(script_file)],
                block_network=True,
                target=str(target_root),
                capture_output=True, text=True,
                timeout=timeout_s,
                caller_label=f"audit-dark-verify-{language}",
                tool_paths=[str(script_file.parent)],
            )
        except ImportError:
            logger.warning(
                "sandbox unavailable, falling back to unsandboxed execution for %s",
                language,
            )
            from core.config import RaptorConfig
            proc = subprocess.run(
                cmd_prefix + [str(script_file)],
                capture_output=True, text=True,
                timeout=timeout_s,
                env=RaptorConfig.get_safe_env(),
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
        if script_file and script_file.exists():
            with contextlib.suppress(OSError):
                script_file.unlink()


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
    try:
        from core.sandbox.context import run as sandbox_run
        proc = sandbox_run(
            [str(binary)],
            block_network=True,
            target=str(target_root),
            capture_output=True, text=True,
            timeout=timeout_s,
            caller_label="audit-dark-verify-native",
            tool_paths=[str(binary.parent)],
            env=env,
            strict_env=True,
        )
    except ImportError:
        logger.warning(
            "sandbox unavailable, falling back to unsandboxed"
            " execution for native binary",
        )
        proc = subprocess.run(
            [str(binary)],
            capture_output=True, text=True,
            timeout=timeout_s,
            env=env,
        )

    sandbox_info = getattr(proc, "sandbox_info", None)
    return _classify_native_output(spec, proc, sandbox_info, lang)


def _classify_native_output(
    spec: DarkWitnessSpec,
    proc: subprocess.CompletedProcess,
    sandbox_info: dict | None,
    lang: str,
) -> DarkVerifyResult:
    """Classify output from a native binary execution."""
    from core.witness.sandbox_outcome import outcome_from_sandbox_info
    from core.witness.types import WitnessOutcome

    outcome, detail = outcome_from_sandbox_info(sandbox_info, proc.returncode)

    if outcome == WitnessOutcome.SANITIZER_REPORT:
        sanitizer_type = detail.get("sanitizer", "")
        return DarkVerifyResult(
            finding_key=spec.finding_key,
            verdict="confirmed",
            language=lang,
            actual_exception=f"sanitizer: {sanitizer_type}",
            match_detail=f"ASan/UBSan fired: {sanitizer_type}",
        )

    if outcome == WitnessOutcome.EXIT_SIGNAL:
        signal = detail.get("signal", "unknown")
        return DarkVerifyResult(
            finding_key=spec.finding_key, verdict="confirmed",
            language=lang,
            actual_exception=f"signal: {signal}",
            match_detail=(
                f"crash signal {signal} confirms bug"
                if spec.expected_crash
                else f"unexpected crash ({signal}) confirms bug"
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
    work_dir = None
    try:
        work_dir = Path(tempfile.mkdtemp(prefix="raptor_dark_c_"))
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

        from core.config import RaptorConfig
        safe_env = RaptorConfig.get_safe_env()

        comp = subprocess.run(
            compile_cmd, capture_output=True, text=True,
            timeout=_COMPILE_TIMEOUT_S, env=safe_env,
        )
        if comp.returncode != 0:
            return DarkVerifyResult(
                finding_key=spec.finding_key, verdict="error", language=lang,
                match_detail=f"compilation failed: {(comp.stderr or '')[:300]}",
            )

        return _run_native_binary(spec, binary, target_root, timeout_s, lang)

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
    finally:
        if work_dir and work_dir.exists():
            with contextlib.suppress(OSError):
                shutil.rmtree(work_dir)


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
    work_dir = None
    try:
        work_dir = Path(tempfile.mkdtemp(prefix="raptor_dark_go_"))
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
        comp = subprocess.run(
            build_cmd, capture_output=True, text=True,
            timeout=_COMPILE_TIMEOUT_S, env=safe_env,
        )
        if comp.returncode != 0:
            stderr = (comp.stderr or "")[:300]
            return DarkVerifyResult(
                finding_key=spec.finding_key, verdict="error", language="go",
                match_detail=f"go build failed: {stderr}",
            )

        return _run_native_binary(spec, binary, target_root, timeout_s, "go")

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
    finally:
        if work_dir and work_dir.exists():
            with contextlib.suppress(OSError):
                shutil.rmtree(work_dir)


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


def _execute_rust(
    spec: DarkWitnessSpec,
    target_root: Path,
    timeout_s: int,
) -> DarkVerifyResult:
    rustc = shutil.which("rustc")
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
    work_dir = None
    try:
        work_dir = Path(tempfile.mkdtemp(prefix="raptor_dark_rs_"))
        harness_file = work_dir / "harness.rs"
        harness_file.write_text(harness_src, encoding="utf-8")
        binary = work_dir / "harness_bin"

        source_file = target_root / spec.file
        source_copy = work_dir / "target_source.rs"
        src_content = source_file.read_text(encoding="utf-8")
        source_copy.write_text(src_content, encoding="utf-8")
        compile_cmd = [
            rustc, "--edition", "2021",
            "-Z", "sanitizer=address",
            "-g", "-o", str(binary),
            str(harness_file), str(source_copy),
        ]

        from core.config import RaptorConfig
        safe_env = RaptorConfig.get_safe_env()

        comp = subprocess.run(
            compile_cmd, capture_output=True, text=True,
            timeout=_COMPILE_TIMEOUT_S, env=safe_env,
        )

        if comp.returncode != 0:
            compile_cmd_simple = [
                rustc, "--edition", "2021",
                "-g", "-o", str(binary),
                str(harness_file), str(source_copy),
            ]
            comp = subprocess.run(
                compile_cmd_simple, capture_output=True, text=True,
                timeout=_COMPILE_TIMEOUT_S, env=safe_env,
            )
            if comp.returncode != 0:
                return DarkVerifyResult(
                    finding_key=spec.finding_key, verdict="error",
                    language="rust",
                    match_detail=f"compilation failed: {(comp.stderr or '')[:300]}",
                )

        return _run_native_binary(spec, binary, target_root, timeout_s, "rust")

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
    finally:
        if work_dir and work_dir.exists():
            with contextlib.suppress(OSError):
                shutil.rmtree(work_dir)


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
    work_dir = None
    try:
        work_dir = Path(tempfile.mkdtemp(prefix="raptor_dark_java_"))
        harness_file = work_dir / "DarkWitnessHarness.java"
        harness_file.write_text(harness_src, encoding="utf-8")

        source_file = target_root / spec.file

        from core.config import RaptorConfig
        safe_env = RaptorConfig.get_safe_env()

        compile_cmd = [
            javac, "-cp",
            f"{work_dir}:{source_file.parent}:{target_root}",
            str(harness_file), str(source_file),
        ]

        comp = subprocess.run(
            compile_cmd, capture_output=True, text=True,
            timeout=_COMPILE_TIMEOUT_S, env=safe_env,
        )
        if comp.returncode != 0:
            return DarkVerifyResult(
                finding_key=spec.finding_key, verdict="error", language="java",
                match_detail=f"compilation failed: {(comp.stderr or '')[:300]}",
            )

        run_cmd = [
            java_bin, "-cp",
            f"{work_dir}:{source_file.parent}:{target_root}",
            "DarkWitnessHarness",
        ]

        try:
            from core.sandbox.context import run as sandbox_run
            proc = sandbox_run(
                run_cmd,
                block_network=True,
                target=str(target_root),
                capture_output=True, text=True,
                timeout=timeout_s,
                caller_label="audit-dark-verify-java",
                tool_paths=[str(work_dir)],
            )
        except ImportError:
            logger.warning(
                "sandbox unavailable, falling back to"
                " unsandboxed execution for java",
            )
            proc = subprocess.run(
                run_cmd, capture_output=True, text=True,
                timeout=timeout_s, env=safe_env,
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
    finally:
        if work_dir and work_dir.exists():
            with contextlib.suppress(OSError):
                shutil.rmtree(work_dir)


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
