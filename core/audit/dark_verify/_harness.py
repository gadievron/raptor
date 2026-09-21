"""Harness generators for each supported language.

Every harness writes JSON to stdout in the same shape:
  {"status": "returned"|"exception"|"import_error", ...}

This lets the shared classifier (_classify_json_output) handle all
interpreted languages uniformly.
"""

from __future__ import annotations

import json
import re
import textwrap
from pathlib import Path, PurePosixPath
from typing import Any, TYPE_CHECKING

from ._resolve import (
    _LUA_PATH_TEMPLATES,
    binding_error,
    derive_lua_require_path,
    derive_perl_use_module,
    derive_php_require_path,
    derive_ruby_require_path,
    derive_js_require_path as _js_require_path,
    file_to_import_path,
)

if TYPE_CHECKING:
    from ._types import DarkWitnessSpec
    from collections.abc import Callable

# ---------------------------------------------------------------------------
# Helpers shared across harness generators
# ---------------------------------------------------------------------------

# Pre-call sentinel the native harnesses write to stderr (flushed)
# immediately before invoking the target function. The classifier only
# accepts a crash/sanitizer signal when the sentinel was observed: the
# LLM controls the prediction AND every field that runs before the
# call, so a pre-call failure (setup line, constructor, initializer)
# must never read as the target crashing. The token half is generated
# in-process AFTER the LLM response is parsed — neither the witness
# LLM nor the scanned repo can know it.
_CALL_MARKER_PREFIX = "__raptor_witness_start__:"

# Every ``witness_token`` value is produced by ``secrets.token_hex``
# in the executors; validate the shape anyway so a caller-supplied
# token can never break out of the string/JSON contexts the harness
# templates embed it in.
_TOKEN_RE = re.compile(r"^[a-f0-9]*\Z")


def _checked_token(witness_token: str) -> str:
    token = str(witness_token or "")
    if not _TOKEN_RE.match(token):
        msg = f"invalid witness token: {token[:40]!r}"
        raise ValueError(msg)
    return token


def _single_quote(s: str) -> str:
    r"""Render *s* as a single-quoted Ruby/Perl/PHP string literal.

    Double-quoted strings interpolate in all three languages — Ruby
    ``#{...}``, Perl ``@{[...]}``/``$var``, PHP ``$var`` — so a
    ``json.dumps``-rendered witness argument is an eval sink.
    Single-quoted strings recognise exactly two escape sequences
    (``\\`` and ``\'``) and interpolate nothing, so escaping those
    two characters makes the value pure data in every one of them.
    """
    return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _lua_quote(s: str) -> str:
    r"""Render *s* as a single-quoted Lua string literal.

    Lua interpolates nothing, but backslash escapes are live in BOTH
    quote styles and a raw newline ends the literal — and JSON's
    ``\uXXXX`` spelling is not valid Lua. Escape the backslash and
    quote, and spell control bytes with Lua's decimal ``\ddd`` form
    (always three digits so a following digit cannot extend it).
    """
    out = []
    for ch in s:
        if ch == "\\":
            out.append("\\\\")
        elif ch == "'":
            out.append("\\'")
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append("\\%03d" % ord(ch))
        else:
            out.append(ch)
    return "'" + "".join(out) + "'"


def _format_args_scripting(
    args: list[Any],
    *,
    nil_kw: str = "nil",
    quote: Callable[[str], str] = _single_quote,
    seq_delims: tuple[str, str] = ("[", "]"),
    map_delims: tuple[str, str] = ("{", "}"),
    kv_fmt: str = "{k} => {v}",
) -> str:
    """Format args for Ruby/PHP/Lua/Perl — every string rendered as a
    non-interpolating literal via *quote*, containers recursively (a
    ``str()`` fallback would smuggle Python ``repr`` quoting — sometimes
    double quotes — into the target language)."""

    def render(a: Any) -> str:
        if isinstance(a, str):
            return quote(a)
        if a is None:
            return nil_kw
        if isinstance(a, bool):
            return "true" if a else "false"
        if isinstance(a, (int, float)):
            return str(a)
        if isinstance(a, (list, tuple)):
            inner = ", ".join(render(x) for x in a)
            return f"{seq_delims[0]}{inner}{seq_delims[1]}"
        if isinstance(a, dict):
            inner = ", ".join(
                kv_fmt.format(k=render(str(k)), v=render(v))
                for k, v in a.items()
            )
            return f"{map_delims[0]}{inner}{map_delims[1]}"
        # Unknown type: render as string DATA, never as code.
        return quote(str(a))

    return ", ".join(render(a) for a in args)


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------


def validate_import_path(
    spec: DarkWitnessSpec,
    target_root: Path,
) -> str | None:
    """Returns an error string if invalid, None if ok.

    The Python executor's binding gate: module_path must be present,
    the finding's file must exist, and the reference must resolve to
    it under CPython's own rules (the resolution engine also refuses a
    repo-planted package-directory shadow of the finding's module).
    """
    expected = file_to_import_path(spec.file, target_root)
    if expected is None:
        return f"non-Python file: {spec.file}"
    if spec.module_path != expected:
        return (
            f"module_path mismatch: LLM said {spec.module_path!r} "
            f"but file {spec.file!r} implies {expected!r}"
        )
    source_file = target_root / spec.file
    if not source_file.is_file():
        return f"source file not found: {spec.file}"
    return binding_error(spec, "python", target_root)


def generate_witness_script(
    spec: DarkWitnessSpec,
    target_root: Path,
    *,
    witness_token: str = "",
) -> str:
    """Render a fixed-template Python script.

    After a successful import the script asserts the LOADED module's
    ``__file__`` is the finding's file, reporting ``binding_error``
    (never a verdict) on mismatch.  This belt is BEST-EFFORT, second
    to the static resolution engine (``_resolve``), which is the
    refusal authority: ``__file__`` is interpreter state read AFTER
    target code has run, so any executing plant can forge it — the
    belt catches only mis-binds where no plant code runs (a shadow
    that appeared after validation, a stale or mismatched
    environment).  Plants that would execute are the static engine's
    job to refuse pre-execution.
    """
    args_json = json.dumps(spec.args)
    kwargs_json = json.dumps(spec.kwargs)
    target_str = str(target_root.resolve())
    expected_file = target_str + "/" + spec.file.replace("\\", "/")
    token = _checked_token(witness_token)
    return textwrap.dedent(f"""\
        import sys, json, os.path
        _tok = {token!r}
        sys.path.insert(0, {target_str!r})
        try:
            from {spec.module_path} import {spec.function}
        except ImportError as e:
            print(json.dumps({{"status": "import_error", "token": _tok, "message": str(e)}}))
            sys.exit(0)
        except Exception as e:
            print(json.dumps({{"status": "import_error", "token": _tok, "message": str(e)}}))
            sys.exit(0)
        _mod = sys.modules.get({spec.module_path!r})
        _loaded = os.path.realpath(getattr(_mod, "__file__", "") or "")
        _expected = os.path.realpath({expected_file!r})
        if _loaded != _expected:
            print(json.dumps({{
                "status": "binding_error",
                "token": _tok,
                "message": "loaded %r, expected %r" % (_loaded, _expected),
            }}))
            sys.exit(0)
        _args = json.loads({args_json!r})
        _kwargs = json.loads({kwargs_json!r})
        try:
            _result = {spec.function}(*_args, **_kwargs)
            print(json.dumps({{"status": "returned", "token": _tok, "value": repr(_result)}}))
        except Exception as e:
            print(json.dumps({{
                "status": "exception",
                "token": _tok,
                "type": type(e).__name__,
                "message": str(e),
            }}))
    """)


# ---------------------------------------------------------------------------
# C / C++
# ---------------------------------------------------------------------------


def generate_c_harness(
    spec: DarkWitnessSpec,
    _target_root: Path,
    *,
    witness_token: str = "",
) -> str:
    """Render a fixed-template C harness."""
    lc = spec.lang_config
    includes = lc.get("includes", [])
    param_types = lc.get("param_types", [])
    return_type = lc.get("return_type", "int")
    setup_lines = lc.get("setup_lines", [])
    arg_exprs = lc.get("arg_expressions", spec.args)
    token = _checked_token(witness_token)
    token_json = f'\\"token\\":\\"{token}\\",' if token else ""

    parts = ['#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n']
    for inc in includes:
        safe = re.sub(r'[^a-zA-Z0-9_/.\-]', '', inc)
        if safe and '..' not in safe and not safe.startswith('/'):
            parts.append(f'#include <{safe}>\n')

    params_str = ", ".join(param_types) if param_types else ""
    parts.append(f'extern {return_type} {spec.function}({params_str});\n')

    parts.append('int main(void) {\n')
    parts.extend(f'    {line}\n' for line in setup_lines)

    if token:
        # Pre-call sentinel: a crash only attributes to the target
        # call if this line reached stderr first (see _harness header).
        parts.append(
            f'    fputs("{_CALL_MARKER_PREFIX}{token}\\n", stderr);\n'
            '    fflush(stderr);\n'
        )

    args_str = ", ".join(str(a) for a in arg_exprs)
    if return_type == "void":
        parts.append(f'    {spec.function}({args_str});\n')
        parts.append(f'    printf("{{\\"status\\":\\"returned\\",{token_json}\\"value\\":\\"void\\"}}\\n");\n')
    else:
        parts.append(f'    {return_type} _result = {spec.function}({args_str});\n')
        fmt = _c_format_for_type(return_type)
        parts.append(f'    printf("{{\\"status\\":\\"returned\\",{token_json}\\"value\\":\\"{fmt}\\"}}\\n"'
                      f', _result);\n')

    parts.append('    return 0;\n}\n')
    return "".join(parts)


def _c_format_for_type(return_type: str) -> str:
    stripped = return_type.strip()
    if stripped.endswith("*"):
        # Every pointer — including char* — prints as %p pointer
        # identity. %s would make the HARNESS dereference the returned
        # buffer after the pre-call sentinel: a function legitimately
        # returning a non-NUL-terminated buffer then overreads inside
        # harness code, and the post-sentinel sanitizer report would
        # classify as a confirmed bug in the target.
        return "%p"
    rt = stripped
    if rt in ("float", "double"):
        return "%g"
    if rt in ("char",):
        return "%c"
    if "unsigned" in return_type or rt in ("size_t",):
        return "%lu"
    if rt in ("long", "long long", "ssize_t", "ptrdiff_t", "int64_t"):
        return "%ld"
    return "%d"


# ---------------------------------------------------------------------------
# Go
# ---------------------------------------------------------------------------


def generate_go_harness(
    spec: DarkWitnessSpec,
    _target_root: Path,
    *,
    witness_token: str = "",
) -> str:
    """Render a fixed-template Go harness."""
    lc = spec.lang_config
    go_package = lc.get("package", "main")
    arg_exprs = lc.get("arg_expressions", [str(a) for a in spec.args])
    return_type = lc.get("return_type", "")
    token = _checked_token(witness_token)

    args_str = ", ".join(arg_exprs)

    parts = ['package main\n\nimport (\n\t"encoding/json"\n\t"fmt"\n\t"os"\n']
    if go_package != "main":
        import_alias = lc.get("import_alias", "target")
        import_path = lc.get("import_path", "")
        if import_path:
            parts.append(f'\t{import_alias} "{import_path}"\n')
    parts.append(')\n\n')

    parts.append('type result struct {\n')
    parts.append('\tStatus string `json:"status"`\n')
    parts.append('\tToken  string `json:"token,omitempty"`\n')
    parts.append('\tValue  string `json:"value"`\n')
    parts.append('\tType   string `json:"type,omitempty"`\n')
    parts.append('\tMsg    string `json:"message,omitempty"`\n')
    parts.append('}\n\n')

    parts.append('func main() {\n')
    parts.append('\tdefer func() {\n')
    parts.append('\t\tif r := recover(); r != nil {\n')
    parts.append('\t\t\tout, _ := json.Marshal(result{\n')
    parts.append('\t\t\t\tStatus: "exception",\n')
    if token:
        parts.append(f'\t\t\t\tToken:  "{token}",\n')
    parts.append('\t\t\t\tType:   "panic",\n')
    parts.append('\t\t\t\tMsg:    fmt.Sprintf("%v", r),\n')
    parts.append('\t\t\t})\n')
    parts.append('\t\t\tfmt.Println(string(out))\n')
    parts.append('\t\t}\n')
    parts.append('\t}()\n')

    prefix = ""
    if go_package != "main":
        prefix = lc.get("import_alias", "target") + "."

    if token:
        # Pre-call sentinel: a crash only attributes to the target
        # call if this line reached stderr first (see _harness header).
        parts.append(
            f'\tos.Stderr.WriteString("{_CALL_MARKER_PREFIX}{token}\\n")\n'
        )

    if return_type:
        parts.append(f'\tv := {prefix}{spec.function}({args_str})\n')
        parts.append('\tout, _ := json.Marshal(result{\n')
        parts.append('\t\tStatus: "returned",\n')
        if token:
            parts.append(f'\t\tToken:  "{token}",\n')
        parts.append('\t\tValue:  fmt.Sprintf("%v", v),\n')
        parts.append('\t})\n')
    else:
        parts.append(f'\t{prefix}{spec.function}({args_str})\n')
        parts.append('\tout, _ := json.Marshal(result{\n')
        parts.append('\t\tStatus: "returned",\n')
        if token:
            parts.append(f'\t\tToken:  "{token}",\n')
        parts.append('\t\tValue:  "void",\n')
        parts.append('\t})\n')

    parts.append('\tfmt.Println(string(out))\n')
    parts.append('\tos.Exit(0)\n')
    parts.append('}\n')
    return "".join(parts)


# ---------------------------------------------------------------------------
# JavaScript / TypeScript
# ---------------------------------------------------------------------------


def generate_js_harness(
    spec: DarkWitnessSpec,
    target_root: Path,
    *,
    witness_token: str = "",
) -> str:
    """Render a fixed-template Node.js harness."""
    require_path = _js_require_path(spec)
    target_str = str(target_root.resolve())
    args_json = json.dumps(spec.args)
    func_name = spec.function
    token_json = json.dumps(_checked_token(witness_token))

    return textwrap.dedent(f"""\
        'use strict';
        const path = require('path');
        const tok = {token_json};
        process.chdir({json.dumps(target_str)});
        let mod;
        try {{
            mod = require(path.resolve({json.dumps(target_str)}, {json.dumps(require_path)}));
        }} catch (e) {{
            console.log(JSON.stringify({{
                status: 'import_error',
                token: tok,
                message: e.message,
            }}));
            process.exit(0);
        }}
        const fn = mod.{func_name} || mod.default && mod.default.{func_name};
        if (!fn) {{
            console.log(JSON.stringify({{
                status: 'import_error',
                token: tok,
                message: 'function {func_name} not found in module',
            }}));
            process.exit(0);
        }}
        const args = {args_json};
        try {{
            const result = fn(...args);
            console.log(JSON.stringify({{
                status: 'returned',
                token: tok,
                value: String(result),
            }}));
        }} catch (e) {{
            console.log(JSON.stringify({{
                status: 'exception',
                token: tok,
                type: e.constructor.name,
                message: e.message,
            }}));
        }}
    """)


def generate_ts_harness(
    spec: DarkWitnessSpec,
    target_root: Path,
    *,
    witness_token: str = "",
) -> str:
    """Render a TypeScript harness (same shape as JS but with TS import)."""
    require_path = _js_require_path(spec)
    target_str = str(target_root.resolve())
    args_json = json.dumps(spec.args)
    func_name = spec.function
    token_json = json.dumps(_checked_token(witness_token))

    return textwrap.dedent(f"""\
        import * as path from 'path';
        const tok = {token_json};
        process.chdir({json.dumps(target_str)});
        let mod: any;
        try {{
            mod = require(path.resolve({json.dumps(target_str)}, {json.dumps(require_path)}));
        }} catch (e: any) {{
            console.log(JSON.stringify({{
                status: 'import_error',
                token: tok,
                message: e.message,
            }}));
            process.exit(0);
        }}
        const fn = mod.{func_name} || (mod.default && mod.default.{func_name});
        if (!fn) {{
            console.log(JSON.stringify({{
                status: 'import_error',
                token: tok,
                message: 'function {func_name} not found in module',
            }}));
            process.exit(0);
        }}
        const args = {args_json};
        try {{
            const result = fn(...args);
            console.log(JSON.stringify({{
                status: 'returned',
                token: tok,
                value: String(result),
            }}));
        }} catch (e: any) {{
            console.log(JSON.stringify({{
                status: 'exception',
                token: tok,
                type: e.constructor.name,
                message: e.message,
            }}));
        }}
    """)


# ---------------------------------------------------------------------------
# Ruby
# ---------------------------------------------------------------------------


def generate_ruby_harness(
    spec: DarkWitnessSpec,
    target_root: Path,
    *,
    witness_token: str = "",
) -> str:
    """Render a fixed-template Ruby harness.

    After a successful require the harness asserts the finding's file
    is among $LOADED_FEATURES — a load that never touched it bound
    some other artifact and reports binding_error, never a verdict.
    Membership is a runtime BELT (a plant that itself requires the
    real file would pass it); the verdict-bearing shadow refusal is
    the static resolution engine's.
    """
    require_path = derive_ruby_require_path(spec)

    target_str = str(target_root.resolve())
    args_str = _format_args_scripting(spec.args, nil_kw="nil")
    token_lit = _single_quote(_checked_token(witness_token))
    expected_lit = _single_quote(
        target_str + "/" + spec.file.replace("\\", "/"))

    return textwrap.dedent(f"""\
        require 'json'
        _tok = {token_lit}
        $LOAD_PATH.unshift({_single_quote(target_str)})
        begin
          require {_single_quote(require_path)}
        rescue LoadError => e
          puts JSON.generate({{ status: 'import_error', token: _tok, message: e.message }})
          exit 0
        end
        _expected = {expected_lit}
        _loaded = $LOADED_FEATURES.any? do |f|
          begin
            File.identical?(f, _expected)
          rescue StandardError
            false
          end
        end
        unless _loaded
          puts JSON.generate({{ status: 'binding_error', token: _tok,
            message: "finding file #{{_expected}} not among loaded features" }})
          exit 0
        end
        begin
          _result = {spec.function}({args_str})
          puts JSON.generate({{ status: 'returned', token: _tok, value: _result.inspect }})
        rescue => e
          puts JSON.generate({{
            status: 'exception',
            token: _tok,
            type: e.class.name,
            message: e.message,
          }})
        end
    """)


# ---------------------------------------------------------------------------
# PHP
# ---------------------------------------------------------------------------


def generate_php_harness(
    spec: DarkWitnessSpec,
    target_root: Path,
    *,
    witness_token: str = "",
) -> str:
    """Render a fixed-template PHP harness."""
    require_path = derive_php_require_path(spec)
    target_str = str(target_root.resolve())
    args_str = _format_args_scripting(
        spec.args, nil_kw="null",
        seq_delims=("[", "]"), map_delims=("[", "]"),
    )
    token_lit = _single_quote(_checked_token(witness_token))

    return textwrap.dedent(f"""\
        <?php
        $_tok = {token_lit};
        try {{
            require_once({_single_quote(target_str + "/" + require_path)});
        }} catch (Throwable $e) {{
            echo json_encode([
                'status' => 'import_error',
                'token' => $_tok,
                'message' => $e->getMessage(),
            ]);
            exit(0);
        }}
        try {{
            $result = {spec.function}({args_str});
            echo json_encode([
                'status' => 'returned',
                'token' => $_tok,
                'value' => var_export($result, true),
            ]);
        }} catch (Throwable $e) {{
            echo json_encode([
                'status' => 'exception',
                'token' => $_tok,
                'type' => get_class($e),
                'message' => $e->getMessage(),
            ]);
        }}
    """)


# ---------------------------------------------------------------------------
# Rust
# ---------------------------------------------------------------------------


def generate_rust_harness(
    spec: DarkWitnessSpec,
    _target_root: Path,
    *,
    witness_token: str = "",
) -> str:
    """Render a fixed-template Rust harness.

    rustc accepts exactly one crate root, so the harness pulls the target
    source in via ``include!`` rather than being compiled alongside it.
    Contract with ``_execute_rust``: the executor copies the target file to
    ``target_source.rs`` next to the harness in the work dir — ``include!``
    resolves relative to the including file, and token-splicing means a
    target file with its own item/mod tree still lands in a valid position
    at the crate root.
    """
    lc = spec.lang_config
    setup_lines = lc.get("setup_lines", [])
    arg_exprs = lc.get("arg_expressions", [str(a) for a in spec.args])
    return_type = lc.get("return_type", "")
    use_path = lc.get("use_path", "")
    token = _checked_token(witness_token)
    token_json = f'\\"token\\":\\"{token}\\",' if token else ""

    args_str = ", ".join(arg_exprs)

    parts = []
    parts.append('// Target source spliced in by _execute_rust (single crate root).\n')
    parts.append('include!("target_source.rs");\n')
    if use_path:
        parts.append(f'use {use_path};\n')
    parts.append('\nfn main() {\n')
    parts.extend(f'    {line}\n' for line in setup_lines)

    if token:
        # Pre-call sentinel: a crash only attributes to the target
        # call if this line reached stderr first (see _harness header).
        parts.append(
            f'    eprintln!("{_CALL_MARKER_PREFIX}{token}");\n'
        )

    if return_type and return_type != "()":
        parts.append(f'    let result = {spec.function}({args_str});\n')
        parts.append(
            '    println!("{{\\"status\\":\\"returned\\",'
            f'{token_json}'
            '\\"value\\":\\"{:?}\\"}}", result);\n'
        )
    else:
        parts.append(f'    {spec.function}({args_str});\n')
        parts.append(
            '    println!("{{\\"status\\":\\"returned\\",'
            f'{token_json}'
            '\\"value\\":\\"void\\"}}");\n'
        )
    parts.append('}\n')
    return "".join(parts)


# ---------------------------------------------------------------------------
# Java
# ---------------------------------------------------------------------------


# Same dotted-identifier allowlist as validate_spec's java-import
# check (defense in depth at the generator: an embedded newline used
# to survive the ';' strip and inject top-level Java code).
_JAVA_IMPORT_SAFE_RE = re.compile(
    r"^(?:static\s+)?[A-Za-z_$][A-Za-z0-9_$]*"
    r"(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*(?:\.\*)?\Z"
)


def generate_java_harness(
    spec: DarkWitnessSpec,
    _target_root: Path,
    *,
    witness_token: str = "",
) -> str:
    """Render a fixed-template Java harness."""
    lc = spec.lang_config
    class_name = lc.get("class_name", "") or PurePosixPath(spec.file).stem
    imports = lc.get("imports", [])
    arg_exprs = lc.get("arg_expressions", [str(a) for a in spec.args])
    is_static = lc.get("is_static", True)
    return_type = lc.get("return_type", "Object")
    token = _checked_token(witness_token)
    token_json = f'\\"token\\":\\"{token}\\",' if token else ""

    args_str = ", ".join(arg_exprs)

    parts = []
    for imp in imports:
        safe_imp = str(imp).replace(";", "").strip()
        if not _JAVA_IMPORT_SAFE_RE.match(safe_imp):
            continue  # validate_spec already rejected the spec; skip here
        parts.append(f'import {safe_imp};\n')

    parts.append('\npublic class DarkWitnessHarness {\n')
    # JSON-string escaper for the epilogue's repo-controlled text
    # (return value's toString(), exception message). Per-char
    # dispatch: backslash and quote get their JSON escapes, and every
    # control char becomes \\uXXXX (same coverage as the Lua lane's
    # json_escape) — so a legitimate multi-line toString()/message
    # stays ONE parseable status line instead of degrading a truthful
    # verdict to inconclusive on an unescaped newline.
    parts.append(
        '    private static String esc(String s) {\n'
        '        StringBuilder b = new StringBuilder();\n'
        '        for (int i = 0; i < s.length(); i++) {\n'
        '            char c = s.charAt(i);\n'
        '            if (c == \'\\\\\') b.append("\\\\\\\\");\n'
        '            else if (c == \'"\') b.append("\\\\\\"");\n'
        '            else if (c < 0x20) b.append('
        'String.format("\\\\u%04x", (int) c));\n'
        '            else b.append(c);\n'
        '        }\n'
        '        return b.toString();\n'
        '    }\n'
    )
    parts.append('    public static void main(String[] args) {\n')
    parts.append('        try {\n')

    call_target = (
        f'{class_name}.{spec.function}' if is_static
        else f'instance.{spec.function}'
    )
    if not is_static:
        parts.append(
            f'            {class_name} instance = new {class_name}();\n'
        )

    if return_type and return_type != "void":
        parts.append(
            f'            {return_type} result = {call_target}({args_str});\n'
        )
        # The return value is repo-controlled text (toString() of a
        # target object): concatenating it raw let a crafted value
        # smuggle duplicate keys into the token-authenticated verdict
        # JSON (json.loads keeps the LAST duplicate, so the injection
        # rode INSIDE the authenticated epilogue). esc() makes it
        # pure data — same escaper as the exception path's _msg.
        parts.append(
            '            String _val = esc(String.valueOf(result));\n'
        )
        parts.append(
            '            System.out.println('
            '"{\\"status\\":\\"returned\\",'
            f'{token_json}'
            '\\"value\\":\\"" + _val + "\\"}");\n'
        )
    else:
        parts.append(f'            {call_target}({args_str});\n')
        parts.append(
            '            System.out.println('
            '"{\\"status\\":\\"returned\\",'
            f'{token_json}'
            '\\"value\\":\\"void\\"}");\n'
        )

    parts.append('        } catch (Exception e) {\n')
    parts.append(
        '            String _msg = e.getMessage() == null ? "" : '
        'esc(e.getMessage());\n'
    )
    parts.append(
        '            System.out.println('
        '"{\\"status\\":\\"exception\\",'
        f'{token_json}'
        '\\"type\\":\\"" + e.getClass().getSimpleName() + "\\",'
        '\\"message\\":\\"" + _msg + "\\"}");\n'
    )
    parts.append('        }\n')
    parts.append('    }\n')
    parts.append('}\n')
    return "".join(parts)


# ---------------------------------------------------------------------------
# Lua
# ---------------------------------------------------------------------------


def generate_lua_harness(
    spec: DarkWitnessSpec,
    target_root: Path,
    *,
    witness_token: str = "",
) -> str:
    """Render a fixed-template Lua harness.

    package.path is rendered from ``_LUA_PATH_TEMPLATES`` — the same
    tuple the resolution engine derives its candidate slots from — so
    the search order the validator reasoned about IS the search order
    the interpreter runs.  Where the interpreter provides
    ``package.searchpath`` (5.2+, LuaJIT) the harness also re-runs the
    search at execution time and reports binding_error when it does
    not land on the finding's file.  Unlike the Python/Perl/Ruby
    post-load belts, this check runs BEFORE ``require`` executes
    anything — it is the one runtime belt target code cannot have
    forged (though the static engine remains the refusal authority
    for plants visible at validation time).
    """
    require_path = derive_lua_require_path(spec)

    args_str = _format_args_scripting(
        spec.args, nil_kw="nil", quote=_lua_quote,
        seq_delims=("{", "}"), map_delims=("{", "}"),
        kv_fmt="[{k}] = {v}",
    )
    target_str = str(target_root.resolve())
    token_lit = _lua_quote(_checked_token(witness_token))
    path_prefix = " .. ".join(
        f"{_lua_quote(target_str)} .. {_lua_quote('/' + t + ';')}"
        for t in _LUA_PATH_TEMPLATES
    )
    expected_lit = _lua_quote(
        target_str + "/" + spec.file.replace("\\", "/"))

    return textwrap.dedent(f"""\
        package.path = {path_prefix} .. package.path
        local _tok = {token_lit}
        local json_ok = true
        local function json_escape(s)
            -- Backslash FIRST: escaping the quote first would let a
            -- message containing backslash-quote re-open the string.
            s = s:gsub('\\\\', '\\\\\\\\')
            s = s:gsub('"', '\\\\"')
            s = s:gsub('%c', function(c)
                return string.format('\\\\u%04X', string.byte(c))
            end)
            return s
        end
        local function json_encode(t)
            local parts = {{}}
            for k, v in pairs(t) do
                local vstr
                if type(v) == "string" then
                    vstr = '"' .. json_escape(v) .. '"'
                else
                    vstr = tostring(v)
                end
                parts[#parts+1] = '"' .. k .. '":' .. vstr
            end
            return '{{' .. table.concat(parts, ',') .. '}}'
        end
        if package.searchpath then
            local _resolved = package.searchpath({_lua_quote(require_path)}, package.path)
            if _resolved ~= {expected_lit} then
                print(json_encode({{status="binding_error", token=_tok,
                    message="loaded " .. tostring(_resolved) .. ", expected " .. {expected_lit}}}))
                os.exit(0)
            end
        end
        local ok_req, mod = pcall(require, {_lua_quote(require_path)})
        if not ok_req then
            print(json_encode({{status="import_error", token=_tok, message=tostring(mod)}}))
            os.exit(0)
        end
        local fn = mod
        if type(mod) == "table" then
            fn = mod.{spec.function}
        end
        if type(fn) ~= "function" then
            print(json_encode({{status="import_error", token=_tok, message="function {spec.function} not found"}}))
            os.exit(0)
        end
        local ok, result = pcall(fn, {args_str})
        if ok then
            print(json_encode({{status="returned", token=_tok, value=tostring(result)}}))
        else
            print(json_encode({{status="exception", token=_tok, type="error", message=tostring(result)}}))
        end
    """)


# ---------------------------------------------------------------------------
# Perl
# ---------------------------------------------------------------------------


def generate_perl_harness(
    spec: DarkWitnessSpec,
    target_root: Path,
    *,
    witness_token: str = "",
) -> str:
    """Render a fixed-template Perl harness.

    After a successful require the harness asserts %INC recorded the
    finding's file for the bareword's ``::``→``/`` + ``.pm`` key,
    reporting binding_error, never a verdict, on mismatch.  Best-effort
    belt behind the static resolution engine (the refusal authority):
    %INC is interpreter state read AFTER the required code has run, so
    an executing plant can rewrite it — the belt catches only
    mis-binds where no plant code runs (e.g. a load served by another
    @INC entry).
    """
    use_module = derive_perl_use_module(spec)

    target_str = str(target_root.resolve())
    args_str = _format_args_scripting(spec.args, nil_kw="undef")
    token_lit = _single_quote(_checked_token(witness_token))
    inc_key = use_module.replace("::", "/") + ".pm"
    expected_lit = _single_quote(target_str + "/" + inc_key)

    return textwrap.dedent(f"""\
        use strict;
        use warnings;
        use JSON::PP;
        use lib {_single_quote(target_str)};
        my $_tok = {token_lit};
        eval {{ require {use_module}; {use_module}->import() if {use_module}->can('import'); }};
        if ($@) {{
            print encode_json({{status => 'import_error', token => $_tok, message => "$@"}});
            exit 0;
        }}
        my $_loaded = $INC{{{_single_quote(inc_key)}}} || '';
        if ($_loaded ne {expected_lit}) {{
            print encode_json({{status => 'binding_error', token => $_tok,
                message => "loaded '$_loaded', expected " . {expected_lit}}});
            exit 0;
        }}
        eval {{
            my $result = {spec.function}({args_str});
            print encode_json({{status => 'returned', token => $_tok, value => "$result"}});
        }};
        if ($@) {{
            my $err = "$@";
            my $type = 'die';
            if (ref $@ && ref($@) =~ /^\\w/) {{
                $type = ref $@;
            }}
            print encode_json({{status => 'exception', token => $_tok, type => $type, message => $err}});
        }}
    """)
