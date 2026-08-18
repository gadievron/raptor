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
from typing import Any

from ._types import DarkWitnessSpec

# ---------------------------------------------------------------------------
# Helpers shared across harness generators
# ---------------------------------------------------------------------------


def _format_args_scripting(args: list[Any], *, nil_kw: str = "nil") -> str:
    """Format args for Ruby/PHP/Lua — languages that use nil/null keywords."""
    parts = []
    for a in args:
        if isinstance(a, str):
            parts.append(json.dumps(a))
        elif a is None:
            parts.append(nil_kw)
        elif isinstance(a, bool):
            parts.append("true" if a else "false")
        else:
            parts.append(str(a))
    return ", ".join(parts)


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------


def file_to_import_path(file_path: str, target_root: Path) -> str | None:
    """``core/audit/gate.py`` → ``core.audit.gate``. None for non-Python."""
    rel = file_path.replace("\\", "/")
    p = PurePosixPath(rel)
    if p.suffix != ".py":
        return None
    parts = list(p.parts)
    parts[-1] = p.stem
    if parts[-1] == "__init__":
        parts = parts[:-1]
    if not parts:
        return None
    return ".".join(parts)


def validate_import_path(
    spec: DarkWitnessSpec,
    target_root: Path,
) -> str | None:
    """Returns an error string if invalid, None if ok."""
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
    return None


def generate_witness_script(
    spec: DarkWitnessSpec,
    target_root: Path,
) -> str:
    """Render a fixed-template Python script."""
    args_json = json.dumps(spec.args)
    kwargs_json = json.dumps(spec.kwargs)
    target_str = str(target_root.resolve())
    return textwrap.dedent(f"""\
        import sys, json
        sys.path.insert(0, {target_str!r})
        try:
            from {spec.module_path} import {spec.function}
        except ImportError as e:
            print(json.dumps({{"status": "import_error", "message": str(e)}}))
            sys.exit(0)
        except Exception as e:
            print(json.dumps({{"status": "import_error", "message": str(e)}}))
            sys.exit(0)
        _args = json.loads({args_json!r})
        _kwargs = json.loads({kwargs_json!r})
        try:
            _result = {spec.function}(*_args, **_kwargs)
            print(json.dumps({{"status": "returned", "value": repr(_result)}}))
        except Exception as e:
            print(json.dumps({{
                "status": "exception",
                "type": type(e).__name__,
                "message": str(e),
            }}))
    """)


# ---------------------------------------------------------------------------
# C / C++
# ---------------------------------------------------------------------------


def generate_c_harness(
    spec: DarkWitnessSpec,
    target_root: Path,
) -> str:
    """Render a fixed-template C harness."""
    lc = spec.lang_config
    includes = lc.get("includes", [])
    param_types = lc.get("param_types", [])
    return_type = lc.get("return_type", "int")
    setup_lines = lc.get("setup_lines", [])
    arg_exprs = lc.get("arg_expressions", spec.args)

    parts = ['#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n']
    for inc in includes:
        safe = re.sub(r'[^a-zA-Z0-9_/.\-]', '', inc)
        if safe and '..' not in safe and not safe.startswith('/'):
            parts.append(f'#include <{safe}>\n')

    params_str = ", ".join(param_types) if param_types else ""
    parts.append(f'extern {return_type} {spec.function}({params_str});\n')

    parts.append('int main(void) {\n')
    for line in setup_lines:
        parts.append(f'    {line}\n')

    args_str = ", ".join(str(a) for a in arg_exprs)
    if return_type == "void":
        parts.append(f'    {spec.function}({args_str});\n')
        parts.append('    printf("{\\\"status\\\":\\\"returned\\\",\\\"value\\\":\\\"void\\\"}\\n");\n')
    else:
        parts.append(f'    {return_type} _result = {spec.function}({args_str});\n')
        fmt = _c_format_for_type(return_type)
        parts.append(f'    printf("{{\\"status\\":\\"returned\\",\\"value\\":\\"{fmt}\\"}}\\n"'
                      f', _result);\n')

    parts.append('    return 0;\n}\n')
    return "".join(parts)


def _c_format_for_type(return_type: str) -> str:
    stripped = return_type.strip()
    if stripped.endswith("*"):
        base = stripped.rstrip("*").strip()
        if base == "char":
            return "%s"
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
    target_root: Path,
) -> str:
    """Render a fixed-template Go harness."""
    lc = spec.lang_config
    go_package = lc.get("package", "main")
    arg_exprs = lc.get("arg_expressions", [str(a) for a in spec.args])
    return_type = lc.get("return_type", "")

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
    parts.append('\tValue  string `json:"value"`\n')
    parts.append('\tType   string `json:"type,omitempty"`\n')
    parts.append('\tMsg    string `json:"message,omitempty"`\n')
    parts.append('}\n\n')

    parts.append('func main() {\n')
    parts.append('\tdefer func() {\n')
    parts.append('\t\tif r := recover(); r != nil {\n')
    parts.append('\t\t\tout, _ := json.Marshal(result{\n')
    parts.append('\t\t\t\tStatus: "exception",\n')
    parts.append('\t\t\t\tType:   "panic",\n')
    parts.append('\t\t\t\tMsg:    fmt.Sprintf("%v", r),\n')
    parts.append('\t\t\t})\n')
    parts.append('\t\t\tfmt.Println(string(out))\n')
    parts.append('\t\t}\n')
    parts.append('\t}()\n')

    prefix = ""
    if go_package != "main":
        prefix = lc.get("import_alias", "target") + "."

    if return_type:
        parts.append(f'\tv := {prefix}{spec.function}({args_str})\n')
        parts.append('\tout, _ := json.Marshal(result{\n')
        parts.append('\t\tStatus: "returned",\n')
        parts.append('\t\tValue:  fmt.Sprintf("%v", v),\n')
        parts.append('\t})\n')
    else:
        parts.append(f'\t{prefix}{spec.function}({args_str})\n')
        parts.append('\tout, _ := json.Marshal(result{\n')
        parts.append('\t\tStatus: "returned",\n')
        parts.append('\t\tValue:  "void",\n')
        parts.append('\t})\n')

    parts.append('\tfmt.Println(string(out))\n')
    parts.append('\tos.Exit(0)\n')
    parts.append('}\n')
    return "".join(parts)


# ---------------------------------------------------------------------------
# JavaScript / TypeScript
# ---------------------------------------------------------------------------


def _js_require_path(spec: DarkWitnessSpec, *, strip_suffixes: tuple[str, ...]) -> str:
    """Resolve require path from spec or file."""
    rp = spec.lang_config.get("require_path", "")
    if rp:
        return rp
    rel = spec.file
    for suffix in strip_suffixes:
        if rel.endswith(suffix):
            rel = rel[: -len(suffix)]
            break
    return "./" + rel


def generate_js_harness(
    spec: DarkWitnessSpec,
    target_root: Path,
) -> str:
    """Render a fixed-template Node.js harness."""
    require_path = _js_require_path(spec, strip_suffixes=(".js", ".mjs", ".cjs"))
    target_str = str(target_root.resolve())
    args_json = json.dumps(spec.args)
    func_name = spec.function

    return textwrap.dedent(f"""\
        'use strict';
        const path = require('path');
        process.chdir({json.dumps(target_str)});
        let mod;
        try {{
            mod = require(path.resolve({json.dumps(target_str)}, {json.dumps(require_path)}));
        }} catch (e) {{
            console.log(JSON.stringify({{
                status: 'import_error',
                message: e.message,
            }}));
            process.exit(0);
        }}
        const fn = mod.{func_name} || mod.default && mod.default.{func_name};
        if (!fn) {{
            console.log(JSON.stringify({{
                status: 'import_error',
                message: 'function {func_name} not found in module',
            }}));
            process.exit(0);
        }}
        const args = {args_json};
        try {{
            const result = fn(...args);
            console.log(JSON.stringify({{
                status: 'returned',
                value: String(result),
            }}));
        }} catch (e) {{
            console.log(JSON.stringify({{
                status: 'exception',
                type: e.constructor.name,
                message: e.message,
            }}));
        }}
    """)


def generate_ts_harness(
    spec: DarkWitnessSpec,
    target_root: Path,
) -> str:
    """Render a TypeScript harness (same shape as JS but with TS import)."""
    require_path = _js_require_path(
        spec, strip_suffixes=(".ts", ".tsx", ".mts", ".cts"),
    )
    target_str = str(target_root.resolve())
    args_json = json.dumps(spec.args)
    func_name = spec.function

    return textwrap.dedent(f"""\
        import * as path from 'path';
        process.chdir({json.dumps(target_str)});
        let mod: any;
        try {{
            mod = require(path.resolve({json.dumps(target_str)}, {json.dumps(require_path)}));
        }} catch (e: any) {{
            console.log(JSON.stringify({{
                status: 'import_error',
                message: e.message,
            }}));
            process.exit(0);
        }}
        const fn = mod.{func_name} || (mod.default && mod.default.{func_name});
        if (!fn) {{
            console.log(JSON.stringify({{
                status: 'import_error',
                message: 'function {func_name} not found in module',
            }}));
            process.exit(0);
        }}
        const args = {args_json};
        try {{
            const result = fn(...args);
            console.log(JSON.stringify({{
                status: 'returned',
                value: String(result),
            }}));
        }} catch (e: any) {{
            console.log(JSON.stringify({{
                status: 'exception',
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
) -> str:
    """Render a fixed-template Ruby harness."""
    lc = spec.lang_config
    require_path = lc.get("require_path", "")
    if not require_path:
        rel = spec.file
        rel = rel.removesuffix(".rb")
        require_path = rel

    target_str = str(target_root.resolve())
    args_str = _format_args_scripting(spec.args, nil_kw="nil")

    return textwrap.dedent(f"""\
        require 'json'
        $LOAD_PATH.unshift({json.dumps(target_str)})
        begin
          require {json.dumps(require_path)}
        rescue LoadError => e
          puts JSON.generate({{ status: 'import_error', message: e.message }})
          exit 0
        end
        begin
          _result = {spec.function}({args_str})
          puts JSON.generate({{ status: 'returned', value: _result.inspect }})
        rescue => e
          puts JSON.generate({{
            status: 'exception',
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
) -> str:
    """Render a fixed-template PHP harness."""
    lc = spec.lang_config
    require_path = lc.get("require_path", spec.file)
    target_str = str(target_root.resolve())
    args_str = _format_args_scripting(spec.args, nil_kw="null")

    return textwrap.dedent(f"""\
        <?php
        try {{
            require_once({json.dumps(target_str + "/" + require_path)});
        }} catch (Throwable $e) {{
            echo json_encode([
                'status' => 'import_error',
                'message' => $e->getMessage(),
            ]);
            exit(0);
        }}
        try {{
            $result = {spec.function}({args_str});
            echo json_encode([
                'status' => 'returned',
                'value' => var_export($result, true),
            ]);
        }} catch (Throwable $e) {{
            echo json_encode([
                'status' => 'exception',
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
    target_root: Path,
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

    args_str = ", ".join(arg_exprs)

    parts = []
    parts.append('// Target source spliced in by _execute_rust (single crate root).\n')
    parts.append('include!("target_source.rs");\n')
    if use_path:
        parts.append(f'use {use_path};\n')
    parts.append('\nfn main() {\n')
    for line in setup_lines:
        parts.append(f'    {line}\n')

    if return_type and return_type != "()":
        parts.append(f'    let result = {spec.function}({args_str});\n')
        parts.append(
            '    println!("{{\\"status\\":\\"returned\\",'
            '\\"value\\":\\"{:?}\\"}}", result);\n'
        )
    else:
        parts.append(f'    {spec.function}({args_str});\n')
        parts.append(
            '    println!("{{\\"status\\":\\"returned\\",'
            '\\"value\\":\\"void\\"}}");\n'
        )
    parts.append('}\n')
    return "".join(parts)


# ---------------------------------------------------------------------------
# Java
# ---------------------------------------------------------------------------


def generate_java_harness(
    spec: DarkWitnessSpec,
    target_root: Path,
) -> str:
    """Render a fixed-template Java harness."""
    lc = spec.lang_config
    class_name = lc.get("class_name", "") or PurePosixPath(spec.file).stem
    imports = lc.get("imports", [])
    arg_exprs = lc.get("arg_expressions", [str(a) for a in spec.args])
    is_static = lc.get("is_static", True)
    return_type = lc.get("return_type", "Object")

    args_str = ", ".join(arg_exprs)

    parts = []
    for imp in imports:
        safe_imp = imp.replace(";", "").strip()
        parts.append(f'import {safe_imp};\n')

    parts.append('\npublic class DarkWitnessHarness {\n')
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
        parts.append(
            '            System.out.println('
            '"{\\"status\\":\\"returned\\",'
            '\\"value\\":\\"" + result + "\\"}");\n'
        )
    else:
        parts.append(f'            {call_target}({args_str});\n')
        parts.append(
            '            System.out.println('
            '"{\\"status\\":\\"returned\\",'
            '\\"value\\":\\"void\\"}");\n'
        )

    parts.append('        } catch (Exception e) {\n')
    parts.append(
        '            String _msg = e.getMessage() == null ? "" : e.getMessage()'
        '.replace("\\\\", "\\\\\\\\").replace("\\"", "\\\\\\"");\n'
    )
    parts.append(
        '            System.out.println('
        '"{\\"status\\":\\"exception\\",'
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
) -> str:
    """Render a fixed-template Lua harness."""
    lc = spec.lang_config
    require_path = lc.get("require_path", "")
    if not require_path:
        rel = spec.file
        rel = rel.removesuffix(".lua")
        require_path = rel.replace("/", ".")

    args_str = _format_args_scripting(spec.args, nil_kw="nil")
    target_str = str(target_root.resolve())

    return textwrap.dedent(f"""\
        package.path = {json.dumps(target_str)} .. '/?.lua;' .. package.path
        local json_ok = true
        local function json_encode(t)
            local parts = {{}}
            for k, v in pairs(t) do
                local vstr
                if type(v) == "string" then
                    vstr = '"' .. v:gsub('"', '\\\\"') .. '"'
                elseif v == nil then
                    vstr = "null"
                else
                    vstr = tostring(v)
                end
                parts[#parts+1] = '"' .. k .. '":' .. vstr
            end
            return '{{' .. table.concat(parts, ',') .. '}}'
        end
        local ok_req, mod = pcall(require, {json.dumps(require_path)})
        if not ok_req then
            print(json_encode({{status="import_error", message=tostring(mod)}}))
            os.exit(0)
        end
        local fn = mod
        if type(mod) == "table" then
            fn = mod.{spec.function}
        end
        if type(fn) ~= "function" then
            print(json_encode({{status="import_error", message="function {spec.function} not found"}}))
            os.exit(0)
        end
        local ok, result = pcall(fn, {args_str})
        if ok then
            print(json_encode({{status="returned", value=tostring(result)}}))
        else
            print(json_encode({{status="exception", type="error", message=tostring(result)}}))
        end
    """)


# ---------------------------------------------------------------------------
# Perl
# ---------------------------------------------------------------------------


def generate_perl_harness(
    spec: DarkWitnessSpec,
    target_root: Path,
) -> str:
    """Render a fixed-template Perl harness."""
    lc = spec.lang_config
    use_module = lc.get("use_module", "")
    if not use_module:
        rel = spec.file
        if rel.endswith((".pl", ".pm")):
            rel = rel[:-3]
        use_module = rel.replace("/", "::")

    target_str = str(target_root.resolve())
    args_str = _format_args_scripting(spec.args, nil_kw="undef")

    return textwrap.dedent(f"""\
        use strict;
        use warnings;
        use JSON::PP;
        use lib {json.dumps(target_str)};
        eval {{ require {use_module}; {use_module}->import() if {use_module}->can('import'); }};
        if ($@) {{
            print encode_json({{status => 'import_error', message => "$@"}});
            exit 0;
        }}
        eval {{
            my $result = {spec.function}({args_str});
            print encode_json({{status => 'returned', value => "$result"}});
        }};
        if ($@) {{
            my $err = "$@";
            my $type = 'die';
            if (ref $@ && ref($@) =~ /^\\w/) {{
                $type = ref $@;
            }}
            print encode_json({{status => 'exception', type => $type, message => $err}});
        }}
    """)
