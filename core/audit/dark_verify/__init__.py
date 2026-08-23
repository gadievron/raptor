"""Witness-execution verification for dark findings.

Dark findings are tool-blind — mechanical detectors can't confirm or
refute them.  This module re-submits each dark finding to the LLM
asking for a *concrete witness* (function, args, expected result),
then mechanically executes that witness against the target codebase
to confirm or refute.

Supports Python, C/C++, Go, JavaScript, TypeScript, Ruby, PHP,
Rust, Java, Lua, and Perl targets.

Anti-hallucination design:
  - The LLM provides structured data (function, args, expected),
    NOT executable code. Every code-bearing field is validated
    against a typed allowlist grammar before generation:
    arg_expressions and native setup_lines (declaration-only),
    param_types / return_type (type spellings), Java imports
    (dotted names). Free-form code never reaches the harness.
  - The harness generates the test from a fixed template.
  - The import/source path is validated against the finding's file,
    and the witness is bound to the finding's FUNCTION — a response
    naming any other function is rejected, never executed.
  - The return value / crash signal is captured independently and
    authenticated: the harness embeds a per-execution token
    (generated in-process after the LLM response is parsed) in its
    JSON epilogue, and native harnesses write a pre-call sentinel to
    stderr. Output without the token, or a crash without the
    sentinel (i.e. before the target call), never confirms.
  - The LLM cannot fake a passing test.

For native targets (C/C++/Rust), the oracle is the *sanitizer/crash
signal* — ASan reports and SIGSEGV are mechanical observations bound
to the target call site by the sentinel; the declaration-only setup
grammar leaves the witness no channel to fabricate them.
"""

from ._types import (
    DarkVerifyResult,
    DarkWitnessSpec,
    language_for_file,
)
from ._harness import (
    file_to_import_path,
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
from ._execute import (
    _classify_output,
    execute_witness,
    validate_spec,
)
from ._prompts import (
    build_witness_prompt,
    parse_witness_response,
)

__all__ = [
    "DarkVerifyResult",
    "DarkWitnessSpec",
    "_classify_output",
    "build_witness_prompt",
    "execute_witness",
    "file_to_import_path",
    "generate_c_harness",
    "generate_go_harness",
    "generate_java_harness",
    "generate_js_harness",
    "generate_lua_harness",
    "generate_perl_harness",
    "generate_php_harness",
    "generate_ruby_harness",
    "generate_rust_harness",
    "generate_ts_harness",
    "generate_witness_script",
    "language_for_file",
    "parse_witness_response",
    "validate_import_path",
    "validate_spec",
]
