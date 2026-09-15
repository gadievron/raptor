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
    (dotted names), the Go import_alias (single identifier).
    Free-form code never reaches the harness.
  - The harness generates the test from a fixed template.
  - Module binding holds in the RESOLUTION direction: every language
    lane asks whether the reference the harness hands the loader
    resolves to the finding's file under the loader's real rules,
    through one engine (_resolve.py) with per-language adapters —
    C/C++/Rust register as structural lanes (compiled directly
    against spec.file). The STATIC engine is the refusal authority:
    an unresolvable reference, or one whose earlier loader slots are
    occupied or unverifiable at validation time, is refused, never
    executed — for the slot models the adapters encode, as probed
    per lane with plantable lookalikes by TestLaneBindingClosure.
    The Python/Ruby/Perl harnesses add a BEST-EFFORT post-load belt
    (module __file__ / %INC / $LOADED_FEATURES): it reports
    binding_error instead of a verdict for mis-binds where no plant
    code runs, but it reads interpreter state after target code has
    executed, so it is not a defense against executing plants — those
    are the static engine's to refuse. Lua's package.searchpath
    re-check runs BEFORE require and is the one belt target code
    cannot have forged. The witness is likewise bound to the
    finding's FUNCTION — a response naming any other function or
    module is rejected, never executed.
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
    floor_refusal_result,
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
    "floor_refusal_result",
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
