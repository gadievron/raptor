"""Cheap preflight for automatic probes with an available defect oracle."""

import shutil

from ._types import DarkWitnessSpec, language_for_file

# ASan/UBSan-observable memory accesses, lifetime violations and arithmetic
# undefined behavior. These are oracle capabilities, not corpus labels.
# In particular, ordinary input rejection, authorization, resource accounting,
# and uninitialized-value claims need other property-specific oracles.
_SANITIZER_CWES = frozenset({
    "CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-124", "CWE-125",
    "CWE-126", "CWE-127", "CWE-131", "CWE-190", "CWE-191", "CWE-193",
    "CWE-369", "CWE-415", "CWE-416", "CWE-476", "CWE-787",
})
_COMPILERS = {"c": "cc", "cpp": "c++", "rust": "rustc"}


def automatic_witness_skip_reason(file: str, cwe: str = "") -> str:
    """Reject definite oracle gaps before paying for witness generation.

    Compiler presence does not guarantee a sanitizer build succeeds (e.g.
    Rust's toolchain may lack sanitizer support). Execution still checks
    instrumentation and admission still requires an independent violation.
    Unknown native claims remain eligible for a possible sanitizer result.
    """
    language = language_for_file(file)
    compiler = _COMPILERS.get(language)
    if compiler is None:
        return "no-independent-witness-oracle"
    label = cwe.strip().upper() if isinstance(cwe, str) else ""
    if label and not label.startswith("CWE-"):
        label = f"CWE-{label}"
    if label and label not in _SANITIZER_CWES:
        return "claim-has-no-sanitizer-oracle"
    if shutil.which(compiler) is None:
        return "witness-compiler-unavailable"
    return ""


def witness_requests_defect_oracle(spec) -> bool:
    """A normal return-value prediction cannot engage the native oracle."""
    return (isinstance(spec, DarkWitnessSpec)
            and spec.language in _COMPILERS
            and (spec.expected_crash is True
                 or isinstance(spec.expected_sanitizer, str) and bool(spec.expected_sanitizer.strip())))
