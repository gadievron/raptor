"""LLM-driven libFuzzer harness generation.

Most modern C/C++ libraries do not ship a binary that reads stdin and
calls into the parser. They expose functions, and the fuzzing community
writes harnesses (LLVMFuzzerTestOneInput) that wire bytes from the fuzzer
into those functions.

Writing a harness is mechanical but tedious. Given a header file and a
target function, the LLM can produce a working harness, including any
required setup, teardown, and bounds handling. This module does that.

Output: a single .c or .cc file containing a libFuzzer entry point. The
caller compiles it with clang -fsanitize=fuzzer,address (or equivalent).
"""

from __future__ import annotations

import logging
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)


@dataclass
class HarnessSpec:
    """Specification for a harness to generate."""

    target_function: str
    header_path: Path
    library_name: str = ""
    include_paths: List[str] = field(default_factory=list)
    extra_includes: List[str] = field(default_factory=list)
    setup_code: str = ""
    teardown_code: str = ""
    notes: str = ""

    def __post_init__(self) -> None:
        self.header_path = Path(self.header_path).resolve()
        if not self.header_path.exists():
            raise FileNotFoundError(f"Header not found: {self.header_path}")


@dataclass
class GeneratedHarness:
    """Result of harness generation."""

    source_code: str
    language: str           # "c" or "cpp"
    suggested_filename: str
    target_function: str
    compile_command: str    # clang -fsanitize=fuzzer,address ... -o harness
    rationale: str          # LLM-provided explanation


_HARNESS_SYSTEM_PROMPT = """You are a senior fuzzing engineer writing a libFuzzer harness for authorised security testing.

You will be given:
  1. A header file describing a target library
  2. The name of a target function to fuzz
  3. Any additional context (setup requirements, lifecycle constraints)

Your job is to produce one self-contained source file that:
  - Defines int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
  - Wires the fuzzer-supplied bytes into the target function in a meaningful way
  - Handles any required initialisation (LLVMFuzzerInitialize if needed)
  - Avoids leaks, double-frees, or state corruption between iterations
  - Returns 0 on success and 0 on failure (libFuzzer expects 0)
  - Compiles cleanly with clang -fsanitize=fuzzer,address

Rules:
  - The target function name will be passed in a slot. Do not change it.
  - If the target takes a (buf, len) pair, pass data and size directly.
  - If it takes a null-terminated string, allocate a copy with a trailing nul.
  - If it takes a structured input (parsed format), parse data conservatively
    and bail early on size constraints rather than crashing on edge cases
    that are not actual bugs in the target.
  - If the target requires global state, set it up in LLVMFuzzerInitialize.
  - Do not call rand() or use any non-deterministic source.

Respond with a JSON object containing:
  - source_code: the full harness source as a string
  - language: "c" or "cpp"
  - rationale: one paragraph explaining your design choices
"""


_FALLBACK_HARNESS_C = """/* Auto-generated libFuzzer harness fallback.
 * The LLM was unavailable or did not produce a valid harness, so this
 * is a generic byte-passing harness. Manual review is recommended.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "{header_basename}"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    if (size == 0) return 0;
    /* TODO: replace this stub with a call to {target_function} */
    (void)data;
    (void)size;
    return 0;
}}
"""


def _extract_target_signature(header_text: str, function_name: str) -> Optional[str]:
    """Best-effort extraction of a function signature from a header.

    Returns the matched declaration line (or block) or None if not found.
    Used only as additional context for the LLM, not for parsing.
    """
    safe_name = re.escape(function_name)
    # Match a declaration that starts somewhere on a line and ends at semicolon
    pattern = re.compile(
        rf"^[^;]*\b{safe_name}\s*\([^)]*\)\s*[a-zA-Z_]*\s*;",
        re.MULTILINE | re.DOTALL,
    )
    match = pattern.search(header_text)
    return match.group(0).strip() if match else None


class HarnessGenerator:
    """Generate libFuzzer harnesses for C/C++ functions."""

    def __init__(self, llm=None) -> None:
        self.llm = llm

    def generate(self, spec: HarnessSpec) -> GeneratedHarness:
        """Produce a libFuzzer harness for the given specification."""
        header_text = spec.header_path.read_text(errors="replace")
        signature = _extract_target_signature(header_text, spec.target_function)

        if self.llm is None:
            logger.warning("No LLM configured, returning fallback harness")
            source = _FALLBACK_HARNESS_C.format(
                header_basename=spec.header_path.name,
                target_function=spec.target_function,
            )
            return GeneratedHarness(
                source_code=source,
                language="c",
                suggested_filename=f"fuzz_{spec.target_function}.c",
                target_function=spec.target_function,
                compile_command=self._compile_command(
                    f"fuzz_{spec.target_function}.c", spec, language="c"
                ),
                rationale="Fallback harness; LLM unavailable.",
            )

        prompt = self._build_prompt(spec, header_text, signature)
        try:
            result, _ = self.llm.generate_structured(
                prompt=prompt,
                schema={
                    "source_code": "full harness source as a string",
                    "language": "either 'c' or 'cpp'",
                    "rationale": "one paragraph explanation",
                },
                system_prompt=_HARNESS_SYSTEM_PROMPT,
            )
        except Exception as e:
            logger.error(f"LLM harness generation failed: {e}")
            return self._fallback(spec, header_text)

        if not result or "source_code" not in result:
            return self._fallback(spec, header_text)

        source = str(result["source_code"]).strip()
        language = str(result.get("language", "cpp")).lower()
        if language not in ("c", "cpp"):
            language = "cpp"

        ext = ".c" if language == "c" else ".cc"
        filename = f"fuzz_{spec.target_function}{ext}"

        return GeneratedHarness(
            source_code=source,
            language=language,
            suggested_filename=filename,
            target_function=spec.target_function,
            compile_command=self._compile_command(filename, spec, language=language),
            rationale=str(result.get("rationale", "")).strip(),
        )

    def _fallback(self, spec: HarnessSpec, header_text: str) -> GeneratedHarness:
        source = _FALLBACK_HARNESS_C.format(
            header_basename=spec.header_path.name,
            target_function=spec.target_function,
        )
        filename = f"fuzz_{spec.target_function}.c"
        return GeneratedHarness(
            source_code=source,
            language="c",
            suggested_filename=filename,
            target_function=spec.target_function,
            compile_command=self._compile_command(filename, spec, language="c"),
            rationale="LLM produced no usable output; fallback harness emitted.",
        )

    def _build_prompt(
        self,
        spec: HarnessSpec,
        header_text: str,
        signature: Optional[str],
    ) -> str:
        parts = [
            f"Target function: {spec.target_function}",
            f"Header file: {spec.header_path.name}",
        ]
        if spec.library_name:
            parts.append(f"Library: {spec.library_name}")
        if signature:
            parts.append(f"Detected signature: {signature}")
        if spec.notes:
            parts.append(f"Notes: {spec.notes}")
        parts.append("")
        parts.append("Header contents (truncated to 8 KB if longer):")
        parts.append("```c")
        parts.append(header_text[:8192])
        parts.append("```")
        return "\n".join(parts)

    def _compile_command(
        self,
        harness_filename: str,
        spec: HarnessSpec,
        language: str = "cpp",
    ) -> str:
        # shlex.quote every interpolation that carries attacker-
        # influenced data (target binary symbol names, include paths
        # parsed from binary metadata, library names from header
        # inspection, generator-emitted filenames). The compile_command
        # is stored as a str on GeneratedHarness and consumed by
        # operators who typically `sh -c` it (or paste into a build
        # script) — an unquoted `target_function` containing `;` or
        # `$(...)` would be straight command injection in that flow.
        # Per PR #488 review.
        compiler = "clang++" if language == "cpp" else "clang"
        includes = " ".join(
            f"-I{shlex.quote(str(p))}" for p in spec.include_paths
        ) if spec.include_paths else ""
        lib_link = (
            f"-l{shlex.quote(spec.library_name)}"
            if spec.library_name else ""
        )
        sanitisers = "-fsanitize=fuzzer,address,undefined"
        opt = "-g -O1"

        return (
            f"{compiler} {sanitisers} {opt} {includes} "
            f"{shlex.quote(harness_filename)} {lib_link} "
            f"-o {shlex.quote(f'fuzz_{spec.target_function}')}"
        ).strip()

    def write(self, harness: GeneratedHarness, out_dir: Path) -> Path:
        """Write the generated harness to disk and return its path."""
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        target_path = out_dir / harness.suggested_filename
        target_path.write_text(harness.source_code)

        compile_script = out_dir / f"build_{harness.target_function}.sh"
        compile_script.write_text(
            "#!/bin/sh\n"
            "set -e\n"
            f"# Generated by RAPTOR for {harness.target_function}\n"
            f"{harness.compile_command}\n"
        )
        compile_script.chmod(0o755)

        logger.info(f"Wrote harness: {target_path}")
        logger.info(f"Wrote build script: {compile_script}")
        return target_path
