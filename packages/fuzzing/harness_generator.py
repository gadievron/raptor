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

from core.security.prompt_defense_profiles import CONSERVATIVE
from core.security.prompt_envelope import (
    PromptBundle,
    TaintedString,
    UntrustedBlock,
    build_prompt,
)
from core.security.prompt_input_preflight import preflight
from core.security.prompt_telemetry import defense_telemetry

logger = logging.getLogger(__name__)

# Symbol grammar for target_function. Unmangled C++ names must keep
# working (`ns::func`, `operator+`, `~Dtor`, `foo<int>`), so a bare
# C-identifier regex is too strict. Allow ASCII alphanumerics plus the
# punctuation that legitimately appears in unmangled symbols; anything
# else (newlines, quotes, backquotes, `$`, `;`, `#`, `/`, `\`) is
# hard-rejected at spec construction.
_SYMBOL_MAX_LEN = 256
_SYMBOL_ALLOWED_RE = re.compile(
    r"^[A-Za-z0-9_:~<>,&*()\[\]+\-=!%^|. ]+$"
)


def _validate_target_symbol(name: str) -> str:
    """Validate target_function against the symbol grammar.

    Returns the name unchanged when it conforms; raises ValueError
    otherwise. The raw symbol only ever reaches (i) generated source,
    where the C identifier slot uses _c_identifier() instead, and
    (ii) the shlex-quoted compile command.
    """
    name = str(name or "")
    if not name.strip():
        raise ValueError("target_function must be a non-empty symbol name")
    if len(name) > _SYMBOL_MAX_LEN:
        raise ValueError(
            f"target_function exceeds {_SYMBOL_MAX_LEN} characters"
        )
    if name.lstrip().startswith("-"):
        raise ValueError(
            f"target_function may not start with '-': {name!r}"
        )
    if not _SYMBOL_ALLOWED_RE.match(name):
        raise ValueError(
            f"target_function contains disallowed characters: {name!r}"
        )
    return name


def _c_identifier(symbol: str) -> str:
    """Derive a C-identifier-safe name from a (possibly C++) symbol.

    Used wherever the symbol lands in an identifier or filename slot
    (`fuzz_<name>.c`, `build_<name>.sh`) — the raw symbol is never
    embedded there. `ns::func<int>` becomes `ns_func_int`.
    """
    ident = re.sub(r"[^A-Za-z0-9_]+", "_", str(symbol or "")).strip("_")
    return ident[:80] or "target"


def _slug(value: str) -> str:
    """Reduce a value to a single bare filename component.

    Same pattern as packages/binary_analysis/harness.py — no path
    separators can survive, so the result can never traverse out of
    the output directory.
    """
    clean = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value or "")).strip("._")
    return clean[:80] or "harness"


@dataclass
class HarnessSpec:
    """Specification for a harness to generate."""

    target_function: str
    header_path: Path
    library_name: str = ""
    include_paths: list[str] = field(default_factory=list)
    extra_includes: list[str] = field(default_factory=list)
    setup_code: str = ""
    teardown_code: str = ""
    notes: str = ""

    def __post_init__(self) -> None:
        self.target_function = _validate_target_symbol(self.target_function)
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
{extra_includes}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    if (size == 0) return 0;
    /* TODO: replace this stub with a call to {target_function} */
    (void)data;
    (void)size;
    return 0;
}}
"""

# Conservative allowlist for caller-supplied extra include names. The
# fallback harness is compiled and executed, so anything outside a
# plain relative header path (quotes, newlines, `..`) is dropped rather
# than interpolated into source text.
_SAFE_INCLUDE_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_./-]*\.(h|hh|hpp)$")


def _render_extra_includes(extra_includes: list[str]) -> str:
    """Render spec.extra_includes as ``#include`` lines (fallback path).

    Silently drops names that fail the conservative allowlist or that
    try to traverse upward.
    """
    lines = []
    for name in extra_includes:
        name = str(name).strip()
        if not _SAFE_INCLUDE_RE.match(name) or ".." in name:
            logger.warning(
                "harness_generator: dropping unsafe extra include %r", name
            )
            continue
        lines.append(f'#include "{name}"')
    return ("\n".join(lines) + "\n") if lines else ""


def _extract_target_signature(header_text: str, function_name: str) -> str | None:
    """Best-effort extraction of a function signature from a header.

    Returns the matched declaration line (or block) or None if not found.
    Used only as additional context for the LLM, not for parsing.
    """
    # Bound the search: the 8 KB truncation elsewhere only applies to
    # the LLM prompt, so a pathological multi-megabyte header with no
    # semicolons would otherwise feed the regex unbounded input.
    header_text = header_text[:262144]
    safe_name = re.escape(function_name)
    # Match a declaration that starts somewhere on a line and ends at
    # semicolon. The prefix is line-bounded (`[^;\n]{0,500}`) so each
    # anchor position scans a bounded window rather than the whole
    # remaining text — the old `[^;]*` prefix was quadratic on large
    # semicolon-free headers.
    pattern = re.compile(
        rf"^[^;\n]{{0,500}}\b{safe_name}\s*\([^)]*\)\s*[a-zA-Z_]*\s*;",
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
        header_text = spec.header_path.read_text(encoding="utf-8", errors="replace")
        signature = _extract_target_signature(header_text, spec.target_function)

        if self.llm is None:
            logger.warning("No LLM configured, returning fallback harness")
            source = _FALLBACK_HARNESS_C.format(
                header_basename=spec.header_path.name,
                target_function=spec.target_function,
                extra_includes=_render_extra_includes(spec.extra_includes),
            )
            filename = f"fuzz_{_c_identifier(spec.target_function)}.c"
            return GeneratedHarness(
                source_code=source,
                language="c",
                suggested_filename=filename,
                target_function=spec.target_function,
                compile_command=self._compile_command(
                    filename, spec, language="c"
                ),
                rationale="Fallback harness; LLM unavailable.",
            )

        bundle = self._build_prompt(spec, header_text, signature)
        system_prompt = next(
            (m.content for m in bundle.messages if m.role == "system"),
            _HARNESS_SYSTEM_PROMPT,
        )
        user_prompt = next(
            (m.content for m in bundle.messages if m.role == "user"), "",
        )
        try:
            result, _ = self.llm.generate_structured(
                prompt=user_prompt,
                schema={
                    "source_code": "full harness source as a string",
                    "language": "either 'c' or 'cpp'",
                    "rationale": "one paragraph explanation",
                },
                system_prompt=system_prompt,
            )
        except Exception as e:  # noqa: BLE001
            logger.error("LLM harness generation failed: %s", e)
            return self._fallback(spec, header_text)

        if not result or "source_code" not in result:
            return self._fallback(spec, header_text)

        source = str(result["source_code"]).strip()
        language = str(result.get("language", "cpp")).lower()
        if language not in ("c", "cpp"):
            language = "cpp"

        ext = ".c" if language == "c" else ".cc"
        filename = f"fuzz_{_c_identifier(spec.target_function)}{ext}"

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
            extra_includes=_render_extra_includes(spec.extra_includes),
        )
        filename = f"fuzz_{_c_identifier(spec.target_function)}.c"
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
        signature: str | None,
    ) -> PromptBundle:
        """Build the layered-defence prompt bundle.

        The target header comes from the repo under analysis — untrusted
        by definition, and the generated harness is subsequently
        COMPILED AND EXECUTED, so a prompt injection here escalates to
        code execution on the operator machine. Header text (and the
        signature extracted from it) therefore rides inside
        ``UntrustedBlock`` envelopes with nonce + CONSERVATIVE-profile
        hardening, never as free prose; identifiers travel as untrusted
        slots. Same pattern as the codeql/sca/web LLM surfaces.
        """
        truncated = header_text[:8192]
        pf = preflight(truncated)
        defense_telemetry.record_preflight(
            hit=pf.has_injection_indicators
        )
        if pf.has_injection_indicators:
            logger.warning(
                "harness_generator: injection indicators in header %s "
                "(indicators=%s) — proceeding with envelope defences",
                spec.header_path.name,
                pf.indicators,
            )

        blocks = [
            UntrustedBlock(
                content=truncated,
                kind="target-header",
                origin=str(spec.header_path),
            ),
        ]
        if signature:
            blocks.append(UntrustedBlock(
                content=signature,
                kind="detected-signature",
                origin=str(spec.header_path),
            ))
        if spec.notes:
            blocks.append(UntrustedBlock(
                content=spec.notes,
                kind="caller-notes",
                origin="harness-spec",
            ))
        # The system prompt promises the LLM "any additional context
        # (setup requirements, lifecycle constraints)" — honour the
        # spec fields that carry it. Same untrusted envelope as notes:
        # the generated harness is compiled and executed.
        if spec.setup_code:
            blocks.append(UntrustedBlock(
                content=spec.setup_code,
                kind="caller-setup-code",
                origin="harness-spec",
            ))
        if spec.teardown_code:
            blocks.append(UntrustedBlock(
                content=spec.teardown_code,
                kind="caller-teardown-code",
                origin="harness-spec",
            ))
        if spec.extra_includes:
            blocks.append(UntrustedBlock(
                content="\n".join(str(i) for i in spec.extra_includes),
                kind="caller-extra-includes",
                origin="harness-spec",
            ))

        slots = {
            "target_function": TaintedString(
                value=spec.target_function, trust="untrusted",
            ),
            "header_file": TaintedString(
                value=spec.header_path.name, trust="untrusted",
            ),
        }
        if spec.library_name:
            slots["library"] = TaintedString(
                value=spec.library_name, trust="untrusted",
            )

        return build_prompt(
            system=_HARNESS_SYSTEM_PROMPT,
            profile=CONSERVATIVE,
            untrusted_blocks=tuple(blocks),
            slots=slots,
        )

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
        # Reduce both filenames to single bare slug components so they
        # can never act as paths, whatever the harness carries.
        target_path = out_dir / _slug(harness.suggested_filename)
        target_path.write_text(harness.source_code, encoding="utf-8")

        compile_script = out_dir / f"build_{_c_identifier(harness.target_function)}.sh"
        # The comment slot must stay a single printable line: replace
        # anything outside printable ASCII (incl. newlines) with `?`.
        comment_name = re.sub(r"[^\x20-\x7e]", "?", harness.target_function)
        compile_script.write_text(
            "#!/bin/sh\n"
            "set -e\n"
            f"# Generated by RAPTOR for {comment_name}\n"
            f"{harness.compile_command}\n",
            encoding="utf-8",
        )
        compile_script.chmod(0o755)

        logger.info("Wrote harness: %s", target_path)
        logger.info("Wrote build script: %s", compile_script)
        return target_path
