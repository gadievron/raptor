"""Tests for the LLM-PoC source pre-scanner.

The scanner runs in ``ExploitValidator.validate_exploit`` before gcc is
invoked. Its job is to reject exfiltration-shaped directives (absolute
or traversing ``#include`` / ``#embed`` / ``__has_include`` / ``.incbin``
/ ``#pragma GCC dependency``) in LLM-generated PoCs without rejecting
the directives a real PoC actually needs (system headers, same-dir or
descending-only quoted includes).
"""

from __future__ import annotations

from packages.autonomous.poc_source_scan import (
    SourceScanViolation,
    format_violations,
    scan,
)


# ---------------------------------------------------------------------------
# Allow: directives a real PoC legitimately uses
# ---------------------------------------------------------------------------

def test_standard_angle_include_allowed():
    assert scan("#include <stdio.h>\nint main(){}") == []


def test_subdir_angle_include_allowed():
    assert scan("#include <sys/socket.h>\nint main(){}") == []


def test_same_dir_quoted_include_allowed():
    assert scan('#include "helper.h"\nint main(){}') == []


def test_descending_subdir_include_allowed():
    assert scan('#include "subdir/util.h"\nint main(){}') == []


def test_has_include_relative_subheader_allowed():
    src = '#if __has_include("opt.h")\n#include "opt.h"\n#endif'
    assert scan(src) == []


def test_empty_source_allowed():
    assert scan("") == []


def test_full_minimal_poc_allowed():
    src = """\
#include <stdio.h>
#include <string.h>
#include "local.h"
int main() {
    char buf[64];
    strcpy(buf, "hello");
    printf("%s\\n", buf);
    return 0;
}
"""
    assert scan(src) == []


# ---------------------------------------------------------------------------
# Block: absolute paths (POSIX + Windows drive-letter)
# ---------------------------------------------------------------------------

def test_absolute_quoted_include_blocked():
    src = '#include "/etc/passwd"\nint main(){}'
    v = scan(src)
    assert len(v) == 1
    assert v[0].directive == "#include"
    assert v[0].path == "/etc/passwd"
    assert v[0].reason == "absolute path"
    assert v[0].line_no == 1


def test_absolute_angle_include_blocked():
    src = '#include </etc/shadow>\nint main(){}'
    v = scan(src)
    assert len(v) == 1
    assert v[0].path == "/etc/shadow"
    assert v[0].reason == "absolute path"


def test_windows_drive_letter_path_blocked():
    src = '#include "C:/Windows/System32/config/SAM"\nint main(){}'
    v = scan(src)
    assert len(v) == 1
    assert v[0].reason == "absolute path"


# ---------------------------------------------------------------------------
# Block: directory traversal
# ---------------------------------------------------------------------------

def test_traversing_quoted_include_blocked():
    src = '#include "../../../etc/passwd"\nint main(){}'
    v = scan(src)
    assert len(v) == 1
    assert v[0].reason == "directory traversal"


def test_traversing_angle_include_blocked():
    src = '#include <../../../etc/passwd>\nint main(){}'
    v = scan(src)
    assert len(v) == 1
    assert v[0].reason == "directory traversal"


def test_traversal_segment_in_middle_blocked():
    src = '#include "subdir/../../../etc/passwd"\nint main(){}'
    v = scan(src)
    assert len(v) == 1
    assert v[0].reason == "directory traversal"


def test_windows_backslash_traversal_blocked():
    src = '#include "..\\..\\etc\\passwd"\nint main(){}'
    v = scan(src)
    assert len(v) == 1
    assert v[0].reason == "directory traversal"


# ---------------------------------------------------------------------------
# Block: other directive shapes that share the threat
# ---------------------------------------------------------------------------

def test_embed_absolute_blocked():
    src = 'const char d[] = {\n#embed "/etc/passwd"\n};'
    v = scan(src)
    assert len(v) == 1
    assert v[0].directive == "#embed"


def test_embed_traversing_blocked():
    src = 'const char d[] = {\n#embed "../../../etc/passwd"\n};'
    v = scan(src)
    assert len(v) == 1
    assert v[0].reason == "directory traversal"


def test_pragma_gcc_dependency_absolute_blocked():
    src = '#pragma GCC dependency "/etc/passwd"\nint main(){}'
    v = scan(src)
    assert len(v) == 1
    assert v[0].directive == "#pragma GCC dependency"


def test_has_include_absolute_oracle_blocked():
    """The bandwidth-1 oracle the live probe confirmed."""
    src = """\
#if __has_include(</etc/passwd>)
#error "PROBE_HIT"
#endif
int main(){}
"""
    v = scan(src)
    assert len(v) == 1
    assert v[0].directive == "__has_include"
    assert v[0].path == "/etc/passwd"


def test_has_include_traversing_oracle_blocked():
    src = '#if __has_include("../../../etc/passwd")\n#endif\nint main(){}'
    v = scan(src)
    assert len(v) == 1
    assert v[0].reason == "directory traversal"


def test_incbin_absolute_blocked():
    src = '__asm__(".incbin \\"/etc/passwd\\"");\nint main(){}'
    v = scan(src)
    assert len(v) == 1
    assert v[0].directive == ".incbin"


def test_incbin_traversing_blocked():
    src = '__asm__(".incbin \\"../../../etc/passwd\\"");\nint main(){}'
    v = scan(src)
    assert len(v) == 1
    assert v[0].reason == "directory traversal"


# ---------------------------------------------------------------------------
# Multiple violations + line numbers + formatting
# ---------------------------------------------------------------------------

def test_multiple_violations_all_reported():
    src = """\
#include "/etc/passwd"
#include "../../etc/shadow"
#include <stdio.h>
#pragma GCC dependency "/proc/version"
"""
    v = scan(src)
    assert len(v) == 3
    paths = sorted(x.path for x in v)
    assert paths == ["../../etc/shadow", "/etc/passwd", "/proc/version"]


def test_violation_line_numbers_correct():
    src = "// header\n\n\n#include \"/etc/passwd\"\nint main(){}"
    v = scan(src)
    assert v[0].line_no == 4


def test_format_violations_includes_path_and_reason():
    src = '#include "/etc/passwd"'
    v = scan(src)
    formatted = format_violations(v)
    assert len(formatted) == 1
    assert "/etc/passwd" in formatted[0]
    assert "absolute path" in formatted[0]
    # Should not say "blocked" or "security" — frames as a coding-style
    # constraint to the refiner LLM rather than advertising the gate.
    assert "security" not in formatted[0].lower()


# ---------------------------------------------------------------------------
# Whitespace / formatting variants the regex must tolerate
# ---------------------------------------------------------------------------

def test_indented_directive_blocked():
    src = '   #include "/etc/passwd"\nint main(){}'
    v = scan(src)
    assert len(v) == 1


def test_extra_spaces_inside_directive_blocked():
    src = '#  include "/etc/passwd"\nint main(){}'
    v = scan(src)
    assert len(v) == 1


def test_has_include_with_whitespace_blocked():
    src = '#if __has_include  (  </etc/passwd>  )\n#endif'
    v = scan(src)
    assert len(v) == 1


# ---------------------------------------------------------------------------
# Integration with ExploitValidator
# ---------------------------------------------------------------------------

def test_validate_exploit_rejects_absolute_include(tmp_path):
    """End-to-end: malicious source goes into validate_exploit, the
    pre-scan rejects it before gcc is ever called."""
    from packages.autonomous.exploit_validator import ExploitValidator
    v = ExploitValidator(work_dir=tmp_path)
    result = v.validate_exploit('#include "/etc/passwd"\nint main(){}', "exfil")
    assert result.success is False
    assert result.compilation_errors
    assert "/etc/passwd" in result.compilation_errors[0]
    # No binary produced
    assert result.exploit_path is None


def test_validate_exploit_passes_clean_source(tmp_path):
    """Sanity: a benign PoC isn't blocked by the pre-scan. We can't
    assert successful compilation without a working gcc on the test host
    (CI may not have one); the assertion is only that the pre-scan
    didn't reject — gcc-result is whatever it is."""
    import shutil
    if shutil.which("gcc") is None:
        import pytest
        pytest.skip("gcc not available in test environment")
    from packages.autonomous.exploit_validator import ExploitValidator
    v = ExploitValidator(work_dir=tmp_path)
    result = v.validate_exploit(
        "#include <stdio.h>\nint main(){return 0;}",
        "clean",
    )
    # Source-scan rejection produces "absolute path" / "directory traversal"
    # in the error list. A real compile failure produces gcc errors. Confirm
    # we don't see the source-scan rejection shape.
    for err in result.compilation_errors:
        assert "absolute path" not in err
        assert "directory traversal" not in err


# ---------------------------------------------------------------------------
# End-to-end: full call site (validate_and_refine) with the live exfil
# payloads that the original probe confirmed leak file contents into stderr
# ---------------------------------------------------------------------------

class _MockRefiner:
    """Stand-in for ``MultiTurnAnalyser`` so the validate_and_refine
    iteration loop can be exercised without a real LLM call. Records
    the errors handed to it on each refinement turn so the test can
    assert that no file content is being relayed to the model."""

    def __init__(self, refined_code: str):
        self.refined_code = refined_code
        self.refinements_seen: list[list[str]] = []

    def refine_exploit_iteratively(self, *, exploit_code, crash_context,
                                    validation_errors, **_kwargs):
        self.refinements_seen.append(list(validation_errors))
        return self.refined_code


# All seven payloads the live probe (/tmp/poc_exfil_probe.py) confirmed
# leak first-line content of the read target into gcc's stderr (or, for
# the silent-success ones, embed the content into the output binary).
_EXFIL_PAYLOADS = {
    "abs_include":         '#include "/etc/passwd"\nint main(){}',
    "angle_abs_include":   '#include </etc/passwd>\nint main(){}',
    "traversing_include":  '#include "../../../../etc/passwd"\nint main(){}',
    "has_include_oracle":  '#if __has_include(</etc/passwd>)\n#error H\n#endif\nint main(){}',
    "incbin_asm":          '__asm__(".incbin \\"/etc/passwd\\"");\nint main(){}',
    "embed_directive":     'const char d[] = {\n#embed "/etc/passwd"\n};\nint main(){}',
    "pragma_dependency":   '#pragma GCC dependency "/etc/passwd"\nint main(){}',
}


def test_e2e_all_known_exfil_shapes_blocked_before_gcc(tmp_path):
    """The full set of payloads the live probe confirmed work today.
    For each: drive ``validate_exploit`` end-to-end and verify (a) the
    call returns failure, (b) the error message is the source-scan
    framing (not gcc stderr), (c) NO known-content fragment from
    ``/etc/passwd`` (specifically the well-known ``root:`` prefix that
    gcc echoes back when it parses the file as C) appears anywhere in
    the returned errors. This is the regression-grade check that the
    verified leak is closed at this call site."""
    from packages.autonomous.exploit_validator import ExploitValidator

    for name, source in _EXFIL_PAYLOADS.items():
        v = ExploitValidator(work_dir=tmp_path)
        result = v.validate_exploit(source, name)
        assert result.success is False, f"{name}: expected rejection, got success"
        assert result.compilation_errors, f"{name}: expected error message"
        # Source-scan framing — proves we rejected pre-gcc, not at compile
        joined = " ".join(result.compilation_errors)
        assert ("absolute path" in joined or "directory traversal" in joined), \
            f"{name}: expected source-scan rejection shape, got: {joined!r}"
        # No file-content artefact. ``root:`` is the first token of every
        # /etc/passwd file gcc would have read in a successful exfil.
        assert "root:" not in joined, \
            f"{name}: file content leaked into rejection message: {joined!r}"
        # No binary produced
        assert result.exploit_path is None, f"{name}: unexpected binary"


def test_e2e_validate_and_refine_loop_handles_source_scan_rejection(tmp_path):
    """Exercise the iterative-refinement loop: malicious PoC enters
    iter 1, source-scan blocks, refiner is asked to fix, returns a
    clean PoC, iter 2 succeeds. The errors fed to the refiner must be
    the source-scan messages — never gcc stderr that could carry
    leaked file content."""
    import shutil
    if shutil.which("gcc") is None:
        import pytest
        pytest.skip("gcc not available in test environment")
    from packages.autonomous.exploit_validator import ExploitValidator

    malicious = '#include "/etc/passwd"\nint main(){}'
    clean = '#include <stdio.h>\nint main(){return 0;}'

    v = ExploitValidator(work_dir=tmp_path)
    refiner = _MockRefiner(refined_code=clean)

    success, final_code, _path = v.validate_and_refine(
        exploit_code=malicious,
        exploit_name="e2e_refine",
        crash_context=None,
        multi_turn_analyser=refiner,
        max_iterations=3,
    )

    assert success is True
    assert final_code == clean
    # Refiner was consulted exactly once (iter-1 rejected → refine →
    # iter-2 compiled clean → loop exits).
    assert len(refiner.refinements_seen) == 1
    iter1_errors = refiner.refinements_seen[0]
    # Errors carry the source-scan framing
    assert any("absolute path" in e for e in iter1_errors)
    # And do NOT leak file content
    for e in iter1_errors:
        assert "root:" not in e


def test_e2e_no_gcc_invocation_when_source_scan_rejects(monkeypatch, tmp_path):
    """Strongest signal: confirm the sandbox/gcc subprocess is NEVER
    reached when the source-scan rejects. Substitutes ``sandbox.run``
    for a probe that would fail loudly if it were called."""
    from packages.autonomous.exploit_validator import ExploitValidator
    import core.sandbox

    sandbox_called = {"hit": False}

    def _explode(*args, **kwargs):
        sandbox_called["hit"] = True
        raise AssertionError("sandbox.run should not be reached for blocked PoCs")

    monkeypatch.setattr(core.sandbox, "run", _explode)
    # Some import sites bind ``run`` directly — patch the namespace
    # too so the validator's local lookup is intercepted.
    import core.sandbox.context
    monkeypatch.setattr(core.sandbox.context, "run", _explode)

    v = ExploitValidator(work_dir=tmp_path)
    for name, source in _EXFIL_PAYLOADS.items():
        result = v.validate_exploit(source, name)
        assert result.success is False
    assert sandbox_called["hit"] is False
