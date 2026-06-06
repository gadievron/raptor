"""Tests for the tightened ``actions/upload-artifact`` and
``actions/cache`` sinks.

Pre-tightening: fired ``high`` on ANY job that bound a secret to
env AND used the action.  This produced FP-floods on real
workflows (mitmproxy: secret in env for one step + unrelated
upload-artifact for build output).

Post-tightening:
  * ``upload-artifact``: high only when a prior step in the same
    job actually wrote env / a secret-bound var to disk; otherwise
    medium (informational, reviewable).
  * ``actions/cache``: medium with env-to-disk evidence; low
    otherwise.
"""

from __future__ import annotations

from pathlib import Path

from packages.sca.supply_chain.gha_secret_flow import scan_target


def _write_wf(tmp_path: Path, body: str) -> Path:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    p = wf_dir / "wf.yml"
    p.write_text(body, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# upload-artifact — high WITH env-to-disk evidence
# ---------------------------------------------------------------------------

def test_upload_artifact_with_env_dump_fires_high(tmp_path: Path) -> None:
    """``env > /tmp/snapshot`` then upload-artifact = high."""
    _write_wf(tmp_path, """\
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
          name: snap
          path: /tmp/snapshot
""")
    hits = scan_target(tmp_path, [], [])
    upload = [h for h in hits if h.sink_kind == "upload_artifact"]
    assert upload and upload[0].severity == "high"


def test_upload_artifact_with_printenv_dump_fires_high(
    tmp_path: Path,
) -> None:
    """``printenv > path`` is also an env-dump."""
    _write_wf(tmp_path, """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    env:
      TOK: ${{ secrets.NPM_TOKEN }}
    steps:
      - run: printenv > /tmp/env.txt
      - uses: actions/upload-artifact@v4
        with: { name: x, path: /tmp/env.txt }
""")
    hits = scan_target(tmp_path, [], [])
    upload = [h for h in hits if h.sink_kind == "upload_artifact"]
    assert upload and upload[0].severity == "high"


def test_upload_artifact_with_echo_secret_var_fires_high(
    tmp_path: Path,
) -> None:
    """``echo $TOK > file`` where TOK is the secret-bound env var."""
    _write_wf(tmp_path, """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    env:
      TOK: ${{ secrets.NPM_TOKEN }}
    steps:
      - run: echo "$TOK" > /tmp/leak
      - uses: actions/upload-artifact@v4
        with: { name: x, path: /tmp/leak }
""")
    hits = scan_target(tmp_path, [], [])
    upload = [h for h in hits if h.sink_kind == "upload_artifact"]
    assert upload and upload[0].severity == "high"


# ---------------------------------------------------------------------------
# upload-artifact — medium WITHOUT env-to-disk evidence
# ---------------------------------------------------------------------------

def test_upload_artifact_without_env_dump_downgrades_to_medium(
    tmp_path: Path,
) -> None:
    """The mitmproxy FP shape: job has secret in env (for one step's
    auth) + upload-artifact for unrelated build output.  No
    env-to-disk write detected — downgrade to medium."""
    _write_wf(tmp_path, """\
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      TOK: ${{ secrets.NPM_TOKEN }}
    steps:
      - uses: actions/setup-node@v4
      - run: npm install --auth-token $TOK
      - run: npm run build
      - uses: actions/upload-artifact@v4
        with:
          name: dist
          path: dist/
""")
    hits = scan_target(tmp_path, [], [])
    upload = [h for h in hits if h.sink_kind == "upload_artifact"]
    assert upload and upload[0].severity == "medium"


def test_upload_artifact_without_secret_env_no_finding(
    tmp_path: Path,
) -> None:
    """No secret-tainted env binding at all → no upload-artifact
    finding (whether or not env is dumped)."""
    _write_wf(tmp_path, """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: env > /tmp/snapshot
      - uses: actions/upload-artifact@v4
        with: { name: x, path: /tmp/snapshot }
""")
    hits = scan_target(tmp_path, [], [])
    upload = [h for h in hits if h.sink_kind == "upload_artifact"]
    assert not upload


# ---------------------------------------------------------------------------
# actions/cache severity gradient
# ---------------------------------------------------------------------------

def test_cache_with_env_dump_fires_medium(tmp_path: Path) -> None:
    """Cache + env-to-disk write = medium (the cache outlives the
    runner; the on-disk env file could end up cached)."""
    _write_wf(tmp_path, """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    env:
      TOK: ${{ secrets.NPM_TOKEN }}
    steps:
      - run: env > /tmp/cache/env.txt
      - uses: actions/cache@v4
        with: { key: c, path: /tmp/cache }
""")
    hits = scan_target(tmp_path, [], [])
    cache = [h for h in hits if h.sink_kind == "cache_save"]
    assert cache and cache[0].severity == "medium"


def test_cache_without_env_dump_downgrades_to_low(tmp_path: Path) -> None:
    """Cache + secret env binding but no env-to-disk → low."""
    _write_wf(tmp_path, """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    env:
      TOK: ${{ secrets.NPM_TOKEN }}
    steps:
      - uses: actions/setup-node@v4
      - run: npm install --auth-token $TOK
      - uses: actions/cache@v4
        with: { key: c, path: ~/.npm }
""")
    hits = scan_target(tmp_path, [], [])
    cache = [h for h in hits if h.sink_kind == "cache_save"]
    assert cache and cache[0].severity == "low"


# ---------------------------------------------------------------------------
# Env-write detection edge cases
# ---------------------------------------------------------------------------

def test_env_to_github_env_not_counted_as_env_dump(tmp_path: Path) -> None:
    """``env > $GITHUB_ENV`` is the GHA cross-step laundering shape;
    it's already covered by the laundering detector.  Do NOT also
    count it as an ``env_written_to_disk`` for the upload sink (it
    doesn't write to a regular file the upload can capture)."""
    _write_wf(tmp_path, """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    env:
      TOK: ${{ secrets.NPM_TOKEN }}
    steps:
      - run: env >> $GITHUB_ENV
      - uses: actions/upload-artifact@v4
        with: { name: x, path: dist/ }
""")
    hits = scan_target(tmp_path, [], [])
    upload = [h for h in hits if h.sink_kind == "upload_artifact"]
    # Should be medium (no real env-to-disk), not high.
    assert upload and upload[0].severity == "medium"
