"""Tests for ``packages.sca.rewriters.dockerfile_arg``.

Covers in-place rewriting of Dockerfile ARG version-pin lines:
applied happy path, idempotency, mismatch refusal, not-found
skip, multiple edits in one file, and the registry-dispatch
integration."""

from __future__ import annotations

from pathlib import Path


from packages.sca.rewriters import RewriteEdit, rewrite
from packages.sca.rewriters.dockerfile_arg import rewrite_dockerfile_arg


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_arg_rewrite_applies_when_old_value_matches(
    tmp_path: Path,
) -> None:
    """The canonical case: ARG present at expected old value →
    rewrite to new value in place."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM python:3.12\nARG SEMGREP_VERSION=1.50.0\n")
    edits = [RewriteEdit(
        locator="SEMGREP_VERSION", old_value="1.50.0", new_value="1.119.0",
    )]
    results = rewrite_dockerfile_arg(dockerfile, edits)
    assert len(results) == 1
    assert results[0].applied
    assert results[0].reason == "applied"
    assert "ARG SEMGREP_VERSION=1.119.0" in dockerfile.read_text()
    assert "1.50.0" not in dockerfile.read_text()


def test_arg_rewrite_no_change_when_already_at_target(
    tmp_path: Path,
) -> None:
    """File already at target version → idempotent skip. Adapts
    Natalie's PR #467's ``if old_version == new_version: continue``
    pattern. Important: re-running the bumper after a successful
    PR shouldn't repeatedly touch the file."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("ARG SEMGREP_VERSION=1.119.0\n")
    orig_mtime = dockerfile.stat().st_mtime
    edits = [RewriteEdit(
        locator="SEMGREP_VERSION", old_value="1.50.0", new_value="1.119.0",
    )]
    results = rewrite_dockerfile_arg(dockerfile, edits)
    assert not results[0].applied
    assert results[0].reason == "no_change"
    # File mtime unchanged → confirms no rewrite happened.
    assert dockerfile.stat().st_mtime == orig_mtime


def test_arg_rewrite_not_found_when_arg_absent(
    tmp_path: Path,
) -> None:
    """The ARG isn't in the file → ``not_found``. The bumper
    sees this when a plan was generated for a Dockerfile that
    has since had the ARG removed."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("ARG OTHER_VERSION=1.0\n")
    edits = [RewriteEdit(
        locator="SEMGREP_VERSION", old_value="1.50.0", new_value="1.119.0",
    )]
    results = rewrite_dockerfile_arg(dockerfile, edits)
    assert not results[0].applied
    assert results[0].reason == "not_found"
    assert dockerfile.read_text() == "ARG OTHER_VERSION=1.0\n"


def test_arg_rewrite_value_mismatch_refuses(
    tmp_path: Path,
) -> None:
    """File has a different value than the plan expected — refuse
    to overwrite. Operator probably bumped manually, or the plan
    is stale. Surface the mismatch so the operator can
    re-generate the plan."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("ARG SEMGREP_VERSION=1.117.0\n")
    edits = [RewriteEdit(
        locator="SEMGREP_VERSION", old_value="1.50.0", new_value="1.119.0",
    )]
    results = rewrite_dockerfile_arg(dockerfile, edits)
    assert not results[0].applied
    assert "value_mismatch" in results[0].reason
    assert "1.117.0" in results[0].reason         # actual
    assert "1.50.0" in results[0].reason          # expected
    # File untouched.
    assert dockerfile.read_text() == "ARG SEMGREP_VERSION=1.117.0\n"


# ---------------------------------------------------------------------------
# Multiple edits in one file
# ---------------------------------------------------------------------------

def test_multiple_edits_in_one_file(tmp_path: Path) -> None:
    """A devcontainer Dockerfile typically pins several tool
    versions. The rewriter handles them in one pass + atomic
    write."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.12-bookworm\n"
        "ARG SEMGREP_VERSION=1.50.0\n"
        "ARG CLAUDE_CODE_VERSION=2.0.0\n"
        "ARG CODEQL_VERSION=2.25.0\n"
        "RUN install\n"
    )
    edits = [
        RewriteEdit("SEMGREP_VERSION", "1.50.0", "1.119.0"),
        RewriteEdit("CLAUDE_CODE_VERSION", "2.0.0", "2.1.138"),
        # CODEQL stays unchanged (operator omitted from plan).
    ]
    results = rewrite_dockerfile_arg(dockerfile, edits)
    assert all(r.applied for r in results)
    text = dockerfile.read_text()
    assert "ARG SEMGREP_VERSION=1.119.0" in text
    assert "ARG CLAUDE_CODE_VERSION=2.1.138" in text
    assert "ARG CODEQL_VERSION=2.25.0" in text    # untouched


def test_partial_failure_keeps_successful_edits(tmp_path: Path) -> None:
    """Some edits succeed, others fail — file still gets written
    with the successful changes; the failed edits return failures
    in the result list."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "ARG GOOD_VERSION=1.0.0\n"
        "ARG STALE_VERSION=2.5.0\n"      # actual value
    )
    edits = [
        RewriteEdit("GOOD_VERSION", "1.0.0", "1.1.0"),
        RewriteEdit("STALE_VERSION", "2.0.0", "2.6.0"),  # mismatch
        RewriteEdit("ABSENT_VERSION", "1.0", "1.1"),      # not_found
    ]
    results = rewrite_dockerfile_arg(dockerfile, edits)
    by_locator = {r.edit.locator: r for r in results}
    assert by_locator["GOOD_VERSION"].applied
    assert not by_locator["STALE_VERSION"].applied
    assert "value_mismatch" in by_locator["STALE_VERSION"].reason
    assert by_locator["ABSENT_VERSION"].reason == "not_found"
    text = dockerfile.read_text()
    assert "ARG GOOD_VERSION=1.1.0" in text         # rewrote
    assert "ARG STALE_VERSION=2.5.0" in text         # left alone


# ---------------------------------------------------------------------------
# Edge cases — whitespace, quoting, comments
# ---------------------------------------------------------------------------

def test_arg_rewrite_preserves_quoting(tmp_path: Path) -> None:
    """``ARG FOO="1.2.3"`` (quoted) gets rewritten to a quoted
    new value. The parser strips quotes from the extracted value,
    so the edit's old_value is unquoted; we preserve the
    quotation by matching the file's shape."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text('ARG SEMGREP_VERSION="1.50.0"\n')
    edits = [RewriteEdit("SEMGREP_VERSION", "1.50.0", "1.119.0")]
    rewrite_dockerfile_arg(dockerfile, edits)
    text = dockerfile.read_text()
    assert 'ARG SEMGREP_VERSION="1.119.0"' in text


def test_arg_rewrite_tolerates_whitespace_around_equals(
    tmp_path: Path,
) -> None:
    """Some operators write ``ARG FOO = 1.2.3`` with spaces.
    The regex tolerates whitespace around ``=`` — common in
    hand-formatted Dockerfiles."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("ARG  SEMGREP_VERSION = 1.50.0\n")
    edits = [RewriteEdit("SEMGREP_VERSION", "1.50.0", "1.119.0")]
    results = rewrite_dockerfile_arg(dockerfile, edits)
    assert results[0].applied


def test_arg_rewrite_only_matches_exact_arg_name(
    tmp_path: Path,
) -> None:
    """``SEMGREP_VERSION`` shouldn't accidentally match
    ``CUSTOM_SEMGREP_VERSION`` or ``SEMGREP_VERSION_FALLBACK``.
    The regex word-boundary on the ARG name avoids substring
    confusion."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "ARG CUSTOM_SEMGREP_VERSION=9.9.9\n"
        "ARG SEMGREP_VERSION=1.50.0\n"
        "ARG SEMGREP_VERSION_FALLBACK=0.0.1\n"
    )
    edits = [RewriteEdit("SEMGREP_VERSION", "1.50.0", "1.119.0")]
    rewrite_dockerfile_arg(dockerfile, edits)
    text = dockerfile.read_text()
    assert "ARG SEMGREP_VERSION=1.119.0" in text
    # The two near-matches must NOT have been touched.
    assert "ARG CUSTOM_SEMGREP_VERSION=9.9.9" in text
    assert "ARG SEMGREP_VERSION_FALLBACK=0.0.1" in text


# ---------------------------------------------------------------------------
# Registry dispatch
# ---------------------------------------------------------------------------

def test_registry_dispatch_recognises_dockerfile(tmp_path: Path) -> None:
    """``rewrite(path, edits)`` dispatches to the Dockerfile-ARG
    rewriter when ``path.name == 'Dockerfile'``. Confirms the
    predicate registration wired."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("ARG SEMGREP_VERSION=1.50.0\n")
    edits = [RewriteEdit("SEMGREP_VERSION", "1.50.0", "1.119.0")]
    results = rewrite(dockerfile, edits)
    assert len(results) == 1
    assert results[0].applied


def test_registry_dispatch_recognises_dockerfile_dot_variant(
    tmp_path: Path,
) -> None:
    """``Dockerfile.dev``, ``some.Dockerfile``, ``foo.dockerfile``
    are all recognised by the predicate. Mirrors the inline-
    installs parser's discovery."""
    for name in ("Dockerfile.dev", "build.Dockerfile", "ci.dockerfile"):
        df = tmp_path / name
        df.write_text("ARG FOO_VERSION=1.0\n")
        edits = [RewriteEdit("FOO_VERSION", "1.0", "2.0")]
        results = rewrite(df, edits)
        assert len(results) == 1, f"failed on {name}"
        assert results[0].applied, f"failed on {name}"


def test_registry_dispatch_skips_unknown_file(tmp_path: Path) -> None:
    """Path that's not a Dockerfile → no rewriter, returns empty
    list (caller treats as "surface not supported")."""
    f = tmp_path / "random.txt"
    f.write_text("nothing\n")
    results = rewrite(f, [RewriteEdit("X", "1.0", "2.0")])
    assert results == []


# ---------------------------------------------------------------------------
# Atomic write — file persists / doesn't get corrupted on error
# ---------------------------------------------------------------------------

def test_atomic_write_uses_replace_not_truncate(tmp_path: Path) -> None:
    """Even if the rewrite is interrupted mid-write, the original
    file shouldn't be left in a corrupt state. Verified
    indirectly: after a successful rewrite, the file contents
    are exactly the new text (no leftover prefix from a partial
    overwrite of a longer file)."""
    dockerfile = tmp_path / "Dockerfile"
    long_original = (
        "ARG SEMGREP_VERSION=1.50.0\n"
        + "# " + "x" * 5000 + "\n"
    )
    dockerfile.write_text(long_original)
    edits = [RewriteEdit("SEMGREP_VERSION", "1.50.0", "1.119.0")]
    rewrite_dockerfile_arg(dockerfile, edits)
    text = dockerfile.read_text()
    # The "ARG ... = 1.50.0" must be gone; the long comment must
    # still be present in full.
    assert "1.50.0" not in text
    assert "x" * 5000 in text


# ---------------------------------------------------------------------------
# Idempotency — re-running produces no further changes
# ---------------------------------------------------------------------------

def test_rewrite_is_idempotent(tmp_path: Path) -> None:
    """Run the same edit twice. First run applies; second run
    reports ``no_change`` (the file is already at the target,
    even though the edit's ``old_value`` references a now-stale
    previous state).

    The ``new_value == file_value`` check fires BEFORE the
    ``old_value`` mismatch check — operator-friendly: re-running
    a successful bumper plan shouldn't surface scary
    'value_mismatch' errors when the file just happens to already
    match the target. The stale plan case (file at a DIFFERENT
    non-target value) still raises ``value_mismatch``, covered
    by ``test_arg_rewrite_value_mismatch_refuses``."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("ARG SEMGREP_VERSION=1.50.0\n")
    edits = [RewriteEdit("SEMGREP_VERSION", "1.50.0", "1.119.0")]
    r1 = rewrite_dockerfile_arg(dockerfile, edits)
    assert r1[0].applied
    # Second run: file is at 1.119.0 (target). Friendly skip.
    r2 = rewrite_dockerfile_arg(dockerfile, edits)
    assert not r2[0].applied
    assert r2[0].reason == "no_change"


def test_rewrite_idempotent_when_plan_already_at_target(
    tmp_path: Path,
) -> None:
    """Plan with ``old_value=current`` and ``new_value=current``
    is a no-op. A bumper that re-evaluates and re-issues plans
    won't churn the file."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("ARG FOO_VERSION=1.0\n")
    edits = [RewriteEdit("FOO_VERSION", "1.0", "1.0")]
    results = rewrite_dockerfile_arg(dockerfile, edits)
    # Mismatch / no_change either way — never ``applied``.
    assert not results[0].applied
