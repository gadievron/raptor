"""Tests for ``packages.sca.rewriters.gha_uses``.

GHA ``uses:`` ref-bump rewriter — tag-pinned form supported by
Phase 3.b; SHA+comment form deferred to 3.b.2."""

from __future__ import annotations

from pathlib import Path


from packages.sca.rewriters import RewriteEdit, rewrite
from packages.sca.rewriters.gha_uses import rewrite_gha_uses


def _workflow_path(tmp_path: Path, name: str = "test.yml") -> Path:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True, exist_ok=True)
    return workflows / name


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_tag_pinned_uses_rewrite_applies(tmp_path: Path) -> None:
    """``uses: actions/checkout@v4`` → bump to v5."""
    wf = _workflow_path(tmp_path)
    wf.write_text(
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
    )
    edits = [RewriteEdit(
        locator="actions/checkout",
        old_value="v4", new_value="v5",
    )]
    results = rewrite_gha_uses(wf, edits)
    assert results[0].applied
    assert "uses: actions/checkout@v5" in wf.read_text()


def test_sub_action_path_preserved(tmp_path: Path) -> None:
    """``uses: github/codeql-action/init@v4`` — the ``/init``
    subpath stays intact when the ref bumps."""
    wf = _workflow_path(tmp_path)
    wf.write_text("      - uses: github/codeql-action/init@v4\n")
    edits = [RewriteEdit(
        locator="github/codeql-action",
        old_value="v4", new_value="v5",
    )]
    results = rewrite_gha_uses(wf, edits)
    assert results[0].applied
    text = wf.read_text()
    assert "uses: github/codeql-action/init@v5" in text


def test_no_change_when_already_at_target(tmp_path: Path) -> None:
    """Idempotent."""
    wf = _workflow_path(tmp_path)
    wf.write_text("      - uses: actions/checkout@v5\n")
    edits = [RewriteEdit(
        locator="actions/checkout",
        old_value="v4", new_value="v5",
    )]
    results = rewrite_gha_uses(wf, edits)
    assert not results[0].applied
    assert results[0].reason == "no_change"


def test_value_mismatch_refuses(tmp_path: Path) -> None:
    """Plan stale (file at a different non-target ref) — refuse."""
    wf = _workflow_path(tmp_path)
    wf.write_text("      - uses: actions/checkout@v6\n")
    edits = [RewriteEdit(
        locator="actions/checkout",
        old_value="v4", new_value="v5",
    )]
    results = rewrite_gha_uses(wf, edits)
    assert not results[0].applied
    assert "value_mismatch" in results[0].reason


def test_not_found(tmp_path: Path) -> None:
    """Locator isn't in the file → not_found."""
    wf = _workflow_path(tmp_path)
    wf.write_text("      - uses: actions/setup-python@v4\n")
    edits = [RewriteEdit(
        locator="actions/checkout",
        old_value="v4", new_value="v5",
    )]
    results = rewrite_gha_uses(wf, edits)
    assert not results[0].applied
    assert results[0].reason == "not_found"


def test_sha_pinned_ref_value_mismatch(tmp_path: Path) -> None:
    """SHA-pinned refs (raptor's convention) — Phase 3.b.2 will
    handle these with tag→SHA resolution. For now the rewriter
    refuses politely with a value-mismatch explanation."""
    wf = _workflow_path(tmp_path)
    wf.write_text(
        "      - uses: actions/checkout@"
        "de0fac2e4500dabe0009e67214ff5f5447ce83dd  # was v6\n"
    )
    edits = [RewriteEdit(
        locator="actions/checkout",
        old_value="v6", new_value="v7",
    )]
    results = rewrite_gha_uses(wf, edits)
    assert not results[0].applied
    assert "SHA-pinned" in results[0].reason
    # File untouched.
    assert "de0fac2e" in wf.read_text()


def test_comment_preserved_after_ref_bump(tmp_path: Path) -> None:
    """``uses: foo@v4  # explanatory comment`` — the ``# ...``
    suffix must survive the rewrite."""
    wf = _workflow_path(tmp_path)
    wf.write_text(
        "      - uses: actions/checkout@v4  # node 20 LTS\n"
    )
    edits = [RewriteEdit(
        locator="actions/checkout",
        old_value="v4", new_value="v5",
    )]
    rewrite_gha_uses(wf, edits)
    text = wf.read_text()
    assert "@v5" in text
    assert "# node 20 LTS" in text


# ---------------------------------------------------------------------------
# Registry dispatch
# ---------------------------------------------------------------------------

def test_registry_dispatch_recognises_gha_workflow(tmp_path: Path) -> None:
    wf = _workflow_path(tmp_path)
    wf.write_text("      - uses: actions/checkout@v4\n")
    edits = [RewriteEdit("actions/checkout", "v4", "v5")]
    results = rewrite(wf, edits)
    assert len(results) == 1
    assert results[0].applied


def test_yaml_file_outside_workflows_dir_not_routed(tmp_path: Path) -> None:
    """A YAML file outside ``.github/workflows/`` doesn't dispatch
    to the GHA rewriter. Post-Phase-3.c the yaml_image rewriter
    DOES match generic ``.yml`` files (for k8s / compose image:
    lines) — but it doesn't match the GHA-shaped ``uses:`` line
    in this test file, so no edit applies."""
    other = tmp_path / "config.yml"
    other.write_text("      - uses: actions/checkout@v4\n")
    edits = [RewriteEdit("actions/checkout", "v4", "v5")]
    results = rewrite(other, edits)
    # The yaml_image rewriter is now registered against generic
    # ``.yml`` predicate (Phase 3.c) so we get a "not_found"
    # result rather than an empty list. Crucially: nothing
    # APPLIED.
    assert all(not r.applied for r in results)
    # File untouched.
    assert other.read_text() == "      - uses: actions/checkout@v4\n"


# ---------------------------------------------------------------------------
# SHA-pinned with ``# was vX`` comment (Phase 3.b.2)
# ---------------------------------------------------------------------------

def test_sha_pinned_with_comment_rewrites_both_sha_and_tag(
    tmp_path: Path,
) -> None:
    """Raptor's convention: ``uses: actions/checkout@<40hex>  # was v6``.
    Bumping to v7 rewrites BOTH the SHA and the ``# was`` comment."""
    wf = _workflow_path(tmp_path)
    wf.write_text(
        "      - uses: actions/checkout@"
        "de0fac2e4500dabe0009e67214ff5f5447ce83dd  # was v6\n"
    )
    edits = [RewriteEdit(
        locator="actions/checkout",
        old_value="v6", new_value="v7",
        extra={
            "old_sha": "de0fac2e4500dabe0009e67214ff5f5447ce83dd",
            "new_sha": "ffffffffffffffffffffffffffffffffffffffff",
        },
    )]
    results = rewrite_gha_uses(wf, edits)
    assert results[0].applied
    text = wf.read_text()
    assert "@ffffffffffffffffffffffffffffffffffffffff" in text
    assert "# was v7" in text
    # Old SHA + old tag fully gone.
    assert "de0fac2e" not in text
    assert "was v6" not in text


def test_sha_pinned_preserves_yaml_indent_and_list_marker(
    tmp_path: Path,
) -> None:
    """The YAML indent and ``- `` list marker stay intact through
    the rewrite."""
    wf = _workflow_path(tmp_path)
    wf.write_text(
        "        - uses: actions/checkout@"
        "0000000000000000000000000000000000000000  # was v4\n"
    )
    edits = [RewriteEdit(
        locator="actions/checkout",
        old_value="v4", new_value="v5",
        extra={
            "old_sha": "0" * 40,
            "new_sha": "1" * 40,
        },
    )]
    rewrite_gha_uses(wf, edits)
    text = wf.read_text()
    assert text.startswith("        - uses:")
    assert "@" + "1" * 40 in text


def test_sha_pinned_value_mismatch_on_different_sha(tmp_path: Path) -> None:
    """File has a DIFFERENT SHA than the plan expects → refuse.
    Operator manually bumped, or plan is stale."""
    wf = _workflow_path(tmp_path)
    wf.write_text(
        "      - uses: actions/checkout@"
        "0000000000000000000000000000000000000000  # was v6\n"
    )
    edits = [RewriteEdit(
        locator="actions/checkout",
        old_value="v6", new_value="v7",
        extra={
            "old_sha": "1" * 40,            # doesn't match file
            "new_sha": "2" * 40,
        },
    )]
    results = rewrite_gha_uses(wf, edits)
    assert not results[0].applied
    assert "value_mismatch" in results[0].reason
    assert "000000" in wf.read_text()       # file untouched


def test_sha_pinned_value_mismatch_on_different_was_tag(
    tmp_path: Path,
) -> None:
    """File's ``# was`` comment tag doesn't match plan's
    ``old_value`` — refuse. Same suspend-on-stale-plan semantics."""
    wf = _workflow_path(tmp_path)
    wf.write_text(
        "      - uses: actions/checkout@"
        "0000000000000000000000000000000000000000  # was v5\n"
    )
    edits = [RewriteEdit(
        locator="actions/checkout",
        old_value="v6",                     # file has v5
        new_value="v7",
        extra={"old_sha": "0" * 40, "new_sha": "1" * 40},
    )]
    results = rewrite_gha_uses(wf, edits)
    assert not results[0].applied
    assert "value_mismatch" in results[0].reason


def test_sha_pinned_no_change_when_already_at_target(tmp_path: Path) -> None:
    """File already at target SHA + tag → no_change."""
    wf = _workflow_path(tmp_path)
    wf.write_text(
        "      - uses: actions/checkout@"
        "1111111111111111111111111111111111111111  # was v7\n"
    )
    edits = [RewriteEdit(
        locator="actions/checkout",
        old_value="v6", new_value="v7",
        extra={"old_sha": "0" * 40, "new_sha": "1" * 40},
    )]
    results = rewrite_gha_uses(wf, edits)
    assert not results[0].applied
    assert results[0].reason == "no_change"
