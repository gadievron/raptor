"""Tests for ``packages.sca.rewriters.dockerfile_inline_install``.

Covers in-place rewriting of ``RUN pip install <name>==<version>``
tokens inside Dockerfiles: applied happy path, idempotency,
mismatch refusal, not-found skip, multi-package RUN lines,
multi-line ``\\``-continuation RUNs, and the dispatcher route
through ``dockerfile_from`` keyed on ``extra["kind"] ==
"inline_install_pip"``."""

from __future__ import annotations

from pathlib import Path

from packages.sca.rewriters import RewriteEdit, rewrite
from packages.sca.rewriters.dockerfile_inline_install import (
    rewrite_dockerfile_inline_install,
)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_inline_install_rewrite_applies_when_old_value_matches(
    tmp_path: Path,
) -> None:
    """The canonical case: ``RUN pip install foo==X`` rewritten
    to ``RUN pip install foo==Y`` in place."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.13\n"
        "RUN pip install --no-cache-dir semgrep==1.161.0\n",
    )
    edits = [RewriteEdit(
        locator="semgrep", old_value="1.161.0", new_value="1.163.0",
    )]
    results = rewrite_dockerfile_inline_install(dockerfile, edits)
    assert len(results) == 1
    assert results[0].applied
    assert "semgrep==1.163.0" in dockerfile.read_text()
    assert "semgrep==1.161.0" not in dockerfile.read_text()


def test_inline_install_no_change_when_already_at_target(
    tmp_path: Path,
) -> None:
    """Idempotency: re-running with the same plan after the file
    is already at target → no-change skip, not a value_mismatch."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.13\nRUN pip install semgrep==1.163.0\n",
    )
    edits = [RewriteEdit(
        locator="semgrep", old_value="1.161.0", new_value="1.163.0",
    )]
    results = rewrite_dockerfile_inline_install(dockerfile, edits)
    assert not results[0].applied
    assert results[0].reason == "no_change"


def test_inline_install_value_mismatch_refuses_overwrite(
    tmp_path: Path,
) -> None:
    """If the file's current pin differs from the plan's expected
    old_value, refuse the rewrite — operator may have already
    bumped manually."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.13\nRUN pip install semgrep==1.999.0\n",
    )
    edits = [RewriteEdit(
        locator="semgrep", old_value="1.161.0", new_value="1.163.0",
    )]
    results = rewrite_dockerfile_inline_install(dockerfile, edits)
    assert not results[0].applied
    assert "value_mismatch" in results[0].reason
    # File untouched.
    assert "semgrep==1.999.0" in dockerfile.read_text()


def test_inline_install_not_found_when_pkg_absent(
    tmp_path: Path,
) -> None:
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.13\nRUN pip install requests==2.31.0\n",
    )
    edits = [RewriteEdit(
        locator="semgrep", old_value="1.161.0", new_value="1.163.0",
    )]
    results = rewrite_dockerfile_inline_install(dockerfile, edits)
    assert not results[0].applied
    assert results[0].reason == "not_found"
    assert "requests==2.31.0" in dockerfile.read_text()  # untouched


# ---------------------------------------------------------------------------
# Multi-package RUN lines
# ---------------------------------------------------------------------------

def test_inline_install_multi_package_single_run(
    tmp_path: Path,
) -> None:
    """``RUN pip install foo==1 bar==2`` — only the targeted
    package is rewritten; the rest is left alone."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.13\n"
        "RUN pip install semgrep==1.161.0 black==24.0.0 ruff==0.5.0\n",
    )
    edits = [RewriteEdit(
        locator="black", old_value="24.0.0", new_value="25.0.0",
    )]
    results = rewrite_dockerfile_inline_install(dockerfile, edits)
    assert results[0].applied
    txt = dockerfile.read_text()
    assert "semgrep==1.161.0" in txt
    assert "black==25.0.0" in txt
    assert "ruff==0.5.0" in txt


def test_inline_install_multi_line_continuation(
    tmp_path: Path,
) -> None:
    """RUN bodies that span multiple physical lines via ``\\``
    continuation are common in real Dockerfiles. The rewriter
    matches across lines because it operates on the file's full
    text rather than line-by-line."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.13\n"
        "RUN pip install --no-cache-dir \\\n"
        "        semgrep==1.161.0 \\\n"
        "        black==24.0.0\n",
    )
    edits = [RewriteEdit(
        locator="semgrep", old_value="1.161.0", new_value="1.163.0",
    )]
    results = rewrite_dockerfile_inline_install(dockerfile, edits)
    assert results[0].applied
    assert "semgrep==1.163.0" in dockerfile.read_text()


def test_inline_install_name_collision_word_boundary(
    tmp_path: Path,
) -> None:
    """``foo`` and ``foobar`` share a prefix. The word-boundary
    in the regex must NOT match ``foobar==1.0`` when bumping ``foo``."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.13\n"
        "RUN pip install foo==1.0.0 foobar==2.0.0\n",
    )
    edits = [RewriteEdit(
        locator="foo", old_value="1.0.0", new_value="1.1.0",
    )]
    results = rewrite_dockerfile_inline_install(dockerfile, edits)
    assert results[0].applied
    txt = dockerfile.read_text()
    assert "foo==1.1.0" in txt
    assert "foobar==2.0.0" in txt  # untouched


# ---------------------------------------------------------------------------
# Dispatcher integration through ``rewrite()``
# ---------------------------------------------------------------------------

def test_dispatcher_routes_via_extra_kind(tmp_path: Path) -> None:
    """An edit with ``extra["kind"] == "inline_install_pip"`` is
    routed to the inline-install rewriter by the dockerfile_from
    dispatcher, not to dockerfile_arg or the FROM-image path."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.13\nRUN pip install semgrep==1.161.0\n",
    )
    edits = [RewriteEdit(
        locator="semgrep",
        old_value="1.161.0",
        new_value="1.163.0",
        extra={"kind": "inline_install_pip"},
    )]
    results = rewrite(dockerfile, edits)
    assert len(results) == 1
    assert results[0].applied
    assert "semgrep==1.163.0" in dockerfile.read_text()


def test_dispatcher_mixed_arg_and_inline_install(
    tmp_path: Path,
) -> None:
    """A single ``rewrite()`` call can carry both an ARG edit
    and an inline_install edit; both should land."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.13\n"
        "ARG CODEQL_VERSION=2.15.5\n"
        "RUN pip install semgrep==1.161.0\n",
    )
    edits = [
        RewriteEdit(
            locator="CODEQL_VERSION",
            old_value="2.15.5", new_value="2.25.4",
            extra={"kind": "arg"},
        ),
        RewriteEdit(
            locator="semgrep",
            old_value="1.161.0", new_value="1.163.0",
            extra={"kind": "inline_install_pip"},
        ),
    ]
    results = rewrite(dockerfile, edits)
    assert all(r.applied for r in results)
    txt = dockerfile.read_text()
    assert "ARG CODEQL_VERSION=2.25.4" in txt
    assert "semgrep==1.163.0" in txt
