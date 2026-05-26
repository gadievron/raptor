"""Tests for the ``.pre-commit-config.yaml`` parser."""

from __future__ import annotations

from pathlib import Path

from packages.sca.models import PinStyle
from packages.sca.parsers.precommit import (
    _canonicalise_repo,
    _classify_rev,
    parse,
)


def _write(tmp_path: Path, content: str, name: str = ".pre-commit-config.yaml") -> Path:
    p = tmp_path / name
    p.write_text(content)
    return p


# ---------------------------------------------------------------------------
# Mapped repos → underlying registry
# ---------------------------------------------------------------------------


def test_mapped_ruff_emits_pypi(tmp_path):
    p = _write(tmp_path, """\
repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.6.9
    hooks:
      - id: ruff
""")
    [d] = parse(p)
    assert d.ecosystem == "PyPI"
    assert d.name == "ruff"
    assert d.version == "v0.6.9"
    assert d.purl == "pkg:pypi/ruff@v0.6.9"
    assert d.scope == "dev"
    assert d.source_kind == "precommit"
    assert d.source_extra["hook_ids"] == ["ruff"]
    assert d.parser_confidence.level == "high"


def test_mapped_black_emits_pypi(tmp_path):
    p = _write(tmp_path, """\
repos:
  - repo: https://github.com/psf/black
    rev: 24.10.0
    hooks:
      - id: black
""")
    [d] = parse(p)
    assert d.ecosystem == "PyPI"
    assert d.name == "black"
    assert d.version == "24.10.0"


def test_mapped_eslint_emits_npm(tmp_path):
    """``mirrors-eslint`` maps to npm:eslint, not PyPI."""
    p = _write(tmp_path, """\
repos:
  - repo: https://github.com/pre-commit/mirrors-eslint
    rev: v9.10.0
    hooks:
      - id: eslint
""")
    [d] = parse(p)
    assert d.ecosystem == "npm"
    assert d.name == "eslint"
    assert d.purl == "pkg:npm/eslint@v9.10.0"


def test_mapped_dotgit_url_canonicalises(tmp_path):
    """``...black.git`` maps the same as ``...black``."""
    p = _write(tmp_path, """\
repos:
  - repo: https://github.com/psf/black.git
    rev: 24.10.0
    hooks: []
""")
    [d] = parse(p)
    assert d.ecosystem == "PyPI"
    assert d.name == "black"


def test_mapped_ssh_url_canonicalises(tmp_path):
    p = _write(tmp_path, """\
repos:
  - repo: git@github.com:psf/black.git
    rev: 24.10.0
    hooks: []
""")
    [d] = parse(p)
    assert d.ecosystem == "PyPI"
    assert d.name == "black"


def test_mapped_case_insensitive(tmp_path):
    """``Astral-SH/ruff-PRE-commit`` (mixed case) still maps."""
    p = _write(tmp_path, """\
repos:
  - repo: https://github.com/Astral-SH/ruff-PRE-commit
    rev: v0.6.9
    hooks: []
""")
    [d] = parse(p)
    assert d.name == "ruff"


# ---------------------------------------------------------------------------
# Unmapped repos → GitHub fallback
# ---------------------------------------------------------------------------


def test_unmapped_repo_falls_back_to_github(tmp_path):
    """Some custom-org pre-commit repo isn't in the curated map.
    Emit with ecosystem=GitHub for SBOM visibility."""
    p = _write(tmp_path, """\
repos:
  - repo: https://github.com/myorg/custom-hooks
    rev: v1.0.0
    hooks:
      - id: my-check
""")
    [d] = parse(p)
    assert d.ecosystem == "GitHub"
    assert d.name == "myorg/custom-hooks"
    assert d.purl == "pkg:github/myorg/custom-hooks@v1.0.0"
    # Lower confidence: unmapped means we can't verify the
    # downstream package mapping.
    assert d.parser_confidence.level == "medium"


# ---------------------------------------------------------------------------
# Skip cases
# ---------------------------------------------------------------------------


def test_local_repo_skipped(tmp_path):
    """``repo: local`` declares hooks running scripts in the
    current repo — no external version, nothing to scan."""
    p = _write(tmp_path, """\
repos:
  - repo: local
    hooks:
      - id: my-script
        entry: scripts/check.sh
""")
    assert parse(p) == []


def test_meta_repo_skipped(tmp_path):
    """pre-commit's ``meta`` pseudo-repo for built-in hooks."""
    p = _write(tmp_path, """\
repos:
  - repo: meta
    hooks:
      - id: check-hooks-apply
""")
    assert parse(p) == []


def test_missing_rev_skipped(tmp_path):
    """No ``rev:`` field — skip silently."""
    p = _write(tmp_path, """\
repos:
  - repo: https://github.com/psf/black
    hooks:
      - id: black
""")
    assert parse(p) == []


def test_malformed_yaml(tmp_path):
    p = _write(tmp_path, ":\n  - garbage")
    # Either empty deps OR no crash — both acceptable. Parser must
    # not raise.
    assert parse(p) == []


def test_top_level_array(tmp_path):
    """Top-level array, not dict — common YAML mistake. Don't crash."""
    p = _write(tmp_path, "- foo\n- bar\n")
    assert parse(p) == []


def test_repos_block_not_a_list(tmp_path):
    p = _write(tmp_path, "repos:\n  not_a_list: true\n")
    assert parse(p) == []


def test_yml_extension(tmp_path):
    """Both ``.yaml`` and ``.yml`` extensions are valid pre-commit
    config names."""
    p = _write(tmp_path, """\
repos:
  - repo: https://github.com/psf/black
    rev: 24.10.0
    hooks: []
""", name=".pre-commit-config.yml")
    [d] = parse(p)
    assert d.name == "black"


# ---------------------------------------------------------------------------
# Multi-repo + multi-hook
# ---------------------------------------------------------------------------


def test_multiple_repos_emitted_independently(tmp_path):
    p = _write(tmp_path, """\
repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.6.9
    hooks:
      - id: ruff
  - repo: https://github.com/psf/black
    rev: 24.10.0
    hooks:
      - id: black
  - repo: local
    hooks:
      - id: local-thing
""")
    deps = parse(p)
    by_name = {d.name: d for d in deps}
    assert "ruff" in by_name
    assert "black" in by_name
    assert len(deps) == 2          # local skipped


def test_multiple_hooks_per_repo_emit_one_dep(tmp_path):
    """Multiple hooks under the same repo + rev pin → one
    Dependency. The hook IDs are captured in source_extra for
    SBOM context."""
    p = _write(tmp_path, """\
repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.6.9
    hooks:
      - id: ruff
      - id: ruff-format
""")
    [d] = parse(p)
    assert d.source_extra["hook_ids"] == ["ruff", "ruff-format"]


# ---------------------------------------------------------------------------
# Pin classification
# ---------------------------------------------------------------------------


def test_sha_pin_classified_as_git(tmp_path):
    sha = "a" * 40
    p = _write(tmp_path, f"""\
repos:
  - repo: https://github.com/psf/black
    rev: {sha}
    hooks: []
""")
    [d] = parse(p)
    assert d.pin_style == PinStyle.GIT


def test_classify_rev_helper():
    assert _classify_rev("v1.2.3") == PinStyle.EXACT
    assert _classify_rev("24.10.0") == PinStyle.EXACT
    assert _classify_rev("a" * 40) == PinStyle.GIT
    assert _classify_rev("main") == PinStyle.UNKNOWN


# ---------------------------------------------------------------------------
# _canonicalise_repo helper
# ---------------------------------------------------------------------------


def test_canonicalise_https():
    assert _canonicalise_repo(
        "https://github.com/psf/black",
    ) == "github.com/psf/black"


def test_canonicalise_strips_dotgit():
    assert _canonicalise_repo(
        "https://github.com/psf/black.git",
    ) == "github.com/psf/black"


def test_canonicalise_lowercases():
    assert _canonicalise_repo(
        "https://GitHub.com/PSF/Black",
    ) == "github.com/psf/black"


def test_canonicalise_ssh_form():
    assert _canonicalise_repo(
        "git@github.com:psf/black.git",
    ) == "github.com/psf/black"


def test_canonicalise_returns_none_for_garbage():
    assert _canonicalise_repo("") is None
    assert _canonicalise_repo("not a url") is None


# ---------------------------------------------------------------------------
# additional_dependencies extraction
# ---------------------------------------------------------------------------


def test_additional_dependencies_extracted_for_pypi_hook(tmp_path):
    """``mirrors-mypy`` typically has ``additional_dependencies:
    ["pydantic>=2.5", "types-PyYAML"]``. Each becomes a PyPI
    Dependency in the ``precommit_additional`` source kind."""
    p = _write(tmp_path, """\
repos:
  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.11.2
    hooks:
      - id: mypy
        additional_dependencies: ["pydantic>=2.5", "types-PyYAML"]
""")
    deps = parse(p)
    by_name = {d.name: d for d in deps}
    # The mypy main row + two additional dep rows.
    assert "mypy" in by_name
    assert "pydantic" in by_name
    assert "types-PyYAML" in by_name
    assert by_name["pydantic"].ecosystem == "PyPI"
    assert by_name["pydantic"].version == ">=2.5"
    assert by_name["pydantic"].pin_style == PinStyle.RANGE
    assert by_name["pydantic"].source_kind == "precommit_additional"
    assert by_name["pydantic"].source_extra["hook_id"] == "mypy"


def test_additional_dependencies_inherits_npm_for_npm_hook(tmp_path):
    """``mirrors-eslint`` is npm — its additional_dependencies
    should also be classified as npm."""
    p = _write(tmp_path, """\
repos:
  - repo: https://github.com/pre-commit/mirrors-eslint
    rev: v9.10.0
    hooks:
      - id: eslint
        additional_dependencies: ["eslint-plugin-foo@2.0.0"]
""")
    deps = parse(p)
    by_name = {d.name: d for d in deps}
    assert "eslint-plugin-foo" in by_name
    assert by_name["eslint-plugin-foo"].ecosystem == "npm"
    assert by_name["eslint-plugin-foo"].version == "2.0.0"


def test_additional_dependencies_unmapped_repo_defaults_to_pypi(tmp_path):
    """Unmapped repo + additional_dependencies → default to PyPI
    (the dominant pre-commit shape)."""
    p = _write(tmp_path, """\
repos:
  - repo: https://github.com/myorg/custom-hook
    rev: v1.0.0
    hooks:
      - id: x
        additional_dependencies: ["helper==2.0"]
""")
    deps = parse(p)
    addl = [d for d in deps if d.source_kind == "precommit_additional"]
    assert len(addl) == 1
    assert addl[0].name == "helper"
    assert addl[0].version == "2.0"
    assert addl[0].ecosystem == "PyPI"
    assert addl[0].pin_style == PinStyle.EXACT


def test_additional_dependencies_local_hook_skipped(tmp_path):
    """``repo: local`` hooks shouldn't surface their additional_deps
    — local hook shells out to a script with whatever's already
    installed."""
    p = _write(tmp_path, """\
repos:
  - repo: local
    hooks:
      - id: my-script
        entry: scripts/check.py
        additional_dependencies: ["foo==1.0"]
""")
    deps = parse(p)
    assert deps == []


def test_pep508_extras_stripped(tmp_path):
    """``pydantic[email]>=2.5`` — extras don't survive into the
    package name (purl uses bare name)."""
    p = _write(tmp_path, """\
repos:
  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.11.2
    hooks:
      - id: mypy
        additional_dependencies: ["pydantic[email]>=2.5"]
""")
    deps = parse(p)
    addl = [d for d in deps if d.source_kind == "precommit_additional"]
    assert len(addl) == 1
    assert addl[0].name == "pydantic"
    assert addl[0].version == ">=2.5"


def test_additional_dependencies_string_form_skipped(tmp_path):
    """``additional_dependencies: "foo"`` (string, not list) — non-
    standard, skip silently."""
    p = _write(tmp_path, """\
repos:
  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.11.2
    hooks:
      - id: mypy
        additional_dependencies: "foo"
""")
    deps = parse(p)
    addl = [d for d in deps if d.source_kind == "precommit_additional"]
    assert addl == []


def test_multiple_hooks_each_with_their_own_additional_deps(tmp_path):
    """Two hooks in the same repo, each with their own
    ``additional_dependencies`` list."""
    p = _write(tmp_path, """\
repos:
  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.11.2
    hooks:
      - id: mypy
        additional_dependencies: ["pydantic>=2.5"]
      - id: mypy-strict
        additional_dependencies: ["types-PyYAML"]
""")
    deps = parse(p)
    addl = {d.name: d for d in deps if d.source_kind == "precommit_additional"}
    assert addl["pydantic"].source_extra["hook_id"] == "mypy"
    assert addl["types-PyYAML"].source_extra["hook_id"] == "mypy-strict"
