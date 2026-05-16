"""Tests for ``core.security.codeql_trust``.

Mirrors the structure of ``test_cc_trust.py``:
  - cache reset + trust-override reset autouse fixtures
  - per-class grouping by source-file shape (no config / pack only /
    config only / both / structural pathologies)
  - asserts both the verdict and the printed output (operator visibility)
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# packages/cve_diff/tests/... — we ensure the repo root is on sys.path so
# tests can run when invoked from a sub-directory pytest.
try:
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
except IndexError:                                     # pragma: no cover
    pass

from core.security.codeql_trust import (
    check_repo_codeql_trust,
    set_trust_override,
    _scan_cached,
)


@pytest.fixture(autouse=True)
def _clear_trust_cache():
    """Fresh cache per test so prints happen deterministically."""
    _scan_cached.cache_clear()
    yield
    _scan_cached.cache_clear()


@pytest.fixture(autouse=True)
def _reset_trust_override():
    """Reset the module-level trust flag between tests."""
    set_trust_override(False)
    yield
    set_trust_override(False)


_check = check_repo_codeql_trust


# ---------------------------------------------------------------------------
# No config — silent pass
# ---------------------------------------------------------------------------


class TestNoConfig:
    def test_empty_dir_returns_false_silent(self, tmp_path, capsys):
        assert _check(str(tmp_path)) is False
        assert capsys.readouterr().out == ""

    def test_empty_repo_path_short_circuits(self, tmp_path):
        """``Path("").resolve()`` would yield CWD — guard skips."""
        assert _check("") is False

    def test_nonexistent_path(self, tmp_path):
        assert _check(str(tmp_path / "does-not-exist")) is False


# ---------------------------------------------------------------------------
# codeql-pack.yml / qlpack.yml scanning
# ---------------------------------------------------------------------------


class TestPackFile:
    def test_canonical_only_silent(self, tmp_path, capsys):
        """Pure ``codeql/...`` deps are the canonical case — informative
        only, never blocking. Also no extractor / hooks."""
        (tmp_path / "qlpack.yml").write_text(
            "name: my/pack\n"
            "version: 0.0.1\n"
            "dependencies:\n"
            "  codeql/python-all: '*'\n"
        )
        assert _check(str(tmp_path)) is False
        # No findings → no print
        assert capsys.readouterr().out == ""

    def test_extractor_blocks(self, tmp_path, capsys):
        (tmp_path / "codeql-pack.yml").write_text(
            "name: attacker/evil\n"
            "extractor: ./build/evil-binary\n"
        )
        assert _check(str(tmp_path)) is True
        out = capsys.readouterr().out
        assert "extractor" in out
        assert "evil-binary" in out

    def test_non_canonical_dependency_blocks(self, tmp_path, capsys):
        (tmp_path / "qlpack.yml").write_text(
            "name: my/pack\n"
            "dependencies:\n"
            "  evilcorp/exploits: '*'\n"
            "  codeql/python-all: '*'\n"
        )
        assert _check(str(tmp_path)) is True
        out = capsys.readouterr().out
        assert "non-canonical dep" in out
        assert "evilcorp/exploits" in out
        # Canonical dep should NOT trigger a finding line of its own.
        assert "codeql/python-all" not in out.split("non-canonical dep")[1]

    def test_build_command_blocks(self, tmp_path, capsys):
        (tmp_path / "qlpack.yml").write_text(
            "name: my/pack\n"
            "buildCommand: rm -rf /\n"
        )
        assert _check(str(tmp_path)) is True
        assert "buildCommand" in capsys.readouterr().out

    def test_pre_compile_script_blocks(self, tmp_path, capsys):
        (tmp_path / "qlpack.yml").write_text(
            "name: my/pack\n"
            "preCompileScript: ./setup.sh\n"
        )
        assert _check(str(tmp_path)) is True
        assert "preCompileScript" in capsys.readouterr().out

    def test_dependencies_as_list_blocks(self, tmp_path, capsys):
        """Adversarial: YAML is permissive enough that ``dependencies``
        could be expressed as a flat list rather than the documented
        dict form. The check must inspect both shapes — earlier the
        dict-only ``isinstance`` guard let list-form deps slip past."""
        (tmp_path / "qlpack.yml").write_text(
            "name: x\n"
            "dependencies:\n"
            "  - evilcorp/exploit\n"
            "  - codeql/python-all\n"
        )
        assert _check(str(tmp_path)) is True
        out = capsys.readouterr().out
        assert "non-canonical dep" in out
        assert "evilcorp/exploit" in out

    def test_default_suite_file_traversal_blocks(self, tmp_path, capsys):
        """Adversarial: ``defaultSuiteFile`` with ``../`` or absolute
        path escapes the pack and references operator-side files."""
        (tmp_path / "qlpack.yml").write_text(
            "name: x\n"
            "defaultSuiteFile: ../../etc/passwd\n"
        )
        assert _check(str(tmp_path)) is True
        assert "defaultSuiteFile" in capsys.readouterr().out

    def test_default_suite_file_local_silent(self, tmp_path, capsys):
        """Pack-relative defaultSuiteFile is the canonical case — no
        traversal, no flag."""
        (tmp_path / "qlpack.yml").write_text(
            "name: x\n"
            "defaultSuiteFile: my-suite.qls\n"
        )
        assert _check(str(tmp_path)) is False
        assert capsys.readouterr().out == ""

    def test_extractor_falsy_silent(self, tmp_path, capsys):
        """``extractor: null`` and ``extractor: ""`` aren't real
        extractor declarations — no flag."""
        (tmp_path / "qlpack.yml").write_text(
            "name: x\n"
            "extractor: null\n"
        )
        assert _check(str(tmp_path)) is False
        assert capsys.readouterr().out == ""

    def test_malformed_yaml_blocks(self, tmp_path, capsys):
        (tmp_path / "qlpack.yml").write_text("name: [broken yaml\n  unbalanced")
        assert _check(str(tmp_path)) is True
        assert "malformed YAML" in capsys.readouterr().out

    def test_non_dict_root_blocks(self, tmp_path, capsys):
        (tmp_path / "qlpack.yml").write_text("- just\n- a\n- list\n")
        assert _check(str(tmp_path)) is True
        assert "non-dict YAML" in capsys.readouterr().out

    def test_walks_nested_dirs(self, tmp_path, capsys):
        """codeql walks the source root for pack files; we must too."""
        nested = tmp_path / "deeply" / "nested" / "subdir"
        nested.mkdir(parents=True)
        (nested / "qlpack.yml").write_text(
            "name: my/pack\n"
            "extractor: ./hidden\n"
        )
        assert _check(str(tmp_path)) is True
        assert "extractor" in capsys.readouterr().out

    def test_skips_dotted_dirs(self, tmp_path, capsys):
        """``.git`` / ``.claude/worktrees`` shouldn't be walked — their
        contents aren't part of the pack codeql will load."""
        hidden = tmp_path / ".claude" / "worktrees" / "x"
        hidden.mkdir(parents=True)
        (hidden / "qlpack.yml").write_text(
            "name: my/pack\n"
            "extractor: ./evil\n"
        )
        assert _check(str(tmp_path)) is False
        assert capsys.readouterr().out == ""

    def test_scans_dot_github(self, tmp_path, capsys):
        """``.github`` IS walked because that's where codeql-config.yml
        legitimately lives."""
        gh = tmp_path / ".github" / "codeql"
        gh.mkdir(parents=True)
        (gh / "codeql-config.yml").write_text(
            "name: x\n"
            "manualBuildSteps:\n"
            "  - 'sh evil.sh'\n"
        )
        assert _check(str(tmp_path)) is True
        assert "manualBuildSteps" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# .github/codeql/codeql-config.yml scanning
# ---------------------------------------------------------------------------


class TestCodeqlConfig:
    def _write_config(self, tmp_path: Path, body: str) -> None:
        gh = tmp_path / ".github" / "codeql"
        gh.mkdir(parents=True)
        (gh / "codeql-config.yml").write_text(body)

    def test_canonical_packs_only_silent(self, tmp_path, capsys):
        self._write_config(tmp_path,
            "name: ok\n"
            "packs:\n"
            "  python:\n"
            "    - codeql/python-queries\n"
        )
        assert _check(str(tmp_path)) is False
        assert capsys.readouterr().out == ""

    def test_non_canonical_pack_blocks(self, tmp_path, capsys):
        self._write_config(tmp_path,
            "name: x\n"
            "packs:\n"
            "  python:\n"
            "    - evilcorp/all\n"
            "    - codeql/python-queries\n"
        )
        assert _check(str(tmp_path)) is True
        out = capsys.readouterr().out
        assert "non-canonical pack" in out
        assert "evilcorp/all" in out

    def test_external_query_blocks(self, tmp_path, capsys):
        self._write_config(tmp_path,
            "name: x\n"
            "queries:\n"
            "  - uses: evilcorp/queries/main\n"
        )
        assert _check(str(tmp_path)) is True
        assert "external queries" in capsys.readouterr().out

    def test_relative_local_query_silent(self, tmp_path, capsys):
        self._write_config(tmp_path,
            "name: x\n"
            "queries:\n"
            "  - uses: ./local-suite.qls\n"
        )
        assert _check(str(tmp_path)) is False
        assert capsys.readouterr().out == ""

    def test_manual_build_steps_blocks(self, tmp_path, capsys):
        self._write_config(tmp_path,
            "name: x\n"
            "manualBuildSteps:\n"
            "  - 'sh evil.sh'\n"
        )
        assert _check(str(tmp_path)) is True
        assert "manualBuildSteps" in capsys.readouterr().out

    def test_flat_packs_list(self, tmp_path, capsys):
        self._write_config(tmp_path,
            "name: x\n"
            "packs:\n"
            "  - evilcorp/all\n"
        )
        assert _check(str(tmp_path)) is True
        assert "non-canonical pack" in capsys.readouterr().out

    def test_pack_cache_blocks(self, tmp_path, capsys):
        """Adversarial: ``pack-cache`` redirects codeql's pack download
        cache. A malicious target could point it at a pre-stocked
        in-repo directory so codeql 'downloads' attacker-supplied
        packs from there."""
        self._write_config(tmp_path,
            "name: x\n"
            "pack-cache: /attacker/cache\n"
        )
        assert _check(str(tmp_path)) is True
        assert "pack-cache" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Structural pathologies (oversize, symlink, RAPTOR self-scan)
# ---------------------------------------------------------------------------


class TestStructural:
    def test_symlink_pack_file_blocks(self, tmp_path, capsys):
        target = tmp_path / "real.yml"
        target.write_text("name: real/pack\n")
        link = tmp_path / "qlpack.yml"
        link.symlink_to(target)
        assert _check(str(tmp_path)) is True
        assert "symlink" in capsys.readouterr().out

    def test_oversized_pack_file_blocks(self, tmp_path, capsys):
        # 2 MiB pack file — beyond the 1 MiB cap.
        big = "name: x\n" + ("# pad\n" * 350_000)
        (tmp_path / "qlpack.yml").write_text(big)
        assert _check(str(tmp_path)) is True
        assert "oversized" in capsys.readouterr().out

    def test_raptor_self_scan_short_circuits(self, capsys):
        """Operator running RAPTOR against RAPTOR itself isn't an
        attack — RAPTOR ships its own codeql packs under
        packages/llm_analysis/codeql_packs/."""
        # The module's _RAPTOR_DIR = parents[2] of the module file
        # (core/security/codeql_trust.py), which is the repo root.
        # Use the same.
        from core.security.codeql_trust import _RAPTOR_DIR
        assert _check(str(_RAPTOR_DIR)) is False
        assert capsys.readouterr().out == ""


# ---------------------------------------------------------------------------
# Trust override
# ---------------------------------------------------------------------------


class TestTrustOverride:
    def test_module_flag_unblocks(self, tmp_path, capsys):
        (tmp_path / "qlpack.yml").write_text(
            "name: x\nextractor: ./evil\n"
        )
        # First confirm without override blocks.
        assert _check(str(tmp_path)) is True
        _scan_cached.cache_clear()  # so the warning re-renders below
        capsys.readouterr()  # drop output
        # Set override and confirm pass + override-active warning.
        set_trust_override(True)
        assert _check(str(tmp_path)) is False
        out = capsys.readouterr().out
        assert "trust override active" in out
        assert "extractor" in out

    def test_explicit_arg_overrides_module_flag(self, tmp_path, capsys):
        (tmp_path / "qlpack.yml").write_text(
            "name: x\nextractor: ./evil\n"
        )
        set_trust_override(True)
        # Explicit False forces strict regardless of module flag.
        assert _check(str(tmp_path), trust_override=False) is True

    def test_override_when_no_findings_no_warning(self, tmp_path, capsys):
        (tmp_path / "qlpack.yml").write_text("name: my/pack\n")
        set_trust_override(True)
        assert _check(str(tmp_path)) is False
        # Empty pack file produces no findings → nothing printed even
        # with override active.
        assert capsys.readouterr().out == ""


# ---------------------------------------------------------------------------
# Combined + display sanity
# ---------------------------------------------------------------------------


class TestCombined:
    def test_pack_plus_config_both_reported(self, tmp_path, capsys):
        (tmp_path / "qlpack.yml").write_text(
            "name: x\nextractor: ./bad\n"
        )
        gh = tmp_path / ".github" / "codeql"
        gh.mkdir(parents=True)
        (gh / "codeql-config.yml").write_text(
            "name: y\npacks:\n  - evil/pack\n"
        )
        assert _check(str(tmp_path)) is True
        out = capsys.readouterr().out
        assert "extractor" in out
        assert "non-canonical pack" in out
        assert "qlpack.yml" in out
        assert "codeql-config.yml" in out

    def test_findings_use_safe_truncation(self, tmp_path, capsys):
        """Long extractor values must be truncated; control chars stripped."""
        long_extractor = "./" + "evil" * 100  # 402 chars
        (tmp_path / "qlpack.yml").write_text(
            f"name: x\nextractor: '{long_extractor}'\n"
        )
        _check(str(tmp_path))
        out = capsys.readouterr().out
        # Truncated to ~120 chars + "..."
        assert "..." in out
        # Doesn't dump the full 400+ chars
        assert long_extractor not in out
