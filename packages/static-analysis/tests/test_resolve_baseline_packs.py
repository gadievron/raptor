"""Tests for ``_resolve_baseline_packs`` + ``_pack_tuple_for_id`` —
the QoL #7-7b catalog-driven baseline-pack resolution."""

from __future__ import annotations

import importlib.util
from pathlib import Path

from core.config import RaptorConfig

# packages/static-analysis isn't an importable package (the dir
# name contains a hyphen). Load the module directly via spec so
# the helpers are reachable in tests — same pattern other
# static-analysis tests in this dir use (see e.g.
# test_scanner_semgrep_parallel.py).
_SCANNER_PATH = Path(__file__).resolve().parents[1] / "scanner.py"
_spec = importlib.util.spec_from_file_location(
    "_scanner_under_test_resolve_baseline", _SCANNER_PATH,
)
_scanner = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_scanner)

_pack_tuple_for_id = _scanner._pack_tuple_for_id
_resolve_baseline_packs = _scanner._resolve_baseline_packs


class TestPackTupleForId:
    """Resolve catalog pack-id-suffix → (display_name, full_pack_id)."""

    def test_baseline_pack_id_resolves_to_canonical_tuple(self):
        # ``security-audit`` is in BASELINE_SEMGREP_PACKS; should
        # return the canonical tuple (display name aligns with the
        # baseline registration).
        name, fid = _pack_tuple_for_id("security-audit")
        assert fid == "p/security-audit"
        # Display name matches what BASELINE_SEMGREP_PACKS uses.
        baseline_pair = next(
            (n, f) for n, f in RaptorConfig.BASELINE_SEMGREP_PACKS
            if f == "p/security-audit"
        )
        assert name == baseline_pair[0]

    def test_policy_group_pack_id_resolves_via_mapping(self):
        # ``command-injection`` lives in POLICY_GROUP_TO_SEMGREP_PACK
        # (under the ''injection'' key), not BASELINE. Resolver
        # checks both places.
        name, fid = _pack_tuple_for_id("command-injection")
        assert fid == "p/command-injection"
        # POLICY_GROUP_TO_SEMGREP_PACK has ('semgrep_injection',
        # 'p/command-injection') under 'injection' — verify the
        # name matches.
        policy_pair = next(
            (n, f) for n, f
            in RaptorConfig.POLICY_GROUP_TO_SEMGREP_PACK.values()
            if f == "p/command-injection"
        )
        assert name == policy_pair[0]

    def test_unknown_pack_id_synthesises_name(self):
        # Catalog author shipped a pack the codebase doesn't have
        # a name convention for — synthesise a safe display name
        # rather than crashing.
        name, fid = _pack_tuple_for_id("future-rule-pack")
        assert fid == "p/future-rule-pack"
        # Synthesised name: hyphens → underscores, ``semgrep_``
        # prefix.
        assert name == "semgrep_future_rule_pack"


class TestResolveBaselinePacks:
    """Catalog-aware baseline selection. Operator-explicit
    ``--policy-groups`` happens elsewhere in main; this resolver
    only governs the baseline (what runs when not narrowed)."""

    def test_no_repo_path_returns_hardcoded_baseline(self):
        # No path → can't consult catalog → fall back to hardcoded
        # BASELINE_SEMGREP_PACKS.
        result = _resolve_baseline_packs(None)
        assert list(result) == list(RaptorConfig.BASELINE_SEMGREP_PACKS)

    def test_empty_target_falls_back_to_generic_and_hardcoded(self, tmp_path):
        # Empty target → catalog matches ``generic`` → generic has
        # no semgrep_packs_default → resolver falls back to
        # hardcoded baseline. (``generic`` IS shipped with default
        # packs in the seed YAML, so this test actually exercises
        # the catalog path — but the catalog's packs are
        # ``security-audit + owasp-top-ten`` which differs from
        # the hardcoded baseline's three-pack set. Assert the
        # returned list at least exists and is non-empty; specific
        # equality with hardcoded would conflate test intent.)
        result = _resolve_baseline_packs(tmp_path)
        # generic.yml ships ``security-audit`` + ``owasp-top-ten``
        # in default. Verify resolver picked it up (catalog-aware
        # path fires).
        assert len(result) >= 1
        assert any(fid == "p/security-audit" for _, fid in result)

    def test_c_userspace_daemon_target_uses_catalog_default(self, tmp_path):
        # Build a tree matching c.userspace-daemon detection.
        (tmp_path / "configure.ac").write_text("")
        (tmp_path / "Makefile.am").write_text("")
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "main.c").write_text("")
        result = _resolve_baseline_packs(tmp_path)
        # c.userspace-daemon.yml ships:
        #   default: [security-audit, command-injection, owasp-top-ten]
        # Verify all three are in the result (in the canonical
        # tuple shape).
        pack_ids = {fid for _, fid in result}
        assert "p/security-audit" in pack_ids
        assert "p/command-injection" in pack_ids
        assert "p/owasp-top-ten" in pack_ids

    def test_python_web_app_target_uses_catalog_default(self, tmp_path):
        (tmp_path / "manage.py").write_text("")
        (tmp_path / "settings.py").write_text("")
        (tmp_path / "urls.py").write_text("")
        result = _resolve_baseline_packs(tmp_path)
        # python.web-app.yml ships a broader set including
        # ``python-django`` / ``python-flask`` packs — verify
        # security-audit + owasp-top-ten at minimum are in.
        pack_ids = {fid for _, fid in result}
        assert "p/security-audit" in pack_ids
        assert "p/owasp-top-ten" in pack_ids


class TestCatalogLoadFailureTolerated:
    """Best-effort: catalog substrate failures must not break the
    scan. Resolver falls back to hardcoded baseline silently."""

    def test_catalog_exception_falls_back_to_hardcoded(self, monkeypatch, tmp_path):
        import core.run.target_types as tt
        def _boom(_path):
            raise RuntimeError("catalog corrupted")
        monkeypatch.setattr(tt, "load", _boom)
        result = _resolve_baseline_packs(tmp_path)
        assert list(result) == list(RaptorConfig.BASELINE_SEMGREP_PACKS)
