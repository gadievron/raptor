"""Tests for ``_resolve_rules_applied`` — fixes the
catalog-vs-policy-group mismatch where the coverage report falsely
flagged groups as not-used when a catalog had actually added them
to the baseline."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from core.config import RaptorConfig

_SCANNER_PATH = Path(__file__).resolve().parents[1] / "scanner.py"
_spec = importlib.util.spec_from_file_location(
    "_scanner_under_test_resolve_rules_applied", _SCANNER_PATH,
)
_scanner = importlib.util.module_from_spec(_spec)
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
_spec.loader.exec_module(_scanner)

_resolve_rules_applied = _scanner._resolve_rules_applied


# ---------------------------------------------------------------------------
# Helper: synthesise the local rule_dirs that ``--policy-groups all`` would
# pass — every dir under SEMGREP_RULES_DIR that matches a policy group key.
# ---------------------------------------------------------------------------

def _all_local_policy_dirs() -> list:
    """Local rule dirs whose name matches a POLICY_GROUP key —
    these are the ones the ``--policy-groups all`` expansion
    actually triggers via scanner.py's rule-dir loop."""
    base = RaptorConfig.SEMGREP_RULES_DIR
    pg_keys = set(RaptorConfig.POLICY_GROUP_TO_SEMGREP_PACK.keys())
    return sorted(
        str(p) for p in base.iterdir()
        if p.is_dir() and p.name in pg_keys
    )


class TestAllExpansionViaRuleDirs:
    """``--policy-groups all`` passes every local rule dir to
    semgrep_scan_parallel, which auto-adds the corresponding
    registry pack when the dir name matches a policy_group key.
    The reverse-mapping below recovers which policy groups got
    exercised."""

    def test_all_expansion_via_rule_dirs_matches_every_extant_group(self):
        # Drive _resolve_rules_applied with the rules_dirs that
        # ``--policy-groups all`` would actually produce; the
        # applied set should equal every policy_group with a
        # local rule dir (which on a populated checkout is the
        # full set MINUS any policy group lacking a local dir).
        local_pg_dirs = _all_local_policy_dirs()
        result = _resolve_rules_applied(
            groups=["all"], resolved_baseline=[],
            rules_dirs=local_pg_dirs,
        )
        # On the shipped checkout, every policy group EXCEPT
        # ``best-practices`` has a local rule dir. Walking the
        # ``flows/`` dir auto-adds ``p/default``, which is ALSO
        # ``best-practices``'s pack — so ``best-practices`` lands
        # in applied too, via the shared-pack reverse-mapping.
        # All 6 groups should be present.
        assert set(result) == set(
            RaptorConfig.POLICY_GROUP_TO_SEMGREP_PACK.keys()
        )

    def test_all_does_not_leak_literal_all(self):
        # Regression: pre-fix stored 'all' in the list. Make sure
        # 'all' is never in the final rules_applied output.
        result = _resolve_rules_applied(
            groups=["all"], resolved_baseline=[], rules_dirs=[],
        )
        assert "all" not in result


class TestSharedPackReverseMapping:
    """When two policy groups share a pack id (``flows`` and
    ``best-practices`` both → ``p/default``), running one
    correctly marks both as applied — the rendered ''not used''
    line shouldn't single out the no-local-dir group when its
    shared pack actually ran."""

    def test_flows_runs_implies_best_practices_applied(self, tmp_path):
        # Synthesise a rules_dirs that includes ``flows`` but not
        # ``best-practices`` (which doesn't exist as a local dir
        # anyway). Both policy groups share ``p/default``, so
        # both should land in applied.
        flows_dir = tmp_path / "flows"
        flows_dir.mkdir()
        result = _resolve_rules_applied(
            groups=["flows"], resolved_baseline=[],
            rules_dirs=[str(flows_dir)],
        )
        assert "flows" in result
        assert "best-practices" in result

    def test_no_local_dir_group_not_falsely_applied(self, tmp_path):
        # Pre-correctness-fix version of the helper marked
        # ``best-practices`` as applied on ``--policy-groups all``
        # without checking the rule-dir exists, because it
        # blindly expanded ``all`` → all groups. The pack-id
        # driven version only marks it when its pack ran.
        result = _resolve_rules_applied(
            groups=["all"], resolved_baseline=[], rules_dirs=[],
        )
        # No rule dirs passed → no packs ran via rule-dir loop;
        # no baseline either. best-practices must NOT be in
        # applied.
        assert "best-practices" not in result


class TestCatalogReverseMapping:
    """Catalog-driven baseline pack additions reverse-map to
    their corresponding policy_group keys."""

    def test_command_injection_pack_registers_injection_group(self):
        baseline = [
            ("semgrep_security_audit", "p/security-audit"),
            ("semgrep_injection", "p/command-injection"),
            ("semgrep_owasp_top_10", "p/owasp-top-ten"),
        ]
        result = _resolve_rules_applied(
            groups=[], resolved_baseline=baseline, rules_dirs=[],
        )
        assert "injection" in result

    def test_jwt_pack_registers_auth_group(self):
        baseline = [("semgrep_auth", "p/jwt")]
        result = _resolve_rules_applied(
            groups=[], resolved_baseline=baseline, rules_dirs=[],
        )
        assert "auth" in result

    def test_default_pack_registers_both_flows_and_best_practices(self):
        # Catalog-driven ``p/default`` is the shared pack for two
        # policy groups; the reverse-mapping correctly marks BOTH.
        baseline = [("semgrep_default", "p/default")]
        result = _resolve_rules_applied(
            groups=[], resolved_baseline=baseline, rules_dirs=[],
        )
        assert "flows" in result
        assert "best-practices" in result

    def test_unknown_baseline_pack_doesnt_register_a_group(self):
        baseline = [("semgrep_random", "p/some-future-pack")]
        result = _resolve_rules_applied(
            groups=[], resolved_baseline=baseline, rules_dirs=[],
        )
        # No policy groups exercised → empty list (rules_dirs
        # fallback also empty here).
        assert result == []


class TestRuleDirMatching:
    """When a rule dir's name matches a policy_group key, the
    scanner auto-adds the registry pack — so the group lands in
    applied via the pack-id reverse-mapping."""

    def test_injection_rule_dir_registers_injection_group(self, tmp_path):
        injection_dir = tmp_path / "injection"
        injection_dir.mkdir()
        result = _resolve_rules_applied(
            groups=["injection"], resolved_baseline=[],
            rules_dirs=[str(injection_dir)],
        )
        assert "injection" in result

    def test_non_policy_group_rule_dir_doesnt_register(self, tmp_path):
        # Local rule dir whose name doesn't match any policy
        # group (e.g. ``crypto`` — exists locally but has no
        # policy_group registry mapping, only local rules).
        crypto_dir = tmp_path / "crypto"
        crypto_dir.mkdir()
        result = _resolve_rules_applied(
            groups=["crypto"], resolved_baseline=[],
            rules_dirs=[str(crypto_dir)],
        )
        # Crypto isn't in POLICY_GROUP_TO_SEMGREP_PACK → no
        # registry pack added → no policy group in applied.
        # Falls through to rules_dirs fallback.
        assert result == ["crypto"]


class TestFallbackToRuleDirs:
    """When no policy group was exercised, fall back to local
    rule-dir basenames — preserves pre-fix shape for the
    genuinely-empty case."""

    def test_empty_inputs_with_rules_dirs_fall_back(self, tmp_path):
        # All rule dirs are non-policy-group names → no policy
        # groups marked → fallback fires.
        dir1 = tmp_path / "01-injection"
        dir2 = tmp_path / "02-crypto"
        result = _resolve_rules_applied(
            groups=[], resolved_baseline=[],
            rules_dirs=[str(dir1), str(dir2)],
        )
        assert "01-injection" in result
        assert "02-crypto" in result

    def test_truly_empty_inputs_return_empty_list(self):
        result = _resolve_rules_applied(
            groups=[], resolved_baseline=[], rules_dirs=[],
        )
        assert result == []


# ---------------------------------------------------------------------------
# Integration test — _resolve_rules_applied output flows through
# _missing_semgrep_groups; assert the operator-facing "not used" check
# sees an empty list when everything ran.
# ---------------------------------------------------------------------------


def _missing_for(rules_applied: list) -> list:
    """Run the coverage-summary's missing-groups check against a
    synthetic ``tools`` dict carrying ``rules_applied``."""
    from core.coverage.summary import _missing_semgrep_groups
    return _missing_semgrep_groups({
        "semgrep": {
            "rules_applied": rules_applied,
            "packs": [],
            "files_failed": [],
            "files_examined": 1,
            "files_total": 1,
            "version": "1.79.0",
        }
    })


class TestEndToEndMissingGroups:
    """The contract the operator actually reads: when every
    policy-group's pack ran, ``_missing_semgrep_groups`` returns
    ``[]`` — no ''Semgrep policy group(s) not used'' line is
    rendered. This is the regression the c.userspace-daemon scan
    surfaced — let's pin it from both ends."""

    def test_all_expansion_yields_zero_missing(self):
        # When --policy-groups all runs against a full checkout,
        # every policy group's pack runs → missing should be [].
        result = _resolve_rules_applied(
            groups=["all"], resolved_baseline=[],
            rules_dirs=_all_local_policy_dirs(),
        )
        assert _missing_for(result) == []

    def test_c_userspace_daemon_catalog_baseline_yields_zero_missing(self):
        # The catalog that surfaced the bug: ``injection`` shows
        # as not-used in the pre-fix world; post-fix it lands in
        # applied via the catalog reverse-mapping plus the
        # rule-dir loop. Run the realistic combined input.
        baseline = [
            ("semgrep_security_audit", "p/security-audit"),
            ("semgrep_injection", "p/command-injection"),
            ("semgrep_owasp_top_10", "p/owasp-top-ten"),
        ]
        result = _resolve_rules_applied(
            groups=["all"], resolved_baseline=baseline,
            rules_dirs=_all_local_policy_dirs(),
        )
        # All 6 policy groups exercised → no missing.
        assert _missing_for(result) == []

    def test_no_groups_no_baseline_lists_every_group_missing(self):
        # Sanity counter-test: when nothing exercises a policy
        # group, all 6 SHOULD show as missing (this is the
        # behaviour the operator legitimately wants for an
        # opt-out / partial-coverage scan).
        result = _resolve_rules_applied(
            groups=[], resolved_baseline=[], rules_dirs=[],
        )
        missing = _missing_for(result)
        assert set(missing) == set(
            RaptorConfig.POLICY_GROUP_TO_SEMGREP_PACK.keys()
        )
