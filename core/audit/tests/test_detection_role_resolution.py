"""_is_detection_only resolves the stock-rule root fail-closed.

The rule path was joined against ``os.environ.get("RAPTOR_DIR", ".")``
— a doctrine-violating CWD fallback: with RAPTOR_DIR unset (embedders,
bare pytest from another directory) the isfile check missed, and a
stock DETECTION-role rule read as a dynamic per-hypothesis rule —
i.e. promotion-grade (fail-open into the promotion gate).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.audit.orchestrator import _is_detection_only

_RAPTOR_DIR = str(Path(__file__).resolve().parents[3])


class TestDetectionRoleResolution:
    def test_unset_raptor_dir_fails_closed(self, monkeypatch, tmp_path):
        monkeypatch.delenv("RAPTOR_DIR", raising=False)
        monkeypatch.chdir(tmp_path)  # CWD carries no engine/ tree
        assert _is_detection_only("coccinelle:alloc_narrow_count") is True

    def test_stock_detection_rule_resolves_with_raptor_dir(
        self, monkeypatch, tmp_path,
    ):
        monkeypatch.setenv("RAPTOR_DIR", _RAPTOR_DIR)
        monkeypatch.chdir(tmp_path)  # resolution must not lean on CWD
        assert _is_detection_only("coccinelle:alloc_narrow_count") is True

    def test_dynamic_rule_still_promotes(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_DIR", _RAPTOR_DIR)
        assert _is_detection_only(
            "coccinelle:hypothesis-generated-nonexistent-rule",
        ) is False

    def test_nonbase_free_requires_independent_origin_evidence(self, monkeypatch, tmp_path):
        from core.audit.sweep import get_rule_role

        monkeypatch.setenv("RAPTOR_DIR", _RAPTOR_DIR)
        monkeypatch.chdir(tmp_path)
        rule = Path(_RAPTOR_DIR) / "engine/coccinelle/rules/free_nonbase_ptr.cocci"
        assert get_rule_role(str(rule)) == "detection"
        assert _is_detection_only("coccinelle:free_nonbase_ptr") is True


    def test_is_err_return_requires_independent_errno_contract(self, monkeypatch, tmp_path):
        from core.audit.sweep import get_rule_role

        monkeypatch.setenv("RAPTOR_DIR", _RAPTOR_DIR)
        monkeypatch.chdir(tmp_path)
        rule = Path(_RAPTOR_DIR) / "engine/coccinelle/rules/is_err_not_ptr_err.cocci"
        assert get_rule_role(str(rule)) == "detection"
        assert _is_detection_only("coccinelle:is_err_not_ptr_err") is True


    def test_snprintf_boundary_requires_complete_output_contract(self, monkeypatch, tmp_path):
        from core.audit.sweep import get_rule_role

        monkeypatch.setenv("RAPTOR_DIR", _RAPTOR_DIR)
        monkeypatch.chdir(tmp_path)
        rule = Path(_RAPTOR_DIR) / "engine/coccinelle/rules/snprintf_truncation_boundary.cocci"
        assert get_rule_role(str(rule)) == "detection"
        assert _is_detection_only("coccinelle:snprintf_truncation_boundary") is True


    def test_strncpy_read_requires_independent_termination_evidence(self, monkeypatch, tmp_path):
        from core.audit.sweep import get_rule_role

        monkeypatch.setenv("RAPTOR_DIR", _RAPTOR_DIR)
        monkeypatch.chdir(tmp_path)
        rule = Path(_RAPTOR_DIR) / "engine/coccinelle/rules/strncpy_no_nul.cocci"
        assert get_rule_role(str(rule)) == "detection"
        assert _is_detection_only("coccinelle:strncpy_no_nul") is True


    @pytest.mark.parametrize("rule_name", ["rcu_no_lock", "rcu_dereference_outside_rcu"])
    def test_rcu_local_lock_checks_require_caller_context(self, monkeypatch, tmp_path, rule_name):
        from core.audit.sweep import get_rule_role

        monkeypatch.setenv("RAPTOR_DIR", _RAPTOR_DIR)
        monkeypatch.chdir(tmp_path)
        rule = Path(_RAPTOR_DIR) / "engine/coccinelle/rules" / f"{rule_name}.cocci"
        assert get_rule_role(str(rule)) == "detection"
        assert _is_detection_only(f"coccinelle:{rule_name}") is True


    @pytest.mark.parametrize("rule_name", ["sensitive_data_leak", "dead_memset_free"])
    def test_clear_requests_require_sensitivity_and_compiler_context(self, monkeypatch, tmp_path, rule_name):
        from core.audit.sweep import get_rule_role

        monkeypatch.setenv("RAPTOR_DIR", _RAPTOR_DIR)
        monkeypatch.chdir(tmp_path)
        rule=Path(_RAPTOR_DIR) / "engine/coccinelle/rules" / f"{rule_name}.cocci"
        assert get_rule_role(str(rule)) == "detection"
        assert _is_detection_only(f"coccinelle:{rule_name}") is True


    def test_usercopy_type_spellings_require_target_layout_review(self, monkeypatch, tmp_path):
        from core.audit.sweep import get_rule_role

        monkeypatch.setenv("RAPTOR_DIR", _RAPTOR_DIR)
        monkeypatch.chdir(tmp_path)
        rule = Path(_RAPTOR_DIR) / "engine/coccinelle/rules/copy_user_size_mismatch.cocci"
        assert get_rule_role(str(rule)) == "detection"
        assert _is_detection_only("coccinelle:copy_user_size_mismatch") is True


    def test_uid_casts_require_range_and_target_width_review(self, monkeypatch, tmp_path):
        from core.audit.sweep import get_rule_role

        monkeypatch.setenv("RAPTOR_DIR", _RAPTOR_DIR)
        monkeypatch.chdir(tmp_path)
        rule = Path(_RAPTOR_DIR) / "engine/coccinelle/rules/uid_truncation.cocci"
        assert get_rule_role(str(rule)) == "detection"
        assert _is_detection_only("coccinelle:uid_truncation") is True


    def test_literal_shift_widths_require_target_abi_review(self, monkeypatch, tmp_path):
        from core.audit.sweep import get_rule_role

        monkeypatch.setenv("RAPTOR_DIR", _RAPTOR_DIR)
        monkeypatch.chdir(tmp_path)
        rule = Path(_RAPTOR_DIR) / "engine/coccinelle/rules/shift_overflow.cocci"
        assert get_rule_role(str(rule)) == "detection"
        assert _is_detection_only("coccinelle:shift_overflow") is True


    def test_divisor_zero_test_requires_independent_range_evidence(self, monkeypatch, tmp_path):
        from core.audit.sweep import get_rule_role

        monkeypatch.setenv("RAPTOR_DIR", _RAPTOR_DIR)
        monkeypatch.chdir(tmp_path)
        rule = Path(_RAPTOR_DIR) / "engine/coccinelle/rules/division_by_zero.cocci"
        assert get_rule_role(str(rule)) == "detection"
        assert _is_detection_only("coccinelle:division_by_zero") is True
