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
        from core.audit.evidence_grade import is_tool_evidence, is_verification_evidence

        receipt = "coccinelle:hypothesis-generated-nonexistent-rule"
        assert is_tool_evidence(receipt)
        assert is_verification_evidence(receipt)

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


    @pytest.mark.parametrize("rule_name", ["popen_fclose", "use_after_fclose", "double_close", "use_after_close", "fdopendir_double_close", "double_free", "use_after_free", "realloc_losing_ptr", "resource_leak_err", "mmap_leak_err", "mmap_free"])
    def test_stream_patterns_require_lifetime_and_ownership_review(self, monkeypatch, tmp_path, rule_name):
        from core.audit.evidence_grade import is_verification_evidence
        from core.audit.sweep import get_rule_role

        monkeypatch.setenv("RAPTOR_DIR", _RAPTOR_DIR)
        monkeypatch.chdir(tmp_path)
        rule = Path(_RAPTOR_DIR) / "engine/coccinelle/rules" / f"{rule_name}.cocci"
        assert get_rule_role(str(rule)) == "detection"
        assert _is_detection_only(f"coccinelle:{rule_name}") is True
        assert not is_verification_evidence(f"coccinelle:{rule_name}")


@pytest.mark.parametrize("owner,alias,role", [
    ("free_nonbase_ptr", "free_nonbase_ptr_inc", "detection"),
    ("double_close", "double_fclose", "detection"),
    ("stack_addr_escape", "stack_addr_escape_outparam", "detection"),
    ("va_arg_mismatch", "va_arg_promoted_type", "verification"),
    ("va_arg_mismatch", "va_arg_promoted_type_short", "verification"),
])
def test_shipped_variants_inherit_their_real_owner(monkeypatch, tmp_path, owner, alias, role):
    from core.audit.evidence_grade import is_tool_evidence, is_verification_evidence
    from core.audit.sweep import get_rule_role

    monkeypatch.setenv("RAPTOR_DIR", _RAPTOR_DIR)
    monkeypatch.chdir(tmp_path)
    rules = Path(_RAPTOR_DIR) / "engine/coccinelle/rules"
    assert not (rules / f"{alias}.cocci").exists()
    assert get_rule_role(str(rules / f"{owner}.cocci")) == role
    assert _is_detection_only(f"coccinelle:{alias}") is (role == "detection")
    assert is_verification_evidence(f"coccinelle:{alias}") is (role == "verification")
    assert is_tool_evidence(f"coccinelle:{alias}") is (role == "verification")


@pytest.mark.parametrize("stamp", [
    "coccinelle:free_nonbase_ptr_inc+coccinelle:double_fclose",
    "llm-claimed:coccinelle:free_nonbase_ptr_inc",
])
def test_variant_stamps_cannot_manufacture_verification(monkeypatch, stamp):
    from core.audit.evidence_grade import is_tool_evidence, is_verification_evidence
    from core.audit.orchestrator import _promotion_grade_receipt

    monkeypatch.setenv("RAPTOR_DIR", _RAPTOR_DIR)
    assert not is_tool_evidence(stamp)
    assert not is_verification_evidence(stamp)
    assert not _promotion_grade_receipt(stamp)


def test_export_does_not_attribute_verification_to_detection_alias(monkeypatch):
    from core.audit.evidence_grade import EvidenceSource, grade_review_result

    monkeypatch.setenv("RAPTOR_DIR", _RAPTOR_DIR)
    stamp = "semgrep:independent-proof+coccinelle:free_nonbase_ptr_inc"
    sources = {item.source for item in grade_review_result({"hypothesis": "candidate"}, stamp)}
    assert EvidenceSource.SEMGREP in sources
    assert EvidenceSource.COCCINELLE not in sources
    sources = {item.source for item in grade_review_result(
        {"hypothesis": "candidate"}, "coccinelle:va_arg_promoted_type",
    )}
    assert EvidenceSource.COCCINELLE in sources


def test_classifier_unavailable_cannot_grant_variant_authority(monkeypatch):
    import core.audit.evidence_grade as grading

    monkeypatch.setenv("RAPTOR_DIR", _RAPTOR_DIR)
    original = grading._channel_detection_classifier
    monkeypatch.setattr(grading, "_channel_detection_classifier",
                        lambda ns: None if ns == "coccinelle" else original(ns))
    for receipt in ("coccinelle:free_nonbase_ptr_inc", "coccinelle:va_arg_promoted_type",
                    "coccinelle:hypothesis-generated"):
        assert not grading.is_tool_evidence(receipt)
        assert not grading.is_verification_evidence(receipt)
        assert grading.is_tool_evidence(f"semgrep:independent-proof+{receipt}")


@pytest.mark.parametrize("stamp", [
    "coccinelle:free_nonbase_ptr_inc+semgrep:independent-proof",
    "semgrep:independent-proof+coccinelle:free_nonbase_ptr_inc",
    "coccinelle:free_nonbase_ptr_inc+coccinelle:va_arg_promoted_type",
    "coccinelle:va_arg_promoted_type+coccinelle:free_nonbase_ptr_inc",
])
def test_independent_proof_keeps_authority_in_either_receipt_order(monkeypatch, stamp):
    from core.audit.evidence_grade import is_tool_evidence, is_verification_evidence
    from core.audit.orchestrator import _promotion_grade_receipt

    monkeypatch.setenv("RAPTOR_DIR", _RAPTOR_DIR)
    assert is_tool_evidence(stamp)
    assert is_verification_evidence(stamp)
    assert _promotion_grade_receipt(stamp)


@pytest.mark.parametrize("owner,reported", [
    ("uid_truncation", "uid_truncation"),
    ("inet_ntoa_double_call", "inet_ntoa_double_call"),
    ("shift_overflow", "shift_overflow"),
    ("shift_overflow", "shift_overflow_int"),
    ("shift_overflow", "shift_overflow_long"),
    ("shift_overflow", "shift_overflow_negative"),
    ("division_by_zero", "division_by_zero"),
    ("division_by_zero", "division_by_zero_param"),
    ("division_by_zero", "modulo_by_zero_param"),
    ("copy_user_size_mismatch", "copy_user_size_mismatch"),
    ("copy_user_size_mismatch", "copy_from_user_sizeof_ptr"),
    ("integer_overflow_alloc", "integer_overflow_alloc"),
    ("negative_errno_unsigned_return", "negative_errno_unsigned_return"),
    ("double_close", "double_close"),
    ("double_close", "double_fclose"),
    ("fdopendir_double_close", "fdopendir_double_close"),
    ("use_after_close", "use_after_close"),
    ("use_after_fclose", "use_after_fclose"),
    ("alloc_narrow_count", "alloc_narrow_count"),
    ("double_sizeof", "double_sizeof"),
    ("double_sizeof", "pointer_scaling_double"),
    ("sizeof_container_of", "sizeof_container_of"),
    ("malloc_strlen_strcpy", "malloc_strlen_strcpy"),
    ("sizeof_array_param", "sizeof_array_param"),
    ("sizeof_array_param", "sizeof_array_param_unsized"),
])
def test_partial_patterns_require_independent_evidence(monkeypatch, owner, reported):
    from core.audit.evidence_grade import is_tool_evidence, is_verification_evidence
    from core.audit.sweep import get_rule_role, is_confirm_only_coccinelle_rule

    monkeypatch.setenv("RAPTOR_DIR", _RAPTOR_DIR)
    rule = Path(_RAPTOR_DIR) / "engine/coccinelle/rules" / f"{owner}.cocci"
    assert rule.is_file()
    assert get_rule_role(str(rule)) == "detection"
    assert is_confirm_only_coccinelle_rule(str(rule))
    receipt = f"coccinelle:{reported}"
    assert _is_detection_only(receipt)
    assert not is_tool_evidence(receipt)
    assert not is_verification_evidence(receipt)
    assert is_verification_evidence(receipt + "+coccinelle:free_stack_array")


@pytest.mark.parametrize("rule_name", ["packet_length_inverted_guard", "scatterlist_frag_undersize", "rcu_no_lock", "rcu_dereference_outside_rcu"])
def test_partial_kernel_patterns_require_independent_verification(monkeypatch, tmp_path, rule_name):
    from core.audit.evidence_grade import is_verification_evidence
    from core.audit.sweep import get_rule_role

    monkeypatch.setenv("RAPTOR_DIR", _RAPTOR_DIR)
    monkeypatch.chdir(tmp_path)
    rule = Path(_RAPTOR_DIR) / "engine/coccinelle/rules" / f"{rule_name}.cocci"
    assert get_rule_role(str(rule)) == "detection"
    assert _is_detection_only(f"coccinelle:{rule_name}")
    assert not is_verification_evidence(f"coccinelle:{rule_name}")


@pytest.mark.parametrize("rule_name", ["missing_bounds_check", "missing_null_check", "unchecked_return", "strncpy_no_nul", "snprintf_truncation_boundary", "snprintf_advance"])
def test_partial_buffer_patterns_need_independent_verification(monkeypatch, tmp_path, rule_name):
    from core.audit.evidence_grade import is_verification_evidence
    from core.audit.sweep import get_rule_role

    monkeypatch.setenv("RAPTOR_DIR", _RAPTOR_DIR)
    monkeypatch.chdir(tmp_path)
    rule = Path(_RAPTOR_DIR) / "engine/coccinelle/rules" / f"{rule_name}.cocci"
    assert get_rule_role(str(rule)) == "detection"
    assert _is_detection_only(f"coccinelle:{rule_name}")
    assert not is_verification_evidence(f"coccinelle:{rule_name}")


@pytest.mark.parametrize('rule_id', [
    'sign_extension_widen', 'sign_extension_char', 'sign_extension_short',
])
def test_signed_widening_requires_negative_value_and_use_evidence(monkeypatch, tmp_path, rule_id):
    from core.audit.evidence_grade import is_tool_evidence, is_verification_evidence
    from core.audit.sweep import get_rule_role

    monkeypatch.setenv('RAPTOR_DIR', _RAPTOR_DIR)
    monkeypatch.chdir(tmp_path)
    rule = Path(_RAPTOR_DIR) / 'engine/coccinelle/rules/sign_extension_widen.cocci'
    receipt = f'coccinelle:{rule_id}'
    assert get_rule_role(str(rule)) == 'detection'
    assert _is_detection_only(receipt)
    assert not is_tool_evidence(receipt)
    assert not is_verification_evidence(receipt)


def test_signal_handler_calls_require_execution_context(monkeypatch, tmp_path):
    from core.audit.evidence_grade import is_tool_evidence, is_verification_evidence
    from core.audit.sweep import get_rule_role

    monkeypatch.setenv('RAPTOR_DIR', _RAPTOR_DIR)
    monkeypatch.chdir(tmp_path)
    rule = Path(_RAPTOR_DIR) / 'engine/coccinelle/rules/signal_handler_unsafe.cocci'
    receipt = 'coccinelle:signal_handler_unsafe'
    assert get_rule_role(str(rule)) == 'detection'
    assert _is_detection_only(receipt)
    assert not is_tool_evidence(receipt)
    assert not is_verification_evidence(receipt)


def test_uncatchable_signal_calls_require_action_and_error_review(monkeypatch, tmp_path):
    from core.audit.evidence_grade import is_tool_evidence, is_verification_evidence
    from core.audit.sweep import get_rule_role

    monkeypatch.setenv('RAPTOR_DIR', _RAPTOR_DIR)
    monkeypatch.chdir(tmp_path)
    rule = Path(_RAPTOR_DIR) / 'engine/coccinelle/rules/signal_sigkill_sigstop.cocci'
    receipt = 'coccinelle:signal_sigkill_sigstop'
    assert get_rule_role(str(rule)) == 'detection'
    assert _is_detection_only(receipt)
    assert not is_tool_evidence(receipt)
    assert not is_verification_evidence(receipt)


def test_lock_orders_require_object_and_concurrency_evidence(monkeypatch, tmp_path):
    from core.audit.evidence_grade import is_tool_evidence, is_verification_evidence
    from core.audit.sweep import get_rule_role

    monkeypatch.setenv('RAPTOR_DIR', _RAPTOR_DIR)
    monkeypatch.chdir(tmp_path)
    rule = Path(_RAPTOR_DIR) / 'engine/coccinelle/rules/lock_order_violation.cocci'
    receipt = 'coccinelle:lock_order_violation'
    assert get_rule_role(str(rule)) == 'detection'
    assert _is_detection_only(receipt)
    assert not is_tool_evidence(receipt)
    assert not is_verification_evidence(receipt)


def test_chroot_calls_require_working_directory_context(monkeypatch, tmp_path):
    from core.audit.evidence_grade import is_tool_evidence, is_verification_evidence
    from core.audit.sweep import get_rule_role

    monkeypatch.setenv('RAPTOR_DIR', _RAPTOR_DIR)
    monkeypatch.chdir(tmp_path)
    rule = Path(_RAPTOR_DIR) / 'engine/coccinelle/rules/chroot_no_chdir.cocci'
    receipt = 'coccinelle:chroot_no_chdir'
    assert get_rule_role(str(rule)) == 'detection'
    assert _is_detection_only(receipt)
    assert not is_tool_evidence(receipt)
    assert not is_verification_evidence(receipt)


def test_nonliteral_formats_require_attacker_provenance(monkeypatch, tmp_path):
    from core.audit.evidence_grade import is_tool_evidence, is_verification_evidence
    from core.audit.sweep import get_rule_role

    monkeypatch.setenv('RAPTOR_DIR', _RAPTOR_DIR)
    monkeypatch.chdir(tmp_path)
    rule = Path(_RAPTOR_DIR) / 'engine/coccinelle/rules/format_string.cocci'
    receipt = 'coccinelle:format_string'
    assert get_rule_role(str(rule)) == 'detection'
    assert _is_detection_only(receipt)
    assert not is_tool_evidence(receipt)
    assert not is_verification_evidence(receipt)


def test_byte_order_pairs_require_width_and_intent_evidence(monkeypatch, tmp_path):
    from core.audit.evidence_grade import is_tool_evidence, is_verification_evidence
    from core.audit.sweep import get_rule_role

    monkeypatch.setenv('RAPTOR_DIR', _RAPTOR_DIR)
    monkeypatch.chdir(tmp_path)
    rule = Path(_RAPTOR_DIR) / 'engine/coccinelle/rules/double_byteswap.cocci'
    receipt = 'coccinelle:double_byteswap'
    assert get_rule_role(str(rule)) == 'detection'
    assert _is_detection_only(receipt)
    assert not is_tool_evidence(receipt)
    assert not is_verification_evidence(receipt)


@pytest.mark.parametrize('rule_id', ['socket_no_cloexec', 'accept_no_cloexec'])
def test_socket_inheritance_requires_lifetime_and_exec_context(monkeypatch, tmp_path, rule_id):
    from core.audit.evidence_grade import is_tool_evidence, is_verification_evidence
    from core.audit.sweep import get_rule_role, is_confirm_only_coccinelle_rule

    monkeypatch.setenv('RAPTOR_DIR', _RAPTOR_DIR)
    monkeypatch.chdir(tmp_path)
    rule = Path(_RAPTOR_DIR) / 'engine/coccinelle/rules/socket_no_cloexec.cocci'
    receipt = f'coccinelle:{rule_id}'
    assert get_rule_role(str(rule)) == 'detection'
    assert is_confirm_only_coccinelle_rule(str(rule))
    assert _is_detection_only(receipt)
    assert not is_tool_evidence(receipt)
    assert not is_verification_evidence(receipt)


@pytest.mark.parametrize('rule_id', ['unchecked_strtol', 'strtol_null_endptr'])
def test_string_conversions_require_input_and_parsing_context(monkeypatch, tmp_path, rule_id):
    from core.audit.evidence_grade import is_tool_evidence, is_verification_evidence
    from core.audit.sweep import get_rule_role, is_confirm_only_coccinelle_rule

    monkeypatch.setenv('RAPTOR_DIR', _RAPTOR_DIR)
    monkeypatch.chdir(tmp_path)
    rule = Path(_RAPTOR_DIR) / 'engine/coccinelle/rules/unchecked_strtol.cocci'
    receipt = f'coccinelle:{rule_id}'
    assert get_rule_role(str(rule)) == 'detection'
    assert is_confirm_only_coccinelle_rule(str(rule))
    assert _is_detection_only(receipt)
    assert not is_tool_evidence(receipt)
    assert not is_verification_evidence(receipt)


def test_lock_imbalance_requires_acquisition_and_release_context(monkeypatch, tmp_path):
    from core.audit.cwe_dispatch import cocci_rules_for_cwe
    from core.audit.evidence_grade import is_tool_evidence, is_verification_evidence
    from core.audit.sweep import get_rule_role, is_confirm_only_coccinelle_rule

    monkeypatch.setenv('RAPTOR_DIR', _RAPTOR_DIR)
    monkeypatch.chdir(tmp_path)
    rule = Path(_RAPTOR_DIR) / 'engine/coccinelle/rules/lock_imbalance.cocci'
    assert 'lock_imbalance.cocci' in cocci_rules_for_cwe('CWE-362')
    assert 'lock_imbalance.cocci' in cocci_rules_for_cwe('CWE-667')
    assert get_rule_role(str(rule)) == 'detection'
    assert is_confirm_only_coccinelle_rule(str(rule))
    receipt = 'coccinelle:lock_imbalance'
    assert _is_detection_only(receipt)
    assert not is_tool_evidence(receipt)
    assert not is_verification_evidence(receipt)


@pytest.mark.parametrize('rule_id', ['stack_addr_escape', 'stack_addr_escape_outparam'])
def test_address_assignments_require_retained_lifetime_evidence(monkeypatch, tmp_path, rule_id):
    from core.audit.evidence_grade import is_tool_evidence, is_verification_evidence
    from core.audit.sweep import get_rule_role, is_confirm_only_coccinelle_rule

    monkeypatch.setenv('RAPTOR_DIR', _RAPTOR_DIR)
    monkeypatch.chdir(tmp_path)
    rule = Path(_RAPTOR_DIR) / 'engine/coccinelle/rules/stack_addr_escape.cocci'
    receipt = f'coccinelle:{rule_id}'
    assert get_rule_role(str(rule)) == 'detection'
    assert is_confirm_only_coccinelle_rule(str(rule))
    assert _is_detection_only(receipt)
    assert not is_tool_evidence(receipt)
    assert not is_verification_evidence(receipt)


def test_rcu_publication_expressions_require_lifetime_context(monkeypatch, tmp_path):
    from core.audit.evidence_grade import is_tool_evidence, is_verification_evidence
    from core.audit.sweep import get_rule_role, is_confirm_only_coccinelle_rule

    monkeypatch.setenv('RAPTOR_DIR', _RAPTOR_DIR)
    monkeypatch.chdir(tmp_path)
    rule = Path(_RAPTOR_DIR) / 'engine/coccinelle/rules/kfree_not_rcu.cocci'
    receipt = 'coccinelle:kfree_not_rcu'
    assert get_rule_role(str(rule)) == 'detection'
    assert is_confirm_only_coccinelle_rule(str(rule))
    assert _is_detection_only(receipt)
    assert not is_tool_evidence(receipt)
    assert not is_verification_evidence(receipt)


def test_list_deletions_require_cursor_and_traversal_evidence(monkeypatch, tmp_path):
    from core.audit.evidence_grade import is_tool_evidence, is_verification_evidence
    from core.audit.sweep import get_rule_role

    monkeypatch.setenv('RAPTOR_DIR', _RAPTOR_DIR)
    monkeypatch.chdir(tmp_path)
    rule = Path(_RAPTOR_DIR) / 'engine/coccinelle/rules/unsafe_list_del.cocci'
    receipt = 'coccinelle:unsafe_list_del'
    assert get_rule_role(str(rule)) == 'detection'
    assert _is_detection_only(receipt)
    assert not is_tool_evidence(receipt)
    assert not is_verification_evidence(receipt)
