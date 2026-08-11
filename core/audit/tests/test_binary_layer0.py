"""Tests for core.audit.binary_layer0."""

from __future__ import annotations

from core.audit.binary_layer0 import (
    BinaryMetadata,
    EvidenceTier,
    Layer0Finding,
    Layer0Result,
    PatternID,
    check_format_string,
    check_indirect_flow,
    check_lock_imbalance,
    check_missing_clear,
    check_sign_confusion,
    check_toctou,
    check_unchecked_return,
    format_layer0_context,
    format_layer0_summary,
    scan_function,
)


class TestFormatString:
    def test_printf_one_arg(self):
        calls = [{"callee": "printf", "arg_count": 1}]
        findings = check_format_string("vuln", calls)
        assert len(findings) == 1
        assert findings[0].pattern_id == PatternID.FORMAT_STRING

    def test_printf_two_args_ok(self):
        calls = [{"callee": "printf", "arg_count": 2}]
        findings = check_format_string("safe", calls)
        assert len(findings) == 0

    def test_fprintf_two_args(self):
        calls = [{"callee": "fprintf", "arg_count": 2}]
        findings = check_format_string("vuln", calls)
        assert len(findings) == 1

    def test_non_printf(self):
        calls = [{"callee": "puts", "arg_count": 1}]
        findings = check_format_string("safe", calls)
        assert len(findings) == 0


class TestUncheckedReturn:
    def test_malloc_unchecked(self):
        calls = [{"callee": "malloc", "return_checked": False}]
        findings = check_unchecked_return("alloc", calls)
        assert len(findings) == 1
        assert findings[0].confidence == "high"

    def test_malloc_checked(self):
        calls = [{"callee": "malloc", "return_checked": True}]
        findings = check_unchecked_return("alloc", calls)
        assert len(findings) == 0

    def test_read_unchecked(self):
        calls = [{"callee": "read", "return_checked": False}]
        findings = check_unchecked_return("reader", calls)
        assert len(findings) == 1
        assert findings[0].confidence == "medium"


class TestToctou:
    def test_access_then_open(self):
        calls = [{"callee": "access"}, {"callee": "open"}]
        findings = check_toctou("vuln", calls)
        assert len(findings) == 1
        assert "TOCTOU" in findings[0].description

    def test_stat_then_open(self):
        calls = [{"callee": "stat"}, {"callee": "fopen"}]
        findings = check_toctou("vuln", calls)
        assert len(findings) == 1

    def test_no_toctou(self):
        calls = [{"callee": "open"}, {"callee": "read"}]
        findings = check_toctou("safe", calls)
        assert len(findings) == 0


class TestLockImbalance:
    def test_lock_without_unlock(self):
        calls = [{"callee": "pthread_mutex_lock"}]
        findings = check_lock_imbalance("vuln", calls)
        assert len(findings) == 1
        assert "deadlock" in findings[0].description

    def test_lock_with_unlock(self):
        calls = [
            {"callee": "pthread_mutex_lock"},
            {"callee": "pthread_mutex_unlock"},
        ]
        findings = check_lock_imbalance("safe", calls)
        assert len(findings) == 0

    def test_no_lock(self):
        calls = [{"callee": "printf"}]
        findings = check_lock_imbalance("safe", calls)
        assert len(findings) == 0


class TestMissingClear:
    def test_sensitive_without_clear(self):
        calls = [{"callee": "strcmp"}]
        findings = check_missing_clear("verify_password", calls)
        assert len(findings) == 1
        assert findings[0].evidence_tier == EvidenceTier.HEURISTIC

    def test_sensitive_with_explicit_bzero(self):
        calls = [{"callee": "explicit_bzero"}]
        findings = check_missing_clear("encrypt_key", calls)
        assert len(findings) == 0

    def test_sensitive_with_memset(self):
        calls = [{"callee": "memset"}]
        findings = check_missing_clear("decrypt_token", calls)
        assert len(findings) == 0

    def test_non_sensitive(self):
        calls = [{"callee": "printf"}]
        findings = check_missing_clear("process_data", calls)
        assert len(findings) == 0


class TestSignConfusion:
    def test_movsxd_before_alloc(self):
        instrs = [{"mnemonic": "movsxd", "context": "malloc"}]
        findings = check_sign_confusion("alloc", instrs)
        assert len(findings) == 1
        assert findings[0].vuln_type == "integer_overflow"

    def test_movsxd_unrelated(self):
        instrs = [{"mnemonic": "movsxd", "context": "loop counter"}]
        findings = check_sign_confusion("iter", instrs)
        assert len(findings) == 0

    def test_no_movsxd(self):
        instrs = [{"mnemonic": "mov", "context": "malloc"}]
        findings = check_sign_confusion("alloc", instrs)
        assert len(findings) == 0


class TestIndirectFlow:
    def test_high_density_no_cfi(self):
        result = check_indirect_flow("dispatch", indirect_calls=5)
        assert result is not None
        assert result.pattern_id == PatternID.INDIRECT_FLOW

    def test_high_density_with_cfi(self):
        result = check_indirect_flow("dispatch", indirect_calls=5, has_cfi=True)
        assert result is None

    def test_low_density(self):
        result = check_indirect_flow("simple", indirect_calls=1)
        assert result is None


class TestScanFunction:
    def test_combines_patterns(self):
        calls = [
            {"callee": "printf", "arg_count": 1},
            {"callee": "malloc", "return_checked": False},
        ]
        findings = scan_function("vuln", calls, file="a.c")
        assert len(findings) >= 2
        pattern_ids = {f.pattern_id for f in findings}
        assert PatternID.FORMAT_STRING in pattern_ids
        assert PatternID.UNCHECKED_RETURN in pattern_ids

    def test_clean_function(self):
        calls = [{"callee": "printf", "arg_count": 2}]
        findings = scan_function("safe", calls)
        assert len(findings) == 0


class TestBinaryMetadata:
    def test_missing_mitigations(self):
        meta = BinaryMetadata(has_nx=True, has_pie=False)
        missing = meta.missing_mitigations
        assert "PIE" in missing
        assert "NX" not in missing

    def test_all_present(self):
        meta = BinaryMetadata(
            has_pie=True, has_full_relro=True, has_nx=True,
            has_stack_canary=True, has_fortify=True,
        )
        assert meta.missing_mitigations == []

    def test_to_finding_when_missing(self):
        meta = BinaryMetadata(has_pie=False)
        finding = meta.to_finding()
        assert finding is not None
        assert finding.evidence_tier == EvidenceTier.HEADER_BACKED

    def test_to_finding_when_all_present(self):
        meta = BinaryMetadata(
            has_pie=True, has_full_relro=True, has_nx=True,
            has_stack_canary=True, has_fortify=True,
        )
        assert meta.to_finding() is None

    def test_to_dict(self):
        meta = BinaryMetadata(has_pie=True, binary_path="/bin/test")
        d = meta.to_dict()
        assert d["has_pie"] is True
        assert d["binary_path"] == "/bin/test"


class TestLayer0Result:
    def test_empty_result(self):
        result = Layer0Result()
        assert result.finding_count == 0
        assert result.by_pattern() == {}

    def test_by_pattern(self):
        result = Layer0Result(findings=[
            Layer0Finding(
                pattern_id=PatternID.FORMAT_STRING,
                function="f1", description="test",
            ),
            Layer0Finding(
                pattern_id=PatternID.FORMAT_STRING,
                function="f2", description="test2",
            ),
            Layer0Finding(
                pattern_id=PatternID.TOCTOU,
                function="f3", description="test3",
            ),
        ])
        groups = result.by_pattern()
        assert len(groups) == 2
        assert len(groups[PatternID.FORMAT_STRING]) == 2

    def test_to_dict(self):
        result = Layer0Result(
            findings=[Layer0Finding(
                pattern_id=PatternID.FORMAT_STRING,
                function="f", description="d",
            )],
            functions_scanned=10,
            patterns_checked=7,
        )
        d = result.to_dict()
        assert d["finding_count"] == 1
        assert d["functions_scanned"] == 10


class TestFormatContext:
    def test_empty(self):
        assert format_layer0_context([]) == ""

    def test_with_findings(self):
        findings = [Layer0Finding(
            pattern_id=PatternID.FORMAT_STRING,
            function="vuln", description="printf with 1 arg",
        )]
        text = format_layer0_context(findings)
        assert "Layer 0" in text
        assert "vuln()" in text

    def test_with_metadata(self):
        meta = BinaryMetadata(has_pie=False, has_nx=True)
        text = format_layer0_context([], meta)
        assert "PIE" in text


class TestFormatSummary:
    def test_empty(self):
        result = Layer0Result()
        assert "no mechanical findings" in format_layer0_summary(result)

    def test_with_findings(self):
        result = Layer0Result(findings=[
            Layer0Finding(
                pattern_id=PatternID.FORMAT_STRING,
                function="f", description="d",
            ),
        ])
        s = format_layer0_summary(result)
        assert "1 findings" in s
