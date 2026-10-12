"""Tests for the Frida memory-scan template."""

from packages.frida.runner import load_script_source


def test_memory_scan_uses_existing_template_interface():
    source, _ = load_script_source("memory-scan", None)

    assert "Memory.scan(" in source
    assert "send(Object.assign(" in source
    assert "category: 'memory_scan'" in source


def test_memory_scan_has_default_binary_signatures():
    source, _ = load_script_source("memory-scan", None)

    for signature in (
        "7F 45 4C 46",
        "00 61 73 6D",
        "64 65 78 0A ?? ?? ?? 00",
        "CF FA ED FE",
        "CE FA ED FE",
        "FE ED FA CF",
        "FE ED FA CE",
        "CA FE BA BE",
    ):
        assert signature in source


def test_memory_scan_is_bounded_and_reports_errors():
    source, _ = load_script_source("memory-scan", None)

    assert "protection: 'rw-'" in source
    assert "return !range.file;" in source
    assert "MAX_RANGES = 32" in source
    assert "var rangesRemaining = ranges.length - rangeIndex;" in source
    assert "var rangeBudget = Math.ceil(remaining / rangesRemaining);" in source
    assert "Math.min(range.size, rangeBudget, remaining)" in source
    assert """if (partialRange) {
                noteLimit('range_byte_budget', rangeBudget);
              }
              nextRange();""" in source
    assert "MAX_SCAN_BYTES = 16 * 1024 * 1024" in source
    assert "MAX_MATCHES = 100" in source
    assert "scan_errors: scanErrorCount" in source
    assert "completed_with_errors" in source
