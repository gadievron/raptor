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
    assert "var rangeBudget = Math.floor(budget.remaining / rangesRemaining);" in source
    assert "var cycleBudget = Math.min(" in source
    assert "MAX_SCAN_BYTES_PER_FLUSH = 512 * 1024" in source
    assert "var scanSize = Math.min(" in source
    assert "MAX_SCAN_BYTES - scannedBytes" in source
    assert "MAX_SCAN_BYTES = 16 * 1024 * 1024" in source
    assert "MAX_MATCHES = 100" in source
    assert "scan_errors: scanErrorCount" in source
    assert "completed_with_errors" in source

def test_memory_scan_is_flush_driven_and_module_ranges_are_preserved():
    source, _ = load_script_source("memory-scan", None)

    assert "function onFlushMsg(msg)" in source
    assert "recv('raptor:flush', onFlushMsg)" in source
    assert "msg.final === true" in source
    assert "scanConfiguredMemory();" not in source
    assert "selectedModule.enumerateRanges('r--')" in source
    assert "if (offset === range.size)" in source
    assert "if (offset < 0 || offset > range.size)" in source
    assert "range.size > previousSize" in source
    assert "patternBytes(other.pattern) - 1" in source
    assert ": range.size;" in source
    assert "max_scan_bytes_per_flush: MAX_SCAN_BYTES_PER_FLUSH" in source
    assert "var scanSize = Math.min(" in source
    assert "seenMatches[matchKey]" in source
    assert "noteLimit('final_scan_incomplete', MAX_SCAN_BYTES_PER_FLUSH)" in source
