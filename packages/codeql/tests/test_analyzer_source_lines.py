"""Autonomous source highlights use the SARIF LF-coordinate model."""

import logging

from packages.codeql import autonomous_analyzer as module


def test_analyzer_marks_the_reported_source_line(tmp_path):
    source = tmp_path / "owned.c"
    finding = module.CodeQLFinding("cpp/owned", "owned", "owned", "warning",
                                  "owned.c", 2, 2, "snippet_fallback")
    analyzer = module.AutonomousCodeQLAnalyzer.__new__(module.AutonomousCodeQLAnalyzer)
    analyzer.logger = logging.getLogger("owned-analyzer-source-lines")
    controls = [b"first\nowned_sink();\n", b"first\r\nowned_sink();\r\n"]
    separators = ("\r", "\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029")
    cases = controls + [
        ('const char *p = "prefix' + sep + 'suffix";\nowned_sink();\n').encode()
        for sep in separators
    ]
    for raw in cases:
        source.write_bytes(raw)
        result = analyzer.read_vulnerable_code(finding, tmp_path, context_lines=0)
        assert result == ">>>    2: owned_sink();", raw
        context = analyzer.read_vulnerable_code(finding, tmp_path, context_lines=1)
        assert [line for line in context.split("\n") if line.startswith(">>> ")] == [
            ">>>    2: owned_sink();"], raw


def test_analyzer_cap_counts_raw_crlf_characters(tmp_path, monkeypatch, caplog):
    source = tmp_path / "owned.c"
    source.write_bytes(b"a\r\nb\r\nc\r\n")
    finding = module.CodeQLFinding("cpp/owned", "owned", "owned", "warning",
                                  "owned.c", 2, 2, "snippet_fallback")
    analyzer = module.AutonomousCodeQLAnalyzer.__new__(module.AutonomousCodeQLAnalyzer)
    analyzer.logger = logging.getLogger("owned-analyzer-raw-cap")
    original = module.read_contained_text_capped
    calls = []

    def capped(root, path, **kwargs):
        result = original(root, path, max_chars=4, **kwargs)
        calls.append(result)
        return result

    monkeypatch.setattr(module, "read_contained_text_capped", capped)
    assert analyzer.read_vulnerable_code(finding, tmp_path, context_lines=0) == ""
    assert calls == [("a\r\n", True)]
    assert any("truncated prefix" in record.message for record in caplog.records)
