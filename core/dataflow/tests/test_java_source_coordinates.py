"""Java folding text must share the CFG's raw LF source coordinates."""
import pytest

from core.dataflow import sanitizer_cut_parity as parity
from core.dataflow import smt_barrier as sb

pytest.importorskip("tree_sitter_java")
SOURCE = ('class App {\n void handle(String value) {\n'
          ' // note\r String item = "safe";\n item = value;\n consume(item);\n }\n}\n')


def test_parity_cannot_fold_an_earlier_constant_at_a_shifted_line(tmp_path):
    path = tmp_path / "App.java"
    path.write_bytes(SOURCE.encode())
    verdict = parity.value_bound_verdict_for({"file_path": str(path), "language": "java",
                                              "cwe": "CWE-79", "source_line": 4, "sink_line": 5})
    assert verdict == "no_suppress"


def test_production_cannot_fold_an_earlier_constant_at_a_shifted_line(tmp_path, monkeypatch):
    path = tmp_path / "App.java"
    path.write_bytes(SOURCE.encode())
    monkeypatch.setattr(sb._sc_config, "value_bound_enabled", lambda: True)
    result = sb._value_bound_dominates(file_path=str(path), validator_line=4, sink_line=5,
                                      cwe="CWE-79", language="java")
    assert result is False


@pytest.mark.parametrize("crlf", [False, True])
def test_real_constant_assignment_still_suppresses_in_both_consumers(tmp_path, monkeypatch, crlf):
    source = SOURCE.replace("// note\r ", "").replace('item = value;', 'item = "fixed";')
    if crlf:
        source = source.replace("\n", "\r\n")
    path = tmp_path / "App.java"
    path.write_bytes(source.encode())
    finding = {"file_path": str(path), "language": "java", "cwe": "CWE-79",
               "source_line": 4, "sink_line": 5}
    assert parity.value_bound_verdict_for(finding) == "suppress"
    monkeypatch.setattr(sb._sc_config, "value_bound_enabled", lambda: True)
    assert sb._value_bound_dominates(file_path=str(path), validator_line=4, sink_line=5,
                                     cwe="CWE-79", language="java") is True
