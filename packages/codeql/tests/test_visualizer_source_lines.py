"""Rendered context uses the same LF line coordinates as SARIF."""
import json
import re

from packages.codeql.dataflow_validator import DataflowPath, DataflowStep
from packages.codeql.dataflow_visualizer import DataflowVisualizer


def test_html_context_keeps_sarif_lf_coordinates_for_raw_source(tmp_path):
    visualizer = DataflowVisualizer(tmp_path / "reports")
    cases = ["int first; // prefix\rnoise\nint expected_second;\n",
             "int first; // prefix\u2028noise\nint expected_second;\n",
             "int first; // prefix\x85noise\nint expected_second;\n",
             "int first;\r\nint expected_second;\r\n",
             "int first;\nint expected_second;\n"]
    for index, source in enumerate(cases):
        (tmp_path / "owned.c").write_bytes(source.encode("utf-8"))
        flow = DataflowPath(
            source=DataflowStep("owned.c", 2, 1, "source", "source"),
            sink=DataflowStep("owned.c", 2, 1, "sink", "sink"),
            intermediate_steps=[], sanitizers=[], rule_id="owned", message="owned",
        )
        output = visualizer.generate_html(flow, f"owned{index}", tmp_path)
        match = re.search(r"const nodes = (.*);", output.read_text(encoding="utf-8"))
        assert match is not None
        nodes = json.loads(match.group(1))
        assert len(nodes) == 2
        for node in nodes:
            marked = [line for line in node["code_context"].split("\n") if line.startswith(">>>")]
            assert marked == [">>>    2 | int expected_second;"], (index, marked)
