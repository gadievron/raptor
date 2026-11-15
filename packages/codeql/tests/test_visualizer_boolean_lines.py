"""Boolean SARIF lines cannot select a source window in HTML reports."""
import json
import re

from packages.codeql.dataflow_validator import DataflowPath, DataflowStep
from packages.codeql.dataflow_visualizer import DataflowVisualizer


def test_html_boolean_lines_are_unknown_while_integer_context_renders(tmp_path):
    (tmp_path / "owned.c").write_text("int owned_marker;\n", encoding="utf-8")
    visualizer = DataflowVisualizer(tmp_path / "reports")
    for index, line in enumerate((True, False, 1)):
        flow = DataflowPath(
            source=DataflowStep("owned.c", line, 1, "source", "source"),
            sink=DataflowStep("owned.c", line, 1, "sink", "sink"),
            intermediate_steps=[], sanitizers=[], rule_id="owned", message="owned",
        )
        output = visualizer.generate_html(flow, f"owned{index}", tmp_path)
        match = re.search(r"const nodes = (.*);", output.read_text(encoding="utf-8"))
        assert match is not None
        nodes = json.loads(match.group(1))
        assert len(nodes) == 2
        for node in nodes:
            if isinstance(line, bool):
                assert node["code_context"] == "Invalid line number in dataflow node"
            else:
                assert "owned_marker" in node["code_context"]
                assert ">>>" in node["code_context"]
