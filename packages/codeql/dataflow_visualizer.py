#!/usr/bin/env python3
"""
CodeQL Dataflow Visualizer

Creates visual representations of CodeQL dataflow paths in multiple formats:
- HTML interactive viewer (D3.js based)
- Mermaid diagrams (for markdown documentation)
- ASCII terminal visualization (quick viewing)
- Graphviz DOT format (for advanced customization)
"""

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional
from html import escape

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.logging import get_logger
from packages.codeql.dataflow_validator import DataflowPath, DataflowStep

logger = get_logger()


class DataflowVisualizer:
    """
    Generate visualizations of CodeQL dataflow paths.

    Supports multiple output formats for different use cases:
    - HTML: Interactive browser-based visualization
    - Mermaid: Markdown-compatible diagrams
    - ASCII: Terminal-based quick view
    - DOT: Graphviz format for custom rendering
    """

    def __init__(self, output_dir: Path):
        """
        Initialize visualizer.

        Args:
            output_dir: Directory to save visualizations
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.logger = get_logger()

    def visualize_all_formats(
        self,
        dataflow: DataflowPath,
        finding_id: str,
        repo_path: Path
    ) -> Dict[str, Path]:
        """
        Generate all visualization formats for a dataflow path.

        Args:
            dataflow: DataflowPath object
            finding_id: Unique identifier for this finding
            repo_path: Repository root path

        Returns:
            Dictionary mapping format names to output file paths
        """
        outputs = {}

        # Generate each format
        try:
            outputs['html'] = self.generate_html(dataflow, finding_id, repo_path)
            self.logger.info(f"Generated HTML visualization: {outputs['html']}")
        except Exception as e:
            self.logger.warning(f"Failed to generate HTML: {e}")

        try:
            outputs['mermaid'] = self.generate_mermaid(dataflow, finding_id)
            self.logger.info(f"Generated Mermaid diagram: {outputs['mermaid']}")
        except Exception as e:
            self.logger.warning(f"Failed to generate Mermaid: {e}")

        try:
            outputs['ascii'] = self.generate_ascii(dataflow, finding_id)
            self.logger.info(f"Generated ASCII visualization: {outputs['ascii']}")
        except Exception as e:
            self.logger.warning(f"Failed to generate ASCII: {e}")

        try:
            outputs['dot'] = self.generate_dot(dataflow, finding_id)
            self.logger.info(f"Generated DOT file: {outputs['dot']}")
        except Exception as e:
            self.logger.warning(f"Failed to generate DOT: {e}")

        return outputs

    def generate_html(
        self,
        dataflow: DataflowPath,
        finding_id: str,
        repo_path: Path
    ) -> Path:
        """
        Generate interactive HTML visualization.

        Creates a self-contained HTML file with embedded D3.js visualization.

        Args:
            dataflow: DataflowPath object
            finding_id: Unique identifier
            repo_path: Repository root path

        Returns:
            Path to generated HTML file
        """
        output_file = self.output_dir / f"{finding_id}_dataflow.html"

        # Build nodes and edges data
        nodes = []
        edges = []

        # Add source node
        nodes.append({
            'id': 0,
            'type': 'source',
            'label': dataflow.source.label,
            'file': dataflow.source.file_path,
            'line': dataflow.source.line,
            'snippet': dataflow.source.snippet
        })

        # Add intermediate nodes
        for i, step in enumerate(dataflow.intermediate_steps, 1):
            is_sanitizer = any(s in step.label.lower() for s in ['sanitiz', 'validat', 'filter', 'escape'])
            nodes.append({
                'id': i,
                'type': 'sanitizer' if is_sanitizer else 'step',
                'label': step.label,
                'file': step.file_path,
                'line': step.line,
                'snippet': step.snippet
            })
            edges.append({'source': i - 1, 'target': i})

        # Add sink node
        sink_id = len(nodes)
        nodes.append({
            'id': sink_id,
            'type': 'sink',
            'label': dataflow.sink.label,
            'file': dataflow.sink.file_path,
            'line': dataflow.sink.line,
            'snippet': dataflow.sink.snippet
        })
        edges.append({'source': sink_id - 1, 'target': sink_id})

        # Read source code for each location
        for node in nodes:
            try:
                file_path = repo_path / node['file']
                if file_path.exists():
                    with open(file_path) as f:
                        lines = f.readlines()

                    start = max(0, node['line'] - 6)
                    end = min(len(lines), node['line'] + 5)

                    context = []
                    for i in range(start, end):
                        marker = ">>>" if i == node['line'] - 1 else "   "
                        context.append(f"{marker} {i + 1:4d} | {lines[i].rstrip()}")

                    node['code_context'] = '\n'.join(context)
                else:
                    node['code_context'] = f"File not found: {node['file']}"
            except Exception as e:
                node['code_context'] = f"Error reading file: {e}"

        # Generate HTML
        html_content = self._create_html_template(
            finding_id=finding_id,
            rule_id=dataflow.rule_id,
            message=dataflow.message,
            nodes=nodes,
            edges=edges,
            sanitizers=dataflow.sanitizers
        )

        with open(output_file, 'w') as f:
            f.write(html_content)

        return output_file

    def _create_html_template(
        self,
        finding_id: str,
        rule_id: str,
        message: str,
        nodes: List[Dict],
        edges: List[Dict],
        sanitizers: List[str]
    ) -> str:
        """Create HTML template with embedded visualization."""

        nodes_json = json.dumps(nodes)
        edges_json = json.dumps(edges)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dataflow Visualization - {escape(finding_id)}</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 20px;
        }}

        .header {{
            background: #252526;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            border-left: 4px solid #007acc;
        }}

        .header h1 {{
            color: #007acc;
            margin-bottom: 10px;
            font-size: 24px;
        }}

        .header .rule {{
            color: #ce9178;
            font-family: 'Courier New', monospace;
            margin-bottom: 8px;
        }}

        .header .message {{
            color: #d4d4d4;
            line-height: 1.6;
        }}

        .sanitizers {{
            background: #2d2d30;
            padding: 12px;
            border-radius: 6px;
            margin-top: 12px;
            border-left: 3px solid #4ec9b0;
        }}

        .sanitizers h3 {{
            color: #4ec9b0;
            font-size: 14px;
            margin-bottom: 8px;
        }}

        .sanitizer-list {{
            list-style: none;
            padding-left: 0;
        }}

        .sanitizer-list li {{
            color: #ce9178;
            padding: 4px 0;
            font-family: 'Courier New', monospace;
            font-size: 13px;
        }}

        .container {{
            display: flex;
            gap: 20px;
        }}

        .visualization {{
            flex: 1;
            background: #252526;
            border-radius: 8px;
            padding: 20px;
            min-height: 600px;
        }}

        .details {{
            width: 400px;
            background: #252526;
            border-radius: 8px;
            padding: 20px;
            max-height: 800px;
            overflow-y: auto;
        }}

        .details h2 {{
            color: #007acc;
            font-size: 18px;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 1px solid #3e3e42;
        }}

        .node-info {{
            margin-bottom: 20px;
            padding: 15px;
            background: #2d2d30;
            border-radius: 6px;
        }}

        .node-info h3 {{
            color: #4ec9b0;
            font-size: 14px;
            margin-bottom: 8px;
        }}

        .node-info .location {{
            color: #ce9178;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            margin-bottom: 10px;
        }}

        .node-info .code {{
            background: #1e1e1e;
            padding: 12px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            line-height: 1.5;
            overflow-x: auto;
            white-space: pre;
            color: #d4d4d4;
            border-left: 3px solid #007acc;
        }}

        .node circle {{
            stroke: #fff;
            stroke-width: 2px;
            cursor: pointer;
            transition: all 0.3s;
        }}

        .node:hover circle {{
            stroke-width: 4px;
            filter: brightness(1.2);
        }}

        .node.source circle {{
            fill: #f48771;
        }}

        .node.sink circle {{
            fill: #d16969;
        }}

        .node.step circle {{
            fill: #4ec9b0;
        }}

        .node.sanitizer circle {{
            fill: #dcdcaa;
        }}

        .node text {{
            fill: #d4d4d4;
            font-size: 12px;
            font-family: 'Segoe UI', sans-serif;
            pointer-events: none;
        }}

        .link {{
            stroke: #569cd6;
            stroke-width: 2px;
            fill: none;
            marker-end: url(#arrowhead);
        }}

        .legend {{
            position: absolute;
            top: 20px;
            right: 20px;
            background: #2d2d30;
            padding: 15px;
            border-radius: 6px;
            border: 1px solid #3e3e42;
        }}

        .legend h3 {{
            color: #007acc;
            font-size: 14px;
            margin-bottom: 10px;
        }}

        .legend-item {{
            display: flex;
            align-items: center;
            margin-bottom: 8px;
            font-size: 13px;
        }}

        .legend-color {{
            width: 20px;
            height: 20px;
            border-radius: 50%;
            margin-right: 10px;
            border: 2px solid #fff;
        }}

        ::-webkit-scrollbar {{
            width: 10px;
        }}

        ::-webkit-scrollbar-track {{
            background: #1e1e1e;
        }}

        ::-webkit-scrollbar-thumb {{
            background: #3e3e42;
            border-radius: 5px;
        }}

        ::-webkit-scrollbar-thumb:hover {{
            background: #4e4e52;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>CodeQL Dataflow Visualization</h1>
        <div class="rule">Rule: {escape(rule_id)}</div>
        <div class="message">{escape(message)}</div>
        {f'''
        <div class="sanitizers">
            <h3>Detected Sanitizers:</h3>
            <ul class="sanitizer-list">
                {"".join(f"<li>{escape(s)}</li>" for s in sanitizers)}
            </ul>
        </div>
        ''' if sanitizers else ''}
    </div>

    <div class="container">
        <div class="visualization">
            <div class="legend">
                <h3>Legend</h3>
                <div class="legend-item">
                    <div class="legend-color" style="background: #f48771;"></div>
                    <span>Source (User Input)</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #4ec9b0;"></div>
                    <span>Intermediate Step</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #dcdcaa;"></div>
                    <span>Sanitizer/Validator</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #d16969;"></div>
                    <span>Sink (Dangerous Op)</span>
                </div>
            </div>
            <svg id="dataflow-svg"></svg>
        </div>

        <div class="details">
            <h2>Node Details</h2>
            <div id="node-details">
                <p style="color: #858585; font-style: italic;">Click on a node to see details</p>
            </div>
        </div>
    </div>

    <script>
        const nodes = {nodes_json};
        const edges = {edges_json};

        // Set up SVG
        const svg = d3.select("#dataflow-svg");
        const container = svg.node().parentElement;
        const width = container.clientWidth;
        const height = 600;

        svg.attr("width", width).attr("height", height);

        // Define arrowhead
        svg.append("defs").append("marker")
            .attr("id", "arrowhead")
            .attr("viewBox", "0 -5 10 10")
            .attr("refX", 25)
            .attr("refY", 0)
            .attr("markerWidth", 6)
            .attr("markerHeight", 6)
            .attr("orient", "auto")
            .append("path")
            .attr("d", "M0,-5L10,0L0,5")
            .attr("fill", "#569cd6");

        // Calculate positions (vertical layout)
        const nodeSpacing = height / (nodes.length + 1);
        nodes.forEach((node, i) => {{
            node.x = width / 2;
            node.y = nodeSpacing * (i + 1);
        }});

        // Draw edges
        const links = svg.append("g").selectAll("path")
            .data(edges)
            .enter().append("path")
            .attr("class", "link")
            .attr("d", d => {{
                const source = nodes[d.source];
                const target = nodes[d.target];
                return `M${{source.x}},${{source.y}} L${{target.x}},${{target.y}}`;
            }});

        // Draw nodes
        const nodeGroup = svg.append("g").selectAll("g")
            .data(nodes)
            .enter().append("g")
            .attr("class", d => `node ${{d.type}}`)
            .attr("transform", d => `translate(${{d.x}},${{d.y}})`)
            .on("click", (event, d) => showNodeDetails(d));

        nodeGroup.append("circle")
            .attr("r", 20);

        nodeGroup.append("text")
            .attr("dy", -30)
            .attr("text-anchor", "middle")
            .text((d, i) => {{
                if (d.type === 'source') return 'SOURCE';
                if (d.type === 'sink') return 'SINK';
                return `STEP ${{i}}`;
            }});

        function showNodeDetails(node) {{
            const detailsDiv = d3.select("#node-details");
            detailsDiv.html(`
                <div class="node-info">
                    <h3>${{node.type.toUpperCase()}}</h3>
                    <div class="location">${{node.file}}:${{node.line}}</div>
                    <p style="margin-bottom: 10px; color: #d4d4d4;">${{node.label}}</p>
                    <div class="code">${{node.code_context || node.snippet}}</div>
                </div>
            `);
        }}

        // Show first node by default
        if (nodes.length > 0) {{
            showNodeDetails(nodes[0]);
        }}
    </script>
</body>
</html>
"""

    def generate_mermaid(self, dataflow: DataflowPath, finding_id: str) -> Path:
        """
        Generate Mermaid diagram for markdown documentation.

        Args:
            dataflow: DataflowPath object
            finding_id: Unique identifier

        Returns:
            Path to generated Mermaid file
        """
        output_file = self.output_dir / f"{finding_id}_dataflow.mmd"

        lines = []
        lines.append("```mermaid")
        lines.append("graph TD")
        lines.append("")

        # Add source node
        lines.append(f'    A0["🔴 SOURCE<br/>{self._escape_mermaid(dataflow.source.label)}<br/><i>{dataflow.source.file_path}:{dataflow.source.line}</i>"]')
        lines.append('    style A0 fill:#f48771,stroke:#fff,stroke-width:2px,color:#000')
        lines.append("")

        # Add intermediate nodes
        prev_id = "A0"
        for i, step in enumerate(dataflow.intermediate_steps, 1):
            node_id = f"A{i}"
            is_sanitizer = any(s in step.label.lower() for s in ['sanitiz', 'validat', 'filter', 'escape'])

            emoji = "🛡️" if is_sanitizer else "⚙️"
            color = "#dcdcaa" if is_sanitizer else "#4ec9b0"

            lines.append(f'    {node_id}["{emoji} STEP {i}<br/>{self._escape_mermaid(step.label)}<br/><i>{step.file_path}:{step.line}</i>"]')
            lines.append(f'    style {node_id} fill:{color},stroke:#fff,stroke-width:2px,color:#000')
            lines.append(f'    {prev_id} --> {node_id}')
            lines.append("")
            prev_id = node_id

        # Add sink node
        sink_id = f"A{len(dataflow.intermediate_steps) + 1}"
        lines.append(f'    {sink_id}["🔥 SINK<br/>{self._escape_mermaid(dataflow.sink.label)}<br/><i>{dataflow.sink.file_path}:{dataflow.sink.line}</i>"]')
        lines.append(f'    style {sink_id} fill:#d16969,stroke:#fff,stroke-width:2px,color:#000')
        lines.append(f'    {prev_id} --> {sink_id}')
        lines.append("")

        lines.append("```")
        lines.append("")
        lines.append(f"**Rule:** `{dataflow.rule_id}`")
        lines.append("")
        lines.append(f"**Message:** {dataflow.message}")

        if dataflow.sanitizers:
            lines.append("")
            lines.append("**Detected Sanitizers:**")
            for san in dataflow.sanitizers:
                lines.append(f"- {san}")

        with open(output_file, 'w') as f:
            f.write('\n'.join(lines))

        return output_file

    def _escape_mermaid(self, text: str) -> str:
        """Escape text for Mermaid syntax."""
        # Truncate long text
        if len(text) > 60:
            text = text[:57] + "..."

        # Escape special characters
        text = text.replace('"', '&quot;')
        text = text.replace('[', '&#91;')
        text = text.replace(']', '&#93;')
        text = text.replace('(', '&#40;')
        text = text.replace(')', '&#41;')
        text = text.replace('<', '&lt;')
        text = text.replace('>', '&gt;')
        text = text.replace('#', '&#35;')

        return text

    def generate_ascii(self, dataflow: DataflowPath, finding_id: str) -> Path:
        """
        Generate ASCII terminal visualization.

        Args:
            dataflow: DataflowPath object
            finding_id: Unique identifier

        Returns:
            Path to generated ASCII file
        """
        output_file = self.output_dir / f"{finding_id}_dataflow.txt"

        lines = []
        lines.append("=" * 80)
        lines.append("CODEQL DATAFLOW VISUALIZATION")
        lines.append("=" * 80)
        lines.append("")
        lines.append(f"Rule: {dataflow.rule_id}")
        lines.append(f"Message: {dataflow.message}")
        lines.append("")

        if dataflow.sanitizers:
            lines.append("Detected Sanitizers:")
            for san in dataflow.sanitizers:
                lines.append(f"  • {san}")
            lines.append("")

        lines.append("=" * 80)
        lines.append("DATAFLOW PATH")
        lines.append("=" * 80)
        lines.append("")

        # Source
        lines.append("┌─────────────────────────────────────────────────────────────────────────────┐")
        lines.append("│ 🔴 SOURCE (User-Controlled Input)                                          │")
        lines.append("└─────────────────────────────────────────────────────────────────────────────┘")
        lines.append(f"  Location: {dataflow.source.file_path}:{dataflow.source.line}:{dataflow.source.column}")
        lines.append(f"  Label: {dataflow.source.label}")
        if dataflow.source.snippet:
            lines.append(f"  Snippet: {dataflow.source.snippet[:70]}")
        lines.append("")
        lines.append("       │")
        lines.append("       │  Data flows through...")
        lines.append("       ▼")
        lines.append("")

        # Intermediate steps
        for i, step in enumerate(dataflow.intermediate_steps, 1):
            is_sanitizer = any(s in step.label.lower() for s in ['sanitiz', 'validat', 'filter', 'escape'])

            if is_sanitizer:
                lines.append("┌─────────────────────────────────────────────────────────────────────────────┐")
                lines.append(f"│ 🛡️  STEP {i}: SANITIZER/VALIDATOR                                            │")
                lines.append("└─────────────────────────────────────────────────────────────────────────────┘")
            else:
                lines.append("┌─────────────────────────────────────────────────────────────────────────────┐")
                lines.append(f"│ ⚙️  STEP {i}: Intermediate Processing                                       │")
                lines.append("└─────────────────────────────────────────────────────────────────────────────┘")

            lines.append(f"  Location: {step.file_path}:{step.line}:{step.column}")
            lines.append(f"  Label: {step.label}")
            if step.snippet:
                lines.append(f"  Snippet: {step.snippet[:70]}")
            lines.append("")
            lines.append("       │")
            lines.append("       ▼")
            lines.append("")

        # Sink
        lines.append("┌─────────────────────────────────────────────────────────────────────────────┐")
        lines.append("│ 🔥 SINK (Dangerous Operation)                                              │")
        lines.append("└─────────────────────────────────────────────────────────────────────────────┘")
        lines.append(f"  Location: {dataflow.sink.file_path}:{dataflow.sink.line}:{dataflow.sink.column}")
        lines.append(f"  Label: {dataflow.sink.label}")
        if dataflow.sink.snippet:
            lines.append(f"  Snippet: {dataflow.sink.snippet[:70]}")
        lines.append("")

        lines.append("=" * 80)
        lines.append("")

        with open(output_file, 'w') as f:
            f.write('\n'.join(lines))

        # Also print to logger for terminal viewing
        self.logger.info("ASCII Dataflow Visualization:")
        for line in lines[:30]:  # Print first 30 lines to log
            self.logger.info(line)
        if len(lines) > 30:
            self.logger.info(f"... ({len(lines) - 30} more lines in {output_file})")

        return output_file

    def generate_dot(self, dataflow: DataflowPath, finding_id: str) -> Path:
        """
        Generate Graphviz DOT format for advanced customization.

        Args:
            dataflow: DataflowPath object
            finding_id: Unique identifier

        Returns:
            Path to generated DOT file
        """
        output_file = self.output_dir / f"{finding_id}_dataflow.dot"

        lines = []
        lines.append("digraph dataflow {")
        lines.append("    rankdir=TB;")
        lines.append("    node [shape=box, style=filled, fontname=\"Helvetica\"];")
        lines.append("    edge [color=\"#569cd6\", penwidth=2];")
        lines.append("")
        lines.append(f'    label="CodeQL Dataflow: {self._escape_dot(dataflow.rule_id)}";')
        lines.append('    labelloc="t";')
        lines.append('    fontsize=16;')
        lines.append("")

        # Source node
        lines.append(f'    node0 [label="SOURCE\\n{self._escape_dot(dataflow.source.label)}\\n{dataflow.source.file_path}:{dataflow.source.line}", fillcolor="#f48771"];')

        # Intermediate nodes
        for i, step in enumerate(dataflow.intermediate_steps, 1):
            is_sanitizer = any(s in step.label.lower() for s in ['sanitiz', 'validat', 'filter', 'escape'])
            color = "#dcdcaa" if is_sanitizer else "#4ec9b0"
            node_type = "SANITIZER" if is_sanitizer else f"STEP {i}"

            lines.append(f'    node{i} [label="{node_type}\\n{self._escape_dot(step.label)}\\n{step.file_path}:{step.line}", fillcolor="{color}"];')

        # Sink node
        sink_id = len(dataflow.intermediate_steps) + 1
        lines.append(f'    node{sink_id} [label="SINK\\n{self._escape_dot(dataflow.sink.label)}\\n{dataflow.sink.file_path}:{dataflow.sink.line}", fillcolor="#d16969"];')

        lines.append("")

        # Edges
        for i in range(sink_id):
            lines.append(f'    node{i} -> node{i + 1};')

        lines.append("}")

        with open(output_file, 'w') as f:
            f.write('\n'.join(lines))

        # Add instructions
        instructions_file = self.output_dir / f"{finding_id}_dataflow_instructions.txt"
        with open(instructions_file, 'w') as f:
            f.write(f"To render the DOT file:\n\n")
            f.write(f"# Install Graphviz (if not already installed):\n")
            f.write(f"# macOS: brew install graphviz\n")
            f.write(f"# Ubuntu: sudo apt-get install graphviz\n\n")
            f.write(f"# Render to PNG:\n")
            f.write(f"dot -Tpng {output_file.name} -o {finding_id}_dataflow.png\n\n")
            f.write(f"# Render to SVG:\n")
            f.write(f"dot -Tsvg {output_file.name} -o {finding_id}_dataflow.svg\n\n")
            f.write(f"# Render to PDF:\n")
            f.write(f"dot -Tpdf {output_file.name} -o {finding_id}_dataflow.pdf\n")

        return output_file

    def _escape_dot(self, text: str) -> str:
        """Escape text for DOT syntax."""
        if len(text) > 50:
            text = text[:47] + "..."
        return text.replace('"', '\\"').replace('\n', '\\n')


def main():
    """CLI entry point for testing."""
    import argparse
    from packages.codeql.dataflow_validator import DataflowValidator

    parser = argparse.ArgumentParser(description="Visualize CodeQL dataflow paths")
    parser.add_argument("--sarif", required=True, help="SARIF file")
    parser.add_argument("--repo", required=True, help="Repository path")
    parser.add_argument("--finding-index", type=int, default=0, help="Finding index")
    parser.add_argument("--out", help="Output directory", default="./dataflow_visualizations")
    parser.add_argument("--format", choices=['html', 'mermaid', 'ascii', 'dot', 'all'], default='all', help="Output format")

    args = parser.parse_args()

    # Load SARIF
    with open(args.sarif) as f:
        sarif = json.load(f)

    # Get finding
    results = sarif["runs"][0]["results"]
    if args.finding_index >= len(results):
        print(f"Finding index {args.finding_index} out of range (0-{len(results)-1})")
        return

    finding = results[args.finding_index]

    # Extract dataflow (using validator's extractor)
    validator = DataflowValidator(llm_client=None)  # Don't need LLM for extraction
    dataflow = validator.extract_dataflow_from_sarif(finding)

    if not dataflow:
        print(f"Finding {args.finding_index} does not contain dataflow information")
        return

    # Generate visualizations
    visualizer = DataflowVisualizer(Path(args.out))
    finding_id = finding.get('ruleId', 'unknown').replace('/', '_')

    if args.format == 'all':
        outputs = visualizer.visualize_all_formats(dataflow, finding_id, Path(args.repo))
        print("\nGenerated visualizations:")
        for fmt, path in outputs.items():
            print(f"  {fmt}: {path}")
    else:
        if args.format == 'html':
            output = visualizer.generate_html(dataflow, finding_id, Path(args.repo))
        elif args.format == 'mermaid':
            output = visualizer.generate_mermaid(dataflow, finding_id)
        elif args.format == 'ascii':
            output = visualizer.generate_ascii(dataflow, finding_id)
        elif args.format == 'dot':
            output = visualizer.generate_dot(dataflow, finding_id)

        print(f"\nGenerated {args.format} visualization: {output}")


if __name__ == "__main__":
    main()
