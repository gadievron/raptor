"""
Diagram package,Mermaid diagram generation from /understand and /validate outputs.

Public API:
    from packages.diagram import render_and_write, render_directory
    from packages.diagram import generate_context_map, generate_flow_trace
    from packages.diagram import generate_attack_tree, generate_attack_paths

Usage:
    # Render all diagrams from an output directory into diagrams.md
    from packages.diagram import render_and_write
    from pathlib import Path

    output_file = render_and_write(Path(".out/code-understanding-20240101/"), target="myapp")
    print(f"Diagrams written to {output_file}")

    # Or render just one type
    from packages.diagram import generate_context_map
    from core.json import load_json

    data = load_json(Path("context-map.json"))
    mermaid = generate_context_map(data)
"""

from .renderer import render_and_write, render_directory
from .context_map import generate as generate_context_map, generate_from_file as context_map_from_file
from .flow_trace import generate as generate_flow_trace, generate_from_file as flow_trace_from_file
from .attack_tree import generate as generate_attack_tree, generate_from_file as attack_tree_from_file
from .attack_paths import generate as generate_attack_paths, generate_from_file as attack_paths_from_file
from .hypotheses import generate as generate_hypotheses, generate_from_file as hypotheses_from_file

__all__ = [
    "render_and_write",
    "render_directory",
    "generate_context_map",
    "generate_flow_trace",
    "generate_attack_tree",
    "generate_attack_paths",
    "generate_hypotheses",
    "context_map_from_file",
    "flow_trace_from_file",
    "attack_tree_from_file",
    "attack_paths_from_file",
    "hypotheses_from_file",
]

__version__ = "0.1.0"
