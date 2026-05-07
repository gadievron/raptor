#!/usr/bin/env python3
"""
generate_diagram.py — CLI for generating Mermaid diagrams from /understand and /validate outputs.

Usage:
    python3 generate_diagram.py <output-directory> [--target <name>] [--stdout]

Examples:
    python3 generate_diagram.py .out/code-understanding-20240101/
    python3 generate_diagram.py .out/exploitability-validation-20240101/ --target myapp
    python3 generate_diagram.py .out/code-understanding-20240101/ --stdout
"""

import argparse
import sys
from pathlib import Path

# generate_diagram.py -> repo root. Belt + braces against subprocess
# invocation under a sandboxed env that strips PYTHONPATH.
sys.path.insert(0, str(Path(__file__).resolve().parent))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate Mermaid diagrams from /understand and /validate JSON outputs."
    )
    parser.add_argument(
        "out_dir",
        help="Path to an /understand or /validate output directory containing JSON files."
    )
    parser.add_argument(
        "--target",
        metavar="NAME",
        help="Target name to include in the diagram header (optional).",
        default=None,
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="Print diagram markdown to stdout instead of writing diagrams.md.",
    )
    parser.add_argument(
        "--type",
        metavar="TYPE",
        choices=["context-map", "flow-trace", "attack-tree", "attack-paths", "hypotheses", "all"],
        default="all",
        dest="diagram_type",
        help="Which diagram type to generate (default: all).",
    )

    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    if not out_dir.exists():
        print(f"error: directory not found: {out_dir}", file=sys.stderr)
        return 1
    if not out_dir.is_dir():
        print(f"error: not a directory: {out_dir}", file=sys.stderr)
        return 1

    # Single-type rendering shortcuts
    if args.diagram_type != "all":
        from packages.diagram import (
            context_map_from_file,
            flow_trace_from_file,
            attack_tree_from_file,
            attack_paths_from_file,
            hypotheses_from_file,
        )
        type_map = {
            "context-map": ("context-map.json", context_map_from_file),
            "flow-trace": (None, None),  # handled specially below
            "attack-tree": ("attack-tree.json", attack_tree_from_file),
            "attack-paths": ("attack-paths.json", attack_paths_from_file),
            "hypotheses": ("hypotheses.json", hypotheses_from_file),
        }
        if args.diagram_type == "flow-trace":
            traces = sorted(out_dir.glob("flow-trace-*.json"))
            if not traces:
                print("error: no flow-trace-*.json files found", file=sys.stderr)
                return 1
            parts = []
            for tf in traces:
                mermaid = flow_trace_from_file(tf)
                parts.append(f"## {tf.stem}\n\n```mermaid\n{mermaid}\n```")
            content = "\n\n".join(parts)
        else:
            fname, fn = type_map[args.diagram_type]
            fpath = out_dir / fname
            if not fpath.exists():
                print(f"error: {fname} not found in {out_dir}", file=sys.stderr)
                return 1
            mermaid = fn(fpath)
            content = f"```mermaid\n{mermaid}\n```"

        if args.stdout:
            print(content)
        else:
            out_file = out_dir / f"diagram-{args.diagram_type}.md"
            out_file.write_text(content, encoding="utf-8")
            print(f"Written: {out_file}")
        return 0

    # Full render
    from packages.diagram import render_and_write, render_directory

    if args.stdout:
        content = render_directory(out_dir, target=args.target)
        print(content)
    else:
        out_file = render_and_write(out_dir, target=args.target)
        print(f"Written: {out_file}")

        # Count what was rendered
        json_files = [
            f for f in ["context-map.json", "attack-surface.json",
                         "attack-tree.json", "attack-paths.json"]
            if (out_dir / f).exists()
        ]
        traces = list(out_dir.glob("flow-trace-*.json"))
        parts = []
        if json_files:
            parts.append(f"{len(json_files)} surface/tree file(s)")
        if traces:
            parts.append(f"{len(traces)} flow trace(s)")
        if parts:
            print(f"Rendered: {', '.join(parts)}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
