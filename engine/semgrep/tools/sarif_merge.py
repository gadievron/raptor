#!/usr/bin/env python3
"""
Simple SARIF merger - combines multiple SARIF files into one.
"""
import sys
from pathlib import Path

from core.json import save_json


def merge_sarif_files(output_path: str, input_paths: list) -> None:
    """Merge multiple SARIF files into one."""
    from core.sarif.parser import merge_sarif

    merged = merge_sarif(input_paths)

    # Write merged output
    save_json(output_path, merged)

    print(f"Merged {len(input_paths)} SARIF files into {output_path}")
    print(f"Total runs: {len(merged['runs'])}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: sarif_merge.py OUTPUT_FILE INPUT_FILE1 [INPUT_FILE2 ...]", file=sys.stderr)
        sys.exit(1)

    output = sys.argv[1]
    inputs = sys.argv[2:]

    merge_sarif_files(output, inputs)
