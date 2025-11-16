#!/usr/bin/env python3
"""
Simple SARIF merger - combines multiple SARIF files into one.
"""
import json
import sys
from pathlib import Path


def merge_sarif_files(output_path: str, input_paths: list) -> None:
    """Merge multiple SARIF files into one."""
    merged = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": []
    }

    for input_path in input_paths:
        try:
            with open(input_path) as f:
                sarif = json.load(f)

            # Add all runs from this SARIF
            if "runs" in sarif:
                merged["runs"].extend(sarif["runs"])

        except Exception as e:
            print(f"Warning: Failed to merge {input_path}: {e}", file=sys.stderr)
            continue

    # Write merged output
    with open(output_path, 'w') as f:
        json.dump(merged, f, indent=2)

    print(f"Merged {len(input_paths)} SARIF files into {output_path}")
    print(f"Total runs: {len(merged['runs'])}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: sarif_merge.py OUTPUT_FILE INPUT_FILE1 [INPUT_FILE2 ...]", file=sys.stderr)
        sys.exit(1)

    output = sys.argv[1]
    inputs = sys.argv[2:]

    merge_sarif_files(output, inputs)
