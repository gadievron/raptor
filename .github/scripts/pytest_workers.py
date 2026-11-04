#!/usr/bin/env python3
"""Choose bounded file-level pytest parallelism without collecting twice."""

from __future__ import annotations

import argparse
from pathlib import Path


def worker_count(targets: list[str], *, maximum: int = 2) -> int:
    """Use the runner's cores; keep a single selected file in process.

    loadfile keeps a module's fixtures and process-global test resources
    together. A directory may contain many modules, so allow the full cap.
    """
    if not targets or maximum < 1:
        raise ValueError("test targets and a positive worker limit are required")
    modules: set[Path] = set()
    has_directory = False
    for target in targets:
        path = Path(target.partition("::")[0])
        if not path.exists():
            raise ValueError(f"test target does not exist: {target}")
        has_directory |= path.is_dir()
        modules.add(path.resolve())
    count = maximum if has_directory else min(maximum, len(modules))
    return count if count > 1 else 0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("targets", nargs="+")
    parser.add_argument("--maximum", type=int, default=2)
    args = parser.parse_args()
    try:
        print(worker_count(args.targets, maximum=args.maximum))
    except ValueError as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
