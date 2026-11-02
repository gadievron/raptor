#!/usr/bin/env python3
"""Public compatibility entry point for the canonical ZKPoX package CLI."""
import sys
import core.startup.process_init  # noqa: F401
from packages.zkpox.cli import main

if __name__ == "__main__":
    sys.exit(main())
