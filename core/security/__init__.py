"""Shared security primitives used across RAPTOR components.

Each submodule covers one narrow concern — import directly from the
submodule (`from core.security.log_sanitisation import escape_nonprintable`)
rather than from this package root. The package exists to give security-
relevant helpers a single discoverable home; it deliberately does not
re-export anything.
"""
