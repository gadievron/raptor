"""
RAPTOR Static Analysis Package

Scanner for security vulnerabilities using Semgrep and CodeQL.
"""

# Note: Directory name is 'static-analysis' but Python imports use relative path
from .scanner import main

__all__ = ["main"]
