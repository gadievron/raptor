"""
RAPTOR Static Analysis Package

Scanner for security vulnerabilities using Semgrep and CodeQL.
"""

# Note: Directory name is 'static-analysis' (hyphen) makes it an invalid Python
# package identifier. Relative imports work when loaded via sys.path, but fail
# when pytest collects tests from subdirectories. Guard to allow both use cases.
try:
    from .scanner import main
    __all__ = ["main"]
except ImportError:
    pass
