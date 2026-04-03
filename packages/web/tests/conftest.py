import pytest

collect_ignore = []

try:
    import bs4  # noqa: F401
    import requests  # noqa: F401
except ImportError:
    # Skip all web tests if optional dependencies aren't installed
    collect_ignore.append("test_scanner_none_llm.py")
