#!/usr/bin/env python3
"""
RAPTOR Web Application Security Testing Module

Provides agentic web application testing capabilities:
- HTTP discovery and crawling
- Intelligent fuzzing
- Authentication testing
- API discovery
- Dynamic vulnerability detection
"""

try:
    from .client import WebClient
    from .crawler import WebCrawler
    from .fuzzer import WebFuzzer
    from .scanner import WebScanner

    __all__ = [
        'WebClient',
        'WebCrawler',
        'WebFuzzer',
        'WebScanner',
    ]
except ImportError:
    # bs4/requests not installed — web module unavailable
    __all__ = []
