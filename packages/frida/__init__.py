"""
RAPTOR Frida Integration Package

Dynamic instrumentation and runtime analysis using Frida.
"""

__version__ = "1.0.0"
__author__ = "RAPTOR Security Framework"

from .scanner import FridaScanner

__all__ = ["FridaScanner"]
