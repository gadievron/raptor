"""Fixture package root — exercises ``__init__`` re-exports.

``deep_fn`` is a TRANSITIVE re-export (this file re-exports what
``sub/__init__.py`` itself re-exports from ``sub/impl.py``), so the
alias only resolves once the fixed-point pass has run twice.
"""
from .helpers import top_helper
from .sub import deep_fn

__all__ = ["top_helper", "deep_fn"]
