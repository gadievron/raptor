"""Bounded C/C++ shared-state context and experimental semantic study.

Candidates are investigation context, never mechanical proof of a bug.
"""

from .index import build_access_index
from .model import Limits
from .slices import build_slices

__all__ = ["Limits", "build_access_index", "build_slices"]
