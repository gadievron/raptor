"""Local language explanations, separate from target study and evidence.

An answer supplies reference material; it never establishes that a target
expression satisfies the rule's conditions or that a finding is proven.
"""

from .resolver import ReferenceAnswer, ReferenceContext, ReferenceEntry, lookup

__all__ = ["ReferenceAnswer", "ReferenceContext", "ReferenceEntry", "lookup"]
