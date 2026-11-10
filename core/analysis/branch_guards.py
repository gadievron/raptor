"""Producer-owned boolean branch facts tied to graph node identity.

A selected branch establishes control truth. Value stability and source-model
fidelity are separate obligations for consumers of that premise.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Generic, TypeVar

N = TypeVar("N")


@dataclass(frozen=True)
class BranchGuard(Generic[N]):
    branch: N
    condition: str
    line: int
    polarity: bool
