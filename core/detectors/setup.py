"""Run-owned preparation resources shared by analysis entry points.

Create once per run and pass explicitly to consumers. Preparation remains lazy;
constructing this owner neither walks a target nor probes or launches tools.
Only directory discovery is shared today. Compiler/preprocessor outputs with
potentially different flags and macro environments remain independent.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from core.audit.run_memo import BoundedMemo


@dataclass
class AnalysisSetup:
    """Bounded preparation state; never reuse after a run's target can change.

    A caller may supply an existing run memo to adopt its ownership without
    allocating a second cache. Keys retain target and translation-unit directory
    identity; consumers receive copies of discovered include lists.
    """

    include_dirs_memo: BoundedMemo[list[str]] = field(
        default_factory=lambda: BoundedMemo(64), repr=False,
    )
