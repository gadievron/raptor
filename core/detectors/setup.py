"""Run-owned preparation resources shared by analysis entry points.

Create once per run and pass explicitly to consumers. Preparation remains lazy;
constructing this owner neither walks a target nor probes or launches tools.
Directory discovery and bounded successful preprocessor snapshots are shared.
Different flags and macro environments retain independent preparation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.audit.preprocessor_view import ExpandedView

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
    # Enable only when the run plans another consumer of the prepared views.
    preprocessed_views: PreparedViews | None = field(default=None, repr=False)


class PreparedViews:
    """Small successful snapshots; admission stops at the byte budget.

    Keep early views rather than evicting them during a sequential first pass:
    otherwise a later sequential consumer can miss every entry. Concurrent
    misses prepare independently so another caller's tool run cannot consume
    this caller's deadline. No tool work runs while the cache lock is held.
    """

    def __init__(self, max_bytes: int = 8 * 1024 * 1024) -> None:
        import threading
        self._lock = threading.Lock()
        self._values: dict[tuple, ExpandedView] = {}
        self._max_bytes = max_bytes
        self.retained_bytes = 0
        self.hit_count = 0
        self.miss_count = 0

    def get(self, key: tuple) -> ExpandedView | None:
        from dataclasses import replace
        with self._lock:
            view = self._values.get(key)
            if view is None:
                self.miss_count += 1
                return None
            self.hit_count += 1
            return replace(view, errors=list(view.errors))

    def put(self, key: tuple, view: ExpandedView) -> bool:
        from dataclasses import replace
        import sys
        if not view.ok or len(view.line_map) > 32_000:
            return False
        def size(value):
            return sys.getsizeof(value) + (sum(size(v) for v in value) if isinstance(value, tuple) else 0)
        # Include the key and immutable map/text, overcounting repeated strings
        # rather than underestimating a map's much larger Python representation.
        cost = 512 + size(key) + size((view.file_path, view.text, view.line_map, view.tool))
        if cost > 2 * 1024 * 1024:
            return False
        with self._lock:
            if key in self._values or len(self._values) >= 32 or self.retained_bytes + cost > self._max_bytes:
                return False
            self._values[key] = replace(view, errors=list(view.errors))
            self.retained_bytes += cost
            return True
