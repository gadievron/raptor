"""Compact lookup for inclusive source-line spans with overwrite priority."""

from bisect import bisect_right
from heapq import heappop, heappush
from typing import TYPE_CHECKING, TypeVar, overload

if TYPE_CHECKING:
    from collections.abc import Iterable


_Default = TypeVar("_Default")


class LineSpanIndex:
    """Lookup equivalent to assigning each span's lines into a dictionary.

    Later spans overwrite earlier ones, including partial overlaps. Native
    integer bounds and string labels are required. Storage and construction
    depend on span count, not covered line count; no span-width cap applies.
    This is a lookup interface, not a mutable or iterable mapping.
    """

    MIN_COMPACT_LINES = 256

    def __init__(self, spans: Iterable[tuple[int, int, str]]) -> None:
        self._spans = tuple((lo, hi, value) for lo, hi, value in spans)
        events: dict[int, list[tuple[int, int, str]]] = {}
        for priority, (start, end, value) in enumerate(self._spans):
            if type(start) is not int or type(end) is not int or type(value) is not str:
                raise TypeError("line spans require native integer bounds and string labels")
            if start > end:
                continue
            events.setdefault(start, []).append((-priority, end, value))
            events.setdefault(end + 1, [])
        self._starts: list[int] = []
        self._ends: list[int] = []
        self._values: list[str] = []
        self._mapping: dict[int, str] | None = None
        active: list[tuple[int, int, str]] = []
        positions = sorted(events)
        for index, start in enumerate(positions[:-1]):
            for item in events[start]:
                heappush(active, item)
            while active and active[0][1] < start:
                heappop(active)
            if active:
                self._starts.append(start)
                self._ends.append(positions[index + 1] - 1)
                self._values.append(active[0][2])

    @staticmethod
    def worthwhile(spans: list[tuple[int, int, str]]) -> bool:
        """Prefer compact storage only when span expansion dominates setup.

        This chooses a representation, never a span or finding limit.
        Callers must already have validated native bounds and labels.
        """
        width = sum(max(0, end - start + 1) for start, end, _ in spans)
        return width >= LineSpanIndex.MIN_COMPACT_LINES and width > 32 * len(spans)

    def __bool__(self) -> bool:
        return bool(self._starts)

    @overload
    def get(self, line: int) -> str | None: ...

    @overload
    def get(self, line: int, default: _Default) -> str | _Default: ...

    def get(self, line: int, default: _Default | None = None) -> str | _Default | None:
        """Return the winning label at *line*, or *default* in gaps.

        Non-native query keys retain dictionary hash/equality semantics by
        lazily materializing the original assignments. Native lookups never
        expand covered lines.
        """
        if type(line) is not int:
            if self._mapping is None:
                mapping: dict[int, str] = {}
                for start, end, value in self._spans:
                    for row in range(start, end + 1):
                        mapping[row] = value
                self._mapping = mapping
            return self._mapping.get(line, default)
        index = bisect_right(self._starts, line) - 1
        if index >= 0 and line <= self._ends[index]:
            return self._values[index]
        return default

    def preceding(self, line: int, default: str = "", *, floor: int = 1) -> str:
        """Label at the last assigned line in ``[floor, line]``.

        Matches a sequential scan that carries its previous label through
        uncovered gaps. Keys before *floor* never seed that scan. Bounds
        must be native integers.
        """
        if type(line) is not int or type(floor) is not int:
            raise TypeError("scan bounds must be native integers")
        if line < floor:
            return default
        index = bisect_right(self._starts, line) - 1
        if index >= 0 and self._ends[index] >= floor:
            return self._values[index]
        return default
