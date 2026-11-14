"""Bounded declaration byte custody; neither execution nor build authentication."""

from dataclasses import dataclass, field
import hashlib
import json
from threading import RLock

from core.audit.prepared_invocation_candidate import CandidateUnavailable, InvocationCandidate, _constant, _object, select_candidate


@dataclass(frozen=True)
class DeclarationCapture:
    database_bytes: bytes
    database_sha256: str
    entry_intervals: tuple[tuple[int, int], ...]
    declared_build_association: str
    _identity: object = field(repr=False, compare=False)

    @property
    def authenticated_build(self) -> bool:
        return False


@dataclass(frozen=True)
class SelectedDeclaration:
    capture: DeclarationCapture
    selected_interval: tuple[int, int]
    selected_entry_bytes: bytes
    invocation: InvocationCandidate

    @property
    def authenticated_build(self) -> bool:
        return False


def _positive(value):
    return type(value) is int and value > 0


def capture_declaration(raw: bytes, *, declared_build_association: str,
                        max_database_bytes: int, max_entries: int,
                        max_entry_bytes: int, max_depth: int) -> DeclarationCapture:
    """Own immutable whole bytes and exact top-level object intervals.

    Association is a caller declaration, not authenticated provenance. The byte
    scanner only finds boundaries; strict JSON decoding validates their syntax.
    It never serialises dictionaries or interprets command strings.
    """
    if not all(_positive(v) for v in (max_database_bytes, max_entries, max_entry_bytes, max_depth)):
        raise CandidateUnavailable("invalid_capture_budget")
    if type(raw) is not bytes or not raw or len(raw) > max_database_bytes:
        raise CandidateUnavailable("database_bytes_unavailable")
    if (type(declared_build_association) is not str or not declared_build_association
            or "\0" in declared_build_association):
        raise CandidateUnavailable("build_association_unavailable")
    # Validate UTF-8 without converting scanner offsets into character offsets.
    try:
        raw.decode("utf-8")
    except UnicodeError as exc:
        raise CandidateUnavailable("malformed_database") from exc
    size = len(raw)
    pos = 0

    def whitespace(index):
        while index < size and raw[index] in b" \t\r\n":
            index += 1
        return index

    pos = whitespace(pos)
    if pos == size or raw[pos] != ord("["):
        raise CandidateUnavailable("database_not_array")
    pos = whitespace(pos + 1)
    intervals = []
    if pos < size and raw[pos] == ord("]"):
        pos = whitespace(pos + 1)
    else:
        while True:
            if pos == size or raw[pos] != ord("{"):
                raise CandidateUnavailable("entry_not_object")
            start = pos
            stack = []
            quoted = False
            escaped = False
            while pos < size:
                byte = raw[pos]
                if quoted:
                    if escaped:
                        escaped = False
                    elif byte == ord("\\"):
                        escaped = True
                    elif byte == ord('"'):
                        quoted = False
                elif byte == ord('"'):
                    quoted = True
                elif byte in b"{[":
                    stack.append(byte)
                    if len(stack) > max_depth:
                        raise CandidateUnavailable("entry_depth_exceeded")
                elif byte in b"}]":
                    if not stack or (stack.pop(), byte) not in ((123, 125), (91, 93)):
                        raise CandidateUnavailable("malformed_database")
                    if not stack:
                        pos += 1
                        break
                pos += 1
                if pos - start > max_entry_bytes:
                    raise CandidateUnavailable("entry_bytes_unavailable")
            if stack or quoted or pos - start > max_entry_bytes:
                raise CandidateUnavailable("entry_bytes_unavailable")
            entry = raw[start:pos]
            try:
                value = json.loads(entry.decode("utf-8"), object_pairs_hook=_object,
                                   parse_constant=_constant)
            except CandidateUnavailable:
                raise
            except (ValueError, RecursionError) as exc:
                raise CandidateUnavailable("malformed_database") from exc
            if type(value) is not dict:
                raise CandidateUnavailable("entry_not_object")
            intervals.append((start, pos))
            if len(intervals) > max_entries:
                raise CandidateUnavailable("entry_count_unavailable")
            pos = whitespace(pos)
            if pos == size:
                raise CandidateUnavailable("malformed_database")
            if raw[pos] == ord("]"):
                pos = whitespace(pos + 1)
                break
            if raw[pos] != ord(","):
                raise CandidateUnavailable("malformed_database")
            pos = whitespace(pos + 1)
    if pos != size:
        raise CandidateUnavailable("trailing_database_bytes")
    return DeclarationCapture(raw, hashlib.sha256(raw).hexdigest(), tuple(intervals),
                              declared_build_association, object())


class DeclarationOwner:
    """Bounded identity custody, not a security capability or measured build.

    Retained-byte limits count raw database bytes, declared association UTF-8
    bytes and issued entry slices. They are payload limits, not heap accounting.
    Equal inputs are distinct captures and each issued selection is charged.
    """

    def __init__(self, *, max_retained_bytes: int, max_captures: int, max_selections: int):
        if not all(_positive(v) for v in (max_retained_bytes, max_captures, max_selections)):
            raise CandidateUnavailable("invalid_owner_budget")
        self._max_retained_bytes = max_retained_bytes
        self._max_captures = max_captures
        self._max_selections = max_selections
        self._captures = {}
        self._selections = {}
        self._retained_bytes = 0
        self._closed = False
        self._lock = RLock()

    @property
    def retained_payload_bytes(self) -> int:
        with self._lock:
            return self._retained_bytes

    def _open(self):
        if self._closed:
            raise CandidateUnavailable("owner_closed")

    def capture(self, raw: bytes, **budgets) -> DeclarationCapture:
        with self._lock:
            self._open()
            if len(self._captures) >= self._max_captures:
                raise CandidateUnavailable("capture_retention_exhausted")
            capture = capture_declaration(raw, **budgets)
            try:
                charge = len(raw) + len(capture.declared_build_association.encode("utf-8"))
            except UnicodeError as exc:
                raise CandidateUnavailable("build_association_unavailable") from exc
            if charge > self._max_retained_bytes - self._retained_bytes:
                raise CandidateUnavailable("payload_retention_exhausted")
            self._captures[id(capture)] = (capture, charge)
            self._retained_bytes += charge
            return capture

    def select(self, capture: DeclarationCapture, translation_unit: str, *,
               max_entry_bytes: int, max_entries: int) -> SelectedDeclaration:
        with self._lock:
            self._open()
            owned = self._captures.get(id(capture))
            if owned is None or owned[0] is not capture:
                raise CandidateUnavailable("capture_not_owned")
            if len(self._selections) >= self._max_selections:
                raise CandidateUnavailable("selection_retention_exhausted")
            entries = tuple(capture.database_bytes[start:end] for start, end in capture.entry_intervals)
            invocation = select_candidate(entries, translation_unit,
                                          max_entry_bytes=max_entry_bytes, max_entries=max_entries)
            positions = [i for i, entry in enumerate(entries) if entry == invocation.selected_entry_bytes]
            if len(positions) != 1:
                raise CandidateUnavailable("ambiguous_entry_slice")
            charge = len(invocation.selected_entry_bytes)
            if charge > self._max_retained_bytes - self._retained_bytes:
                raise CandidateUnavailable("payload_retention_exhausted")
            interval = capture.entry_intervals[positions[0]]
            selected = SelectedDeclaration(capture, interval, invocation.selected_entry_bytes, invocation)
            self._selections[id(selected)] = (selected, charge)
            self._retained_bytes += charge
            return selected

    def retains(self, selected: SelectedDeclaration) -> bool:
        with self._lock:
            issued = self._selections.get(id(selected))
            if self._closed or type(selected) is not SelectedDeclaration or issued is None or issued[0] is not selected:
                return False
            owned = self._captures.get(id(selected.capture))
            return owned is not None and owned[0] is selected.capture

    def release_selection(self, selected: SelectedDeclaration) -> bool:
        with self._lock:
            issued = self._selections.get(id(selected))
            if issued is None or issued[0] is not selected:
                return False
            del self._selections[id(selected)]
            self._retained_bytes -= issued[1]
            return True

    def release_capture(self, capture: DeclarationCapture) -> bool:
        with self._lock:
            owned = self._captures.get(id(capture))
            if owned is None or owned[0] is not capture:
                return False
            selections = [key for key, (selected, _) in self._selections.items()
                          if selected.capture is capture]
            for key in selections:
                _, charge = self._selections.pop(key)
                self._retained_bytes -= charge
            del self._captures[id(capture)]
            self._retained_bytes -= owned[1]
            return True

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._selections.clear()
            self._captures.clear()
            self._retained_bytes = 0
