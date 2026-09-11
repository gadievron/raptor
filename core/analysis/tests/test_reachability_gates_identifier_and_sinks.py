"""Identifier-gate anchoring and sink-vocabulary tests for
:mod:`core.analysis.reachability_gates`."""
from __future__ import annotations

from core.analysis.reachability_gates import (
    DANGEROUS_LIBC_SINKS,
    _CONDUIT_CALL_RE,
    _joern_find_callers,
    check_sink_guarded,
    query_sink_arg_index,
    query_unguarded_sinks,
)


class _ServerMustNotQuery:
    """Stub server: alive, but any query() call is a test failure —
    the identifier gate must reject the name before a query fires."""

    def is_alive(self) -> bool:
        return True

    def query(self, *a, **k):
        raise AssertionError("query() must not be reached")


class _ServerEcho:
    """Stub server returning a fixed healthy reply."""

    def __init__(self, raw_output: str):
        self._raw = raw_output

    def is_alive(self) -> bool:
        return True

    def query(self, *a, **k):
        class _R:
            errors: list = []
            raw_output = self._raw
        return _R()


# ---------------------------------------------------------------------------
# Identifier gates: a trailing newline must not pass
# ---------------------------------------------------------------------------


def test_trailing_newline_rejected_by_every_identifier_gate():
    server = _ServerMustNotQuery()
    # ``$`` also matches just before a trailing newline; each gate
    # must use full-string anchoring so ``name\n`` is refused before
    # any query-template interpolation.
    assert _joern_find_callers("handler\n", server) == []
    assert check_sink_guarded("handler\n", server) is None
    assert query_unguarded_sinks("handler\n", server) == []
    assert query_sink_arg_index("handler\n", "memcpy", server) == []
    assert query_sink_arg_index("handler", "memcpy\n", server) == []


def test_plain_identifier_still_accepted():
    # Two-direction: a well-formed name passes the gate and reaches
    # the query (healthy zero-caller reply → empty list, not None).
    server = _ServerEcho("nothing relevant\n")
    assert _joern_find_callers("handler", server) == []


# ---------------------------------------------------------------------------
# Sink vocabulary: process-spawn family + stpcpy
# ---------------------------------------------------------------------------


def test_spawn_family_and_stpcpy_in_sink_vocabulary():
    for name in ("posix_spawn", "posix_spawnp", "fexecve", "stpcpy"):
        assert name in DANGEROUS_LIBC_SINKS


def test_conduit_regex_derivation_picks_up_new_sinks():
    # The conduit regex is DERIVED from the constant — the new names
    # must match call-shaped mentions.
    for name in ("posix_spawn", "posix_spawnp", "fexecve", "stpcpy"):
        assert _CONDUIT_CALL_RE.search(f"passes argv to {name}(cmd)")
    # posix_spawnp must not be half-matched as posix_spawn only.
    m = _CONDUIT_CALL_RE.search("calls posix_spawnp(path)")
    assert m is not None and "posix_spawnp" in m.group(0)
