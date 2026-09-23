"""Never-raise conformance harness over the whole parser registry.

Every registered manifest parser documents the same boundary
contract: hostile input degrades to a warning + empty result, never
an escaping exception, in bounded time. This harness derives the
parser universe MECHANICALLY from the dispatch registries (the same
source the dispatcher resolves from — a parser cannot register
without entering this test) and drives each parser with a shared
hostile corpus: deep nesting (recursion blowups), huge integers
(CPython digit-limit ValueError), null bytes / binary garbage,
truncations, and pathological YAML flow nesting.

Non-vacuity: ``test_harness_detects_planted_violation`` plants a
contract-violating parser and asserts the same drive logic flags it.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

# Importing the package registers every parser (side-effect imports
# in packages/sca/parsers/__init__.py).
from packages.sca import parsers as _parsers
from packages.sca.parsers._safe_read import scan_root_context

# Per-call wall ceiling. Generous vs the milliseconds honest refusal
# takes, far below the minutes an unbounded blowup takes.
_WALL_CEILING_S = 10.0

# ---------------------------------------------------------------------------
# Hostile corpus — shapes, not files: each entry is (corpus_id, bytes).
# Sizes are tuned to trip the historical escape classes (recursion
# limit ~1000, int digit limit 4300, flow-depth bound 1000) while
# keeping each parse fast.
# ---------------------------------------------------------------------------
HOSTILE_CORPUS: list[tuple[str, bytes]] = [
    ("deep-toml-arrays", b"x = " + b"[" * 3000),
    ("deep-json-objects", b'{"a":' * 3000),
    # 50k: deep enough to overflow the YAML loader C-stack when the
    # flow-depth pre-bound is absent (the guard fires at ~30-40k).
    ("deep-yaml-flow", b"__metadata: {version: 8}\nx: " + b"[" * 50000),
    ("deep-xml", b"<a>" * 3000),
    ("huge-int-version", b'[project]\ndependencies = ["p=='
     + b"9" * 50000 + b'"]'),
    ("huge-digit-line", b"p==" + b"9" * 50000 + b"\n"),
    ("null-bytes", b"\x00" * 64 + b'{["\x00' + b"\xff" * 64),
    ("binary-garbage", bytes(range(256)) * 8),
    ("truncated-multibyte", "a: caf".encode() + b"\xc3"),
    ("empty", b""),
]


def _registered_parsers() -> list[tuple[str, str, object]]:
    """(case_id, representative_filename, parse_fn) per registration.

    Derived from the live dispatch registries so the universe can
    never drift from what the dispatcher actually serves.
    """
    cases: list[tuple[str, str, object]] = []
    seen: set[tuple[int, str]] = set()
    for filename, fn in sorted(_parsers._REGISTRY.items()):
        key = (id(fn), filename)
        if key not in seen:
            seen.add(key)
            cases.append((f"file:{filename}", filename, fn))
    for suffix, fn in sorted(_parsers._SUFFIX_REGISTRY.items()):
        cases.append((f"suffix:{suffix}", f"sample{suffix}", fn))
    for idx, (_pred, fn) in enumerate(_parsers._PREDICATE_REGISTRY):
        # The contract holds on the parse callable regardless of how
        # dispatch found it; a generic name exercises the fn even
        # when the predicate's naming convention is unknown here.
        cases.append((f"predicate:{idx}:{fn.__module__}",
                      "requirements.txt", fn))
    return cases


def _drive(fn: object, path: Path) -> str | None:
    """Run one parser against one hostile file.

    Returns None when the boundary contract held, else a violation
    description. This is the assertion core the non-vacuity check
    reuses.
    """
    started = time.monotonic()
    try:
        fn(path)  # type: ignore[operator]
    except Exception as exc:  # noqa: BLE001 — the contract under test
        return (
            f"{type(exc).__name__} escaped the parser boundary: "
            f"{str(exc)[:120]}"
        )
    elapsed = time.monotonic() - started
    if elapsed > _WALL_CEILING_S:
        return f"parse took {elapsed:.1f}s (ceiling {_WALL_CEILING_S}s)"
    return None


_CASES = _registered_parsers()


def test_universe_is_nonempty_and_broad():
    """The mechanical derivation must keep seeing the ecosystem
    spread — an import/registration regression that empties the
    registry must fail here, not silently skip every case."""
    assert len(_CASES) >= 25, [c[0] for c in _CASES]


@pytest.mark.parametrize(
    "case_id,filename,fn", _CASES, ids=[c[0] for c in _CASES],
)
@pytest.mark.parametrize(
    "corpus_id,payload", HOSTILE_CORPUS, ids=[c[0] for c in HOSTILE_CORPUS],
)
def test_parser_never_raises_on_hostile_input(
    tmp_path: Path, case_id: str, filename: str, fn: object,
    corpus_id: str, payload: bytes,
) -> None:
    target = tmp_path / filename
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(payload)
    with scan_root_context(tmp_path):
        violation = _drive(fn, target)
    assert violation is None, f"{case_id} × {corpus_id}: {violation}"


def test_harness_detects_planted_violation(tmp_path: Path) -> None:
    """Non-vacuity: a contract-violating parser must be flagged."""

    def planted(_: Path) -> list:
        raise RecursionError("planted contract violation")

    target = tmp_path / "planted.lock"
    target.write_bytes(b"x")
    violation = _drive(planted, target)
    assert violation is not None
    assert "RecursionError" in violation


def test_harness_detects_planted_hang(tmp_path: Path, monkeypatch) -> None:
    """Non-vacuity for the time bound (simulated clock — no real
    10s sleep in the suite)."""
    clock = iter([0.0, 100.0])
    monkeypatch.setattr(time, "monotonic", lambda: next(clock))

    def slow(_: Path) -> list:
        return []

    target = tmp_path / "slow.lock"
    target.write_bytes(b"x")
    violation = _drive(slow, target)
    assert violation is not None
    assert "ceiling" in violation
