"""Per-run memo for deterministic tool-chain sweep steps.

``_run_tool_chain`` re-dispatches the same (rule, file, function,
scope) sweep many times per run: the same hypothesis recurs across
review passes, critique re-checks, suspicious-promotion sweeps and
reused verdicts, and each dispatch re-spawns a semgrep / spatch /
codeql / compiler / SMT-child subprocess to recompute an identical
answer.  The memo caches the step's *result object* keyed on the
step's semantic inputs so only the subprocess is skipped — every
consuming site still performs its own bookkeeping (tier counters,
receipts, journal rows) on the returned result exactly as for a
fresh run.

Scope and soundness contract:

* Only deterministic, side-effect-free step classes are eligible
  (:data:`MEMOIZABLE_STEP_TYPES` — the semgrep / coccinelle / codeql /
  smt / compiler sweeps).  Steps whose results depend on mutable run
  state (dynamic/frida observation, dark-verify witness execution,
  Joern server sessions, channels that read SharedState or fold
  earlier chain receipts into their corroboration) are never
  memoized.
* Keys are built from CONTENT hashes of the steering inputs (rule /
  query text, target file bytes, source excerpt) plus the scoping
  values that select what the tool looks at (function name, line
  range, hypothesis binding).  Paths and mtimes alone never key an
  entry.  Any input that cannot be hashed makes the whole key ``None``
  and the step runs unmemoized.  The coccinelle leg memoizes at FILE
  scope — spatch always scans the whole file, so its key carries no
  function/line dimension and one entry serves every function in the
  file (scoping happens after retrieval); a vocab-rendered rule keys
  on the RENDERED rule bytes, so a vocabulary change is a miss.
* The memo lives exactly one run (it is owned by the run's
  ``OrchestratorConfig``) and the audited target tree is read-only for
  that lifetime, which is what bounds inputs the key cannot
  practically hash in full (a TU's ``#include`` closure, a CodeQL
  database's row data — the database is additionally pinned by its
  metadata file's content hash).
* ``error`` outcomes are never stored: a transient failure (tool
  timeout, sandbox refusal) pinned for the run would suppress every
  later retry of that step.  Results whose negative-control leg
  errored (``details["negative_control_error"]``) are never stored
  either: they are uncapped only because a broken control must not
  fabricate inconclusive outcomes, and pinning one would replay the
  uncapped verdict forever without re-running the control.
* Stored and returned values are deep copies, so no two consumers
  ever share a mutable result object with each other or with the
  cache.
"""

from __future__ import annotations

import copy
import hashlib
import logging
import threading
from collections import OrderedDict
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)

# Step types _run_tool_chain may route through the memo.  Everything
# else is stateful or folds prior chain receipts into its result and
# must re-run per dispatch.
MEMOIZABLE_STEP_TYPES: frozenset[str] = frozenset({
    "semgrep", "coccinelle", "codeql", "smt", "compiler",
})

# Bounded size trade-off: a larger cap keeps step results alive for
# reuse across the late phases (critique, promotion, secondary
# sweeps re-dispatch chains hours after first review on big runs) at
# the price of holding every cached SweepResult — matches, raw
# details — in memory for the whole run; a smaller cap bounds memory
# but evicts exactly the entries those late phases would have hit,
# turning their re-checks back into subprocess spawns.  1024 entries
# of typical sweep results is single-digit MiB.
MAX_MEMO_ENTRIES = 1024


def hash_text(text: str) -> str:
    """Content hash of an in-memory string input."""
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def hash_file(path: str | Path | None) -> str | None:
    """Content hash of a file input, or None when it cannot be read.

    ``None`` deliberately poisons the memo key (see
    :meth:`SweepMemo.make_key`): an unreadable input means the step's
    real inputs are unknown, so the step must run unmemoized.
    """
    if not path:
        return None
    try:
        # Streaming hash — never buffers the whole file (memoised
        # inputs can be large expanded-TU artifacts).
        from core.hash import sha256_file
        return sha256_file(Path(path))
    except OSError:
        return None


class SweepMemo:
    """Thread-safe, bounded, per-run memo of sweep step results."""

    def __init__(self, max_entries: int = MAX_MEMO_ENTRIES) -> None:
        self._lock = threading.Lock()
        self._entries: OrderedDict[tuple, Any] = OrderedDict()
        self._max_entries = max_entries
        self.hits = 0
        self.misses = 0

    @staticmethod
    def make_key(
        tool: str, parts: dict[str, str | int | None],
    ) -> tuple | None:
        """Build a memo key, or None when any input is un-hashable.

        ``parts`` values are content hashes or plain scoping scalars;
        a ``None`` value marks an input whose content could not be
        hashed, and the whole key degrades to "don't memoize".
        """
        items: list[tuple[str, str | int]] = []
        for name in sorted(parts):
            value = parts[name]
            if value is None:
                return None
            items.append((name, value))
        return (tool, tuple(items))

    def get(self, key: tuple) -> Any | None:
        """A deep copy of the cached result, or None on miss."""
        with self._lock:
            try:
                result = self._entries[key]
            except KeyError:
                self.misses += 1
                return None
            self._entries.move_to_end(key)
            self.hits += 1
        return copy.deepcopy(result)

    def put(self, key: tuple, result: Any) -> None:
        """Cache *result* (deep-copied) unless it is an error outcome
        or its negative-control leg errored.

        A result stamped ``details["negative_control_error"]`` was
        allowed to stay uncapped only because a broken control run
        must not fabricate an inconclusive outcome for THAT dispatch —
        nothing was banked in the control cache. Pinning it would
        replay the uncapped confirmation on every re-dispatch
        (critique / promotion re-checks) without ever re-running the
        control, permanently disarming the presence-detector cap for
        the run. Refuse instead: the next dispatch re-runs the whole
        step, control included, and can cap.
        """
        if getattr(result, "outcome", None) == "error":
            return
        details = getattr(result, "details", None)
        if isinstance(details, dict) and details.get(
            "negative_control_error",
        ):
            return
        stored = copy.deepcopy(result)
        with self._lock:
            self._entries[key] = stored
            self._entries.move_to_end(key)
            while len(self._entries) > self._max_entries:
                self._entries.popitem(last=False)

    def get_or_run(
        self, key: tuple | None, runner: Callable[[], Any],
    ) -> Any:
        """The cached result for *key*, else ``runner()`` (cached).

        A ``None`` key always runs unmemoized.  The runner executes
        outside the lock, so concurrent first dispatches of the same
        key may both run — a benign duplication; last store wins.
        """
        if key is None:
            return runner()
        cached = self.get(key)
        if cached is not None:
            logger.debug(
                "sweep_memo hit: %s (%d hits / %d misses)",
                key[0], self.hits, self.misses,
            )
            return cached
        result = runner()
        self.put(key, result)
        return result
