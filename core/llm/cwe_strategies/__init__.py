"""CWE-specialized review strategies for ``/audit`` Phase A.

The general "look for bugs" prompt works for input-validation
defects in straight-line code. Some bug classes need fundamentally
different reasoning — race windows for concurrency, ownership for
memory management, alias semantics for zero-copy paths. This
package provides a small set of mechanically-picked **strategies**
that prime the LLM's reasoning depth for the bug class at hand.

Each strategy carries:

  * Signals — function paths, header includes, function-name
    keywords. The picker uses these to decide which strategies
    apply to a given target function.
  * Key questions — the prompts the LLM should be answering for
    this bug class (not "is there a bug?" but "what does this
    function trust?", "where does the lock window open?").
  * Prompt addendum — prose appended to the base review prompt
    for this strategy.
  * Exemplars — 1-2 worked CVE examples per strategy showing the
    vulnerable pattern + the reasoning that found it. Not the
    patch, not the CVE description: the *reasoning*.

Multiple strategies can apply at once. A network packet handler
holding a lock gets both ``input_handling`` and ``concurrency``.
Strategies are data, not code — adding one is writing a YAML file.

Initial consumer:
  * ``raptor_audit.py`` Phase A driver — picks strategies per
    function, renders prompts, dispatches to ``LLMClient``.

Companion design: ``~/design/audit.md``,
"Adaptive review strategies" section.
"""

from __future__ import annotations

from .loader import (
    StrategyLoadError,
    builtin_strategies_dir,
    load_all,
    load_strategy,
)
from .models import Exemplar, Signals, Strategy
from .picker import GENERAL, pick_strategies
from .prompts import (
    DEFAULT_MAX_BYTES,
    render_strategies,
    render_strategy,
)

__all__ = [
    "DEFAULT_MAX_BYTES",
    "Exemplar",
    "GENERAL",
    "Signals",
    "Strategy",
    "StrategyLoadError",
    "builtin_strategies_dir",
    "load_all",
    "load_strategy",
    "pick_strategies",
    "render_strategies",
    "render_strategy",
]
