"""Private-case replay-eval lane (maintainer tier).

Parametrises over the locally-supplied replay-case corpus
(``core/audit/corpus/replay-cases`` — machinery ships in-tree, case
content is local-only; see ``replay_eval`` for the bundle contract)
and replays each case through the frozen-transcript seam, enforcing
the pinned verdict expectations.

On runners without the case content — every public runner — the lane
SKIPS WITH NOTICE. That skip is deliberate and budgeted: the CI
workflow records this lane's junit skip count against the skip-count
budget gate, so a maintainer runner that silently loses its case
corpus (count grows) is caught rather than rotting green.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from replay_eval import CASES_DIR, discover_cases, run_replay_case  # noqa: E402

# Import-time probe only (pure filesystem walk): the heavy pipeline
# imports live inside run_replay_case and are exercised only where
# cases exist or the synthetic harness tests run.
_CASES = discover_cases()

_SKIP_NOTICE = (
    f"replay-eval cases not present on this runner (local-only content "
    f"under {CASES_DIR.relative_to(Path(__file__).resolve().parents[2])}) "
    f"— private-case replay eval skipped with notice"
)


@pytest.mark.parametrize(
    "case_dir",
    _CASES or [None],
    ids=[p.name for p in _CASES] or ["no-local-cases"],
)
def test_replay_eval_case(case_dir: Path | None, tmp_path: Path) -> None:
    if case_dir is None:
        pytest.skip(_SKIP_NOTICE)
    pytest.importorskip(
        "packages.llm_analysis.agent",
        reason="replay-eval lane needs the analysis pipeline's "
               "dependencies installed",
    )
    run_replay_case(case_dir, tmp_path)
