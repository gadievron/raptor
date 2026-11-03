"""Drift guard for the core.llm.coerce adoption sweep.

Pins the swept ``generate_structured`` unwrap sites to
``structured_result`` (import-or-fail style, same pattern as
packages/llm_analysis/tests/test_preflight_cost_gate.py): each module
must import the helper and must not re-grow the
``response.result if hasattr(response, "result") else ...`` idiom.

Deliberately NOT swept (bespoke semantics, not copies):

* ``core/security/envelope_probe.py`` — three-way stringification of
  the probe reply (dict → content/json.dumps, non-dict → str);
  ``structured_result``'s indexable fallback would change what a
  non-StructuredResponse return stringifies to.
* ``packages/hypothesis_validation/runner._extract_data`` — accepts a
  ``.data`` leg and rejects non-dict payloads outright; the
  substrate's tuple-indexing tolerance is not equivalent.
* Fence stripping: NO fence consumer was converged in this sweep.
  The JSON consumers (iris/audit spec parsers, batch_glance,
  llm_summaries, spec_inference, dark_verify) use first-block or
  all-fence-lines-dropped selection; converging them on the
  injection-hardened LAST-block ``strip_json_fences`` would change
  parse semantics, and converging them on the FIRST-block
  ``extract_fenced_code`` contradicts its own "NOT for JSON"
  contract. The freeform-code consumers each carry documented
  tag-preference behaviour (```cocci / ```c / diff-shaped) that the
  generic first-block extractor cannot express. Both substrate
  functions keep their existing wave-2 adopters only.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]

_UNWRAP_ADOPTERS = [
    "core/concepts/study.py",
    "core/audit/corpus/run_corpus.py",
    "core/audit/security_classifier.py",
    "packages/llm_analysis/dataflow_dispatch_client.py",
    "packages/llm_analysis/dataflow_validation.py",
]

_HAND_ROLLED = re.compile(
    r"""hasattr\(\s*\w+\s*,\s*['"]result['"]\s*\)"""
)


@pytest.mark.parametrize("rel_path", _UNWRAP_ADOPTERS)
def test_module_imports_substrate(rel_path):
    src = (REPO_ROOT / rel_path).read_text(encoding="utf-8")
    assert re.search(
        r"from core\.llm\.coerce import .*\bstructured_result\b", src
    ), f"{rel_path} must import structured_result from core.llm.coerce"


@pytest.mark.parametrize("rel_path", _UNWRAP_ADOPTERS)
def test_no_hand_rolled_unwrap(rel_path):
    src = (REPO_ROOT / rel_path).read_text(encoding="utf-8")
    assert not _HAND_ROLLED.search(src), (
        f"{rel_path} re-grew a hasattr(..., 'result') unwrap; use "
        "core.llm.coerce.structured_result"
    )
