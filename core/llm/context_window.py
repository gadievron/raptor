"""Line-window limits for per-finding classifier context.

The per-finding classifiers (/agentic and /analyze via
``packages.llm_analysis.agent``, /codeql via
``packages.codeql.autonomous_analyzer`` and
``packages.codeql.dataflow_validator``) all build their LLM context by
slicing raw source lines around a finding.  The window sizes are a
shared policy decision — the same limit was previously spelled as a
bare literal at each site, so the sibling copies could drift apart
silently.  This module is the single source of truth; consumers use
these as defaults and keep accepting per-call overrides where they
already did.

Every limit here trades the same two failure modes and the value must
be argued in BOTH directions (see each constant's comment):

- Too small: the evidence that decides the verdict — a bounds check a
  screen above the sink, a sanitizer called just after the flagged
  line, the guard that gates a dataflow step — falls outside the
  window.  The classifier then reasons from a fragment: it flags code
  a nearby guard actually protects (false positive) or trusts a
  fragment that merely looks checked (false negative).
- Too large: every extra line is billed on EVERY finding (and for
  dataflow windows, on every step of every path), and distant
  unrelated code dilutes the model's attention away from the flagged
  lines — larger windows measurably bury the sink rather than
  explain it.

These are the shipped defaults, pinned by
``core/llm/tests/test_context_window.py``; changing a value is a
behaviour change, not a refactor.
"""

from __future__ import annotations

#: Lines of surrounding context before AND after the finding's own
#: line range in the main analysis prompt (the "function ±50 lines"
#: window). Too small: guards and sanitizers elsewhere in the host
#: function are invisible, so exploitability is judged on a fragment.
#: Too large: the surrounding-context block dominates the prompt's
#: token bill per finding and pushes the flagged lines further from
#: the model's focus; most functions fit well inside ±50 already, so
#: growth past this mostly adds NEIGHBOURING functions' code, which
#: misleads more than it informs.
FINDING_CONTEXT_LINES: int = 50

#: Head-of-file fallback when a finding carries no line numbers at
#: all (some SARIF producers omit startLine): the classifier sees the
#: first N lines of the file. Too small: the verdict on an
#: unlocatable finding degenerates to a guess over a handful of
#: includes. Too large: this window is by construction UNTARGETED —
#: there is no reason the relevant code is in the head at all, so
#: extra lines buy tokens spent on likely-irrelevant content rather
#: than better-placed evidence.
NO_LINE_INFO_HEAD_LINES: int = 100

#: Lines before/after ONE dataflow node (source, sink, or
#: intermediate step) when rendering a per-step code snippet — used
#: for the analysis prompt's dataflow path and for SMT path-condition
#: extraction. Too small: the branch condition that gates the step
#: (an ``if`` immediately above the flagged line) falls outside, so
#: the analysis loses the guard and the SMT pass extracts an
#: incomplete condition set. Too large: the cost multiplies by the
#: number of steps on the path, adjacent steps' windows duplicate the
#: same lines, and unrelated conditions inside a wide window pollute
#: the extracted predicate set (refuting feasible paths).
DATAFLOW_STEP_CONTEXT_LINES: int = 5

#: Lines before/after each dataflow node in the dedicated
#: dataflow-VALIDATION prompt (``DataflowValidator``'s deep
#: sanitizer/reachability analysis). Wider than
#: ``DATAFLOW_STEP_CONTEXT_LINES`` because this prompt's whole job is
#: judging sanitization around each hop, and it runs once per
#: validated path rather than per finding. Too small: sanitizers
#: adjacent to the hop are invisible and the validation re-derives
#: the scanner's shallow view. Too large: same per-step
#: multiplication as above — the validation prompt carries source,
#: sink AND every intermediate step, so the window is the biggest
#: token lever this prompt has.
DATAFLOW_VALIDATION_CONTEXT_LINES: int = 10
