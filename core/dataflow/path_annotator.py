"""Path annotation: match candidate validators against function calls
in :class:`Finding` step snippets.

This is the **structural** half of PR1's evidence pipeline — pure
AST / tree-sitter parsing, no LLM. It takes:

* a :class:`Finding` whose source/sink/intermediate steps each carry
  a snippet of code, and
* a candidate-validator pool (typically extracted by PR1b's LLM
  pass, but the annotator doesn't care where the pool came from)

and produces one :class:`StepAnnotation` per step recording:

* which candidates' calls appear in the step's snippet
  (``on_path_validators``)
* which other identifiers the snippet references (``variables_referenced``,
  approximate via a regex over identifier-shaped tokens)
* which calls the snippet makes that the annotator did *not* match
  to any candidate (``inlined_helpers``)

Language-aware via :func:`core.inventory.languages.detect_language`.
Per-language call extraction reuses the AST/tree-sitter machinery
already in :mod:`core.inventory.call_graph` — gracefully degrades to
an empty annotation when:

* the language isn't supported (e.g. C/C++, where we have no
  call-graph extractor today),
* the language module isn't installed (tree-sitter grammars are
  optional dependencies),
* the snippet doesn't parse cleanly.

Empty annotations are honest signal: the downstream LLM sees that
this step's call data wasn't recoverable and weighs the rest of the
evidence accordingly.
"""

from __future__ import annotations

import re
from typing import (
    Callable,
    Dict,
    Optional,
    Sequence,
    Set,
    Tuple,
)

from core.dataflow.finding import Finding, Step
from core.dataflow.sanitizer_evidence import (
    CandidateValidator,
    StepAnnotation,
)
from core.inventory.call_graph import (
    FileCallGraph,
    extract_call_graph_go,
    extract_call_graph_java,
    extract_call_graph_javascript,
    extract_call_graph_python,
    extract_call_graph_ruby,
    extract_call_graph_rust,
)
from core.inventory.languages import detect_language


# Tree-sitter / AST extractor by language. Keys match
# ``LANGUAGE_MAP``'s values in ``core.inventory.languages``.
_EXTRACTORS: Dict[str, Callable[[str], FileCallGraph]] = {
    "python": extract_call_graph_python,
    "javascript": extract_call_graph_javascript,
    "typescript": extract_call_graph_javascript,
    "java": extract_call_graph_java,
    "go": extract_call_graph_go,
    "rust": extract_call_graph_rust,
    "ruby": extract_call_graph_ruby,
}


# Identifier-shaped tokens for the ``variables_referenced`` field.
# Cross-language by construction — most languages share the same
# identifier shape. Keywords leak through but the downstream LLM
# filters those mentally; the field is informational, not a sink set.
_IDENTIFIER_RE = re.compile(r"\b[A-Za-z_][A-Za-z_0-9]*\b")


def _extract_call_chains(snippet: str, language: Optional[str]) -> Tuple[Tuple[str, ...], ...]:
    extractor = _EXTRACTORS.get(language) if language else None
    if extractor is None:
        return ()
    try:
        graph = extractor(snippet)
    except Exception:  # pragma: no cover - extractor robustness varies
        return ()
    return tuple(tuple(c.chain) for c in graph.calls if c.chain)


def _extract_identifiers(snippet: str) -> Tuple[str, ...]:
    return tuple(_IDENTIFIER_RE.findall(snippet))


def _chain_matches_candidate(
    chain: Sequence[str], candidate: CandidateValidator
) -> bool:
    """A call chain matches a candidate if it ends with the candidate's
    name or matches its qualified name.

    Examples (candidate.name="escape_sql", qualified_name="db.helpers.escape_sql"):

      chain=["escape_sql"]                 → match (bare-name suffix)
      chain=["helpers", "escape_sql"]      → match (suffix of qualified)
      chain=["db", "helpers", "escape_sql"] → match (full qualified)
      chain=["other", "escape_sql"]        → match (suffix on bare name)
      chain=["escape"]                     → no match (different name)
    """
    qualified_parts = candidate.qualified_name.split(".")
    if _ends_with(chain, qualified_parts):
        return True
    name_parts = candidate.name.split(".") if "." in candidate.name else [candidate.name]
    return _ends_with(chain, name_parts)


def _ends_with(chain: Sequence[str], suffix: Sequence[str]) -> bool:
    if not suffix or len(suffix) > len(chain):
        return False
    return list(chain[-len(suffix):]) == list(suffix)


def _join_chain(chain: Sequence[str]) -> str:
    return ".".join(chain)


def _annotate_step(
    step: Step,
    step_index: int,
    candidates: Sequence[CandidateValidator],
) -> StepAnnotation:
    language = detect_language(step.file_path)
    chains = _extract_call_chains(step.snippet, language)

    on_path: Set[str] = set()
    helpers: Set[str] = set()
    callee_tokens: Set[str] = set()

    for chain in chains:
        callee_tokens.update(chain)
        matched = False
        for c in candidates:
            if _chain_matches_candidate(chain, c):
                on_path.add(c.qualified_name)
                matched = True
                break
        if not matched:
            helpers.add(_join_chain(chain))

    identifiers = _extract_identifiers(step.snippet)
    variables: Set[str] = set()
    for token in identifiers:
        if token in callee_tokens:
            continue
        # Strip the obvious built-ins/keywords that pollute the field
        # without filtering aggressively — downstream LLM tolerates noise.
        if token in _COMMON_NOISE:
            continue
        variables.add(token)

    return StepAnnotation(
        step_index=step_index,
        on_path_validators=tuple(sorted(on_path)),
        variables_referenced=tuple(sorted(variables)),
        inlined_helpers=tuple(sorted(helpers)),
    )


# Cross-language tokens that are never variable references in any
# realistic snippet — keeps the variables_referenced field readable
# without language-specific keyword tables. The set is deliberately
# small; aggressive filtering would hide real signal.
_COMMON_NOISE: Set[str] = {
    "if", "else", "for", "while", "return", "true", "false", "null",
    "None", "True", "False", "import", "from", "let", "const", "var",
    "function", "def", "class", "public", "private", "static",
    "void", "new", "this", "self", "in", "is", "not", "and", "or",
}


def annotate_finding(
    finding: Finding,
    candidates: Sequence[CandidateValidator],
) -> Tuple[StepAnnotation, ...]:
    """Annotate every step of ``finding`` (source, intermediate, sink).

    Step indices: ``0`` = source, ``len(intermediate_steps) + 1`` = sink.
    Returns one :class:`StepAnnotation` per step, in path order.
    """
    all_steps = (finding.source,) + tuple(finding.intermediate_steps) + (finding.sink,)
    return tuple(
        _annotate_step(step, i, candidates) for i, step in enumerate(all_steps)
    )
