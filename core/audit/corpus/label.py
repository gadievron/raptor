"""Label schema for the /audit calibration corpus.

Each label describes one function with a known ground-truth review
verdict.  Labels are committed as ``.label.json`` files under
``core/audit/corpus/labels/<bug_class>/``.  Source code is never
committed — it is fetched on demand at pinned refs; the URL registry
lives in ``sources.json`` (see ``core.audit.corpus.sources``).
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


SCHEMA_VERSION = 1

VALID_BUG_CLASSES = frozenset({
    "aliasing", "lifecycle", "variant",
    "auth", "clean", "concurrency", "integer",
    "trap", "uninitialised", "fail_open",
})

VALID_EXPECTED_STATUSES = frozenset({
    "finding", "clean", "dormant",
})

# How much source the reviewer must be shown for the label's verdict
# to be adjudicable.  ``function`` (default) — the pinned span alone;
# ``peer_set`` — the pinned span plus every peer call site named in
# the rationale (consistency-channel labels); ``file`` — the whole
# containing file.
VALID_EXCERPT_SCOPES = frozenset({
    "function", "peer_set", "file",
})

# Review modes the runner exposes via --mode.  ``run_corpus`` builds
# its argparse choices from this set — labels and runner cannot drift.
VALID_REVIEW_MODES = frozenset({
    "security", "bug_first", "quality", "ensemble",
})

# Length of ``SourcePin.span_sha`` — matches the repo-wide span-hash
# convention (``core.staleness``: SHA-256[:12] over the raw span lines
# joined by ``\n``), the same format /annotate stamps into annotation
# metadata.  One convention means a pin hash and an annotation hash of
# the same span are directly comparable.
SPAN_SHA_LEN = 12

_HEX_DIGITS = frozenset("0123456789abcdef")


def compute_span_sha(text: str, line_start: int, line_end: int) -> str:
    """Span hash of ``text``'s 1-indexed inclusive line range.

    Delegates to ``core.staleness.hash_spans_text`` so labels,
    annotations, and the inventory share one hashing primitive.
    Returns ``""`` for an invalid range.
    """
    from core.staleness import hash_spans_text

    return hash_spans_text(text, [(line_start, line_end)])[0]


@dataclass(frozen=True)
class SourcePin:
    """Pinned location of a function in an upstream repository.

    ``span_sha`` (optional) content-addresses the pinned line range:
    the span hash (see ``compute_span_sha``) of lines
    ``line_start..line_end`` of ``file`` at ``sha``.  A pin that
    carries it can be verified byte-for-byte against the pinned tree
    — line-number drift is detected (and often relocated) instead of
    silently reviewing the wrong span.  Older labels omit it; the
    corpus linter's ``--stamp`` backfills it for pins that verify
    (``python3 -m core.audit.corpus.lint``).
    """

    repo: str
    sha: str
    file: str
    line_start: int
    line_end: int
    span_sha: str = ""

    def __post_init__(self) -> None:
        if self.span_sha and (
            len(self.span_sha) != SPAN_SHA_LEN
            or not set(self.span_sha) <= _HEX_DIGITS
        ):
            raise ValueError(
                f"Invalid span_sha {self.span_sha!r}: must be "
                f"{SPAN_SHA_LEN} lowercase hex chars "
                f"(core.staleness span-hash convention)"
            )


@dataclass(frozen=True)
class FunctionLabel:
    """Ground-truth label for one function."""

    function_id: str
    bug_class: str
    expected_status: str
    rationale: str
    source: SourcePin
    labeler: str
    labeled_at: str
    schema_version: int = SCHEMA_VERSION
    cwe: str = ""
    cve: str = ""
    expected_mechanism: str = ""
    excerpt_scope: str = "function"
    expected_mode_results: Dict[str, str] = field(default_factory=dict)
    # Optional per-engine exact-rule expectations for the mechanical
    # rule-verification runner (``rule_eval``): engine name -> list of
    # rule ids that should hit this label.  When an engine is pinned
    # here, rule_eval's targeting join uses exact membership for that
    # engine; engines left unpinned fall back to class/CWE targeting.
    # Validation is deliberately lenient — shape only — so labels can
    # pin rules from engines (or rule sets) this checkout doesn't ship.
    expected_rule_hits: Dict[str, List[str]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.bug_class not in VALID_BUG_CLASSES:
            raise ValueError(
                f"Invalid bug_class {self.bug_class!r}; "
                f"must be one of {sorted(VALID_BUG_CLASSES)}"
            )
        if self.expected_status not in VALID_EXPECTED_STATUSES:
            raise ValueError(
                f"Invalid expected_status {self.expected_status!r}; "
                f"must be one of {sorted(VALID_EXPECTED_STATUSES)}"
            )
        if self.excerpt_scope not in VALID_EXCERPT_SCOPES:
            raise ValueError(
                f"Invalid excerpt_scope {self.excerpt_scope!r}; "
                f"must be one of {sorted(VALID_EXCERPT_SCOPES)}"
            )
        for mode, status in self.expected_mode_results.items():
            if mode not in VALID_REVIEW_MODES:
                raise ValueError(
                    f"Invalid expected_mode_results mode {mode!r}; "
                    f"must be one of {sorted(VALID_REVIEW_MODES)}"
                )
            if status not in VALID_EXPECTED_STATUSES:
                raise ValueError(
                    f"Invalid expected_mode_results status {status!r} "
                    f"for mode {mode!r}; "
                    f"must be one of {sorted(VALID_EXPECTED_STATUSES)}"
                )
        for engine, rule_ids in self.expected_rule_hits.items():
            if not isinstance(engine, str) or not engine:
                raise ValueError(
                    f"Invalid expected_rule_hits engine {engine!r}; "
                    f"must be a non-empty string"
                )
            if not isinstance(rule_ids, list) or not all(
                isinstance(r, str) and r for r in rule_ids
            ):
                raise ValueError(
                    f"Invalid expected_rule_hits for engine {engine!r}; "
                    f"must be a list of non-empty rule-id strings"
                )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def load_label(path: Path) -> FunctionLabel:
    """Load a label from a .label.json file."""
    raw = json.loads(path.read_text())
    return FunctionLabel(
        schema_version=raw.get("schema_version", 1),
        function_id=raw["function_id"],
        bug_class=raw["bug_class"],
        expected_status=raw["expected_status"],
        rationale=raw["rationale"],
        source=SourcePin(**raw["source"]),
        labeler=raw["labeler"],
        labeled_at=raw["labeled_at"],
        cwe=raw.get("cwe", ""),
        cve=raw.get("cve", ""),
        expected_mechanism=raw.get("expected_mechanism", ""),
        excerpt_scope=raw.get("excerpt_scope", "function"),
        expected_mode_results=raw.get("expected_mode_results", {}),
        expected_rule_hits=raw.get("expected_rule_hits", {}),
    )


def load_all_labels(
    corpus_dir: Optional[Path] = None,
    bug_class: Optional[str] = None,
) -> List[FunctionLabel]:
    """Load all labels from the corpus, optionally filtered by class.

    Duplicate ``function_id`` values are an error: results, splices,
    and checkpoints are all keyed by function_id, so a duplicate would
    silently collapse to last-wins downstream.
    """
    if corpus_dir is None:
        corpus_dir = Path(__file__).parent / "labels"
    labels = []
    seen: Dict[str, Path] = {}
    duplicates: List[str] = []
    for label_file in sorted(corpus_dir.rglob("*.label.json")):
        label = load_label(label_file)
        prev = seen.get(label.function_id)
        if prev is not None:
            duplicates.append(
                f"{label.function_id!r} in {label_file} "
                f"(already labelled in {prev})"
            )
        else:
            seen[label.function_id] = label_file
        if bug_class and label.bug_class != bug_class:
            continue
        labels.append(label)
    if duplicates:
        raise ValueError(
            f"{len(duplicates)} duplicate function_id(s) in corpus: "
            + "; ".join(duplicates)
        )
    return labels
