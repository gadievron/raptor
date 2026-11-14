"""Bounded advisory context for an already-produced synthesis match.

A checker match selects source for another review; it is not a verification
receipt, and this module neither executes a checker nor creates proof facts.
"""
from __future__ import annotations

from dataclasses import dataclass, field, fields
from hashlib import sha256
import json
from typing import TypeGuard

from core.security.prompt_envelope import wrap_untrusted

_MAX_FILE = 4096
_MAX_FUNCTION = 512
_MAX_SERIALIZED = 8192
_POLICY = "synthesis-match-context-v1"
_MAX_RULE = 256
_MAX_SNIPPET = 1800
_MAX_PROVENANCE = 1800


@dataclass(frozen=True)
class SynthesisReviewContext:
    file: str
    function: str
    line_start: int
    line_end: int
    match_line: int
    rule_id: str
    rule_id_chars_omitted: int
    snippet: str
    snippet_chars_omitted: int
    provenance: str
    provenance_chars_omitted: int
    _canonical: str = field(init=False, default="", repr=False, compare=False)
    _section: str = field(init=False, default="", repr=False, compare=False)

    def __post_init__(self):
        canonical = self.encoded_payload()
        if canonical is None:
            raise ValueError("invalid synthesis review context")
        object.__setattr__(self, "_canonical", canonical)
        object.__setattr__(self, "_section", _section(canonical))

    def encoded_payload(self) -> str | None:
        strings = ((self.file, _MAX_FILE), (self.function, _MAX_FUNCTION),
                   (self.rule_id, _MAX_RULE), (self.snippet, _MAX_SNIPPET),
                   (self.provenance, _MAX_PROVENANCE))
        if (any(not _text(value) or len(value) > limit for value, limit in strings)
                or not self.file or self.file.startswith("binary:") or not self.function
                or not self.rule_id.strip()
                or any(type(value) is not int for value in
                       (self.line_start, self.line_end, self.match_line))
                or not 0 < self.line_start <= self.match_line <= self.line_end
                or any(type(value) is not int or value < 0 for value in
                       (self.rule_id_chars_omitted, self.snippet_chars_omitted,
                        self.provenance_chars_omitted))):
            return None
        data = {item.name: getattr(self, item.name) for item in fields(self)
                if not item.name.startswith("_")}
        encoded = json.dumps(data, sort_keys=True, ensure_ascii=True, allow_nan=False)
        return encoded if len(encoded) <= _MAX_SERIALIZED else None

    @property
    def version(self) -> str:
        # Identity describes the actual bounded payload, never its random
        # envelope nonce. A deepcopy retains the one rendered section.
        return sha256((_POLICY + "\\0" + self._canonical).encode("utf-8")).hexdigest()


def _text(value: object) -> TypeGuard[str]:
    if not isinstance(value, str):
        return False
    try:
        value.encode("utf-8")
    except UnicodeError:
        return False
    return True


def build_synthesis_review_context(gap: dict) -> SynthesisReviewContext | None:
    """Keep the producer's exact selected occurrence and explicit clipping.

    The caller must separately retain the original live source binding. These
    strings cannot authenticate source, executed analysis or rule provenance.
    """
    file, function = gap.get("file"), gap.get("name")
    start, end, match = (gap.get(key) for key in
                         ("line_start", "line_end", "synthesis_hit_line"))
    rule, snippet = gap.get("synthesis_rule_id"), gap.get("synthesis_snippet", "")
    if (not _text(file) or not file or file.startswith("binary:")
            or not _text(function) or not function
            or type(start) is not int or type(end) is not int or type(match) is not int
            or not 0 < start <= match <= end
            or not _text(rule) or not rule.strip() or not _text(snippet)):
        return None
    try:
        provenance = json.dumps(gap.get("synthesis_provenance"), sort_keys=True,
                                ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError, UnicodeError, RecursionError):
        return None
    try:
        return SynthesisReviewContext(
            file, function, start, end, match,
            rule[:_MAX_RULE], max(0, len(rule) - _MAX_RULE),
            snippet[:_MAX_SNIPPET], max(0, len(snippet) - _MAX_SNIPPET),
            provenance[:_MAX_PROVENANCE], max(0, len(provenance) - _MAX_PROVENANCE),
        )
    except ValueError:
        return None


def _section(canonical: str) -> str:
    return (
        "\n### Advisory match from a run-synthesized checker\n"
        "A producer reported this match and selected the supplied source for "
        "another review. The match and rule provenance are advisory context, "
        "not confirmation, refutation, source authentication or proof of "
        "execution/reachability. Review the actual supplied function and "
        "distinguish a proposed pattern from a verified concern. Clipped "
        "fields explicitly disclose their omitted character counts.\n"
        + wrap_untrusted(canonical, kind="synthesis_match", origin="review")
    )


def render_synthesis_review_context(value: object) -> str:
    if not isinstance(value, SynthesisReviewContext):
        return ""
    try:
        canonical = value.encoded_payload()
        return value._section if canonical is not None and canonical == value._canonical else ""
    except (AttributeError, TypeError, ValueError, UnicodeError):
        return ""


def bind_initial_synthesis_context(context: dict, value: object) -> bool:
    """Bind this producer's bounded section to an actual initial source view."""
    from core.source.lines import split_lines
    from core.audit.orchestrator import _raw_ihv_review_source

    if not isinstance(value, SynthesisReviewContext) or not render_synthesis_review_context(value):
        return False
    if (type(context.get("line_start")) is not int
            or (context.get("file"), context.get("function"), context.get("line_start"))
            != (value.file, value.function, value.line_start)):
        return False
    source = context.get("source")
    if not isinstance(source, str) or not source:
        return False
    raw = _raw_ihv_review_source(source, value.line_start)
    if value.line_start + len(split_lines(raw)) - 1 != value.line_end:
        return False
    if context.get("line_end") is not None and (
            type(context["line_end"]) is not int or context["line_end"] != value.line_end):
        return False
    context["line_end"] = value.line_end
    context["synthesis_review_context"] = value
    from core.audit.continuation_context import context_spec

    spec = context_spec(context, kind="synthesis_match", version=value.version)
    if spec is None:
        return False
    context["continuation_context_inputs"] = (spec,)
    return True
