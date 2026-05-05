"""
Root-cause analyzer. Ported from code-differ/packages/root_cause/analyzer.py
(746 LOC → ~120 LOC). The reference version bundled CWE classification,
pattern-database scoring, and a 7-stage "why chain" builder. We collapse all
three into a single LLM call driven by a Jinja2 prompt and parse the JSON.

Pattern-database scoring (the reference's "signals") is intentionally dropped
for Phase 2: the curated 5-CVE gate doesn't depend on it and the plan's
`pattern_database_enhanced.json` was empty. If a signal framework is needed
later, it lives here, not in the prompt.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from string import Template

from cve_diff.core.models import DiffBundle
from cve_diff.llm.client import ResilientLLMClient

DEFAULT_MODEL = "claude-opus-4-7"
DIFF_PROMPT_LIMIT = 32_000  # Bytes of diff passed to the model.

# The single LLM prompt template uses ``${var}`` substitutions only —
# no loops, no conditionals, no inheritance — so ``string.Template``
# (stdlib) covers it without pulling in jinja2. Templates live as
# ``.txt`` next to this module; pre-2026-05-02 used ``.j2`` with
# jinja2's ``{{ var }}`` syntax.
_PROMPTS_DIR = Path(__file__).parent.parent / "llm" / "prompts"


def _load_template(name: str) -> Template:
    return Template((_PROMPTS_DIR / name).read_text(encoding="utf-8"))


class RootCauseAnalysisError(RuntimeError):
    """Raised by the LLM-driven root-cause analyser only.

    Renamed from ``AnalysisError`` to avoid collision with
    ``cve_diff.core.exceptions.AnalysisError`` (which the pipeline raises
    for shape rejection / extraction failures). The CLI used to import
    *this* class and try to catch the pipeline's exceptions with it —
    they were two different classes with the same name, so the CLI's
    typed-exception handler never fired and every notes-only/packaging-
    only rejection crashed uncaught.
    """


# Backwards-compat alias for any external caller that still imports
# the old name. New code should use RootCauseAnalysisError directly.
AnalysisError = RootCauseAnalysisError


@dataclass(frozen=True)
class RootCause:
    cwe_id: str
    vulnerability_type: str
    summary: str
    why_chain: tuple[str, ...]
    affected_functions: tuple[str, ...]
    confidence: float
    model_id: str
    input_tokens: int
    output_tokens: int


@dataclass
class RootCauseAnalyzer:
    client: ResilientLLMClient = field(default_factory=ResilientLLMClient)
    model_id: str = DEFAULT_MODEL
    diff_limit: int = DIFF_PROMPT_LIMIT

    def analyze(self, bundle: DiffBundle) -> RootCause:
        prompt = self._render_prompt(bundle)
        response = self.client.complete(
            model_id=self.model_id,
            prompt=prompt,
            system=(
                "You are a precise, concise security engineer. Always respond "
                "with a single valid JSON object matching the requested schema. "
                "No prose before or after the JSON."
            ),
            max_tokens=1500,
        )
        data = _parse_json_payload(response.text)
        try:
            return RootCause(
                cwe_id=_normalize_cwe(data["cwe_id"]),
                vulnerability_type=str(data["vulnerability_type"]),
                summary=str(data["summary"]),
                why_chain=tuple(str(x) for x in data.get("why_chain", [])),
                affected_functions=tuple(str(x) for x in data.get("affected_functions", [])),
                confidence=float(data.get("confidence", 0.0)),
                model_id=response.model_id,
                input_tokens=response.input_tokens,
                output_tokens=response.output_tokens,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise AnalysisError(f"response missing required field: {exc}. got={data!r}") from exc

    def _render_prompt(self, bundle: DiffBundle) -> str:
        tmpl = _load_template("root_cause.txt")
        diff_text = bundle.diff_text
        if len(diff_text) > self.diff_limit:
            diff_text = diff_text[: self.diff_limit] + "\n[...truncated...]"
        # ``substitute`` (not ``safe_substitute``) so a missing key
        # raises immediately rather than silently leaving ``$placeholder``
        # in the rendered prompt.
        return tmpl.substitute(
            cve_id=bundle.cve_id,
            repository_url=bundle.repo_ref.repository_url,
            commit_after=bundle.commit_after,
            commit_before=bundle.commit_before,
            files_changed=bundle.files_changed,
            diff_bytes=bundle.bytes_size,
            diff_limit=self.diff_limit,
            diff_text=diff_text,
        )


_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(?P<body>\{.*?\})\s*```", re.DOTALL)


def _parse_json_payload(text: str) -> dict:
    """Accept bare JSON or a fenced code block; raise AnalysisError on bad input."""
    text = text.strip()
    m = _JSON_FENCE_RE.search(text)
    if m:
        text = m.group("body")
    else:
        first = text.find("{")
        last = text.rfind("}")
        if first >= 0 and last > first:
            text = text[first : last + 1]
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise AnalysisError(f"model returned non-JSON payload: {exc}") from exc


_CWE_RE = re.compile(r"CWE[-_\s]?(\d+)", re.IGNORECASE)


def _normalize_cwe(value: str) -> str:
    m = _CWE_RE.search(str(value))
    if not m:
        raise AnalysisError(f"not a CWE id: {value!r}")
    return f"CWE-{m.group(1)}"
