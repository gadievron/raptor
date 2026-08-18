"""Static security-audit purpose framing for auxiliary LLM call classes.

A comparison audit lost two whole call classes to provider
content-policy refusals: every ``summary`` (18/18) and every
``spec_inference`` (19/19) call was rejected with "can't help with
this", while all 36 ``review`` calls succeeded in the same run.

Diffing the prompts explains the split: the review system prompt opens
with the auditor role and walks a full audit methodology ("You are a
security auditor reviewing code", hypothesis steps, tool-evidence
demotion, verdict discipline) — an unmistakable defensive code-review
context. The refused classes presented bare target code plus a
security-flavoured extraction ask ("extract taint flows to
security-sensitive callees", "infer the security specification") with
NO stated purpose or authorization context — the exact shape a
provider's safety layer reads as attack-surface mapping for its own
sake.

Version history — measured, not guessed:

* v1 was a single purpose paragraph. The follow-up head-to-head run
  carried it on the wire and the aux classes were STILL refused
  15/15 (summary) + 19/19 (spec_inference), each an immediate hard
  refusal (``stop_reason=refusal``, ~3s), while the context-rich
  review class went 35/35 on the same route.
* Root cause (isolated by direct probes, one per configuration): the
  refusals were CONJUNCTIVE — the extraction ask over a base64+
  sentinel-encoded payload. The identical summary ask over the same
  function rendered plaintext succeeded outright, and the encoded
  envelope has months of clean service under judgment-shaped asks
  (classify / refute / verify / compose). Framing was never the
  discriminating variable; the payload rendering was. The operative
  fix is ``transparent_payload=True`` on the two security-extraction
  call classes (see core.audit._util.envelope_prompt) with
  compensating injection defences (source-grounding, pre-call
  preflight, envelope-echo discard) at those call sites.
* v2 (below) is retained as an honest-context improvement: it states
  the auditor role, the audit's defensive methodology, who authorized
  it, and exactly what consumes the output. Measured alone it is NOT
  sufficient (v2 + encoded payload still refused); it rides along as
  better context, not as the fix.

:data:`SECURITY_AUDIT_FRAMING` is STATIC text — never interpolated
with target-derived content — and is prepended to the (trusted)
system prompt of every auxiliary /audit call class via
:func:`with_audit_framing`, upstream of the prompt envelope: the
envelope discipline (untrusted content in ``UntrustedBlock``/slots,
instructions in system) is unchanged.

A refusal that persists despite full honest context is the model's
answer and is respected: the pipeline books it (telemetry disposition
``blocked``, ``stop_reason`` surfaced), falls back to mechanical
(Joern / AST) summaries, and moves on. No call class retries or
reworks a refused prompt against the live model.
"""

from __future__ import annotations

SECURITY_AUDIT_FRAMING = (
    "You are a security auditor working inside RAPTOR's "
    "hypothesis-driven code audit — an authorized, defensive review "
    "of a codebase the operator owns or is explicitly authorized to "
    "audit.\n"
    "\n"
    "How the audit works, end to end: reviewers form hypotheses about "
    "potential defects in the reviewed code; deterministic "
    "verification tools (Semgrep, Coccinelle, CodeQL, Joern, SMT "
    "solvers) confirm or refute each hypothesis; confirmed issues go "
    "to human triage and are fixed in the reviewed code. The "
    "pipeline's output is verdicts and patches for the code's own "
    "maintainers — standard defensive security-audit work.\n"
    "\n"
    "This call is one mechanical sub-step of that pipeline. You are "
    "asked for the same intermediate program facts a static-analysis "
    "engine derives mechanically — function summaries, parameter "
    "preconditions, parameter-to-callee data-flow relationships, "
    "error paths, state transitions, behavioural contracts. Your "
    "structured output feeds the deterministic verification tools and "
    "the patch generator named above; it is standard program analysis "
    "in service of finding, confirming, and fixing defects."
)


def with_audit_framing(system: str) -> str:
    """Prepend the audit-purpose framing to *system* (idempotent).

    Idempotence matters because some system prompts are composed from
    already-framed bases (engine-grammar suffixes, correction
    appendices); double framing would waste cached-prefix tokens and
    read as prompt noise.
    """
    if system.startswith(SECURITY_AUDIT_FRAMING):
        return system
    return SECURITY_AUDIT_FRAMING + "\n\n" + system
