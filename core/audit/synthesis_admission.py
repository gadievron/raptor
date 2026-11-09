"""Source request binding shared by synthesis consumers."""

import logging

from core.inventory.binary_builder import BINARY_PATH_PREFIX
from .claim_verification import ClaimVerification
from .refutation_source import capture_source_identity
from .verification_results import ToolChainResult

logger = logging.getLogger(__name__)


def bind_synthesis_request(outcome, config, hyp, source, *, excerpt_line_start=None):
    """Bind exact synthesis input without spending an attempt.

    The excerpt origin may precede the claim occurrence. Missing legacy and
    binary source identities stay unknown; this binding certifies no proof.
    """
    snippet = source or (outcome.review_result or {}).get("source_snippet", "")
    if snippet is None:
        snippet = ""
    if not isinstance(snippet, str) or (source is not None and not isinstance(source, str)):
        outcome.tools_skipped = (outcome.tools_skipped or set()) | {"checker_synthesis"}
        request = ToolChainResult(file=outcome.file, function=outcome.function,
            line_start=outcome.line, hypothesis=hyp["mechanism"])
        record_scope_rejection(ClaimVerification(hyp, binding=request.binding), outcome, config,
                               hypothesis=hyp["mechanism"], reason="invalid-source-input")
        return None
    identity = None if outcome.file.startswith(BINARY_PATH_PREFIX) else capture_source_identity(
        config.target_path, outcome.file, excerpt=snippet,
        line_start=outcome.line if excerpt_line_start is None else excerpt_line_start,
    )
    request = ToolChainResult(file=outcome.file, function=outcome.function,
        line_start=outcome.line, hypothesis=hyp["mechanism"], source_identity=identity)
    if identity is None and snippet and not outcome.file.startswith(BINARY_PATH_PREFIX):
        current_source = capture_source_identity(config.target_path, outcome.file)
        if current_source is not None:
            outcome.tools_skipped = (outcome.tools_skipped or set()) | {"checker_synthesis"}
            try:
                from .check_trace import record_source_input_rejection

                record_source_input_rejection(config.out_dir, request, current_source=current_source,
                                              requested_tools={"checker_synthesis"})
            except Exception:
                logger.warning("could not record synthesis source input rejection", exc_info=True)
            return None
    return request, snippet


def record_scope_rejection(verification, outcome, config, *, hypothesis, reason, current_source=None):
    """A failed handoff is diagnostic evidence, never a refutation."""
    try:
        if reason == "source-version-drift" and verification.binding is not None:
            from .check_trace import record_source_invalidation

            record_source_invalidation(
                config.out_dir, verification.binding, source_identity_after=current_source,
                prior_receipts=verification.receipts, prior_outcomes=(), phase="claim_admission",
            )
        else:
            from .check_trace import record_claim_scope_rejection

            record_claim_scope_rejection(
                config.out_dir, verification.binding, reason=reason, receipts=verification.receipts,
                attempted_scope={"file": outcome.file, "function": outcome.function,
                                 "line_start": outcome.line, "hypothesis": hypothesis,
                                 "review_hypothesis": (outcome.review_result or {}).get("hypothesis")},
            )
    except Exception:
        logger.warning("could not record verification scope rejection", exc_info=True)
