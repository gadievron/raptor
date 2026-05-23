"""Adapter: LLM-emitted exploit → ``core.witness.Witness``.

``/agentic`` synthesises an exploit per finding (via
``AutonomousSecurityAgentV2``), compile-verifies it, and runs the
intent-match judge over the result — but never *executes* the
exploit. The exploit-source bytes are still a witness of intent:
recording them under the canonical Witness type makes them
available alongside fuzz-generated witnesses for downstream
consumers (reporting, future ZKPoX bundle assembly, future
calibrated IntentMatchJudge) on the same data path.

The witness records:

  * ``source = LLM_EMIT_RUN``
  * ``observed_outcome = NOT_RUN`` — by design, ``/agentic``
    doesn't execute exploits. Future Tier-1.5 native execution
    will produce ``EXIT_SIGNAL`` / ``SANITIZER_REPORT`` /
    ``FLAG_CAPTURED`` witnesses for the same finding; the
    bytes_hash matches across both, so the witness store
    dedups the LLM artefact when the executed run lands.
  * ``outcome_detail`` carries the compile verdict + intent-match
    verdict so reporting can filter without re-reading the
    exploit text.

Adapter lives in ``packages/llm_analysis/`` rather than
``core/witness/`` so the dependency arrow points the right way
(packages depend on core, not vice versa).
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from core.hash import sha256_file
from core.witness import Witness, WitnessOutcome, WitnessSource
from core.witness.types import compute_bytes_hash


def witness_from_exploit(
    exploit_code: str,
    finding_id: str,
    cwe_id: Optional[str] = None,
    rule_id: Optional[str] = None,
    file_path: Optional[str] = None,
    compiled: Optional[bool] = None,
    compile_error_count: int = 0,
    intent_verdict: Optional[str] = None,
    intent_confidence: Optional[float] = None,
    target_source_path: Optional[Path] = None,
    target_binary_path: Optional[Path] = None,
    produced_by: str = "agentic",
) -> tuple[Witness, bytes]:
    """Wrap an LLM-emitted exploit as a ``Witness`` + the raw bytes.

    Returns ``(witness, bytes_)``. Callers typically pass both
    straight to ``WitnessStore.put(witness, bytes_)``.

    ``exploit_code`` is UTF-8 encoded once with ``errors="replace"``
    so unpaired surrogates from a poorly-decoded LLM response don't
    raise ``UnicodeEncodeError`` — the replacement byte sequence is
    what gets hashed and stored. The replacement is conservative
    (U+FFFD per invalid codepoint) so semantically-meaningful
    exploit text survives intact; only the genuinely-broken bytes
    are normalised. The resulting bytes are the canonical witness.

    ``compiled`` carries the verify verdict; ``None`` is the right
    encoding for "verification not attempted" (e.g.
    ``--no-verify-exploits``).

    ``intent_verdict`` is one of ``"matches"``/``"off_target"``/
    ``"uncertain"`` (the strings, not the enum — keeping the
    witness store free of llm_analysis-specific imports). ``None``
    means the judge wasn't run.

    ``target_source_path`` is optional; when provided and the file
    exists, it's hashed and stored so a later run can verify it's
    still the same source before claiming the witness holds.

    ``target_binary_path`` is the analogous slot for binaries — used
    when the LLM-emitted exploit was synthesised against a built
    target (e.g. crash-agent's path from a fuzz crash). The
    ``/agentic`` path normally has source only, no binary.
    """
    data = exploit_code.encode("utf-8", errors="replace")
    bytes_hash = compute_bytes_hash(data)

    outcome_detail: dict = {"finding_id": finding_id}
    if cwe_id:
        outcome_detail["cwe_id"] = cwe_id
    if rule_id:
        outcome_detail["rule_id"] = rule_id
    if file_path:
        outcome_detail["file_path"] = file_path
    if compiled is not None:
        outcome_detail["compiled"] = compiled
    if compile_error_count:
        outcome_detail["compile_error_count"] = compile_error_count
    if intent_verdict is not None:
        outcome_detail["intent_verdict"] = intent_verdict
    if intent_confidence is not None:
        outcome_detail["intent_confidence"] = intent_confidence

    target_source_hash: Optional[str] = None
    if target_source_path is not None and target_source_path.is_file():
        target_source_hash = sha256_file(target_source_path)

    target_binary_hash: Optional[str] = None
    if target_binary_path is not None and target_binary_path.is_file():
        target_binary_hash = sha256_file(target_binary_path)

    witness = Witness(
        bytes_hash=bytes_hash,
        bytes_len=len(data),
        source=WitnessSource.LLM_EMIT_RUN,
        observed_outcome=WitnessOutcome.NOT_RUN,
        outcome_detail=outcome_detail,
        target_binary_hash=target_binary_hash,
        target_source_hash=target_source_hash,
        produced_by=produced_by,
    )
    return witness, data
