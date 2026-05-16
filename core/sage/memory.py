"""
SAGE-backed fuzzing memory for RAPTOR.

Drop-in replacement for FuzzingMemory that stores knowledge in SAGE
for consensus-validated persistence while keeping JSON as local cache.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

from core.logging import get_logger

from .client import SageClient
from .config import SageConfig
from .hooks import _throttle

logger = get_logger()

# Import the original FuzzingMemory for inheritance
from packages.autonomous.memory import FuzzingMemory, FuzzingKnowledge


def _domain_tag_for_knowledge(k: FuzzingKnowledge) -> str:
    """Route fuzzing knowledge to the SAGE domain that matches its semantics.

    ``exploit_technique`` and ``binary_characteristic`` generalize across
    binaries and campaigns (methodology). ``strategy`` and ``crash_pattern``
    stay under fuzzing/campaign-specific recall.
    """
    if k.knowledge_type in ("exploit_technique", "binary_characteristic"):
        return "raptor-methodology"
    return "raptor-fuzzing"


def _merge_query_hits(
    hit_lists: List[List[Dict[str, Any]]],
    top_k: int,
) -> List[Dict[str, Any]]:
    """Merge SAGE query rows from multiple domains, de-duped by content."""
    seen: set = set()
    out: List[Dict[str, Any]] = []
    for lst in hit_lists:
        for r in lst:
            c = (r.get("content") or "").strip()
            if not c or c in seen:
                continue
            seen.add(c)
            out.append(r)
            if len(out) >= top_k:
                return out
    return out


def _knowledge_to_natural_language(k: FuzzingKnowledge) -> str:
    """Convert a FuzzingKnowledge entry to natural language for SAGE embedding."""
    parts = [
        f"Fuzzing knowledge ({k.knowledge_type}): {k.key}.",
    ]

    if isinstance(k.value, dict):
        for vk, vv in k.value.items():
            if vv is not None and vv != "" and vv != 0:
                parts.append(f"{vk}: {vv}.")
    else:
        parts.append(f"Value: {k.value}.")

    parts.append(
        f"Confidence: {k.confidence:.2f}, "
        f"success: {k.success_count}, failure: {k.failure_count}."
    )

    if k.binary_hash:
        parts.append(f"Binary: {k.binary_hash}.")

    return " ".join(parts)


def _campaign_to_natural_language(campaign: Dict) -> str:
    """Convert a campaign dict to natural language."""
    name = campaign.get("binary_name", "unknown")
    date = campaign.get("date", "unknown")
    crashes = campaign.get("crashes_found", 0)
    strategy = campaign.get("strategy", "unknown")
    return (
        f"Fuzzing campaign for {name} on {date}. "
        f"Strategy: {strategy}. Crashes found: {crashes}."
    )


class SageFuzzingMemory(FuzzingMemory):
    """
    SAGE-backed fuzzing memory.

    Extends FuzzingMemory to store/recall knowledge via SAGE while
    keeping the JSON file as a local cache and fallback.

    Usage::

        memory = SageFuzzingMemory()
        memory.record_strategy_success("AFL_CMPLOG", hash, 5, 2)
        best = memory.get_best_strategy(hash)
        similar = memory.recall_similar("heap overflow strategies")
    """

    def __init__(
        self,
        memory_file: Optional[Path] = None,
        sage_config: Optional[SageConfig] = None,
    ):
        super().__init__(memory_file=memory_file)

        self._sage_config = sage_config or SageConfig.from_env()
        self._sage_client = SageClient(self._sage_config)
        self._sage_available = self._sage_client.is_available()

        if self._sage_available:
            logger.info("SAGE memory enabled — fuzzing knowledge will be persisted to SAGE")
        else:
            logger.info("SAGE unavailable — using JSON fallback only")

    def save(self):
        """Save to JSON (always) and SAGE (when available)."""
        super().save()

        if not self._sage_available:
            return

        stored = 0
        for key, k in self.knowledge.items():
            try:
                if self._sage_client.propose(
                    content=_knowledge_to_natural_language(k),
                    memory_type="observation",
                    domain_tag=_domain_tag_for_knowledge(k),
                    confidence=k.confidence,
                ):
                    stored += 1
                _throttle()
            except Exception as e:
                logger.debug(f"SAGE sync failed for {key}: {e}")

        if stored > 0:
            logger.debug(f"Synced {stored}/{len(self.knowledge)} knowledge entries to SAGE")

    def remember(self, knowledge: FuzzingKnowledge):
        """Store knowledge locally and in SAGE."""
        super().remember(knowledge)

        if not self._sage_available:
            return

        try:
            self._sage_client.propose(
                content=_knowledge_to_natural_language(knowledge),
                memory_type="observation",
                domain_tag=_domain_tag_for_knowledge(knowledge),
                confidence=knowledge.confidence,
            )
        except Exception as e:
            logger.debug(f"SAGE remember failed: {e}")

    def record_campaign(self, campaign_data: Dict):
        """Record campaign locally and in SAGE."""
        super().record_campaign(campaign_data)

        if not self._sage_available:
            return

        try:
            self._sage_client.propose(
                content=_campaign_to_natural_language(campaign_data),
                memory_type="observation",
                domain_tag="raptor-campaigns",
                confidence=0.85,
            )
        except Exception as e:
            logger.debug(f"SAGE campaign store failed: {e}")

    # ------------------------------------------------------------------
    # Semantic recall from SAGE
    # ------------------------------------------------------------------

    def recall_similar(
        self,
        query_text: str,
        domain: str = "raptor-fuzzing",
        top_k: int = 5,
    ) -> List[Dict[str, Any]]:
        """Recall semantically similar fuzzing knowledge from SAGE.

        When ``domain`` is not ``raptor-methodology``, also queries the
        methodology domain and merges (de-duplicated), so exploit-adjacent
        recall still picks up generalised lessons.
        """
        if not self._sage_available:
            return []

        if domain == "raptor-methodology":
            return self._sage_client.query(
                text=query_text,
                domain_tag=domain,
                top_k=top_k,
            )

        primary = self._sage_client.query(
            text=query_text,
            domain_tag=domain,
            top_k=top_k,
        )
        methodology = self._sage_client.query(
            text=(
                "Security fuzzing and exploitation methodology related to: "
                f"{query_text}"
            ),
            domain_tag="raptor-methodology",
            top_k=max(2, min(3, top_k)),
        )
        return _merge_query_hits([primary, methodology], top_k)

    def recall_exploit_patterns(
        self,
        crash_type: str,
        binary_characteristics: Optional[Dict] = None,
        top_k: int = 5,
    ) -> List[Dict[str, Any]]:
        """Recall exploit technique patterns relevant to a crash type."""
        if not self._sage_available:
            return []

        mitigations = ""
        if binary_characteristics:
            active = [k for k, v in binary_characteristics.items() if v]
            if active:
                mitigations = f" with mitigations: {', '.join(active)}"

        text = f"exploit techniques for {crash_type}{mitigations}"
        methodology = self._sage_client.query(
            text=text,
            domain_tag="raptor-methodology",
            top_k=top_k,
        )
        fuzzing = self._sage_client.query(
            text=text,
            domain_tag="raptor-fuzzing",
            top_k=top_k,
        )
        return _merge_query_hits([methodology, fuzzing], top_k)

    def get_statistics(self) -> Dict:
        """Get memory statistics including SAGE status."""
        stats = super().get_statistics()
        stats["sage_enabled"] = self._sage_available
        stats["sage_url"] = self._sage_config.url if self._sage_available else None
        return stats
