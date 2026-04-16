"""
SAGE-backed fuzzing memory for RAPTOR.

Drop-in replacement for FuzzingMemory that stores knowledge in SAGE
for consensus-validated persistence while keeping JSON as local cache.
"""

import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.logging import get_logger

from .client import SageClient
from .config import SageConfig
from .hooks import _run_async

logger = get_logger()

# Import the original FuzzingMemory for inheritance
from packages.autonomous.memory import FuzzingMemory, FuzzingKnowledge


def _knowledge_to_natural_language(k: FuzzingKnowledge) -> str:
    """Convert a FuzzingKnowledge entry to natural language for SAGE embedding."""
    parts = [
        f"Fuzzing knowledge ({k.knowledge_type}): {k.key}.",
    ]

    if isinstance(k.value, dict):
        # Extract meaningful fields from the value dict
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

        # With SAGE enabled
        memory = SageFuzzingMemory()

        # Same API as FuzzingMemory
        memory.record_strategy_success("AFL_CMPLOG", hash, 5, 2)
        best = memory.get_best_strategy(hash)

        # New: semantic recall from SAGE
        similar = await memory.recall_similar("heap overflow strategies")
    """

    def __init__(
        self,
        memory_file: Optional[Path] = None,
        sage_config: Optional[SageConfig] = None,
    ):
        # Initialise the base JSON-backed memory
        super().__init__(memory_file=memory_file)

        self._sage_config = sage_config or SageConfig.from_env()
        self._sage_client = SageClient(self._sage_config)
        self._sage_available = self._sage_client.is_available()

        if self._sage_available:
            logger.info("SAGE memory enabled — fuzzing knowledge will be persisted to SAGE")
        else:
            logger.info("SAGE unavailable — using JSON fallback only")

    # ------------------------------------------------------------------
    # Override save() to also push to SAGE
    # ------------------------------------------------------------------

    def save(self):
        """Save to JSON (always) and SAGE (when available, async fire-and-forget)."""
        # Always save to JSON for local cache
        super().save()

        if not self._sage_available:
            return

        # Sync push to SAGE
        try:
            _run_async(self._sync_to_sage())
        except Exception:
            pass

    async def _sync_to_sage(self):
        """Push current knowledge to SAGE."""
        stored = 0
        for key, k in self.knowledge.items():
            try:
                content = _knowledge_to_natural_language(k)
                success = await self._sage_client.propose(
                    content=content,
                    memory_type="observation",
                    domain_tag="raptor-fuzzing",
                    confidence=k.confidence,
                )
                if success:
                    stored += 1
                # Small delay to avoid overwhelming single-node consensus
                await asyncio.sleep(0.3)
            except Exception as e:
                logger.debug(f"SAGE sync failed for {key}: {e}")

        if stored > 0:
            logger.debug(f"Synced {stored}/{len(self.knowledge)} knowledge entries to SAGE")

    # ------------------------------------------------------------------
    # Override remember() to immediately push to SAGE
    # ------------------------------------------------------------------

    def remember(self, knowledge: FuzzingKnowledge):
        """Store knowledge locally and in SAGE."""
        super().remember(knowledge)

        if not self._sage_available:
            return

        try:
            _run_async(self._remember_in_sage(knowledge))
        except Exception:
            pass

    async def _remember_in_sage(self, knowledge: FuzzingKnowledge):
        """Push a single knowledge entry to SAGE."""
        try:
            content = _knowledge_to_natural_language(knowledge)
            await self._sage_client.propose(
                content=content,
                memory_type="observation",
                domain_tag="raptor-fuzzing",
                confidence=knowledge.confidence,
            )
        except Exception as e:
            logger.debug(f"SAGE remember failed: {e}")

    # ------------------------------------------------------------------
    # Override record_campaign() to also push to SAGE
    # ------------------------------------------------------------------

    def record_campaign(self, campaign_data: Dict):
        """Record campaign locally and in SAGE."""
        super().record_campaign(campaign_data)

        if not self._sage_available:
            return

        try:
            _run_async(self._store_campaign_in_sage(campaign_data))
        except Exception:
            pass

    async def _store_campaign_in_sage(self, campaign_data: Dict):
        """Push a campaign record to SAGE."""
        try:
            content = _campaign_to_natural_language(campaign_data)
            await self._sage_client.propose(
                content=content,
                memory_type="observation",
                domain_tag="raptor-campaigns",
                confidence=0.85,
            )
        except Exception as e:
            logger.debug(f"SAGE campaign store failed: {e}")

    # ------------------------------------------------------------------
    # New: semantic recall from SAGE
    # ------------------------------------------------------------------

    async def recall_similar(
        self,
        query_text: str,
        domain: str = "raptor-fuzzing",
        top_k: int = 5,
    ) -> List[Dict[str, Any]]:
        """
        Recall semantically similar fuzzing knowledge from SAGE.

        Args:
            query_text: Natural language query (e.g. "heap overflow strategies for ASLR binaries")
            domain: SAGE domain to search
            top_k: Max results to return

        Returns:
            List of dicts with content, confidence, and domain keys.
            Empty list if SAGE is unavailable.
        """
        if not self._sage_available:
            return []

        return await self._sage_client.query(
            text=query_text,
            domain_tag=domain,
            top_k=top_k,
        )

    async def recall_exploit_patterns(
        self,
        crash_type: str,
        binary_characteristics: Optional[Dict] = None,
        top_k: int = 5,
    ) -> List[Dict[str, Any]]:
        """
        Recall exploit technique patterns relevant to a crash type.

        Args:
            crash_type: e.g. "heap_overflow", "format_string"
            binary_characteristics: e.g. {"aslr": True, "nx": True}
            top_k: Max results

        Returns:
            Matching SAGE memories about exploit techniques.
        """
        if not self._sage_available:
            return []

        mitigations = ""
        if binary_characteristics:
            active = [k for k, v in binary_characteristics.items() if v]
            if active:
                mitigations = f" with mitigations: {', '.join(active)}"

        query = f"exploit techniques for {crash_type}{mitigations}"
        return await self._sage_client.query(
            text=query,
            domain_tag="raptor-fuzzing",
            top_k=top_k,
        )

    def get_statistics(self) -> Dict:
        """Get memory statistics including SAGE status."""
        stats = super().get_statistics()
        stats["sage_enabled"] = self._sage_available
        stats["sage_url"] = self._sage_config.url if self._sage_available else None
        return stats
