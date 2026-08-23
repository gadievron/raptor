"""
Fuzzing Memory - Learning and Knowledge Persistence

This module enables RAPTOR to learn from past fuzzing campaigns and
improve over time through persistent knowledge storage.
"""

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.json import load_json, save_json
from core.logging import get_logger

logger = get_logger()


@dataclass
class FuzzingKnowledge:
    """
    A piece of learned knowledge from fuzzing.

    Knowledge can be about:
    - Which strategies work well for certain binary types
    - Which mutations led to crashes
    - Which crashes were exploitable
    - Which exploit techniques succeeded
    """

    knowledge_type: str  # strategy, crash_pattern, exploit_technique, binary_characteristic
    key: str  # Identifier for this knowledge (e.g., "asan_binary_strategy", "heap_overflow_pattern")
    value: Any  # The actual knowledge (can be dict, string, number, etc.)

    # Metadata
    confidence: float = 0.5  # 0.0 to 1.0 - how confident are we in this knowledge?
    success_count: int = 0  # How many times has this knowledge led to success?
    failure_count: int = 0  # How many times has it failed?
    last_updated: float = field(default_factory=time.time)

    # Context
    binary_hash: str | None = None  # Which binary did we learn this from?
    campaign_id: str | None = None  # Which fuzzing campaign?

    def update_success(self) -> None:
        """Record a successful application of this knowledge."""
        self.success_count += 1
        self.confidence = min(1.0, self.confidence + 0.1)
        self.last_updated = time.time()

    def update_failure(self) -> None:
        """Record a failed application of this knowledge."""
        self.failure_count += 1
        self.confidence = max(0.0, self.confidence - 0.05)
        self.last_updated = time.time()

    def total_applications(self) -> int:
        """Total times this knowledge has been applied."""
        return self.success_count + self.failure_count

    def success_rate(self) -> float:
        """Calculate success rate (0.0 to 1.0)."""
        total = self.total_applications()
        if total == 0:
            return 0.0
        return self.success_count / total


class FuzzingMemory:
    """
    Persistent memory system for fuzzing knowledge.

    Enables RAPTOR to:
    - Remember what worked in past campaigns
    - Learn from successes and failures
    - Improve strategies over time
    - Share knowledge between fuzzing sessions
    """

    def __init__(self, memory_file: Path | None = None) -> None:
        """
        Initialise fuzzing memory.
        Right now we use json and ideally we should be using sqlite or similar for scalability.

        Args:
            memory_file: Path to JSON file for persistent storage
        """
        if memory_file is None:
            memory_file = Path.home() / ".raptor" / "fuzzing_memory.json"

        self.memory_file = Path(memory_file)
        self.memory_file.parent.mkdir(parents=True, exist_ok=True)

        # In-memory knowledge store
        self.knowledge: dict[str, FuzzingKnowledge] = {}

        # Campaign history
        self.campaigns: list[dict] = []

        # Batched save: avoid writing to disk on every remember() call
        self._dirty_count: int = 0
        self._save_batch_size: int = 50
        self._last_save_time: float = 0.0
        self._save_interval: float = 30.0  # seconds

        # Load existing memory
        self.load()

        # Debug: constructor detail — fires once per process and every
        # RAPTOR subprocess constructs one, so at INFO it was among the
        # top repeated lines in the audit trail.
        logger.debug("Fuzzing memory initialised: %d knowledge entries loaded", len(self.knowledge))

    def load(self) -> None:
        """Load memory from persistent storage."""
        if not self.memory_file.exists():
            logger.debug("No existing memory file at %s", self.memory_file)
            return

        try:
            data = load_json(self.memory_file)
            if not isinstance(data, dict):
                logger.warning("Failed to parse memory file: %s", self.memory_file)
                return

            # Load knowledge entries
            for key, k_dict in data.get("knowledge", {}).items():
                self.knowledge[key] = FuzzingKnowledge(
                    knowledge_type=k_dict["knowledge_type"],
                    key=k_dict["key"],
                    value=k_dict["value"],
                    confidence=k_dict.get("confidence", 0.5),
                    success_count=k_dict.get("success_count", 0),
                    failure_count=k_dict.get("failure_count", 0),
                    last_updated=k_dict.get("last_updated", time.time()),
                    binary_hash=k_dict.get("binary_hash"),
                    campaign_id=k_dict.get("campaign_id"),
                )

            # Load campaign history
            self.campaigns = data.get("campaigns", [])

            logger.debug("Loaded %d knowledge entries, %d past campaigns", len(self.knowledge), len(self.campaigns))

        except Exception as e:  # noqa: BLE001 — memory is additive; never crash the campaign
            logger.error("Failed to load memory: %s", e)

    def flush(self) -> None:
        """Flush any pending dirty state to disk."""
        if self._dirty_count > 0:
            self.save()
            self._dirty_count = 0
            self._last_save_time = time.time()

    def save(self) -> None:
        """Save memory to persistent storage."""
        try:
            data = {
                "knowledge": {
                    key: {
                        "knowledge_type": k.knowledge_type,
                        "key": k.key,
                        "value": k.value,
                        "confidence": k.confidence,
                        "success_count": k.success_count,
                        "failure_count": k.failure_count,
                        "last_updated": k.last_updated,
                        "binary_hash": k.binary_hash,
                        "campaign_id": k.campaign_id,
                    }
                    for key, k in self.knowledge.items()
                },
                "campaigns": self.campaigns,
                "last_saved": time.time(),
            }

            save_json(self.memory_file, data)

            logger.debug("Memory saved to %s", self.memory_file)

        except Exception as e:  # noqa: BLE001 — memory is additive; never crash the campaign
            logger.error("Failed to save memory: %s", e)

    def remember(self, knowledge: FuzzingKnowledge) -> None:
        """
        Store a piece of knowledge.

        Args:
            knowledge: Knowledge to remember
        """
        key = f"{knowledge.knowledge_type}:{knowledge.key}"

        if key in self.knowledge:
            # Update existing knowledge
            existing = self.knowledge[key]
            existing.value = knowledge.value
            existing.last_updated = time.time()
            logger.debug("Updated knowledge: %s", key)
        else:
            # Store new knowledge
            self.knowledge[key] = knowledge
            logger.info("Learned new knowledge: %s", key)

        self._dirty_count += 1
        now = time.time()
        elapsed = now - self._last_save_time
        if (
            self._dirty_count >= self._save_batch_size
            or elapsed >= self._save_interval
        ):
            self.save()
            self._dirty_count = 0
            self._last_save_time = now

    def recall(self, knowledge_type: str, key: str) -> FuzzingKnowledge | None:
        """
        Retrieve a piece of knowledge.

        Args:
            knowledge_type: Type of knowledge to recall
            key: Specific key to look up

        Returns:
            Knowledge if found, None otherwise
        """
        lookup_key = f"{knowledge_type}:{key}"
        return self.knowledge.get(lookup_key)

    def find_similar(self, knowledge_type: str,
                     min_confidence: float = 0.5) -> list[FuzzingKnowledge]:
        """
        Find all knowledge of a certain type with sufficient confidence.

        Args:
            knowledge_type: Type of knowledge to find
            min_confidence: Minimum confidence threshold

        Returns:
            List of matching knowledge entries
        """
        results = [k for k in self.knowledge.values() if k.knowledge_type == knowledge_type and k.confidence >= min_confidence]

        # Sort by confidence (highest first)
        results.sort(key=lambda x: x.confidence, reverse=True)
        return results

    def record_strategy_success(self, strategy_name: str, binary_hash: str,
                                crashes_found: int, exploitable_crashes: int) -> None:
        """
        Record that a fuzzing strategy was successful.

        The stored ``value`` dict is a snapshot of the most recent run —
        each call overwrites the previous crash counts rather than
        accumulating them. Cumulative history lives in the entry's
        success/failure counters (``update_success`` / ``update_failure``),
        unlike ``record_crash_pattern`` which accumulates counts inside
        ``value`` itself.

        Args:
            strategy_name: Name of the strategy
            binary_hash: Hash of the binary fuzzed
            crashes_found: Number of crashes found
            exploitable_crashes: Number of exploitable crashes
        """
        key = f"strategy_{strategy_name}_{binary_hash}"

        knowledge = self.recall("strategy", key)
        if knowledge is None:
            knowledge = FuzzingKnowledge(
                knowledge_type="strategy",
                key=key,
                value={
                    "name": strategy_name,
                    "crashes_found": crashes_found,
                    "exploitable_crashes": exploitable_crashes,
                },
                binary_hash=binary_hash,
            )

        # Update with success
        if crashes_found > 0:
            knowledge.update_success()
        else:
            knowledge.update_failure()

        # Update value
        knowledge.value = {
            "name": strategy_name,
            "crashes_found": crashes_found,
            "exploitable_crashes": exploitable_crashes,
        }

        self.remember(knowledge)
        logger.info("Recorded strategy result: %s - %s crashes", strategy_name, crashes_found)

    def record_crash_pattern(self, signal: str, function: str,
                            binary_hash: str, exploitable: bool) -> None:
        """
        Record a crash pattern for learning.

        Unlike ``record_strategy_success`` (latest-run snapshot), the
        stored ``value`` dict accumulates: each call increments
        ``total_count`` and, when exploitable, ``exploitable_count``.

        Args:
            signal: Crash signal (e.g., "SIGSEGV")
            function: Function where crash occurred
            binary_hash: Hash of the binary
            exploitable: Whether crash was exploitable
        """
        key = f"{signal}_{function}"

        knowledge = self.recall("crash_pattern", key)
        if knowledge is None:
            knowledge = FuzzingKnowledge(
                knowledge_type="crash_pattern",
                key=key,
                value={
                    "signal": signal,
                    "function": function,
                    "exploitable_count": 0,
                    "total_count": 0,
                },
                binary_hash=binary_hash,
            )

        # Update counts
        value = knowledge.value
        value["total_count"] += 1
        if exploitable:
            value["exploitable_count"] += 1
            knowledge.update_success()
        else:
            knowledge.update_failure()

        knowledge.value = value
        self.remember(knowledge)

    def record_exploit_technique(self, technique: str, crash_type: str,
                                binary_characteristics: dict, success: bool) -> None:
        """
        Record whether an exploit technique worked.

        Args:
            technique: Exploit technique used (e.g., "ROP", "heap_spray")
            crash_type: Type of crash (e.g., "heap_overflow", "stack_overflow")
            binary_characteristics: Binary features (ASLR, NX, etc.)
            success: Whether exploit succeeded
        """
        key = f"{technique}_{crash_type}"

        knowledge = self.recall("exploit_technique", key)
        if knowledge is None:
            knowledge = FuzzingKnowledge(
                knowledge_type="exploit_technique",
                key=key,
                value={
                    "technique": technique,
                    "crash_type": crash_type,
                    "binary_characteristics": binary_characteristics,
                },
            )

        if success:
            knowledge.update_success()
        else:
            knowledge.update_failure()

        self.remember(knowledge)
        logger.info("Recorded exploit technique: %s - %s", technique, 'success' if success else 'failure')

    def get_best_strategy(self, binary_hash: str) -> str | None:
        """
        Get the best fuzzing strategy for a binary based on past experience.

        Args:
            binary_hash: Hash of the binary

        Returns:
            Strategy name if found, None otherwise
        """
        # Find all strategies for this binary
        strategies = [
            k for k in self.knowledge.values()
            if k.knowledge_type == "strategy" and k.binary_hash == binary_hash
        ]

        if not strategies:
            return None

        # Sort by confidence and success rate
        strategies.sort(key=lambda k: (k.confidence, k.success_rate()), reverse=True)

        best = strategies[0]
        logger.info(
            "Best strategy for binary: %s (confidence: %.2f, success rate: %.2f)",
            best.value['name'], best.confidence, best.success_rate(),
        )

        return best.value["name"]

    def is_crash_likely_exploitable(self, signal: str, function: str) -> float:
        """
        Predict if a crash is likely exploitable based on past patterns.

        Args:
            signal: Crash signal
            function: Function where crash occurred

        Returns:
            Probability between 0.0 and 1.0
        """
        key = f"{signal}_{function}"
        knowledge = self.recall("crash_pattern", key)

        if knowledge is None:
            # No past data - use signal-based heuristic
            signal_probs = {
                "SIGSEGV": 0.7, 11: 0.7,
                "SIGABRT": 0.5, 6: 0.5,
                "SIGILL": 0.4, 4: 0.4,
                "SIGFPE": 0.2, 8: 0.2,
            }
            # Callers may pass signal as a string-encoded int ("11")
            # which misses the int key (11).  Normalise first.
            lookup_key: Any = signal
            try:
                lookup_key = int(signal)
            except (TypeError, ValueError):
                pass
            return signal_probs.get(lookup_key, 0.3)

        # Use historical data
        value = knowledge.value
        if value["total_count"] == 0:
            return 0.3

        exploitable_rate = value["exploitable_count"] / value["total_count"]

        # Combine with confidence
        return exploitable_rate * knowledge.confidence

    def record_campaign(self, campaign_data: dict) -> None:
        """
        Record a complete fuzzing campaign for future reference.

        Args:
            campaign_data: Dictionary with campaign information
        """
        campaign_data["timestamp"] = time.time()
        campaign_data["date"] = datetime.now(timezone.utc).isoformat()

        self.campaigns.append(campaign_data)
        # save() serialises the entire knowledge dict too, so any pending
        # dirty entries are persisted here — reset the batch counters like
        # flush() does, or the next remember()/flush() rewrites the same
        # data redundantly.
        self.save()
        self._dirty_count = 0
        self._last_save_time = time.time()

        logger.info("Recorded campaign: %s", campaign_data.get('binary_name', 'unknown'))

    def get_statistics(self) -> dict:
        """Get memory statistics."""
        stats = {
            "total_knowledge": len(self.knowledge),
            "total_campaigns": len(self.campaigns),
            "knowledge_by_type": {},
            "average_confidence": 0.0,
        }

        # Count by type
        for k in self.knowledge.values():
            k_type = k.knowledge_type
            if k_type not in stats["knowledge_by_type"]:
                stats["knowledge_by_type"][k_type] = 0
            stats["knowledge_by_type"][k_type] += 1

        # Average confidence
        if self.knowledge:
            stats["average_confidence"] = sum(
                k.confidence for k in self.knowledge.values()
            ) / len(self.knowledge)

        return stats

    def prune_low_confidence(self, threshold: float = 0.2) -> None:
        """
        Remove knowledge with very low confidence.

        Args:
            threshold: Minimum confidence to keep
        """
        before_count = len(self.knowledge)

        self.knowledge = {
            key: k for key, k in self.knowledge.items()
            if k.confidence >= threshold
        }

        pruned = before_count - len(self.knowledge)
        if pruned > 0:
            logger.info("Pruned %s low-confidence knowledge entries", pruned)
            # Full-state save — reset the batch counters (see record_campaign).
            self.save()
            self._dirty_count = 0
            self._last_save_time = time.time()
