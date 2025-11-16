#!/usr/bin/env python3
"""
Fuzzing Memory - Learning and Knowledge Persistence

This module enables RAPTOR to learn from past fuzzing campaigns and
improve over time through persistent knowledge storage.
"""

import json
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

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
    binary_hash: Optional[str] = None  # Which binary did we learn this from?
    campaign_id: Optional[str] = None  # Which fuzzing campaign?

    def update_success(self):
        """Record a successful application of this knowledge."""
        self.success_count += 1
        self.confidence = min(1.0, self.confidence + 0.1)
        self.last_updated = time.time()

    def update_failure(self):
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

    def __init__(self, memory_file: Optional[Path] = None):
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
        self.knowledge: Dict[str, FuzzingKnowledge] = {}

        # Campaign history
        self.campaigns: List[Dict] = []

        # Load existing memory
        self.load()

        logger.info(f"Fuzzing memory initialised: {len(self.knowledge)} knowledge entries loaded")

    def load(self):
        """Load memory from persistent storage."""
        if not self.memory_file.exists():
            logger.info(f"No existing memory file at {self.memory_file}")
            return

        try:
            with open(self.memory_file, 'r') as f:
                data = json.load(f)

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

            logger.info(f"Loaded {len(self.knowledge)} knowledge entries, {len(self.campaigns)} past campaigns")

        except Exception as e:
            logger.error(f"Failed to load memory: {e}")

    def save(self):
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

            with open(self.memory_file, 'w') as f:
                json.dump(data, f, indent=2)

            logger.debug(f"Memory saved to {self.memory_file}")

        except Exception as e:
            logger.error(f"Failed to save memory: {e}")

    def remember(self, knowledge: FuzzingKnowledge):
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
            logger.debug(f"Updated knowledge: {key}")
        else:
            # Store new knowledge
            self.knowledge[key] = knowledge
            logger.info(f"Learned new knowledge: {key}")

        self.save()

    def recall(self, knowledge_type: str, key: str) -> Optional[FuzzingKnowledge]:
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
                     min_confidence: float = 0.5) -> List[FuzzingKnowledge]:
        """
        Find all knowledge of a certain type with sufficient confidence.

        Args:
            knowledge_type: Type of knowledge to find
            min_confidence: Minimum confidence threshold

        Returns:
            List of matching knowledge entries
        """
        results = []
        for k in self.knowledge.values():
            if k.knowledge_type == knowledge_type and k.confidence >= min_confidence:
                results.append(k)

        # Sort by confidence (highest first)
        results.sort(key=lambda x: x.confidence, reverse=True)
        return results

    def record_strategy_success(self, strategy_name: str, binary_hash: str,
                                crashes_found: int, exploitable_crashes: int):
        """
        Record that a fuzzing strategy was successful.

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
        logger.info(f"Recorded strategy result: {strategy_name} - {crashes_found} crashes")

    def record_crash_pattern(self, signal: str, function: str,
                            binary_hash: str, exploitable: bool):
        """
        Record a crash pattern for learning.

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
                                binary_characteristics: Dict, success: bool):
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
        logger.info(f"Recorded exploit technique: {technique} - {'success' if success else 'failure'}")

    def get_best_strategy(self, binary_hash: str) -> Optional[str]:
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
        logger.info(f"Best strategy for binary: {best.value['name']} "
                   f"(confidence: {best.confidence:.2f}, success rate: {best.success_rate():.2f})")

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
                "SIGSEGV": 0.7,  # Memory corruption - often exploitable
                "SIGABRT": 0.5,  # Heap issues - sometimes exploitable
                "SIGILL": 0.4,   # Illegal instruction - less often exploitable
                "SIGFPE": 0.2,   # Arithmetic - rarely exploitable
            }
            return signal_probs.get(signal, 0.3)

        # Use historical data
        value = knowledge.value
        if value["total_count"] == 0:
            return 0.3

        exploitable_rate = value["exploitable_count"] / value["total_count"]

        # Combine with confidence
        return exploitable_rate * knowledge.confidence

    def record_campaign(self, campaign_data: Dict):
        """
        Record a complete fuzzing campaign for future reference.

        Args:
            campaign_data: Dictionary with campaign information
        """
        campaign_data["timestamp"] = time.time()
        campaign_data["date"] = datetime.now().isoformat()

        self.campaigns.append(campaign_data)
        self.save()

        logger.info(f"Recorded campaign: {campaign_data.get('binary_name', 'unknown')}")

    def get_statistics(self) -> Dict:
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

    def prune_low_confidence(self, threshold: float = 0.2):
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
            logger.info(f"Pruned {pruned} low-confidence knowledge entries")
            self.save()
