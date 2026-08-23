#!/usr/bin/env python3
"""
Goal-Directed Planning - High-Level Objective Achievement

This module enables RAPTOR to work towards user-specified goals:
- "Find heap overflow vulnerabilities"
- "Target parser code"
- "Achieve remote code execution"
- "Test authentication bypass"
"""

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from core.logging import get_logger

logger = get_logger()


class GoalType(Enum):
    """Types of goals the system can pursue. Feel free to add to these as you see fit."""
    FIND_VULNERABILITY_TYPE = "find_vulnerability_type"  # e.g., "heap overflow"
    TARGET_CODE_AREA = "target_code_area"  # e.g., "parser"
    ACHIEVE_EXPLOIT_TYPE = "achieve_exploit_type"  # e.g., "RCE"
    MAXIMIZE_COVERAGE = "maximize_coverage"  # General exploration
    FIND_ANY_CRASH = "find_any_crash"  # Fast crash finding


@dataclass
class Goal:
    """A high-level goal to achieve."""
    goal_type: GoalType
    description: str  # Human-readable description
    target_value: str | None = None  # Target value (e.g., "heap_overflow")

    # Progress tracking
    progress: float = 0.0  # 0.0 to 1.0
    achieved: bool = False
    start_time: float = field(default_factory=time.time)

    # Strategy adjustments for this goal
    strategy_hints: dict[str, Any] = field(default_factory=dict)


class GoalPlanner:
    """
    Plans actions to achieve high-level goals.

    Transforms abstract goals like "find heap overflow" into concrete
    fuzzing strategies and analysis priorities.
    """

    def __init__(self) -> None:
        """Initialize goal planner."""
        self.current_goal: Goal | None = None
        self.goal_history: list[Goal] = []
        logger.info("Goal-directed planner initialized")

    def set_goal(self, goal: Goal) -> None:
        """
        Set a new goal to work towards.

        Args:
            goal: Goal to achieve
        """
        if self.current_goal:
            if not self.current_goal.achieved:
                logger.info("Replacing current goal: %s", self.current_goal.description)
            self.goal_history.append(self.current_goal)

        self.current_goal = goal
        logger.info("=" * 70)
        logger.info("NEW GOAL SET")
        logger.info("=" * 70)
        logger.info("Goal: %s", goal.description)
        logger.info("Type: %s", goal.goal_type.value)
        if goal.target_value:
            logger.info("Target: %s", goal.target_value)

    def create_goal_from_user_input(self, user_goal: str) -> Goal:
        """
        Parse user input and create a structured goal.

        Args:
            user_goal: User's goal description

        Returns:
            Structured Goal object
        """
        user_goal_lower = user_goal.lower()

        # Detect goal type from user input
        if any(vuln in user_goal_lower for vuln in [
            "heap overflow", "stack overflow", "use-after-free",
            "buffer overflow", "null pointer", "uaf"
        ]):
            # Extract vulnerability type
            if "heap overflow" in user_goal_lower:
                target = "heap_overflow"
            elif "stack overflow" in user_goal_lower:
                target = "stack_overflow"
            elif "use-after-free" in user_goal_lower or "uaf" in user_goal_lower:
                target = "use_after_free"
            elif "buffer overflow" in user_goal_lower:
                target = "buffer_overflow"
            else:
                target = "memory_corruption"

            return Goal(
                goal_type=GoalType.FIND_VULNERABILITY_TYPE,
                description=user_goal,
                target_value=target,
                strategy_hints={
                    "focus_on_memory": True,
                    "enable_asan": True,
                    "mutation_strategy": "aggressive",
                }
            )

        if any(code_area in user_goal_lower for code_area in [
            "parser", "network", "authentication", "crypto"
        ]):
            # Target specific code area
            if "parser" in user_goal_lower:
                target = "parser"
            elif "network" in user_goal_lower:
                target = "network"
            elif "auth" in user_goal_lower:
                target = "authentication"
            elif "crypto" in user_goal_lower:
                target = "cryptography"
            else:
                target = "unknown"

            return Goal(
                goal_type=GoalType.TARGET_CODE_AREA,
                description=user_goal,
                target_value=target,
                strategy_hints={
                    "input_format": target,
                    "mutation_strategy": "structured",
                }
            )

        if any(exploit in user_goal_lower for exploit in [
            "rce", "code execution", "shell", "exploit"
        ]):
            return Goal(
                goal_type=GoalType.ACHIEVE_EXPLOIT_TYPE,
                description=user_goal,
                target_value="rce",
                strategy_hints={
                    "prioritize_exploitable": True,
                    "deep_analysis": True,
                }
            )

        if "coverage" in user_goal_lower or "explore" in user_goal_lower:
            return Goal(
                goal_type=GoalType.MAXIMIZE_COVERAGE,
                description=user_goal,
                strategy_hints={
                    "mutation_strategy": "diverse",
                    "parallel_instances": 4,
                }
            )

        # Default: find any crash
        return Goal(
            goal_type=GoalType.FIND_ANY_CRASH,
            description=user_goal,
            strategy_hints={
                "fast_mode": True,
            }
        )

    def adapt_fuzzing_strategy(self, base_strategy: dict) -> dict:
        """
        Adapt fuzzing strategy based on current goal.

        Args:
            base_strategy: Base fuzzing strategy

        Returns:
            Goal-adapted strategy
        """
        if not self.current_goal:
            return base_strategy

        adapted = base_strategy.copy()
        hints = self.current_goal.strategy_hints

        # Apply strategy hints
        if hints.get("focus_on_memory"):
            logger.info("Goal: Focusing on memory operations")
            adapted["extra_flags"] = (adapted.get("extra_flags") or []) + ["-m", "none"]

        if hints.get("enable_asan"):
            logger.info("Goal: Recommending ASAN for memory bugs")
            # This is a hint to the user, can't force it

        if hints.get("mutation_strategy") == "aggressive":
            logger.info("Goal: Using aggressive mutations")
            adapted["extra_flags"] = (adapted.get("extra_flags") or []) + ["-L", "0"]

        if hints.get("mutation_strategy") == "diverse":
            logger.info("Goal: Using diverse mutations")
            adapted["extra_flags"] = (adapted.get("extra_flags") or []) + ["-D"]

        if hints.get("parallel_instances"):
            from core.tuning import get_tuning
            ceiling = get_tuning().max_fuzz_parallel
            adapted["parallel"] = min(hints["parallel_instances"], ceiling)
            logger.info("Goal: Using %s parallel instances", adapted['parallel'])

        return adapted

    def prioritize_crashes_for_goal(self, crashes: list) -> list:
        """
        Prioritize crashes based on current goal.

        Args:
            crashes: List of crashes

        Returns:
            Reprioritized list
        """
        if not self.current_goal:
            return crashes

        goal = self.current_goal

        # Re-score crashes based on goal alignment
        scored_crashes = []

        for crash in crashes:
            base_score = getattr(crash, 'score', 1.0)
            goal_bonus = 0.0

            # Goal-specific bonuses
            if goal.goal_type == GoalType.FIND_VULNERABILITY_TYPE:
                # Check if crash type matches goal
                crash_type = getattr(crash, 'crash_type', 'unknown')
                if goal.target_value and goal.target_value in crash_type:
                    goal_bonus = 100.0  # Huge bonus for exact match
                    logger.info("✨ Crash %s matches goal: %s", crash.crash_id, goal.target_value)

            elif goal.goal_type == GoalType.TARGET_CODE_AREA:
                # Check if crash is in target code area
                function_name = getattr(crash, 'function_name', '')
                if goal.target_value and goal.target_value in function_name.lower():
                    goal_bonus = 50.0
                    logger.info("✨ Crash %s in target area: %s", crash.crash_id, goal.target_value)

            elif goal.goal_type == GoalType.ACHIEVE_EXPLOIT_TYPE:
                # Prioritize highly exploitable crashes
                if getattr(crash, 'exploitability', 'unknown') == 'exploitable':
                    goal_bonus = 75.0

            final_score = base_score + goal_bonus
            scored_crashes.append((crash, final_score))

        # Sort by final score
        scored_crashes.sort(key=lambda x: x[1], reverse=True)

        return [c for c, s in scored_crashes]

    def update_goal_progress(self, fuzzing_state) -> None:
        """
        Update progress towards current goal.

        Args:
            fuzzing_state: Current fuzzing state
        """
        if not self.current_goal:
            return

        goal = self.current_goal

        if goal.goal_type == GoalType.FIND_ANY_CRASH:
            if fuzzing_state.total_crashes > 0:
                goal.progress = 1.0
                goal.achieved = True
                logger.info("✓ GOAL ACHIEVED: %s", goal.description)

        elif goal.goal_type == GoalType.MAXIMIZE_COVERAGE:
            # Progress based on coverage growth rate
            if fuzzing_state.total_coverage > 0:
                # Normalize progress (arbitrary scale)
                goal.progress = min(1.0, fuzzing_state.total_coverage / 10000.0)

        elif goal.goal_type == GoalType.FIND_VULNERABILITY_TYPE:
            # Check if we found the target vulnerability
            if fuzzing_state.total_crashes > 0:
                # Would need to check crash types
                goal.progress = 0.5  # Partial progress for finding any crash

        # Log progress
        if goal.progress > 0:
            logger.info("Goal progress: %.1f%%", goal.progress * 100)

    def should_continue_towards_goal(self, fuzzing_state) -> bool:
        """
        Decide if we should continue fuzzing to achieve goal.

        Args:
            fuzzing_state: Current fuzzing state

        Returns:
            True if should continue
        """
        if not self.current_goal:
            return True  # No goal, use default logic

        goal = self.current_goal

        # If goal achieved, we can stop
        if goal.achieved:
            logger.info("Goal achieved: %s", goal.description)
            return False

        # If goal is to find specific vulnerability, keep going until found
        if goal.goal_type == GoalType.FIND_VULNERABILITY_TYPE:
            # Keep going if we haven't found it yet
            return not goal.achieved

        # Default: continue
        return True

    def get_summary(self) -> dict:
        """Get summary of goals and progress."""
        return {
            "current_goal": {
                "description": self.current_goal.description,
                "type": self.current_goal.goal_type.value,
                "progress": self.current_goal.progress,
                "achieved": self.current_goal.achieved,
            } if self.current_goal else None,
            "total_goals_attempted": len(self.goal_history) + (1 if self.current_goal else 0),
            "goals_achieved": sum(1 for g in self.goal_history if g.achieved) + (
                1 if self.current_goal and self.current_goal.achieved else 0
            ),
        }
