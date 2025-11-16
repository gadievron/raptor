#!/usr/bin/env python3
"""
Fuzzing Planner - Autonomous Decision Making

This module transforms RAPTOR from a fixed pipeline into an intelligent agent
that makes decisions based on fuzzing state and learned knowledge.
"""

import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional

from core.logging import get_logger

logger = get_logger()


class Action(Enum):
    """Actions the fuzzer can take autonomously."""

    # Fuzzing strategy actions
    CONTINUE_FUZZING = "continue_fuzzing"
    STOP_FUZZING = "stop_fuzzing"
    INCREASE_DURATION = "increase_duration"
    CHANGE_MUTATOR = "change_mutator"
    ADD_DICTIONARY = "add_dictionary"
    INTENSIFY_CORPUS = "intensify_corpus"

    # Analysis actions
    DEEP_ANALYSE_CRASH = "deep_analyse_crash"
    SKIP_DUPLICATE_CRASH = "skip_duplicate_crash"
    PRIORITISE_CRASH = "prioritise_crash"

    # Exploit development actions
    VALIDATE_EXPLOIT = "validate_exploit"
    REFINE_EXPLOIT = "refine_exploit"
    TRY_ALTERNATIVE_TECHNIQUE = "try_alternative_technique"

    # Learning actions
    SAVE_STRATEGY = "save_strategy"
    LOAD_STRATEGY = "load_strategy"

    # Goal-directed actions
    FOCUS_ON_PARSER = "focus_on_parser"
    FOCUS_ON_NETWORK = "focus_on_network"
    SEARCH_FOR_RCE = "search_for_rce"


@dataclass
class FuzzingState:
    """Complete state of the fuzzing campaign for decision-making."""

    # Fuzzing metrics
    start_time: float
    current_time: float
    total_execs: int = 0
    execs_per_sec: float = 0.0

    # Coverage metrics
    total_coverage: int = 0
    last_coverage_increase: float = 0.0
    coverage_plateau_duration: float = 0.0

    # Crash metrics
    total_crashes: int = 0
    unique_crashes: int = 0
    crashes_last_minute: int = 0
    exploitable_crashes: int = 0

    # Strategy metrics
    current_strategy: str = "default"
    strategies_tried: List[str] = field(default_factory=list)
    successful_strategies: Dict[str, int] = field(default_factory=dict)

    # Goal state
    target_goal: Optional[str] = None
    goal_progress: float = 0.0

    # Binary characteristics
    binary_path: Path = None
    has_asan: bool = False
    has_afl_instrumentation: bool = False

    def elapsed_time(self) -> float:
        """Calculate elapsed time in seconds."""
        return self.current_time - self.start_time

    def is_coverage_stalled(self, threshold_seconds: float = 300) -> bool:
        """Check if coverage hasn't increased in threshold time."""
        return self.coverage_plateau_duration > threshold_seconds

    def is_finding_crashes(self) -> bool:
        """Check if we're actively finding crashes."""
        return self.crashes_last_minute > 0


class FuzzingPlanner:
    """
    Autonomous planner that makes intelligent decisions about fuzzing strategy.

    Instead of following a fixed pipeline, the planner:
    1. Observes the current fuzzing state
    2. Reasons about what's working and what's not
    3. Decides on the next action autonomously
    4. Learns from successes and failures
    """

    def __init__(self, memory=None):
        """
        Initialise the fuzzing planner.

        Args:
            memory: FuzzingMemory instance for learning (optional)
        """
        self.memory = memory
        self.decision_history = []
        logger.info("Autonomous Fuzzing Planner initialised")

    def decide_next_action(self, state: FuzzingState) -> Action:
        """
        Make an autonomous decision about what to do next.

        This is the core of the autonomous system. Instead of a fixed pipeline,
        we reason about the current state and make intelligent decisions.

        Args:
            state: Current fuzzing state

        Returns:
            Action to take next
        """
        logger.info("=" * 70)
        logger.info("AUTONOMOUS DECISION MAKING")
        logger.info("=" * 70)
        logger.info(f"Elapsed time: {state.elapsed_time():.1f}s")
        logger.info(f"Total crashes: {state.total_crashes}")
        logger.info(f"Unique crashes: {state.unique_crashes}")
        logger.info(f"Coverage: {state.total_coverage}")
        logger.info(f"Execs/sec: {state.execs_per_sec:.1f}")

        # Decision tree - prioritise by urgency and impact
        action = None
        reasoning = ""

        # 1. Check if we've found interesting crashes recently
        if state.crashes_last_minute > 0:
            action = Action.CONTINUE_FUZZING
            reasoning = f"Found {state.crashes_last_minute} crashes in last minute - keep going"

        # 2. Check if coverage is stalled
        elif state.is_coverage_stalled(threshold_seconds=180):
            action = Action.CHANGE_MUTATOR
            reasoning = f"Coverage stalled for {state.coverage_plateau_duration:.0f}s - try different mutator"

        # 3. Check if we're making progress
        elif state.total_coverage > 0 and state.execs_per_sec > 10:
            action = Action.CONTINUE_FUZZING
            reasoning = "Making steady progress with good throughput"

        # 4. Check if we should stop (no progress, long time)
        elif state.elapsed_time() > 3600 and state.total_crashes == 0:
            action = Action.STOP_FUZZING
            reasoning = "Over 1 hour with no crashes - likely not vulnerable"

        # 5. Default: keep fuzzing
        else:
            action = Action.CONTINUE_FUZZING
            reasoning = "Default strategy: continue fuzzing"

        # Log the decision
        logger.info(f"Decision: {action.value}")
        logger.info(f"Reasoning: {reasoning}")

        # Record decision in history
        self.decision_history.append({
            "time": state.current_time,
            "action": action,
            "reasoning": reasoning,
            "state_snapshot": {
                "crashes": state.total_crashes,
                "coverage": state.total_coverage,
                "execs_per_sec": state.execs_per_sec,
            }
        })

        return action

    def should_continue_fuzzing(self, state: FuzzingState,
                                target_duration: Optional[float] = None) -> bool:
        """
        Decide if fuzzing should continue or stop.

        This replaces the fixed duration timer with intelligent decision-making.

        Args:
            state: Current fuzzing state
            target_duration: Target duration in seconds (can be overridden)

        Returns:
            True if fuzzing should continue
        """
        action = self.decide_next_action(state)

        if action == Action.STOP_FUZZING:
            logger.info("Autonomous decision: STOP fuzzing")
            return False

        if action == Action.INCREASE_DURATION:
            logger.info("Autonomous decision: EXTEND fuzzing beyond target duration")
            return True

        # Check if we've exceeded target duration (if set)
        if target_duration and state.elapsed_time() >= target_duration:
            # But if we're finding crashes, keep going!
            if state.crashes_last_minute > 0:
                logger.info(f"Target duration reached, but found {state.crashes_last_minute} crashes recently")
                logger.info("Autonomous decision: CONTINUE fuzzing (overriding duration)")
                return True
            else:
                logger.info("Target duration reached and no recent crashes")
                return False

        return True

    def recommend_crash_priority(self, crashes: List, state: FuzzingState) -> List:
        """
        Intelligently prioritise which crashes to analyse first.

        Instead of simple signal-based ranking, consider:
        - Which crashes are most likely exploitable
        - Which crashes give us new information
        - Which crashes match our goals

        Args:
            crashes: List of crashes to prioritise
            state: Current fuzzing state

        Returns:
            Prioritised list of crashes
        """
        logger.info("Autonomously prioritising crashes for analysis...")

        # Score each crash based on multiple factors
        crash_scores = []

        for crash in crashes:
            score = 0.0
            factors = []

            # Factor 1: Signal priority (baseline)
            signal_scores = {
                "11": 10.0,  # SIGSEGV - memory corruption
                "06": 8.0,   # SIGABRT - heap issues
                "04": 6.0,   # SIGILL - code execution
                "08": 4.0,   # SIGFPE - arithmetic
            }
            signal_score = signal_scores.get(crash.signal, 2.0)
            score += signal_score
            factors.append(f"signal:{signal_score:.1f}")

            # Factor 2: Input size (smaller = easier to exploit)
            if crash.size < 100:
                score += 5.0
                factors.append("small_input:5.0")
            elif crash.size < 1000:
                score += 2.0
                factors.append("medium_input:2.0")

            # Factor 3: Goal alignment (if we have a target)
            if state.target_goal:
                if "parser" in state.target_goal.lower() and "parse" in str(crash.input_file):
                    score += 10.0
                    factors.append("goal_match:10.0")

            # Store score
            crash_scores.append((crash, score, factors))

        # Sort by score (highest first)
        crash_scores.sort(key=lambda x: x[1], reverse=True)

        # Log prioritisation
        logger.info(f"Crash prioritisation (top 5):")
        for i, (crash, score, factors) in enumerate(crash_scores[:5], 1):
            logger.info(f"  {i}. {crash.crash_id} - Score: {score:.1f} - Factors: {', '.join(factors)}")

        # Return prioritised list
        return [c for c, s, f in crash_scores]

    def select_fuzzing_strategy(self, state: FuzzingState) -> Dict[str, any]:
        """
        Select optimal fuzzing strategy based on current state.

        Instead of always using the same AFL configuration, adapt based on:
        - What's working
        - What we've learned
        - The current goal

        Args:
            state: Current fuzzing state

        Returns:
            Dictionary of AFL parameters to use
        """
        strategy = {
            "name": "adaptive",
            "timeout": 1000,
            "parallel": 1,
            "extra_flags": [],
        }

        # If coverage is stalled, try more aggressive mutations
        if state.is_coverage_stalled():
            logger.info("Coverage stalled - using aggressive mutation strategy")
            strategy["name"] = "aggressive"
            strategy["extra_flags"].append("-L")  # MOpt mode
            strategy["extra_flags"].append("-0")  # Zero stack

        # If we have ASAN, reduce timeout (crashes faster)
        if state.has_asan:
            logger.info("ASAN detected - reducing timeout")
            strategy["timeout"] = 500

        # If no AFL instrumentation, use more parallel instances
        if not state.has_afl_instrumentation:
            logger.info("No AFL instrumentation - increasing parallelisation")
            strategy["parallel"] = min(4, strategy["parallel"] * 2)

        # Learn from history
        if self.memory and state.current_strategy in state.successful_strategies:
            success_count = state.successful_strategies[state.current_strategy]
            logger.info(f"Current strategy has {success_count} past successes - continuing")

        logger.info(f"Selected strategy: {strategy['name']}")
        return strategy

    def get_decision_summary(self) -> Dict:
        """Get summary of all decisions made."""
        return {
            "total_decisions": len(self.decision_history),
            "decisions": self.decision_history,
        }
