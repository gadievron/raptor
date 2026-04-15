"""
RAPTOR Autonomous Fuzzing System

Transforms RAPTOR from automation to true autonomy through:
- Intelligent decision-making and planning
- Learning from past successes and failures
- Multi-turn reasoning with LLMs
- Goal-directed behaviour
- Adaptive strategies based on feedback
"""

from .planner import FuzzingPlanner, FuzzingState, Action
from .memory import FuzzingMemory, FuzzingKnowledge
from .unified_memory import UnifiedMemory, SecretScanPolicy
from .memory_exports import export_memory_views
from .dialogue import MultiTurnAnalyser
from .exploit_validator import ExploitValidator, ValidationResult
from .goal_planner import GoalPlanner, Goal, GoalType
from .corpus_generator import CorpusGenerator

__all__ = [
    "FuzzingPlanner",
    "FuzzingState",
    "Action",
    "FuzzingMemory",
    "FuzzingKnowledge",
    "UnifiedMemory",
    "SecretScanPolicy",
    "export_memory_views",
    "MultiTurnAnalyser",
    "ExploitValidator",
    "ValidationResult",
    "GoalPlanner",
    "Goal",
    "GoalType",
    "CorpusGenerator",
]
