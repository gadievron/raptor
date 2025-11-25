"""
Code Coverage Skill

Use gcov to track which lines of code are executed during crash reproduction.
"""

from pathlib import Path

SKILL_DIR = Path(__file__).parent
LINE_CHECKER_CPP = SKILL_DIR / "line_checker.cpp"

__all__ = ['SKILL_DIR', 'LINE_CHECKER_CPP']
