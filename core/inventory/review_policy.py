"""Default review kinds shared by audit scheduling and coverage reporting.

Named layouts and aliases use ``class`` like existing C/C++ type items.
Their field/layout declarations can carry security invariants even though
no function body executes. Pure declarations and literal macros remain
excluded; callers may explicitly opt those kinds in.
"""

FUNCTION_KINDS = frozenset({"function", "method", ""})
DEFAULT_EXTRA_KINDS = frozenset({"top_level", "macro", "global", "class"})
DEFAULT_REVIEWABLE_KINDS = FUNCTION_KINDS | DEFAULT_EXTRA_KINDS
