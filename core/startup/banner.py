"""RAPTOR startup banner — formatting and display.

Pure presentation. Takes structured data from init.py, produces
the terminal banner. No logic, no checks, no side effects.
"""

import random

from . import REPO_ROOT


def read_logo() -> str:
    """Read the ASCII logo from the raptor-offset file."""
    path = REPO_ROOT / "raptor-offset"
    return path.read_text().rstrip() if path.exists() else ""


def read_random_quote() -> str:
    """Pick a random quote from the hackers-8ball file."""
    path = REPO_ROOT / "hackers-8ball"
    if path.exists():
        lines = [l.strip() for l in path.read_text().splitlines() if l.strip()]
        if lines:
            return random.choice(lines)
    return '"Hack the planet!"'


def format_banner(logo, quote, tool_results, tool_warnings, llm_lines,
                  llm_warnings, env_parts, env_warnings, project_line=None):
    """Format the startup banner from gathered data.

    Args:
        logo: ASCII art string.
        quote: Random quote string.
        tool_results: List of (name, found) tuples.
        tool_warnings: List of warning strings from tool checks.
        llm_lines: List of pre-formatted LLM status lines.
        llm_warnings: List of warning strings from LLM checks.
        env_parts: List of short env status strings.
        env_warnings: List of warning strings from env checks.
        project_line: One-line project status, or None.

    Returns:
        Formatted banner string.
    """
    lines = []

    if logo:
        lines.append(logo)
        lines.append("")

    # Tools
    tool_parts = [f"{name} {'✓' if ok else '✗'}" for name, ok in tool_results]
    lines.append(f" tools: {'  '.join(tool_parts)}")

    # Env
    lines.append(f"   env: {'  '.join(env_parts)}")

    # LLM
    lines.extend(llm_lines)

    lines.append("")

    # Warnings: unavailable first, then limited, then other
    all_raw = tool_warnings + env_warnings + llm_warnings
    ordered = (
        [w for w in all_raw if "unavailable" in w] +
        [w for w in all_raw if "limited" in w] +
        [w for w in all_raw if "unavailable" not in w and "limited" not in w]
    )
    if ordered:
        lines.append(f"  warn: {ordered[0]}")
        for w in ordered[1:]:
            lines.append(f"        {w}")
        lines.append("")

    # Active project
    if project_line:
        lines.append(f"   {project_line}")
        lines.append("")

    lines.append("  For defensive security research, education, and authorized penetration testing.")
    lines.append("")
    lines.append(f"raptor:~$ {quote}")

    return "\n".join(lines)
