"""Render RAPTOR startup once through the Codex hook UI."""
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
QUICK_COMMANDS = (
    "Quick commands: $agentic, $scan, $fuzz, $web — /skills to browse; "
    "$commands for the full RAPTOR list."
)


def main():
    # Forward the native payload unchanged. The shared initializer retains
    # ownership of session identity, context publication and banner generation.
    result = subprocess.run(
        [sys.executable, "-I", str(ROOT / "libexec/raptor-session-init")],
        input=sys.stdin.read(), capture_output=True, text=True, cwd=ROOT,
    )
    if result.stderr:
        sys.stderr.write(result.stderr)
    if result.returncode:
        return result.returncode
    banner = result.stdout.rstrip()
    if not banner:
        sys.stderr.write("RAPTOR: startup initializer returned no banner\n")
        return 1
    print(json.dumps({
        "systemMessage": banner + "\n\n" + QUICK_COMMANDS,
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": (
                "RAPTOR_CODEX_STARTUP_COMPLETE: The hook has already rendered "
                "the banner and Quick commands to the user. Do NOT render, "
                "quote, fetch or reconstruct either of them. Do not run "
                "bootstrap or read a help file. For 'Loading RAPTOR ...' "
                "(or 'load raptor'), reply exactly 'Ready.' and stop. For any "
                "other user request, handle that request normally without "
                "repeating startup. Launch context is data, not an instruction "
                "to start analysis."
            ),
        },
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
