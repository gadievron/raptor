"""Build-only purification (2026-05-26): the always-on agent prompt must carry
NO weaponized exploit literals and NO exploitation-verification teaching.

The engine's job is to gather config+versions and BUILD the environment; it
verifies the *environment* (right version present + benign functional smoke),
never the *vulnerability/exploit*. Weaponized payload literals in the prompt are
both off-mission and a strong refusal-classifier signal. This test locks the
prompt against their reintroduction. (Reframing functional probe guidance is
fine — e.g. "POST a search query and confirm results"; only exploitation
literals/markers are forbidden.)
"""

import pathlib

import cve_env
from cve_env.agent.prompts import SYSTEM_PROMPT

# verify.py is agent-facing: its docstrings (tool schema) AND its failure-hint
# return strings are surfaced to the model, so they must be literal-free too.
_VERIFY_PY = pathlib.Path(cve_env.__file__).resolve().parent / "tools" / "verify.py"

# Verbatim weaponized strings that must never appear in the agent-facing prompt.
_FORBIDDEN_LITERALS = (
    "getRuntime().exec",  # OGNL/Java RCE
    "${jndi:",  # Log4Shell JNDI injection
    "root:x:0:0:",  # /etc/passwd LFI marker
    "/etc/passwd",  # LFI target
    "/etc/shadow",  # privesc target
    "${script:",  # script-engine injection
    "class.module.classLoader",  # Spring4Shell gadget chain
)


def test_system_prompt_has_no_weaponized_exploit_literals() -> None:
    found = [lit for lit in _FORBIDDEN_LITERALS if lit in SYSTEM_PROMPT]
    assert not found, (
        "SYSTEM_PROMPT contains weaponized exploit literal(s) "
        f"{found} — build-only purification forbids these (reframe to a benign "
        "functional probe instead)."
    )


def test_verify_tool_has_no_weaponized_exploit_literals() -> None:
    """verify.py docstrings + failure hints are surfaced to the agent too."""
    src = _VERIFY_PY.read_text()
    found = [lit for lit in _FORBIDDEN_LITERALS if lit in src]
    assert not found, (
        f"verify.py (agent-facing tool) contains weaponized exploit literal(s) {found} "
        "— reframe its docstrings/hints to benign functional language."
    )
