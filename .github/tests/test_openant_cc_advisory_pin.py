"""The openant pipeline's cc-trust call is advisory ONLY while openant
performs no Claude Code dispatch — this pin keeps that contract honest.

Why this test exists
--------------------
``raptor_openant.py`` calls ``check_repo_claude_trust`` and continues
regardless of the verdict. That is correct today: the openant pipeline
is API-transport only, so there is no CC dispatch for the verdict to
gate — the call exists to print the danger report (or the
cannot-examine refusal) for the operator, and the CC-dispatching
consumers of openant findings re-check at their own dispatch sites.

The hazard is drift: if openant grows a CC-dispatch path, the gate
would LOOK present at the top of the workflow while gating nothing.
This pin fails first, forcing whoever adds the dispatch to wire it to
the verdict.
"""

from __future__ import annotations

from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]

# Tokens that indicate a Claude Code dispatch path in this codebase.
_CC_DISPATCH_TOKENS = (
    "cc_adapter",
    "skill_dispatch",
    "agentic_passes",
    "claude_bin",
    "block_cc_dispatch",
)


def _openant_sources() -> list[Path]:
    out = [_REPO / "raptor_openant.py"]
    pkg = _REPO / "packages" / "openant"
    if pkg.is_dir():
        out.extend(sorted(pkg.rglob("*.py")))
    return out


def test_advisory_gate_still_present():
    text = (_REPO / "raptor_openant.py").read_text(encoding="utf-8")
    # Call-shaped, not a bare substring: a comment mentioning the name
    # (or a renamed/disabled call) must not satisfy the pin.
    assert "cc_blocked = check_repo_claude_trust(" in text, (
        "raptor_openant.py no longer calls the cc-trust gate (or the "
        "verdict is no longer captured) — the operator loses the "
        "danger report / cannot-examine refusal line"
    )


def test_openant_has_no_cc_dispatch_path():
    problems = []
    for path in _openant_sources():
        text = path.read_text(encoding="utf-8", errors="replace")
        for i, ln in enumerate(text.splitlines(), 1):
            for tok in _CC_DISPATCH_TOKENS:
                if tok in ln:
                    problems.append(
                        f"{path.relative_to(_REPO)}:{i}: {ln.strip()}")
    assert problems == [], (
        "openant grew a CC-dispatch-shaped dependency; its cc-trust "
        "call at raptor_openant.py is advisory-only on the premise "
        "that openant never dispatches Claude Code — gate the new "
        "dispatch on the verdict, then update this pin:\n"
        + "\n".join(problems)
    )
