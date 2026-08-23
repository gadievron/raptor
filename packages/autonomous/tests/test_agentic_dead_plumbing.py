"""Guards against re-introducing dead plumbing in raptor_agentic.py.

Two chains were removed after the dead-code sweep confirmed neither
end existed:

- ``--sage-precall`` forwarding: raptor_agentic conditionally appended
  the flag to the analysis child's argv, but nothing ever wrote
  ``sage_precall_scan.json`` and ``packages/llm_analysis/agent.py``
  never accepted the flag — the child would have died on an unknown
  argument if the file had ever appeared.
- ``--skip-mitigation-checks``: parsed since introduction, never read
  anywhere; there is no per-vulnerability mitigation-check call site
  in the exploit-generation path to wire it to.

These are source-level guards (the argv assembly happens deep inside
``main()`` behind subprocess spawns, so a functional probe would not
be hermetic).
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
AGENTIC = REPO_ROOT / "raptor_agentic.py"


def _source() -> str:
    return AGENTIC.read_text(encoding="utf-8")


class TestDeadPlumbingStaysRemoved:
    def test_no_sage_precall_forwarding(self):
        src = _source()
        assert "--sage-precall" not in src, (
            "raptor_agentic.py forwards --sage-precall again; the "
            "analysis child does not accept it and no producer writes "
            "sage_precall_scan.json — wire both ends or keep it out"
        )

    def test_no_skip_mitigation_checks_flag(self):
        src = _source()
        assert "--skip-mitigation-checks" not in src, (
            "raptor_agentic.py parses --skip-mitigation-checks again; "
            "nothing consumes it — wire it to a mitigation-check call "
            "site or keep it out"
        )
