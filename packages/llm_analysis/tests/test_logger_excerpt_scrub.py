"""LLM-authored free text logged during analysis (sanitizer details,
payload concepts, reasoning, attack scenarios) must be escaped and
bounded at the log site — the record args are what reach the
operator's console."""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from packages.llm_analysis.agent import (  # noqa: E402
    AutonomousSecurityAgentV2,
    VulnerabilityContext,
)

HOSTILE = "\x1b]0;pwned\x07\x9b2J‮evil"
RAW = ("\x1b", "\x07", "\x9b", "‮")


class _FakeLLM:
    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def generate_structured(self, **_kwargs):
        return dict(self._payload), "raw response"


def _vuln(repo: Path) -> VulnerabilityContext:
    (repo / "vuln.c").write_text(
        "void f(char *s){char b[8];strcpy(b,s);}\n"
    )
    finding = {
        "finding_id": "F1",
        "rule_id": "cpp/unbounded-write",
        "file": "vuln.c",
        "startLine": 1,
        "endLine": 1,
        "message": "strcpy into fixed buffer",
        "level": "error",
        "has_dataflow": True,
        "dataflow_path": {
            "source": {"file": "vuln.c", "line": 1, "label": "s"},
            "sink": {"file": "vuln.c", "line": 1, "label": "strcpy"},
            "steps": [],
            "total_steps": 2,
        },
    }
    vuln = VulnerabilityContext(finding, repo)
    # Populate the extracted-dataflow fields validate_dataflow gates on
    # (extraction itself is a separate concern).
    vuln.dataflow_source = {"file": "vuln.c", "line": 1, "column": 0,
                            "label": "s", "snippet": "", "code": ""}
    vuln.dataflow_sink = {"file": "vuln.c", "line": 1, "column": 0,
                          "label": "strcpy", "snippet": "", "code": ""}
    return vuln


def _messages(caplog) -> str:
    return "\n".join(r.getMessage() for r in caplog.records)


def test_validate_dataflow_sanitizer_details_scrubbed(tmp_path, caplog):
    validation = {
        "source_attacker_controlled": True,
        "sanitizers_effective": False,
        "path_reachable": True,
        "is_exploitable": True,
        "exploitability_confidence": 0.9,
        "attack_complexity": "low",
        "false_positive": False,
        "reasoning": "r",
        "sanitizer_details": [{
            "name": f"escape_html{HOSTILE}" + "x" * 4000,
            "purpose": f"purpose {HOSTILE}",
            "bypass_possible": True,
            "bypass_method": f"bypass {HOSTILE}",
        }],
        "attack_payload_concept": f"payload {HOSTILE}",
    }
    agent = SimpleNamespace(
        repo_path=tmp_path,
        out_dir=tmp_path / "out",
        llm=_FakeLLM(validation),
    )
    agent.out_dir.mkdir(exist_ok=True)
    bound = AutonomousSecurityAgentV2.validate_dataflow.__get__(
        agent, type(agent),
    )
    with caplog.at_level(logging.INFO):
        result = bound(_vuln(tmp_path))

    assert result  # validation dict came back
    joined = _messages(caplog)
    assert "Sanitizer Analysis" in joined
    for raw in RAW:
        assert raw not in joined
    # The unbounded name is length-capped at the log site.
    for record in caplog.records:
        assert len(record.getMessage()) < 2_000
