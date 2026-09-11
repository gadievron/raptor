"""Crash-agent artifact + prompt-bundle robustness.

* Prompt bundles read the crash input BOUNDED (only the bytes the
  prompt keeps) and degrade a missing/unreadable input file into a
  graceful ``crash-input-read-error`` block — an unguarded read or
  ``stat()`` would abort analysis of every remaining crash in the
  per-crash loop.
* ``exploit_artifact_path`` is the single source of truth for the
  exploit PoC filename, and the writer uses it — consumers deriving
  the path from the raw crash id (AFL ids contain ``:`` and ``,``)
  read a name that was never written.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from packages.binary_analysis.crash_analyser import CrashContext  # noqa: E402
from packages.llm_analysis.cc_dispatch import _safe_id  # noqa: E402
from packages.llm_analysis.crash_agent import (  # noqa: E402
    CrashAnalysisAgent,
    _build_crash_analysis_bundle,
    _build_crash_exploit_bundle,
    exploit_artifact_path,
)

AFL_ID = "id:000000,sig:11,src:000001,op:havoc,rep:2"


def _ctx(input_file: Path, crash_id: str = AFL_ID) -> CrashContext:
    return CrashContext(
        crash_id=crash_id,
        binary_path=Path("/bin/true"),
        input_file=input_file,
        signal="11",
        crash_type="stack_overflow",
        exploitability="exploitable",
    )


def _bundle_text(bundle) -> str:
    return "\n".join(m.content for m in bundle.messages)


class TestAnalysisBundleInputHandling:

    def test_missing_input_file_degrades_to_error_block(self, tmp_path):
        ctx = _ctx(tmp_path / "gone" / "crash-input")
        bundle = _build_crash_analysis_bundle(
            ctx, lambda s: str(s), lambda r: "regs",
        )
        text = _bundle_text(bundle)
        assert "Error reading input file" in text
        assert "unknown" in text  # input_size slot degraded, not raised

    def test_large_input_only_first_512_bytes_rendered(self, tmp_path):
        f = tmp_path / "crash-input"
        f.write_bytes(b"A" * 512 + b"MARKER-BEYOND-CAP" + b"B" * 4096)
        ctx = _ctx(f)
        bundle = _build_crash_analysis_bundle(
            ctx, lambda s: str(s), lambda r: "regs",
        )
        text = _bundle_text(bundle)
        assert "MARKER-BEYOND-CAP" not in text
        # hex dump of the capped prefix is present ('A' == 0x41;
        # bytes.hex(' ', 16) groups 16 bytes between separators)
        assert "41414141" in text


class TestExploitBundleInputHandling:

    def test_missing_input_file_does_not_raise(self, tmp_path):
        ctx = _ctx(tmp_path / "gone" / "crash-input")
        bundle = _build_crash_exploit_bundle(ctx)
        text = _bundle_text(bundle)
        assert "Error reading input file" in text
        assert "unknown" in text

    def test_present_input_file_size_rendered(self, tmp_path):
        f = tmp_path / "crash-input"
        f.write_bytes(b"XYZ")
        bundle = _build_crash_exploit_bundle(_ctx(f))
        assert "3" in _bundle_text(bundle)


class TestExploitArtifactPath:

    def test_sanitises_afl_id_and_uses_cpp_extension(self, tmp_path):
        p = exploit_artifact_path(tmp_path, AFL_ID)
        assert p.parent == tmp_path / "exploits"
        assert p.name == f"{_safe_id(AFL_ID)}_exploit.cpp"
        assert ":" not in p.name

    def test_writer_uses_canonical_path(self, tmp_path, monkeypatch):
        f = tmp_path / "crash-input"
        f.write_bytes(b"AAAA")
        ctx = _ctx(f)

        class _FakeLLM:
            def generate_structured(self, **kwargs):
                return (
                    {"code": "int main(){return 0;}", "reasoning": "r"},
                    "raw response",
                )

        agent = SimpleNamespace(
            out_dir=tmp_path / "out",
            llm=_FakeLLM(),
            llm_config=None,
            verify_exploits=False,
            judge_intent=False,
            record_witnesses=False,
            execute_exploits=False,
        )
        agent.generate_exploit = CrashAnalysisAgent.generate_exploit.__get__(
            agent, type(agent),
        )

        assert agent.generate_exploit(ctx) is True
        expected = exploit_artifact_path(agent.out_dir, ctx.crash_id)
        assert expected.exists()
        assert expected.read_text() == "int main(){return 0;}"
