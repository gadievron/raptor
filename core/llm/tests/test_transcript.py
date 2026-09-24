"""Unit tests for the LLM transcript record/replay seam.

Covers the module contracts in isolation (recorder redaction +
atomic-append trail shape, replayer matching layers and loud misses,
the env switch, and the client subclass's record/replay dispatch
behaviour with a stub provider — no live LLM anywhere). The
end-to-end /analyze acceptance test lives in
``packages/llm_analysis/tests/test_transcript_replay_e2e.py``.
"""

from __future__ import annotations

import json

import pytest

from core.json.jsonl import load_jsonl
from core.llm.client import LLMClient
from core.llm.config import LLMConfig, ModelConfig
from core.llm.providers import LLMResponse
from core.llm.transcript import (
    TranscriptError,
    TranscriptLLMClient,
    TranscriptRecorder,
    TranscriptReplayer,
    TranscriptReplayMiss,
    TranscriptReplayedError,
    active_transcript,
    build_llm_client,
    reset_active_transcript,
    transcript_replay_active,
    transcript_subject,
)

_SCHEMA = {
    "type": "object",
    "properties": {
        "is_exploitable": {"type": "boolean"},
        "reasoning": {"type": "string"},
    },
}


@pytest.fixture(autouse=True)
def _fresh_session(monkeypatch):
    """Every test starts with no ambient transcript session."""
    monkeypatch.delenv("RAPTOR_LLM_TRANSCRIPT", raising=False)
    reset_active_transcript()
    yield
    reset_active_transcript()


def _record_entry(
    recorder: TranscriptRecorder,
    prompt: str = "analyse this",
    *,
    content: str = "verdict text",
    task_type: str = "analyse",
) -> None:
    recorder.record_generate(
        prompt, "sys", task_type, {},
        LLMResponse(
            content=content, model="m1", provider="anthropic",
            tokens_used=10, cost=0.001, finish_reason="stop",
        ),
    )


# ---------------------------------------------------------------------------
# Env switch
# ---------------------------------------------------------------------------

class TestEnvSwitch:
    def test_unset_means_no_session(self):
        assert active_transcript() is None
        assert transcript_replay_active() is False

    def test_record_mode_resolves(self, tmp_path, monkeypatch):
        path = tmp_path / "t.jsonl"
        monkeypatch.setenv("RAPTOR_LLM_TRANSCRIPT", f"record:{path}")
        reset_active_transcript()
        session = active_transcript()
        assert session is not None and session.mode == "record"
        assert transcript_replay_active() is False

    def test_replay_mode_resolves(self, tmp_path, monkeypatch):
        path = tmp_path / "t.jsonl"
        TranscriptRecorder(path)  # ensure parent handling
        _record_entry(TranscriptRecorder(path))
        monkeypatch.setenv("RAPTOR_LLM_TRANSCRIPT", f"replay:{path}")
        reset_active_transcript()
        session = active_transcript()
        assert session is not None and session.mode == "replay"
        assert transcript_replay_active() is True

    @pytest.mark.parametrize("garbled", [
        "record", "replay:", "append:/tmp/x", "record;/tmp/x", ":",
    ])
    def test_garbled_value_raises(self, garbled, monkeypatch):
        monkeypatch.setenv("RAPTOR_LLM_TRANSCRIPT", garbled)
        reset_active_transcript()
        with pytest.raises(TranscriptError):
            active_transcript()

    def test_directory_path_gets_default_filename(self, tmp_path):
        recorder = TranscriptRecorder(tmp_path)
        assert recorder.path == tmp_path / "llm-transcript.jsonl"

    def test_replay_missing_file_refuses(self, tmp_path):
        with pytest.raises(TranscriptError, match="does not exist"):
            TranscriptReplayer(tmp_path / "absent.jsonl")


# ---------------------------------------------------------------------------
# Recorder
# ---------------------------------------------------------------------------

class TestRecorder:
    def test_writes_one_json_line_per_call(self, tmp_path):
        recorder = TranscriptRecorder(tmp_path / "t.jsonl")
        _record_entry(recorder, "p1")
        _record_entry(recorder, "p2")
        entries = load_jsonl(recorder.path)
        assert [e["seq"] for e in entries] == [0, 1]
        assert all(e["method"] == "generate" for e in entries)
        assert entries[0]["prompt_sha256"] != entries[1]["prompt_sha256"]

    def test_subject_tag_recorded(self, tmp_path):
        recorder = TranscriptRecorder(tmp_path / "t.jsonl")
        with transcript_subject("finding-42"):
            _record_entry(recorder)
        _record_entry(recorder)
        entries = load_jsonl(recorder.path)
        assert entries[0]["subject"] == "finding-42"
        assert entries[1]["subject"] is None

    def test_response_content_is_redacted_at_write(self, tmp_path):
        recorder = TranscriptRecorder(tmp_path / "t.jsonl")
        secret = "AKIA" + "A" * 16
        _record_entry(recorder, content=f"key is {secret}")
        text = recorder.path.read_text()
        assert secret not in text
        assert "[REDACTED]" in text

    def test_structured_result_tree_is_redacted(self, tmp_path):
        recorder = TranscriptRecorder(tmp_path / "t.jsonl")
        secret = "AKIA" + "B" * 16
        from core.llm.providers import StructuredResponse
        recorder.record_generate_structured(
            "p", _SCHEMA, None, "analyse", {},
            StructuredResponse(
                result={"reasoning": f"uses {secret}", "nested": [secret]},
                raw=secret,
            ),
        )
        text = recorder.path.read_text()
        assert secret not in text

    def test_prompt_stored_as_hash_plus_bounded_excerpt(self, tmp_path):
        recorder = TranscriptRecorder(tmp_path / "t.jsonl")
        long_prompt = "x" * 5000 + "\x1b]0;evil\x07"
        _record_entry(recorder, long_prompt)
        (entry,) = load_jsonl(recorder.path)
        assert long_prompt not in json.dumps(entry)
        assert len(entry["prompt_excerpt"]) < 300
        assert "\x1b" not in entry["prompt_excerpt"]

    def test_failed_call_records_error_entry(self, tmp_path):
        recorder = TranscriptRecorder(tmp_path / "t.jsonl")
        recorder.record_error(
            "generate", "p", None, "analyse", {}, RuntimeError("boom"),
        )
        (entry,) = load_jsonl(recorder.path)
        assert entry["error"]["type"] == "RuntimeError"
        assert "response" not in entry


# ---------------------------------------------------------------------------
# Replayer matching
# ---------------------------------------------------------------------------

def _replayer_with(tmp_path, *records) -> TranscriptReplayer:
    recorder = TranscriptRecorder(tmp_path / "t.jsonl")
    for rec in records:
        rec(recorder)
    return TranscriptReplayer(recorder.path)


class TestReplayerMatching:
    def test_exact_prompt_match(self, tmp_path):
        replayer = _replayer_with(
            tmp_path,
            lambda r: _record_entry(r, "alpha", content="A"),
            lambda r: _record_entry(r, "beta", content="B"),
        )
        # Reverse order — exact hashes still route correctly.
        assert replayer.replay_generate("beta", "sys", "analyse", {}).content == "B"
        assert replayer.replay_generate("alpha", "sys", "analyse", {}).content == "A"

    def test_subject_match_survives_prompt_change_and_reorder(self, tmp_path):
        def rec_for(subject, content):
            def _rec(r):
                with transcript_subject(subject):
                    _record_entry(r, f"old prompt {subject}", content=content)
            return _rec

        replayer = _replayer_with(
            tmp_path, rec_for("F1", "one"), rec_for("F2", "two"),
        )
        with transcript_subject("F2"):
            resp = replayer.replay_generate(
                "NEW template F2", "new sys", "analyse", {},
            )
        assert resp.content == "two"
        with transcript_subject("F1"):
            resp = replayer.replay_generate(
                "NEW template F1", "new sys", "analyse", {},
            )
        assert resp.content == "one"

    def test_positional_fallback_within_call_class(self, tmp_path):
        replayer = _replayer_with(
            tmp_path,
            lambda r: _record_entry(r, "old-a", content="first"),
            lambda r: _record_entry(r, "old-b", content="second"),
        )
        assert replayer.replay_generate("new-1", None, "analyse", {}).content == "first"
        assert replayer.replay_generate("new-2", None, "analyse", {}).content == "second"

    def test_entries_consumed_at_most_once(self, tmp_path):
        replayer = _replayer_with(
            tmp_path, lambda r: _record_entry(r, "alpha"),
        )
        replayer.replay_generate("alpha", "sys", "analyse", {})
        with pytest.raises(TranscriptReplayMiss):
            replayer.replay_generate("alpha", "sys", "analyse", {})

    def test_miss_raises_with_report_and_ledger(self, tmp_path):
        replayer = _replayer_with(
            tmp_path, lambda r: _record_entry(r, "alpha"),
        )
        with pytest.raises(TranscriptReplayMiss) as exc:
            replayer.replay_generate("x", None, "other_class", {})
        msg = str(exc.value)
        assert "other_class" in msg
        assert "unconsumed_by_class" in msg
        assert len(replayer.misses) == 1
        assert replayer.misses[0]["requested_call_class"] == "other_class"

    def test_miss_report_escapes_hostile_prompt(self, tmp_path):
        replayer = _replayer_with(
            tmp_path, lambda r: _record_entry(r, "alpha"),
        )
        with pytest.raises(TranscriptReplayMiss) as exc:
            replayer.replay_generate(
                "evil\x1b]0;title\x07prompt", None, "other", {},
            )
        assert "\x1b" not in str(exc.value)

    def test_recorded_error_replays_as_raise(self, tmp_path):
        replayer = _replayer_with(
            tmp_path,
            lambda r: r.record_error(
                "generate", "p", None, "analyse", {},
                RuntimeError("provider down"),
            ),
        )
        with pytest.raises(TranscriptReplayedError, match="RuntimeError"):
            replayer.replay_generate("p", None, "analyse", {})

    def test_structured_replay_enforces_schema_floor(self, tmp_path):
        from core.llm.providers import StructuredResponse
        recorder = TranscriptRecorder(tmp_path / "t.jsonl")
        recorder.record_generate_structured(
            "p", _SCHEMA, None, "analyse", {},
            StructuredResponse(
                result={"is_exploitable": True, "smuggled_field": "x"},
                raw="{}",
            ),
        )
        replayer = TranscriptReplayer(recorder.path)
        with pytest.raises(TranscriptReplayMiss, match="schema floor"):
            replayer.replay_generate_structured(
                "p", _SCHEMA, None, "analyse", {},
            )

    def test_structured_replay_returns_zero_cost(self, tmp_path):
        from core.llm.providers import StructuredResponse
        recorder = TranscriptRecorder(tmp_path / "t.jsonl")
        recorder.record_generate_structured(
            "p", _SCHEMA, None, "analyse", {},
            StructuredResponse(
                result={"is_exploitable": False, "reasoning": "ok"},
                raw="{}", cost=1.23, tokens_used=456, model="m1",
            ),
        )
        replayer = TranscriptReplayer(recorder.path)
        resp = replayer.replay_generate_structured(
            "p", _SCHEMA, None, "analyse", {},
        )
        assert resp.cost == 0.0
        assert resp.tokens_used == 0
        assert resp.cached is True
        assert resp.result == {"is_exploitable": False, "reasoning": "ok"}
        assert resp.model == "m1"


# ---------------------------------------------------------------------------
# Client subclass
# ---------------------------------------------------------------------------

class _StubProvider:
    def __init__(self):
        self.calls = 0
        self.total_cost = 0.0
        self.total_tokens = 0

    def generate(self, prompt, system_prompt=None, **kwargs):
        self.calls += 1
        return LLMResponse(
            content=f"live answer {self.calls}", model="test-model-stub",
            provider="anthropic", tokens_used=7, cost=0.002,
            finish_reason="stop",
        )

    def generate_structured(self, prompt, schema, system_prompt=None,
                            **kwargs):
        self.calls += 1
        return ({"is_exploitable": False, "reasoning": "stubbed"}, "{}")


def _stub_config() -> LLMConfig:
    return LLMConfig(
        primary_model=ModelConfig(
            provider="anthropic", model_name="test-model-stub", api_key="k",
        ),
        enable_caching=False,
        enable_fallback=False,
        enable_cost_tracking=False,
        max_retries=1,
    )


def _record_client(path) -> tuple[TranscriptLLMClient, _StubProvider]:
    client = TranscriptLLMClient(
        _stub_config(), session=TranscriptRecorder(path),
    )
    provider = _StubProvider()
    client._get_provider = lambda model_config: provider
    client.providers["anthropic:test-model-stub"] = provider
    return client, provider


class TestTranscriptClient:
    def test_record_mode_dispatches_and_records(self, tmp_path):
        path = tmp_path / "t.jsonl"
        client, provider = _record_client(path)
        resp = client.generate("hello", task_type="analyse")
        assert resp.content == "live answer 1"
        assert provider.calls == 1
        (entry,) = load_jsonl(path)
        assert entry["method"] == "generate"
        assert entry["response"]["content"] == "live answer 1"

    def test_record_mode_records_structured(self, tmp_path):
        path = tmp_path / "t.jsonl"
        client, provider = _record_client(path)
        result, _raw = client.generate_structured(
            "hello", _SCHEMA, task_type="analyse",
        )
        assert result["is_exploitable"] is False
        (entry,) = load_jsonl(path)
        assert entry["method"] == "generate_structured"
        assert entry["response"]["result"]["reasoning"] == "stubbed"
        assert entry["schema_sha256"]

    def test_record_mode_records_failures(self, tmp_path):
        path = tmp_path / "t.jsonl"
        client, _provider = _record_client(path)

        class _Boom:
            total_cost = 0.0
            total_tokens = 0

            def generate(self, *a, **k):
                raise RuntimeError("wire failure")

        boom = _Boom()
        client._get_provider = lambda model_config: boom
        client.providers["anthropic:test-model-stub"] = boom
        with pytest.raises(Exception):
            client.generate("hello", task_type="analyse")
        entries = load_jsonl(path)
        assert entries and entries[-1]["error"]["type"]

    def test_replay_mode_serves_without_provider(self, tmp_path):
        path = tmp_path / "t.jsonl"
        rec_client, _ = _record_client(path)
        rec_client.generate("hello", task_type="analyse")

        replay_client = TranscriptLLMClient(
            _stub_config(), session=TranscriptReplayer(path),
        )
        resp = replay_client.generate("hello", task_type="analyse")
        assert resp.content == "live answer 1"
        assert resp.cost == 0.0
        # No provider was ever constructed.
        assert replay_client.providers == {}

    def test_replay_mode_provider_dispatch_is_forbidden(self, tmp_path):
        path = tmp_path / "t.jsonl"
        rec_client, _ = _record_client(path)
        rec_client.generate("hello", task_type="analyse")
        replay_client = TranscriptLLMClient(
            _stub_config(), session=TranscriptReplayer(path),
        )
        with pytest.raises(TranscriptError, match="forbidden"):
            replay_client._get_provider(_stub_config().primary_model)


# ---------------------------------------------------------------------------
# build_llm_client
# ---------------------------------------------------------------------------

class TestBuildClient:
    def test_no_session_returns_plain_client(self):
        client = build_llm_client(_stub_config())
        assert type(client) is LLMClient

    def test_record_session_returns_transcript_client(
        self, tmp_path, monkeypatch,
    ):
        monkeypatch.setenv(
            "RAPTOR_LLM_TRANSCRIPT", f"record:{tmp_path / 't.jsonl'}",
        )
        reset_active_transcript()
        client = build_llm_client(_stub_config())
        assert isinstance(client, TranscriptLLMClient)
        assert client.transcript_session.mode == "record"

    def test_replay_with_no_primary_gets_inert_placeholder(
        self, tmp_path, monkeypatch,
    ):
        path = tmp_path / "t.jsonl"
        rec_client, _ = _record_client(path)
        rec_client.generate("hello", task_type="analyse")

        monkeypatch.setenv("RAPTOR_LLM_TRANSCRIPT", f"replay:{path}")
        reset_active_transcript()
        client = build_llm_client(
            LLMConfig(primary_model=None, fallback_models=[]),
        )
        assert isinstance(client, TranscriptLLMClient)
        assert client.config.primary_model is not None
        assert client.config.primary_model.provider == "replay"
        # The placeholder never dispatches — recorded answer served.
        assert client.generate("hello", task_type="analyse").content == \
            "live answer 1"


# ---------------------------------------------------------------------------
# Subject-safe positional fallback (cross-subject steal regression)
# ---------------------------------------------------------------------------

class TestSubjectSafePositional:
    def _tagged_transcript(self, tmp_path) -> TranscriptReplayer:
        """F1=exploitable-ish, F2=clean — both subject-tagged."""
        def rec_for(subject, content):
            def _rec(r):
                with transcript_subject(subject):
                    _record_entry(r, f"prompt {subject}", content=content)
            return _rec
        return _replayer_with(
            tmp_path, rec_for("F1", "exploitable"), rec_for("F2", "clean"),
        )

    def test_new_subject_misses_instead_of_stealing(self, tmp_path):
        """The executed counterexample: a NEW finding F3 at the head
        of the replay queue must MISS — pre-fix it positionally stole
        F1's entry, F1 then stole F2's, and F2 missed: two silently
        wrong verdicts instead of one honest miss."""
        replayer = self._tagged_transcript(tmp_path)
        with pytest.raises(TranscriptReplayMiss):  # noqa: SIM117
            with transcript_subject("F3"):
                replayer.replay_generate(
                    "new prompt F3", None, "analyse", {},
                )
        # F1 and F2 still get their own verdicts afterwards.
        with transcript_subject("F1"):
            assert replayer.replay_generate(
                "new prompt F1", None, "analyse", {},
            ).content == "exploitable"
        with transcript_subject("F2"):
            assert replayer.replay_generate(
                "new prompt F2", None, "analyse", {},
            ).content == "clean"
        assert len(replayer.misses) == 1

    def test_subject_caller_may_take_untagged_entries(self, tmp_path):
        """Old-transcript compat: a subject-declaring caller may still
        fall through to subject-LESS recorded entries positionally."""
        replayer = _replayer_with(
            tmp_path, lambda r: _record_entry(r, "old", content="untagged"),
        )
        with transcript_subject("F1"):
            assert replayer.replay_generate(
                "new", None, "analyse", {},
            ).content == "untagged"

    def test_subjectless_caller_keeps_full_pool(self, tmp_path):
        """A caller with NO subject may take tagged entries in
        recorded order (untagged call sites replaying a tagged
        transcript)."""
        replayer = self._tagged_transcript(tmp_path)
        assert replayer.replay_generate(
            "new-1", None, "analyse", {},
        ).content == "exploitable"
        assert replayer.replay_generate(
            "new-2", None, "analyse", {},
        ).content == "clean"


# ---------------------------------------------------------------------------
# Load bounds and leftover reporting
# ---------------------------------------------------------------------------

class TestLoadBoundsAndLeftovers:
    def test_oversize_transcript_refuses_loudly(self, tmp_path, monkeypatch):
        recorder = TranscriptRecorder(tmp_path / "t.jsonl")
        _record_entry(recorder)
        import core.llm.transcript as transcript_mod
        monkeypatch.setattr(transcript_mod, "_MAX_TOTAL_BYTES", 8)
        with pytest.raises(TranscriptError, match="no usable entries"):
            TranscriptReplayer(recorder.path)

    def test_oversize_line_skipped_like_malformed(
        self, tmp_path, monkeypatch,
    ):
        recorder = TranscriptRecorder(tmp_path / "t.jsonl")
        _record_entry(recorder, "small", content="kept")
        _record_entry(recorder, "big", content="x" * 4096)
        import core.llm.transcript as transcript_mod
        monkeypatch.setattr(transcript_mod, "_MAX_LINE_BYTES", 2048)
        replayer = TranscriptReplayer(recorder.path)
        assert len(replayer.entries) == 1
        assert replayer.replay_generate(
            "small", "sys", "analyse", {},
        ).content == "kept"

    def test_leftover_report_names_unconsumed_subjects(self, tmp_path):
        def rec_for(subject):
            def _rec(r):
                with transcript_subject(subject):
                    _record_entry(r, f"p {subject}")
            return _rec
        replayer = _replayer_with(
            tmp_path, rec_for("F1"), rec_for("F2"),
        )
        with transcript_subject("F1"):
            replayer.replay_generate("p F1", "sys", "analyse", {})
        report = replayer.leftover_report()
        assert report["leftover"] == 1
        assert report["consumed"] == 1
        assert report["unconsumed_by_class"] == {"generate/analyse": 1}
        assert report["unconsumed_subjects_by_class"] == {
            "generate/analyse": ["F2"],
        }

    def test_miss_report_includes_unconsumed_subjects(self, tmp_path):
        def _rec(r):
            with transcript_subject("F\x1b1"):  # hostile-ish subject
                _record_entry(r, "p")
        replayer = _replayer_with(tmp_path, _rec)
        with pytest.raises(TranscriptReplayMiss) as exc:
            replayer.replay_generate("x", None, "other_class", {})
        miss = replayer.misses[0]
        subjects = miss["unconsumed_subjects_by_class"]["generate/analyse"]
        assert len(subjects) == 1
        assert "\x1b" not in subjects[0]  # escaped
        assert "unconsumed_subjects_by_class" in str(exc.value)
