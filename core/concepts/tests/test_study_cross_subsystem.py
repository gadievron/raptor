"""Tests for cross-subsystem boundary synthesis (Phase 3b)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

from core.concepts.model import StudyItem
from core.concepts.study import (
    _build_cross_subsystem_prompt,
    _run_cross_subsystem_synthesis,
)


def _make_item(**kw: object) -> StudyItem:
    defaults = dict(
        id="", kind="function", name="", file="",
        definition="", callees=[], callers=[], calls=[],
    )
    defaults.update(kw)
    return StudyItem(**defaults)


# ------------------------------------------------------------------
# Prompt builder
# ------------------------------------------------------------------

class TestBuildCrossSubsystemPrompt:

    def test_includes_both_subsystem_headings(self) -> None:
        pair = {
            "type_name": "widget",
            "subsystem_a": "drivers",
            "subsystem_b": "net",
            "functions_a": ["drv_send"],
            "functions_b": ["net_recv"],
        }
        items = {
            "widget": _make_item(
                name="widget", kind="struct", file="include/linux/widget.h",
                definition="struct widget { int ref; };",
            ),
            "drv_send": _make_item(
                name="drv_send", file="drivers/foo.c",
                definition="void drv_send(struct widget *w) {}",
            ),
            "net_recv": _make_item(
                name="net_recv", file="net/bar.c",
                definition="void net_recv(struct widget *w) {}",
            ),
        }
        prompt = _build_cross_subsystem_prompt(pair, items)
        assert "**drivers**" in prompt
        assert "**net**" in prompt
        assert "struct widget" in prompt
        assert "drv_send" in prompt
        assert "net_recv" in prompt

    def test_missing_items_silently_skipped(self) -> None:
        pair = {
            "type_name": "gadget",
            "subsystem_a": "a",
            "subsystem_b": "b",
            "functions_a": ["fn_missing"],
            "functions_b": [],
        }
        prompt = _build_cross_subsystem_prompt(pair, {})
        assert "struct gadget" in prompt
        assert "fn_missing" not in prompt

    def test_type_item_formatted_as_focus(self) -> None:
        pair = {
            "type_name": "sg",
            "subsystem_a": "crypto",
            "subsystem_b": "net",
            "functions_a": [],
            "functions_b": [],
        }
        sg = _make_item(
            name="sg", kind="struct", file="include/linux/sg.h",
            definition="struct sg { void *page; unsigned int len; };",
        )
        prompt = _build_cross_subsystem_prompt(pair, {"sg": sg})
        assert "[FOCUS] struct: sg" in prompt


# ------------------------------------------------------------------
# Synthesis function — integration with mock LLM
# ------------------------------------------------------------------

class TestRunCrossSubsystemSynthesis:

    def _write_interactions(
        self, tmp_path: Path, pairs: list[dict],
    ) -> None:
        (tmp_path / "interactions.json").write_text(
            json.dumps({"pairs": pairs}),
        )

    def _mock_llm(self, response: dict) -> MagicMock:
        client = MagicMock()
        client.generate_structured.return_value = response
        client.model_name = "test-model"
        return client

    def test_returns_concepts_and_invariants(self, tmp_path: Path) -> None:
        self._write_interactions(tmp_path, [{
            "type_name": "scatterlist",
            "subsystem_a": "crypto",
            "subsystem_b": "net",
            "functions_a": ["encrypt"],
            "functions_b": ["sendmsg"],
        }])
        items = [
            _make_item(name="scatterlist", kind="struct",
                       file="include/linux/scatterlist.h",
                       definition="struct scatterlist { };"),
            _make_item(name="encrypt", file="crypto/enc.c",
                       definition="void encrypt(void) {}"),
            _make_item(name="sendmsg", file="net/send.c",
                       definition="void sendmsg(void) {}"),
        ]
        llm = self._mock_llm({
            "concepts": [{
                "id": "page_alias",
                "description": "Splice pages alias page-cache pages",
                "evidence": [{"type": "code_path", "file": "net/send.c",
                              "observation": "splice path"}],
                "confidence": "inferred",
            }],
            "invariants": [{
                "id": "no_write_alias",
                "concept": "page_alias",
                "statement": "Must not write through aliased page",
                "negation": "Data corruption via aliased write",
                "confidence": "inferred",
                "relevant_cwes": ["CWE-416"],
            }],
        })

        concepts, invariants = _run_cross_subsystem_synthesis(
            items, tmp_path, llm,
        )

        assert len(concepts) == 1
        assert concepts[0].id.startswith("xsub_scatterlist_")
        assert len(invariants) == 1
        assert invariants[0].id.startswith("xsub_scatterlist_")
        assert "CWE-416" in invariants[0].relevant_cwes

    def test_no_interactions_file_returns_empty(self, tmp_path: Path) -> None:
        llm = self._mock_llm({})
        concepts, invariants = _run_cross_subsystem_synthesis(
            [], tmp_path, llm,
        )
        assert concepts == []
        assert invariants == []
        llm.generate_structured.assert_not_called()

    def test_empty_pairs_returns_empty(self, tmp_path: Path) -> None:
        self._write_interactions(tmp_path, [])
        llm = self._mock_llm({})
        concepts, invariants = _run_cross_subsystem_synthesis(
            [], tmp_path, llm,
        )
        assert concepts == []
        assert invariants == []
        llm.generate_structured.assert_not_called()

    def test_should_stop_respected(self, tmp_path: Path) -> None:
        self._write_interactions(tmp_path, [
            {"type_name": "t1", "subsystem_a": "a", "subsystem_b": "b",
             "functions_a": [], "functions_b": []},
            {"type_name": "t2", "subsystem_a": "c", "subsystem_b": "d",
             "functions_a": [], "functions_b": []},
        ])
        llm = self._mock_llm({"concepts": [], "invariants": []})
        stop_after = 1
        call_count = [0]

        def should_stop():
            call_count[0] += 1
            return call_count[0] > stop_after

        concepts, invariants = _run_cross_subsystem_synthesis(
            [], tmp_path, llm, should_stop=should_stop,
        )
        assert llm.generate_structured.call_count == 1

    def test_llm_failure_skips_pair(self, tmp_path: Path) -> None:
        self._write_interactions(tmp_path, [{
            "type_name": "broken",
            "subsystem_a": "a",
            "subsystem_b": "b",
            "functions_a": [],
            "functions_b": [],
        }])
        llm = MagicMock()
        llm.generate_structured.side_effect = RuntimeError("API down")
        llm.model_name = "test-model"

        concepts, invariants = _run_cross_subsystem_synthesis(
            [], tmp_path, llm,
        )
        assert concepts == []
        assert invariants == []

    def test_id_prefixed_per_type(self, tmp_path: Path) -> None:
        self._write_interactions(tmp_path, [
            {"type_name": "alpha", "subsystem_a": "x", "subsystem_b": "y",
             "functions_a": [], "functions_b": []},
            {"type_name": "beta", "subsystem_a": "x", "subsystem_b": "y",
             "functions_a": [], "functions_b": []},
        ])
        llm = self._mock_llm({
            "concepts": [{"id": "c1", "description": "d",
                          "evidence": [], "confidence": "inferred"}],
            "invariants": [{"id": "i1", "concept": "c1",
                            "statement": "s", "negation": "n",
                            "confidence": "inferred"}],
        })

        concepts, invariants = _run_cross_subsystem_synthesis(
            [], tmp_path, llm,
        )
        ids = {c.id for c in concepts}
        assert "xsub_alpha_c1" in ids
        assert "xsub_beta_c1" in ids
        inv_ids = {i.id for i in invariants}
        assert "xsub_alpha_i1" in inv_ids
        assert "xsub_beta_i1" in inv_ids

    def test_malformed_llm_response_skipped(self, tmp_path: Path) -> None:
        self._write_interactions(tmp_path, [{
            "type_name": "bad",
            "subsystem_a": "a",
            "subsystem_b": "b",
            "functions_a": [],
            "functions_b": [],
        }])
        llm = self._mock_llm({
            "concepts": "not_a_list",
            "invariants": 42,
        })

        concepts, invariants = _run_cross_subsystem_synthesis(
            [], tmp_path, llm,
        )
        assert concepts == []
        assert invariants == []

    def test_progress_callback_fired(self, tmp_path: Path) -> None:
        self._write_interactions(tmp_path, [{
            "type_name": "t",
            "subsystem_a": "a",
            "subsystem_b": "b",
            "functions_a": [],
            "functions_b": [],
        }])
        llm = self._mock_llm({
            "concepts": [{"id": "c", "description": "d",
                          "evidence": [], "confidence": "inferred"}],
            "invariants": [],
        })
        progress_calls = []

        def on_progress(phase, msg):
            progress_calls.append((phase, msg))

        _run_cross_subsystem_synthesis(
            [], tmp_path, llm, on_progress=on_progress,
        )
        assert any(p == "boundary_synthesis" for p, _ in progress_calls)
