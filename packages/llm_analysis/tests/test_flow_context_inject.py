"""Flow-trace + caller call-site context in /agentic per-finding prompts."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from packages.llm_analysis.flow_context_inject import (
    MAX_HOPS_PER_TRACE,
    clear_flow_context_cache,
    context_blocks_for_finding,
    prepare_flow_context,
)


@pytest.fixture(autouse=True)
def _reset():
    clear_flow_context_cache()
    yield
    clear_flow_context_cache()


def _trace(trace_id="TRACE-001", steps=None, **extra):
    data = {
        "id": trace_id,
        "name": "POST /api/query -> db_query",
        "meta": {"entry_point": "handle_query"},
        "steps": steps if steps is not None else [
            {
                "step": 1,
                "type": "entry",
                "definition": "src/http.c:10",
                "description": "parse_request reads the body",
                "tainted_var": "buf",
            },
            {
                "step": 2,
                "type": "call",
                "call_site": "src/http.c:44",
                "definition": "src/svc.c:22",
                "description": "dispatch(buf) forwards untrusted data",
                "tainted_var": "buf",
            },
            {
                "step": 3,
                "type": "sink",
                "definition": "src/db.c:9",
                "description": "db_query(buf) executes the query",
                "tainted_var": "buf",
            },
        ],
        "proximity": 8,
        "attacker_control": {"level": "full", "what": "request body"},
        "summary": {"verdict": "flow_confirmed"},
    }
    data.update(extra)
    return data


def _write_understand_dir(tmp_path: Path, traces=None) -> Path:
    udir = tmp_path / "understand_1"
    udir.mkdir(parents=True, exist_ok=True)
    for i, trace in enumerate(traces if traces is not None else [_trace()]):
        (udir / f"flow-trace-{i:03d}.json").write_text(json.dumps(trace))
    return udir


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True, exist_ok=True)
    (repo / "src" / "http.c").write_text(
        "int handle_query(char *b) {\n"      # 1
        "    char buf[64];\n"                # 2
        "    dispatch(b);\n"                 # 3
        "    return 0;\n"                    # 4
        "}\n",
    )
    return repo


class TestFlowTraceBlocks:
    def test_matching_trace_becomes_block(self, tmp_path: Path):
        repo = _repo(tmp_path)
        udir = _write_understand_dir(tmp_path)
        prepare_flow_context(repo, understand_dir=udir)

        blocks = context_blocks_for_finding({
            "repo_path": str(repo),
            "file_path": "src/svc.c",
            "metadata": {"name": "dispatch"},
        })
        kinds = [b.kind for b in blocks]
        assert "flow-trace-context" in kinds
        block = next(b for b in blocks if b.kind == "flow-trace-context")
        assert block.origin == "understand-flow-trace"
        assert "TRACE-001" in block.content
        assert "src/svc.c:22" in block.content
        assert "tainted: buf" in block.content
        assert "attacker control: full" in block.content

    def test_unrelated_finding_gets_nothing(self, tmp_path: Path):
        repo = _repo(tmp_path)
        udir = _write_understand_dir(tmp_path)
        prepare_flow_context(repo, understand_dir=udir)

        blocks = context_blocks_for_finding({
            "repo_path": str(repo),
            "file_path": "src/other.c",
            "metadata": {"name": "unrelated_fn"},
        })
        assert blocks == ()

    def test_unprepared_repo_returns_empty(self, tmp_path: Path):
        blocks = context_blocks_for_finding({
            "repo_path": str(tmp_path),
            "file_path": "src/http.c",
            "metadata": {"name": "handle_query"},
        })
        assert blocks == ()

    def test_hop_count_bounded(self, tmp_path: Path):
        repo = _repo(tmp_path)
        steps = [
            {
                "step": i,
                "type": "call",
                "definition": f"src/http.c:{i}",
                "description": f"hop {i}",
            }
            for i in range(1, 30)
        ]
        udir = _write_understand_dir(tmp_path, traces=[_trace(steps=steps)])
        prepare_flow_context(repo, understand_dir=udir)

        blocks = context_blocks_for_finding({
            "repo_path": str(repo),
            "file_path": "src/http.c",
            "metadata": {"name": ""},
            "function": "",
        })
        block = next(b for b in blocks if b.kind == "flow-trace-context")
        hop_lines = [
            line for line in block.content.splitlines()
            if line.strip().startswith(tuple("0123456789"))
        ]
        assert len(hop_lines) <= MAX_HOPS_PER_TRACE
        assert "more hop(s)" in block.content

    def test_trace_cap_per_finding(self, tmp_path: Path):
        repo = _repo(tmp_path)
        traces = [_trace(trace_id=f"TRACE-{i:03d}") for i in range(5)]
        udir = _write_understand_dir(tmp_path, traces=traces)
        prepare_flow_context(repo, understand_dir=udir)

        blocks = context_blocks_for_finding({
            "repo_path": str(repo),
            "file_path": "src/svc.c",
            "metadata": {"name": "dispatch"},
        })
        trace_blocks = [b for b in blocks if b.kind == "flow-trace-context"]
        assert len(trace_blocks) == 2


class TestCallerCallSiteBlocks:
    def test_caller_block_with_call_site(self, tmp_path: Path):
        repo = _repo(tmp_path)
        udir = _write_understand_dir(tmp_path, traces=[])
        # Callers resolved through the context map's call_edges.
        (udir / "context-map.json").write_text(json.dumps({
            "call_edges": [
                {
                    "caller_file": "src/http.c",
                    "caller": "handle_query",
                    "callee": "dispatch",
                },
            ],
        }))
        prepare_flow_context(repo, understand_dir=udir)

        blocks = context_blocks_for_finding({
            "repo_path": str(repo),
            "file_path": "src/svc.c",
            "metadata": {"name": "dispatch"},
        })
        caller_blocks = [b for b in blocks if b.kind == "caller-call-sites"]
        assert len(caller_blocks) == 1
        block = caller_blocks[0]
        assert block.origin == "inventory-call-graph"
        assert "handle_query" in block.content
        # The actual invocation line from the caller's source.
        assert "dispatch(b);" in block.content

    def test_no_callers_no_block(self, tmp_path: Path):
        repo = _repo(tmp_path)
        udir = _write_understand_dir(tmp_path, traces=[])
        (udir / "context-map.json").write_text(json.dumps({
            "call_edges": [],
        }))
        prepare_flow_context(repo, understand_dir=udir)

        blocks = context_blocks_for_finding({
            "repo_path": str(repo),
            "file_path": "src/svc.c",
            "metadata": {"name": "dispatch"},
        })
        assert [b for b in blocks if b.kind == "caller-call-sites"] == []


class TestPromptBundleIntegration:
    def test_blocks_reach_analysis_bundle(self, tmp_path: Path):
        from packages.llm_analysis.prompts.analysis import (
            build_analysis_prompt_bundle_from_finding,
        )

        repo = _repo(tmp_path)
        udir = _write_understand_dir(tmp_path)
        (udir / "context-map.json").write_text(json.dumps({
            "call_edges": [
                {
                    "caller_file": "src/http.c",
                    "caller": "handle_query",
                    "callee": "dispatch",
                },
            ],
        }))
        prepare_flow_context(repo, understand_dir=udir)

        bundle = build_analysis_prompt_bundle_from_finding({
            "rule_id": "c-buffer-overflow",
            "file_path": "src/svc.c",
            "start_line": 22,
            "message": "possible overflow",
            "code": "void dispatch(char *b) { }",
            "repo_path": str(repo),
            "metadata": {"name": "dispatch"},
        })
        user_text = "\n".join(
            m.content for m in bundle.messages if m.role == "user"
        )
        assert "flow-trace-context" in user_text
        assert "TRACE-001" in user_text
        assert "caller-call-sites" in user_text
        assert "handle_query" in user_text

    def test_bundle_unaffected_without_preparation(self, tmp_path: Path):
        from packages.llm_analysis.prompts.analysis import (
            build_analysis_prompt_bundle_from_finding,
        )

        bundle = build_analysis_prompt_bundle_from_finding({
            "rule_id": "c-buffer-overflow",
            "file_path": "src/svc.c",
            "start_line": 22,
            "message": "possible overflow",
            "code": "void dispatch(char *b) { }",
            "repo_path": str(tmp_path),
            "metadata": {"name": "dispatch"},
        })
        user_text = "\n".join(
            m.content for m in bundle.messages if m.role == "user"
        )
        assert "flow-trace-context" not in user_text


class TestBlockPriorities:
    def test_new_kinds_registered_for_budget_shedding(self):
        from packages.llm_analysis.prompts.analysis import (
            _ANALYSIS_BLOCK_PRIORITIES,
        )

        assert "flow-trace-context" in _ANALYSIS_BLOCK_PRIORITIES
        assert "caller-call-sites" in _ANALYSIS_BLOCK_PRIORITIES
        # Sheddable before the never-shed core blocks.
        assert _ANALYSIS_BLOCK_PRIORITIES["flow-trace-context"] > 0
        assert _ANALYSIS_BLOCK_PRIORITIES["caller-call-sites"] > 0
