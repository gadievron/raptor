"""Tests for the opt-in hunt-item ranking in raptor-understand."""

from __future__ import annotations

import importlib.util
import os
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT_PATH = REPO_ROOT / "libexec" / "raptor-understand"

_DOC_RE = re.compile(
    r"id: (\w+)\nBEGIN_DOC_\w+\n(.*?)\nEND_DOC_\w+", re.S,
)
_LINE_RE = re.compile(r"location: [^:]+:(\d+)")


@pytest.fixture
def understand_module():
    os.environ.setdefault("_RAPTOR_TRUSTED", "1")
    from importlib.machinery import SourceFileLoader
    loader = SourceFileLoader("raptor_understand", str(SCRIPT_PATH))
    spec = importlib.util.spec_from_loader("raptor_understand", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class _Response:
    def __init__(self, result):
        self.result = result
        self.cost = 0.001


class FakeRankClient:
    """Ranks hunt items by line number descending."""

    def generate_structured(self, prompt, schema, **kwargs):
        docs = _DOC_RE.findall(prompt)
        scored = sorted(
            ((int(_LINE_RE.search(text).group(1)), bid)
             for bid, text in docs),
            reverse=True,
        )
        return _Response({"ranked_ids": [bid for _v, bid in scored]})


def _item(line):
    return {
        "file": "src/parse.c",
        "line": line,
        "function": f"fn_{line}",
        "snippet": "memcpy(dst, src, n);",
        "confidence": "medium",
        "found_by_models": ["m1"],
    }


def _args(**kwargs):
    defaults = {"hunt_tool": "llm", "max_cost": 0, "rank": True}
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def test_rank_reorders_items(understand_module, monkeypatch):
    monkeypatch.setattr(
        "core.llm.client.LLMClient", lambda *a, **k: FakeRankClient(),
    )
    items = [_item(n) for n in (30, 90, 10, 60)]
    out, cost = understand_module._rank_hunt_items(items, _args())
    assert [i["line"] for i in out] == [90, 60, 30, 10]
    assert cost > 0


def test_rank_skips_slopsquat_and_small(understand_module):
    items = [_item(n) for n in (1, 2, 3, 4)]
    out, cost = understand_module._rank_hunt_items(
        items, _args(hunt_tool="slopsquat"),
    )
    assert out is items
    assert cost == 0.0
    two = [_item(1), _item(2)]
    assert understand_module._rank_hunt_items(two, _args())[0] is two


def test_rank_failure_keeps_merge_order(understand_module, monkeypatch,
                                        capsys):
    class Boom:
        def __init__(self, *a, **k):
            raise RuntimeError("no model")

    monkeypatch.setattr("core.llm.client.LLMClient", Boom)
    items = [_item(n) for n in (30, 90, 10)]
    out, cost = understand_module._rank_hunt_items(items, _args())
    assert out is items
    assert cost == 0.0
    assert "failed" in capsys.readouterr().err
