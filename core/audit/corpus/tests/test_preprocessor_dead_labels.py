"""Preprocessor-dead (#if 0) labels: dormant with a receipt, not error.

Replays the v5 rose_route error cell: the pinned function exists in
the raw fixture text (pin verifies ok), taint-approx indexes it, but
the inventory honours ``#if 0`` and drops it from the checklist — the
label scored ``error not_reviewed:function_not_in_checklist`` and the
pin warning's diagnosis ("name or file path does not exist in the
analysed tree") was factually wrong.  The exclusion IS the dormancy
evidence: the runner maps it to ``dormant`` with the
``inventory:preprocessor_dead`` receipt, and the pin lint notes the
state up front.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from core.audit.corpus.lint import PIN_OK, verify_pin
from core.audit.corpus.run_corpus import _label_preprocessor_dead
from core.audit.corpus.label import load_label

_DEAD_SOURCE = """\
#include <stdio.h>

int live_fn(int x)
{
    return x + 1;
}

#if 0 /* Currently unused */
static void dead_fn(int x)
{
    printf("%d", x);
}
#endif
"""

# dead_fn spans lines 9-12 (inside the #if 0 arm, lines 8-13).
_DEAD_START, _DEAD_END = 9, 12
# live_fn spans lines 3-6.
_LIVE_START, _LIVE_END = 3, 6


def _label(file="net/rose/rose_route.c", start=_DEAD_START, end=_DEAD_END):
    return SimpleNamespace(
        function_id=f"{file}:dead_fn",
        source=SimpleNamespace(
            repo="r", sha="s", file=file, line_start=start, line_end=end,
        ),
    )


class TestRunnerPreprocessorDeadProbe:
    def _tree(self, tmp_path, file="net/rose/rose_route.c"):
        src = tmp_path / file
        src.parent.mkdir(parents=True, exist_ok=True)
        src.write_text(_DEAD_SOURCE, encoding="utf-8")
        return tmp_path

    def test_span_in_dead_arm_is_dead(self, tmp_path):
        tree = self._tree(tmp_path)
        assert _label_preprocessor_dead(tree, _label())

    def test_live_span_is_not_dead(self, tmp_path):
        tree = self._tree(tmp_path)
        assert not _label_preprocessor_dead(
            tree, _label(start=_LIVE_START, end=_LIVE_END),
        )

    def test_non_c_file_is_never_dead(self, tmp_path):
        tree = self._tree(tmp_path, file="mod.py")
        assert not _label_preprocessor_dead(
            tree, _label(file="mod.py"),
        )

    def test_missing_tree_or_file_degrade(self, tmp_path):
        assert not _label_preprocessor_dead(None, _label())
        assert not _label_preprocessor_dead(tmp_path, _label())


class TestLintNotesPreprocessorDead:
    def _label_file(self, tmp_path, start, end):
        p = tmp_path / "dead.label.json"
        p.write_text(json.dumps({
            "schema_version": 1,
            "function_id": "a.c:dead_fn",
            "bug_class": "lifecycle",
            "expected_status": "dormant",
            "rationale": "Preprocessor-dead function.",
            "source": {
                "repo": "r", "sha": "v1", "file": "a.c",
                "line_start": start, "line_end": end,
            },
            "labeler": "test",
            "labeled_at": "2026-08-19",
        }, indent=4) + "\n", encoding="utf-8")
        return load_label(p)

    def test_ok_pin_in_dead_arm_carries_the_note(self, tmp_path):
        tree = tmp_path / "tree"
        tree.mkdir()
        (tree / "a.c").write_text(_DEAD_SOURCE, encoding="utf-8")
        label = self._label_file(tmp_path, _DEAD_START, _DEAD_END)
        check = verify_pin(label, tree)
        assert check.outcome == PIN_OK
        assert check.preprocessor_dead is True
        assert "preprocessor-dead" in check.detail

    def test_live_pin_has_no_note(self, tmp_path):
        tree = tmp_path / "tree"
        tree.mkdir()
        (tree / "a.c").write_text(_DEAD_SOURCE, encoding="utf-8")
        label = self._label_file(tmp_path, _LIVE_START, _LIVE_END)
        # live_fn's span does not contain "dead_fn"; rename the label
        # target so the name check passes.
        label = SimpleNamespace(
            function_id="a.c:live_fn", source=label.source,
        )
        check = verify_pin(label, Path(tree))
        assert check.outcome == PIN_OK
        assert check.preprocessor_dead is False
        assert check.detail == ""
