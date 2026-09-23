"""Flow-nesting depth bound in the shared YAML loader.

Deeply nested flow collections overflow the YAML loader's stack: on
current CPython the C-stack guard converts that into a
RecursionError, but interpreters without the guard die in a native
stack overflow inside libyaml — a hard crash no except clause can
catch. The pre-scan bound turns both into an ordinary YAMLError
before the loader sees the text.
"""

from __future__ import annotations

from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

from packages.sca import _yaml_fast  # noqa: E402

DEEP_FLOW = "__metadata: {version: 8}\nx: " + "[" * 50_000 + "\n"


# A stray double-quote in a plain scalar, then the deep flow run: a
# quote-tracking scanner reads the brackets as string content and
# passes the document through to the loader at full depth — the
# loader does NOT agree about the quoting, so the depth is real.
QUOTE_SWALLOW_BYPASS = 'a: x"y\nb: ' + "[" * 50_000 + "\n"


class TestFlowDepthScanner:
    def test_two_direction_threshold(self):
        limit = _yaml_fast.MAX_FLOW_DEPTH
        assert not _yaml_fast._flow_depth_exceeded("[" * limit)
        assert _yaml_fast._flow_depth_exceeded("[" * (limit + 1))

    def test_closers_decrement(self):
        assert not _yaml_fast._flow_depth_exceeded("[]" * 5_000)
        assert not _yaml_fast._flow_depth_exceeded("{}" * 5_000)

    def test_quote_swallow_shape_is_caught(self):
        assert _yaml_fast._flow_depth_exceeded(QUOTE_SWALLOW_BYPASS)

    def test_quoted_brackets_count_by_design(self):
        # Over-inclusion direction of the quote-blind trade-off: deep
        # bracket runs are refused even inside string syntax. Safe —
        # refusal is the bounded path, and no legitimate manifest
        # carries >MAX_FLOW_DEPTH net-unclosed openers in strings.
        assert _yaml_fast._flow_depth_exceeded('a: "' + "[" * 2_000 + '"')

    def test_modest_quoted_brackets_pass(self):
        doc = 'a: "' + "[" * 200 + '"\n'
        assert not _yaml_fast._flow_depth_exceeded(doc)
        assert _yaml_fast.safe_load(doc) == {"a": "[" * 200}


class TestSafeLoadDepthBound:
    def test_deep_flow_raises_yamlerror(self):
        with pytest.raises(yaml.YAMLError, match="flow nesting"):
            _yaml_fast.safe_load(DEEP_FLOW)

    def test_deep_flow_raises_yamlerror_load_all(self):
        with pytest.raises(yaml.YAMLError, match="flow nesting"):
            _yaml_fast.safe_load_all(DEEP_FLOW)

    def test_quote_swallow_bypass_refused_before_loader(self):
        """The refusal must come from the pre-scan (ordinary
        YAMLError), NOT from the loader blowing its stack: on
        interpreters without CPython's C-stack guard — inside the
        supported >=3.10 floor, not testable on this host — the
        loader-side failure for this shape is a native crash."""
        with pytest.raises(yaml.YAMLError, match="flow nesting"):
            _yaml_fast.safe_load(QUOTE_SWALLOW_BYPASS)

    def test_moderate_nesting_still_loads(self):
        doc = "a: " + "[" * 50 + "1" + "]" * 50 + "\n"
        data = _yaml_fast.safe_load(doc)
        node = data["a"]
        for _ in range(49):
            node = node[0]
        assert node == [1]


class TestYarnBerryHostileFixture:
    def test_deep_flow_berry_returns_empty_with_warning(
        self, tmp_path: Path, caplog,
    ) -> None:
        from packages.sca.parsers.yarn_lock import parse
        p = tmp_path / "yarn.lock"
        p.write_text(DEEP_FLOW)
        with caplog.at_level("WARNING"):
            assert parse(p) == []
        assert any("parse failed for" in m for m in caplog.messages)

    def test_honest_berry_still_parses(self, tmp_path: Path) -> None:
        from packages.sca.parsers.yarn_lock import parse
        p = tmp_path / "yarn.lock"
        p.write_text(
            '__metadata:\n  version: 8\n\n"left-pad@npm:^1.3.0":\n'
            '  version: 1.3.0\n  resolution: "left-pad@npm:1.3.0"\n'
        )
        deps = parse(p)
        assert [d.name for d in deps] == ["left-pad"]


class TestYamlFamilyDeepFlow:
    def test_pnpm_lock_deep_flow_returns_empty(self, tmp_path: Path) -> None:
        from packages.sca.parsers.pnpm_lock import parse
        p = tmp_path / "pnpm-lock.yaml"
        p.write_text("x: " + "[" * 50_000 + "\n")
        assert parse(p) == []
