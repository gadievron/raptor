"""Tests for the strategy YAML loader."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.llm.cwe_strategies import (
    Strategy,
    StrategyLoadError,
    builtin_strategies_dir,
    load_all,
    load_strategy,
)


# ---------------------------------------------------------------------------
# Real bundled strategies
# ---------------------------------------------------------------------------


class TestBuiltinStrategies:
    def test_dir_exists_and_loads(self):
        d = builtin_strategies_dir()
        assert d.is_dir(), f"strategies dir missing: {d}"
        strategies = load_all()
        assert len(strategies) >= 1
        # Sanity: every loaded entry is a Strategy.
        assert all(isinstance(s, Strategy) for s in strategies)

    def test_general_strategy_present(self):
        strategies = load_all()
        names = {s.name for s in strategies}
        assert "general" in names

    def test_loaded_strategies_have_required_shape(self):
        for s in load_all():
            assert s.name
            assert s.description
            # No empty key_questions for shipped strategies.
            assert s.key_questions, f"{s.name} has no key_questions"


# ---------------------------------------------------------------------------
# Loading from disk — round-trip + schema enforcement
# ---------------------------------------------------------------------------


def _write(tmp_path: Path, content: str, name: str = "x.yml") -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


class TestLoadStrategySchema:
    def test_minimal_valid(self, tmp_path):
        p = _write(tmp_path, """
name: minimal
description: A minimal valid strategy
""")
        s = load_strategy(p)
        assert s.name == "minimal"
        assert s.description == "A minimal valid strategy"
        assert s.signals.paths == ()
        assert s.key_questions == ()
        assert s.exemplars == ()

    def test_full_round_trip(self, tmp_path):
        p = _write(tmp_path, """
name: input_handling
description: Parsers, network protocol handlers
signals:
  paths: [net/, drivers/input/]
  includes: [linux/skbuff.h]
  function_keywords: [parse, decode]
key_questions:
  - "What format assumptions does this make?"
  - "Are length fields validated?"
prompt_addendum: |
  Focus on bounds checks.
exemplars:
  - cve: CVE-2023-0179
    title: nftables length confusion
    pattern: |
      Length field trusted before bounds check.
    why_buggy: |
      Caller-controlled length used to size copy.
""")
        s = load_strategy(p)
        assert s.name == "input_handling"
        assert s.signals.paths == ("net/", "drivers/input/")
        assert s.signals.includes == ("linux/skbuff.h",)
        assert s.signals.function_keywords == ("parse", "decode")
        assert len(s.key_questions) == 2
        assert "bounds checks" in s.prompt_addendum
        assert len(s.exemplars) == 1
        assert s.exemplars[0].cve == "CVE-2023-0179"

    def test_to_dict_round_trip(self, tmp_path):
        import json
        p = _write(tmp_path, """
name: x
description: y
signals:
  paths: [a/]
key_questions:
  - "q1?"
exemplars:
  - cve: CVE-1
    title: t
    pattern: p
    why_buggy: w
""")
        s = load_strategy(p)
        d = s.to_dict()
        assert json.dumps(d)  # serialisable
        assert d["signals"]["paths"] == ["a/"]
        assert d["exemplars"][0]["cve"] == "CVE-1"


# ---------------------------------------------------------------------------
# Adversarial — malformed strategy files
# ---------------------------------------------------------------------------


class TestAdversarialSchema:
    def test_missing_name_rejected(self, tmp_path):
        p = _write(tmp_path, "description: no name\n")
        with pytest.raises(StrategyLoadError, match="name"):
            load_strategy(p)

    def test_missing_description_rejected(self, tmp_path):
        p = _write(tmp_path, "name: x\n")
        with pytest.raises(StrategyLoadError, match="description"):
            load_strategy(p)

    def test_unknown_top_level_key_rejected(self, tmp_path):
        p = _write(tmp_path, """
name: x
description: y
typo_field: oops
""")
        with pytest.raises(StrategyLoadError, match="unknown"):
            load_strategy(p)

    def test_unknown_signals_key_rejected(self, tmp_path):
        p = _write(tmp_path, """
name: x
description: y
signals:
  paths: [a/]
  pahts: [b/]   # typo
""")
        with pytest.raises(StrategyLoadError, match="unknown"):
            load_strategy(p)

    def test_unknown_exemplar_key_rejected(self, tmp_path):
        p = _write(tmp_path, """
name: x
description: y
exemplars:
  - cve: CVE-1
    title: t
    pattern: p
    why_buggy: w
    note: extra   # not allowed
""")
        with pytest.raises(StrategyLoadError, match="unknown"):
            load_strategy(p)

    def test_signals_not_a_list_rejected(self, tmp_path):
        p = _write(tmp_path, """
name: x
description: y
signals:
  paths: not_a_list
""")
        with pytest.raises(StrategyLoadError, match="list of strings"):
            load_strategy(p)

    def test_signals_list_with_non_string_rejected(self, tmp_path):
        p = _write(tmp_path, """
name: x
description: y
signals:
  paths: [42, "ok/"]
""")
        with pytest.raises(StrategyLoadError, match="expected string"):
            load_strategy(p)

    def test_exemplar_missing_field_rejected(self, tmp_path):
        p = _write(tmp_path, """
name: x
description: y
exemplars:
  - cve: CVE-1
    title: t
    pattern: p
""")
        with pytest.raises(StrategyLoadError, match="missing required field 'why_buggy'"):
            load_strategy(p)

    def test_invalid_yaml_rejected(self, tmp_path):
        p = _write(tmp_path, "name: x\ndescription: [unclosed\n")
        with pytest.raises(StrategyLoadError, match="invalid YAML"):
            load_strategy(p)

    def test_top_level_not_mapping_rejected(self, tmp_path):
        p = _write(tmp_path, "- just a list\n")
        with pytest.raises(StrategyLoadError, match="must be a mapping"):
            load_strategy(p)

    def test_empty_name_rejected(self, tmp_path):
        p = _write(tmp_path, """
name: ""
description: y
""")
        with pytest.raises(StrategyLoadError, match="non-empty string"):
            load_strategy(p)

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(StrategyLoadError):
            load_strategy(tmp_path / "nope.yml")


# ---------------------------------------------------------------------------
# load_all behaviour
# ---------------------------------------------------------------------------


class TestLoadAll:
    def test_empty_dir_yields_empty_list(self, tmp_path):
        assert load_all(tmp_path) == []

    def test_missing_dir_yields_empty_list(self, tmp_path):
        assert load_all(tmp_path / "nope") == []

    def test_loads_all_yml_files(self, tmp_path):
        _write(tmp_path, "name: a\ndescription: A\n", "a.yml")
        _write(tmp_path, "name: b\ndescription: B\n", "b.yml")
        out = load_all(tmp_path)
        assert {s.name for s in out} == {"a", "b"}

    def test_duplicate_names_rejected(self, tmp_path):
        _write(tmp_path, "name: dup\ndescription: A\n", "a.yml")
        _write(tmp_path, "name: dup\ndescription: B\n", "b.yml")
        with pytest.raises(StrategyLoadError, match="duplicate"):
            load_all(tmp_path)

    def test_non_yml_files_ignored(self, tmp_path):
        _write(tmp_path, "name: a\ndescription: A\n", "a.yml")
        (tmp_path / "README.md").write_text("# notes")
        (tmp_path / "draft.yaml").write_text("name: draft")  # .yaml not .yml
        out = load_all(tmp_path)
        assert len(out) == 1
        assert out[0].name == "a"

    def test_sorted_load_order(self, tmp_path):
        _write(tmp_path, "name: zeta\ndescription: Z\n", "zzz.yml")
        _write(tmp_path, "name: alpha\ndescription: A\n", "aaa.yml")
        _write(tmp_path, "name: middle\ndescription: M\n", "mmm.yml")
        names = [s.name for s in load_all(tmp_path)]
        # File order is alphabetical (aaa.yml, mmm.yml, zzz.yml).
        assert names == ["alpha", "middle", "zeta"]
