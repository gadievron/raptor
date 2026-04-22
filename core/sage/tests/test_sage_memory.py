#!/usr/bin/env python3
"""Tests for SAGE-backed fuzzing memory."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


class TestSageFuzzingMemoryInit(unittest.TestCase):
    """Test SageFuzzingMemory initialization."""

    def test_init_without_sage(self):
        """Should fall back gracefully when SAGE is unavailable."""
        from core.sage.config import SageConfig
        from core.sage.memory import SageFuzzingMemory

        with tempfile.TemporaryDirectory() as tmpdir:
            mem_file = Path(tmpdir) / "test_memory.json"
            config = SageConfig(enabled=False)

            memory = SageFuzzingMemory(memory_file=mem_file, sage_config=config)
            self.assertFalse(memory._sage_available)
            self.assertEqual(len(memory.knowledge), 0)

    def test_init_creates_json_file(self):
        """Should create the JSON file directory."""
        from core.sage.config import SageConfig
        from core.sage.memory import SageFuzzingMemory

        with tempfile.TemporaryDirectory() as tmpdir:
            mem_file = Path(tmpdir) / "subdir" / "memory.json"
            config = SageConfig(enabled=False)

            memory = SageFuzzingMemory(memory_file=mem_file, sage_config=config)
            self.assertTrue(mem_file.parent.exists())


class TestSageFuzzingMemoryAPI(unittest.TestCase):
    """Test that SageFuzzingMemory preserves the FuzzingMemory API."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.mem_file = Path(self.tmpdir) / "test_memory.json"
        from core.sage.config import SageConfig
        from core.sage.memory import SageFuzzingMemory

        config = SageConfig(enabled=False)
        self.memory = SageFuzzingMemory(memory_file=self.mem_file, sage_config=config)

    def test_record_strategy_success(self):
        """record_strategy_success should store knowledge."""
        self.memory.record_strategy_success(
            strategy_name="AFL_CMPLOG",
            binary_hash="abc123",
            crashes_found=5,
            exploitable_crashes=2,
        )
        result = self.memory.recall("strategy", "strategy_AFL_CMPLOG_abc123")
        self.assertIsNotNone(result)
        self.assertEqual(result.value["name"], "AFL_CMPLOG")
        self.assertEqual(result.value["crashes_found"], 5)

    def test_record_crash_pattern(self):
        """record_crash_pattern should store pattern."""
        self.memory.record_crash_pattern(
            signal="SIGSEGV",
            function="parse_input",
            binary_hash="def456",
            exploitable=True,
        )
        result = self.memory.recall("crash_pattern", "SIGSEGV_parse_input")
        self.assertIsNotNone(result)
        self.assertEqual(result.value["signal"], "SIGSEGV")

    def test_record_exploit_technique(self):
        """record_exploit_technique should store technique."""
        self.memory.record_exploit_technique(
            technique="ROP",
            crash_type="stack_overflow",
            binary_characteristics={"aslr": True, "nx": True},
            success=True,
        )
        result = self.memory.recall("exploit_technique", "ROP_stack_overflow")
        self.assertIsNotNone(result)

    def test_get_best_strategy(self):
        """get_best_strategy should return the best strategy."""
        self.memory.record_strategy_success("AFL_CMPLOG", "abc", 10, 3)
        self.memory.record_strategy_success("AFL_PLAIN", "abc", 2, 0)

        best = self.memory.get_best_strategy("abc")
        self.assertEqual(best, "AFL_CMPLOG")

    def test_get_best_strategy_no_data(self):
        """get_best_strategy with no data should return None."""
        result = self.memory.get_best_strategy("unknown_hash")
        self.assertIsNone(result)

    def test_is_crash_likely_exploitable_no_data(self):
        """Should return heuristic when no historical data exists."""
        prob = self.memory.is_crash_likely_exploitable("SIGSEGV", "unknown_func")
        self.assertEqual(prob, 0.7)  # SIGSEGV heuristic

    def test_is_crash_likely_exploitable_with_data(self):
        """Should use historical data when available."""
        # Record a pattern with known exploitability
        self.memory.record_crash_pattern("SIGSEGV", "malloc", "bin1", True)
        self.memory.record_crash_pattern("SIGSEGV", "malloc", "bin1", True)
        self.memory.record_crash_pattern("SIGSEGV", "malloc", "bin1", False)

        prob = self.memory.is_crash_likely_exploitable("SIGSEGV", "malloc")
        self.assertGreater(prob, 0.0)
        self.assertLessEqual(prob, 1.0)

    def test_find_similar(self):
        """find_similar should filter by type and confidence."""
        self.memory.record_strategy_success("s1", "h1", 10, 5)
        self.memory.record_strategy_success("s2", "h2", 0, 0)

        results = self.memory.find_similar("strategy", min_confidence=0.5)
        self.assertTrue(len(results) >= 1)

    def test_record_campaign(self):
        """record_campaign should store campaign data."""
        self.memory.record_campaign({
            "binary_name": "test_binary",
            "strategy": "AFL_CMPLOG",
            "crashes_found": 5,
        })
        self.assertEqual(len(self.memory.campaigns), 1)
        self.assertEqual(self.memory.campaigns[0]["binary_name"], "test_binary")

    def test_get_statistics(self):
        """get_statistics should include sage_enabled field."""
        stats = self.memory.get_statistics()
        self.assertIn("sage_enabled", stats)
        self.assertFalse(stats["sage_enabled"])
        self.assertIn("total_knowledge", stats)
        self.assertIn("total_campaigns", stats)

    def test_prune_low_confidence(self):
        """prune_low_confidence should remove entries below threshold."""
        from packages.autonomous.memory import FuzzingKnowledge

        self.memory.remember(FuzzingKnowledge(
            knowledge_type="test",
            key="high",
            value="good",
            confidence=0.9,
        ))
        self.memory.remember(FuzzingKnowledge(
            knowledge_type="test",
            key="low",
            value="bad",
            confidence=0.1,
        ))

        self.assertEqual(len(self.memory.knowledge), 2)
        self.memory.prune_low_confidence(threshold=0.5)
        self.assertEqual(len(self.memory.knowledge), 1)

    def test_save_and_load(self):
        """Data should persist to JSON and reload."""
        self.memory.record_strategy_success("AFL_CMPLOG", "abc", 5, 2)
        self.memory.save()

        # Create new instance loading from same file
        from core.sage.config import SageConfig
        from core.sage.memory import SageFuzzingMemory

        config = SageConfig(enabled=False)
        memory2 = SageFuzzingMemory(memory_file=self.mem_file, sage_config=config)
        result = memory2.recall("strategy", "strategy_AFL_CMPLOG_abc")
        self.assertIsNotNone(result)


class TestKnowledgeToNaturalLanguage(unittest.TestCase):
    """Test the natural language conversion function."""

    def test_dict_value(self):
        from packages.autonomous.memory import FuzzingKnowledge
        from core.sage.memory import _knowledge_to_natural_language

        k = FuzzingKnowledge(
            knowledge_type="strategy",
            key="test_key",
            value={"name": "AFL_CMPLOG", "crashes_found": 5},
            confidence=0.8,
            success_count=3,
            failure_count=1,
            binary_hash="abc123",
        )
        text = _knowledge_to_natural_language(k)
        self.assertIn("strategy", text)
        self.assertIn("AFL_CMPLOG", text)
        self.assertIn("abc123", text)
        self.assertIn("0.80", text)

    def test_string_value(self):
        from packages.autonomous.memory import FuzzingKnowledge
        from core.sage.memory import _knowledge_to_natural_language

        k = FuzzingKnowledge(
            knowledge_type="crash_pattern",
            key="SIGSEGV_malloc",
            value="memory corruption",
            confidence=0.7,
        )
        text = _knowledge_to_natural_language(k)
        self.assertIn("crash_pattern", text)
        self.assertIn("memory corruption", text)


class TestCampaignToNaturalLanguage(unittest.TestCase):
    """Test campaign natural language conversion."""

    def test_campaign_conversion(self):
        from core.sage.memory import _campaign_to_natural_language

        campaign = {
            "binary_name": "libxml2",
            "date": "2026-04-10",
            "strategy": "AFL_CMPLOG",
            "crashes_found": 12,
        }
        text = _campaign_to_natural_language(campaign)
        self.assertIn("libxml2", text)
        self.assertIn("AFL_CMPLOG", text)
        self.assertIn("12", text)


class TestSageRecallMethods(unittest.TestCase):
    """Test SAGE recall methods return empty when SAGE unavailable."""

    def test_recall_similar_no_sage(self):
        from core.sage.config import SageConfig
        from core.sage.memory import SageFuzzingMemory

        with tempfile.TemporaryDirectory() as tmpdir:
            memory = SageFuzzingMemory(
                memory_file=Path(tmpdir) / "mem.json",
                sage_config=SageConfig(enabled=False),
            )
            self.assertEqual(memory.recall_similar("heap overflow"), [])

    def test_recall_exploit_patterns_no_sage(self):
        from core.sage.config import SageConfig
        from core.sage.memory import SageFuzzingMemory

        with tempfile.TemporaryDirectory() as tmpdir:
            memory = SageFuzzingMemory(
                memory_file=Path(tmpdir) / "mem.json",
                sage_config=SageConfig(enabled=False),
            )
            self.assertEqual(
                memory.recall_exploit_patterns("heap_overflow", {"aslr": True}), []
            )


if __name__ == "__main__":
    unittest.main()
