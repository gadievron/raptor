#!/usr/bin/env python3
"""Tests for core/sage/scripts/_common.py."""

import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock


class TestAsyncMemoryExists(unittest.TestCase):
    """async_memory_exists is the idempotency primitive for seed/register.

    Must return False on any error so callers re-propose rather than
    silently skipping — a duplicate memory is cheap; a missing one
    because of a transient query failure is not.
    """

    def test_returns_true_when_results_present(self):
        from core.sage.scripts._common import async_memory_exists
        client = MagicMock()
        response = MagicMock()
        response.memories = [MagicMock()]
        client.list_memories = AsyncMock(return_value=response)

        result = asyncio.run(async_memory_exists(client, "raptor-agents", "agent:raptor-scan"))

        self.assertTrue(result)
        client.list_memories.assert_awaited_once_with(
            domain="raptor-agents",
            tag="agent:raptor-scan",
            limit=1,
        )

    def test_returns_false_when_empty(self):
        from core.sage.scripts._common import async_memory_exists
        client = MagicMock()
        response = MagicMock()
        response.memories = []
        client.list_memories = AsyncMock(return_value=response)

        result = asyncio.run(async_memory_exists(client, "raptor-agents", "agent:unknown"))

        self.assertFalse(result)

    def test_returns_false_on_query_error(self):
        from core.sage.scripts._common import async_memory_exists
        client = MagicMock()
        client.list_memories = AsyncMock(side_effect=RuntimeError("sage unreachable"))

        result = asyncio.run(async_memory_exists(client, "raptor-agents", "agent:anything"))

        # Error → False → caller re-proposes. Duplicate memory is cheaper
        # than a missing one caused by a transient query failure.
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
