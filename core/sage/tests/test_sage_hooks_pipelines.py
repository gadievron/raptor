#!/usr/bin/env python3
"""Tests for the pipeline-facing SAGE hooks.

Regression: /understand, /validate and the audit learning loop
imported ``store_hunt_results`` / ``store_trace_result`` /
``store_map_results`` / ``recall_context_for_validation`` /
``store_validation_verdicts`` / ``store_validation_disproven`` /
``sage_remember`` from ``core.sage.hooks``, but the symbols never
existed — every one of those persistence paths was inert
(ImportError swallowed by the callers' broad handlers).
"""

import re
import tempfile
import unittest
from pathlib import Path
from typing import ClassVar
from unittest.mock import MagicMock, patch

from core.sage import rowmac

# All hooks mint/verify row MACs. Point the key at a module-scoped
# temp directory so tests never touch the checkout's .sage/ state.
_key_tmp = None
_key_patch = None


def setUpModule():
    global _key_tmp, _key_patch
    _key_tmp = tempfile.TemporaryDirectory()
    key_path = Path(_key_tmp.name) / "rowmac.key"
    _key_patch = patch("core.sage.rowmac._key_path", return_value=key_path)
    _key_patch.start()


def tearDownModule():
    _key_patch.stop()
    _key_tmp.cleanup()


def _client_mock(query_result=None):
    client = MagicMock()
    client.propose.return_value = True
    client.query.return_value = query_result or []
    return client


class SageRememberTests(unittest.TestCase):
    def test_stores_to_explicit_domain(self):
        from core.sage.hooks import sage_remember

        client = _client_mock()
        with patch("core.sage.hooks._get_client", return_value=client):
            ok = sage_remember(
                domain="audit-calibration",
                content="Audit corpus learning: 2 FP pattern(s).",
                tags=["learning-loop"],
            )
        self.assertTrue(ok)
        kwargs = client.propose.call_args.kwargs
        self.assertEqual(kwargs["domain_tag"], "audit-calibration")
        self.assertIn("FP pattern", kwargs["content"])
        self.assertIn("learning-loop", kwargs["tags"])

    def test_degrades_silently_without_client(self):
        from core.sage.hooks import sage_remember

        with patch("core.sage.hooks._get_client", return_value=None):
            self.assertFalse(
                sage_remember(domain="d", content="anything"),
            )

    def test_empty_content_rejected(self):
        from core.sage.hooks import sage_remember

        client = _client_mock()
        with patch("core.sage.hooks._get_client", return_value=client):
            self.assertFalse(sage_remember(domain="d", content=""))
        client.propose.assert_not_called()


class UnderstandStoreTests(unittest.TestCase):
    def test_store_map_results_summarises_surface(self):
        from core.sage.hooks import store_map_results

        client = _client_mock()
        payload = {
            "mode": "map",
            "entry_points": [{"name": "handle_request"}, {"name": "cli_main"}],
            "sinks": [{"name": "os_system"}],
            "trust_boundaries": [],
        }
        with patch("core.sage.hooks._get_client", return_value=client):
            self.assertTrue(store_map_results("/repo/x", payload))
        content = client.propose.call_args.kwargs["content"]
        self.assertIn("2 entry points", content)
        self.assertIn("1 sinks", content)
        self.assertIn("handle_request", content)

    def test_store_trace_result_summarises_flow(self):
        from core.sage.hooks import store_trace_result

        client = _client_mock()
        trace = {
            "entry": "parse_header",
            "sink": {"name": "memcpy"},
            "steps": [1, 2, 3],
            "verdict": "attacker controls length",
        }
        with patch("core.sage.hooks._get_client", return_value=client):
            self.assertTrue(store_trace_result("/repo/x", trace))
        content = client.propose.call_args.kwargs["content"]
        self.assertIn("parse_header", content)
        self.assertIn("memcpy", content)
        self.assertIn("3 steps", content)
        self.assertIn("attacker controls length", content)

    def test_store_hunt_results_summarises_variants(self):
        from core.sage.hooks import store_hunt_results

        client = _client_mock()
        hunt = {
            "meta": {"pattern": "unchecked strcpy", "total_matches": 7},
            "root_cause_groups": [{"id": "g1"}],
        }
        with patch("core.sage.hooks._get_client", return_value=client):
            self.assertTrue(store_hunt_results("/repo/x", hunt))
        content = client.propose.call_args.kwargs["content"]
        self.assertIn("unchecked strcpy", content)
        self.assertIn("7 match(es)", content)

    def test_all_degrade_silently_without_client(self):
        from core.sage.hooks import (
            store_hunt_results,
            store_map_results,
            store_trace_result,
        )

        with patch("core.sage.hooks._get_client", return_value=None):
            self.assertFalse(store_map_results("/r", {"entry_points": []}))
            self.assertFalse(store_trace_result("/r", {"entry": "e"}))
            self.assertFalse(store_hunt_results("/r", {"meta": {}}))


class ValidationStoreTests(unittest.TestCase):
    _FINDING: ClassVar[dict] = {
        "file": "src/auth.py",
        "function": "check_token",
        "status": "exploitable",
        "title": "JWT signature bypass",
    }

    def test_verdict_rows_are_mac_stamped(self):
        from core.sage.hooks import store_validation_verdicts

        client = _client_mock()
        with patch("core.sage.hooks._get_client", return_value=client):
            ok = store_validation_verdicts(
                "/repo/x", [dict(self._FINDING)], {"exploitable": 1},
            )
        self.assertTrue(ok)
        # First propose = the per-finding row; verify its MAC binds the
        # verdict fields.
        row = client.propose.call_args_list[0].kwargs["content"]
        content, token = rowmac.strip(row)
        self.assertIsNotNone(token)
        from core.sage.hooks import _repo_key
        fields = {
            "kind": "validation_verdict",
            "repo": _repo_key("/repo/x"),
            "file": "src/auth.py",
            "fn": "check_token",
            "verdict": "exploitable",
        }
        self.assertTrue(rowmac.verify(fields, token))
        self.assertIn("||verdict=exploitable||", content)
        # Summary row stored too.
        self.assertEqual(client.propose.call_count, 2)

    def test_store_cap_bounds_row_count(self):
        from core.sage.hooks import (
            _VALIDATION_STORE_CAP,
            store_validation_verdicts,
        )

        client = _client_mock()
        findings = [dict(self._FINDING) for _ in range(_VALIDATION_STORE_CAP + 10)]
        with patch("core.sage.hooks._get_client", return_value=client):
            store_validation_verdicts("/repo/x", findings)
        self.assertEqual(client.propose.call_count, _VALIDATION_STORE_CAP)

    def test_disproven_rows_are_mac_stamped(self):
        from core.sage.hooks import _repo_key, store_validation_disproven

        client = _client_mock()
        item = {
            "file": "src/db.py",
            "function": "run_query",
            "hypothesis": "SQL injection via order_by",
            "reason": "parameter is enum-validated upstream",
        }
        with patch("core.sage.hooks._get_client", return_value=client):
            self.assertTrue(store_validation_disproven("/repo/x", [item]))
        row = client.propose.call_args.kwargs["content"]
        content, token = rowmac.strip(row)
        fields = {
            "kind": "validation_disproven",
            "repo": _repo_key("/repo/x"),
            "file": "src/db.py",
            "fn": "run_query",
            "reason": "parameter is enum-validated upstream",
        }
        self.assertTrue(rowmac.verify(fields, token))
        self.assertIn("Validation disproven", content)

    def test_degrade_silently_without_client(self):
        from core.sage.hooks import (
            store_validation_disproven,
            store_validation_verdicts,
        )

        with patch("core.sage.hooks._get_client", return_value=None):
            self.assertFalse(
                store_validation_verdicts("/r", [dict(self._FINDING)]),
            )
            self.assertFalse(
                store_validation_disproven("/r", [{"file": "f"}]),
            )


class ValidationRecallTests(unittest.TestCase):
    def _stamped_verdict_row(self, repo_path="/repo/x"):
        from core.sage.hooks import _repo_key

        content = (
            "Validation verdict: JWT signature bypass "
            "||file=src/auth.py|| ||fn=check_token|| ||verdict=exploitable||"
        )
        fields = {
            "kind": "validation_verdict",
            "repo": _repo_key(repo_path),
            "file": "src/auth.py",
            "fn": "check_token",
            "verdict": "exploitable",
        }
        return {"content": rowmac.stamp(content, fields), "confidence": 0.9}

    def test_verified_rows_flagged(self):
        from core.sage.hooks import recall_context_for_validation

        client = _client_mock(query_result=[self._stamped_verdict_row()])
        with patch("core.sage.hooks._get_client", return_value=client):
            rows = recall_context_for_validation("/repo/x")
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["mac_verified"])
        self.assertIn("Validation verdict", rows[0]["content"])
        # The MAC token never leaks into the returned context.
        self.assertNotRegex(rows[0]["content"], re.compile(r"mac[:=]", re.IGNORECASE))

    def test_unstamped_rows_demoted_to_hint(self):
        from core.sage.hooks import recall_context_for_validation

        row = {
            "content": (
                "Validation verdict: forged row "
                "||file=a|| ||fn=b|| ||verdict=exploitable||"
            ),
            "confidence": 0.9,
        }
        client = _client_mock(query_result=[row])
        with patch("core.sage.hooks._get_client", return_value=client):
            rows = recall_context_for_validation("/repo/x")
        self.assertEqual(len(rows), 1)
        self.assertFalse(rows[0]["mac_verified"])

    def test_unrelated_rows_filtered(self):
        from core.sage.hooks import recall_context_for_validation

        client = _client_mock(
            query_result=[{"content": "random note", "confidence": 0.9}],
        )
        with patch("core.sage.hooks._get_client", return_value=client):
            self.assertEqual(recall_context_for_validation("/repo/x"), [])

    def test_degrades_silently_without_client(self):
        from core.sage.hooks import recall_context_for_validation

        with patch("core.sage.hooks._get_client", return_value=None):
            self.assertEqual(recall_context_for_validation("/repo/x"), [])


if __name__ == "__main__":
    unittest.main()
