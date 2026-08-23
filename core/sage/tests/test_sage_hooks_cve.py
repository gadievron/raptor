#!/usr/bin/env python3
"""Tests for the /cve-diff fix-pointer hook pair
(``store_cve_fix_pointer`` / ``recall_cve_fix_pointer``).

The recall side hands its row a MECHANICAL effect (the pipeline skips
its discovery agent loop), so the MAC gate is hard: unstamped,
tampered, or mismatched rows must be ignored entirely — not demoted to
hints.
"""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

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


FIX = "a" * 40
PARENT = "b" * 40
REPO = "https://github.com/example/proj"


def _stored_content(client=None, **kw):
    """Run a store through a mock client and return the proposed row."""
    from core.sage.hooks import store_cve_fix_pointer

    client = client or _client_mock()
    with patch("core.sage.hooks._get_client", return_value=client):
        ok = store_cve_fix_pointer(
            "CVE-2024-31337", REPO, FIX, PARENT, **kw,
        )
    assert ok
    return client, client.propose.call_args.kwargs


class StoreTests(unittest.TestCase):
    def test_stores_fact_with_decision_fields_and_mac(self):
        client, kwargs = _stored_content(consensus_count=2, shape="source")
        self.assertEqual(kwargs["domain_tag"], "raptor-cve")
        self.assertEqual(kwargs["memory_type"], "fact")
        self.assertEqual(kwargs["confidence"], 0.95)
        content = kwargs["content"]
        self.assertIn("||cve_id=CVE-2024-31337||", content)
        self.assertIn(f"||cve_repo={REPO}||", content)
        self.assertIn(f"||cve_fix={FIX}||", content)
        self.assertIn(f"||cve_parent={PARENT}||", content)
        # MAC token present (stamped by _stamp_row).
        from core.sage import rowmac
        _clean, token = rowmac.strip(content)
        self.assertIsNotNone(token)

    def test_pipeline_only_pointer_gets_lower_confidence(self):
        _client, kwargs = _stored_content(consensus_count=0)
        self.assertEqual(kwargs["confidence"], 0.9)

    def test_degrades_without_client_or_fields(self):
        from core.sage.hooks import store_cve_fix_pointer

        with patch("core.sage.hooks._get_client", return_value=None):
            self.assertFalse(
                store_cve_fix_pointer("CVE-2024-1", REPO, FIX),
            )
        with patch("core.sage.hooks._get_client",
                   return_value=_client_mock()):
            self.assertFalse(store_cve_fix_pointer("", REPO, FIX))
            self.assertFalse(store_cve_fix_pointer("CVE-2024-1", "", FIX))
            self.assertFalse(store_cve_fix_pointer("CVE-2024-1", REPO, ""))


class RecallTests(unittest.TestCase):
    def _recall_with_rows(self, rows, cve_id="CVE-2024-31337"):
        from core.sage.hooks import recall_cve_fix_pointer

        client = _client_mock(query_result=rows)
        with patch("core.sage.hooks._get_client", return_value=client):
            return recall_cve_fix_pointer(cve_id)

    def test_round_trip_returns_pointer(self):
        _client, kwargs = _stored_content(consensus_count=2)
        row = {"content": kwargs["content"], "confidence": 0.95,
               "domain": "raptor-cve"}
        got = self._recall_with_rows([row])
        self.assertEqual(got, {
            "cve_id": "CVE-2024-31337",
            "repository_url": REPO,
            "fix_commit": FIX,
            "parent_commit": PARENT,
        })

    def test_unstamped_row_is_ignored(self):
        content = (
            f"CVE fix pointer: CVE-2024-31337 is fixed by {REPO} @ {FIX}. "
            f"||cve_id=CVE-2024-31337|| ||cve_repo={REPO}|| "
            f"||cve_fix={FIX}|| ||cve_parent={PARENT}||"
        )
        self.assertIsNone(self._recall_with_rows(
            [{"content": content, "confidence": 0.95}],
        ))

    def test_tampered_row_is_ignored(self):
        _client, kwargs = _stored_content()
        tampered = kwargs["content"].replace(FIX, "c" * 40)
        self.assertIsNone(self._recall_with_rows(
            [{"content": tampered, "confidence": 0.95}],
        ))

    def test_other_cve_row_is_ignored(self):
        _client, kwargs = _stored_content()
        self.assertIsNone(self._recall_with_rows(
            [{"content": kwargs["content"], "confidence": 0.95}],
            cve_id="CVE-2020-9999",
        ))

    def test_kill_switch_disables_recall(self):
        from core.sage.hooks import recall_cve_fix_pointer

        client = _client_mock()
        with patch.dict("os.environ", {"RAPTOR_SAGE_CVE_PRIOR": "0"}), \
                patch("core.sage.hooks._get_client", return_value=client):
            self.assertIsNone(recall_cve_fix_pointer("CVE-2024-31337"))
        client.query.assert_not_called()

    def test_degrades_without_client(self):
        from core.sage.hooks import recall_cve_fix_pointer

        with patch("core.sage.hooks._get_client", return_value=None):
            self.assertIsNone(recall_cve_fix_pointer("CVE-2024-31337"))


if __name__ == "__main__":
    unittest.main()
