"""Tri-state verdict accessor semantics.

``read_verdict`` is the one shared read for the ``VERDICT_KEYS``
boolean fields (``is_true_positive`` / ``is_exploitable``). Those
fields are tri-state: True / False / abstained (missing, schema-nulled
None, or malformed shape). Reading an abstention as a NEGATIVE verdict
— via a bool ``.get`` default, ``not``, or an ``==`` bool compare —
has repeatedly demoted findings whose analysis response was merely
malformed.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT))

from core.run.finding_status import VERDICT_KEYS, read_verdict  # noqa: E402


class TestReadVerdict:

    def test_explicit_bools_pass_through(self):
        assert read_verdict({"is_exploitable": True}, "is_exploitable") is True
        assert read_verdict({"is_exploitable": False}, "is_exploitable") is False

    def test_missing_key_is_abstention(self):
        assert read_verdict({}, "is_true_positive") is None

    def test_schema_nulled_none_is_abstention(self):
        assert read_verdict({"is_true_positive": None}, "is_true_positive") is None

    def test_non_bool_shapes_are_abstention(self):
        # Response validation nulls malformed verdicts, but a record
        # that bypassed it ("true", 1, [], {}) must not be coerced
        # into a verdict either way.
        for junk in ("true", "false", 1, 0, [], {}, 0.9):
            assert read_verdict({"is_exploitable": junk}, "is_exploitable") is None

    def test_non_dict_record_is_abstention(self):
        for rec in (None, [], "x", 42):
            assert read_verdict(rec, "is_exploitable") is None  # type: ignore[arg-type]

    def test_verdict_keys_enumerates_both_fields(self):
        assert set(VERDICT_KEYS) == {"is_true_positive", "is_exploitable"}
