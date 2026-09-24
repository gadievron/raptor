"""Taint-approx cache round-trip: JSON object keys are always strings,
so a cached ``direct_flows`` / ``dangerous_flows`` map comes back
str-keyed while consumers index ``params`` with the key and compare it
against ``len(params)`` — int operations. The loader re-keys the flow
maps to int at the single point the cached shape enters the run; a key
that is not a non-negative canonical-decimal parameter index is
dropped (fails toward claiming no flow), and the value / ``params``
shapes consumers unpack, slice, and ``len()`` are validated under the
same drop policy."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.audit.loaders import load_or_build_taint_approx
from core.audit.orchestrator import _clean_check_flows
from core.evidence import EvidenceRecord

_KEY = "a.c:acl_worker"
_PARAMS: list[str] = ["buf", "len", "n"]
# Sentinel so tests can write an explicit JSON null params
# (params=None) distinctly from "use the default list".
_UNSET: Any = object()


def _write_cache(
    out: Path,
    dangerous: dict[str, Any],
    direct: dict[str, Any] | None = None,
    params: Any = _UNSET,
) -> None:
    cache = {
        _KEY: {
            "function": "acl_worker",
            "params": _PARAMS if params is _UNSET else params,
            "direct_flows": direct or {},
            "dangerous_flows": dangerous,
            "has_opaque_flow": False,
        },
    }
    (out / "taint-approx.json").write_text(json.dumps(cache))


def _load(out: Path) -> dict:
    results = load_or_build_taint_approx(None, out)
    assert results is not None
    return results[_KEY]


def _evidence_index(approx: dict) -> dict[str, EvidenceRecord]:
    rec = EvidenceRecord(file="a.c", function="acl_worker")
    rec.taint_approx = approx
    return {_KEY: rec}


class TestCachedFlowIndexCoercion:
    def test_cached_keys_come_back_as_int(self, tmp_path):
        _write_cache(
            tmp_path,
            {"2": [["memcpy", 2]]},
            direct={"0": [["strcpy", 1]]},
        )
        approx = _load(tmp_path)
        assert set(approx["dangerous_flows"]) == {2}
        assert set(approx["direct_flows"]) == {0}

    def test_clean_check_sweep_survives_round_trip(self, tmp_path):
        # The sweep indexes params with the key and compares it
        # against len(params) — str keys from the cache crashed it.
        _write_cache(tmp_path, {"2": [["memcpy", 2]]})
        text = _clean_check_flows(
            "a.c", "acl_worker", _evidence_index(_load(tmp_path)),
        )
        assert text is not None
        assert "`n`" in text
        assert "memcpy" in text

    def test_non_numeric_key_dropped_numeric_kept(self, tmp_path):
        _write_cache(
            tmp_path,
            {"bogus": [["system", 0]], "1": [["memcpy", 2]]},
        )
        approx = _load(tmp_path)
        assert set(approx["dangerous_flows"]) == {1}
        text = _clean_check_flows(
            "a.c", "acl_worker", _evidence_index(approx),
        )
        assert text is not None
        assert "system" not in text
        assert "`len`" in text

    def test_negative_key_dropped(self, tmp_path):
        # A negative index would silently mis-attribute the flow to
        # params[-1] downstream — dropped like non-numeric keys.
        _write_cache(tmp_path, {"-1": [["memcpy", 2]]})
        approx = _load(tmp_path)
        assert approx["dangerous_flows"] == {}

    def test_non_canonical_keys_dropped(self, tmp_path):
        # The producer enumerates positions as str(int) — every other
        # int()-parseable spelling names no real position: whitespace,
        # sign prefixes, underscore separators, non-ASCII decimal
        # digits, and "-0" (int-parses to 0) all drop.
        _write_cache(tmp_path, {
            " 2": [["memcpy", 2]],
            "+2": [["memcpy", 2]],
            "1_0": [["memcpy", 2]],
            "٢": [["memcpy", 2]],
            "-0": [["memcpy", 2]],
        })
        approx = _load(tmp_path)
        assert approx["dangerous_flows"] == {}

    def test_out_of_range_index_named_legibly(self, tmp_path):
        _write_cache(tmp_path, {"7": [["memcpy", 2]]})
        text = _clean_check_flows(
            "a.c", "acl_worker", _evidence_index(_load(tmp_path)),
        )
        assert text is not None
        assert "arg7" in text


class TestCachedFlowShapeValidation:
    def test_non_list_flow_value_dropped(self, tmp_path):
        # Consumers slice the value (sinks[:2]) — a scalar raises
        # 'int' object is not subscriptable.
        _write_cache(tmp_path, {"1": 5, "2": [["memcpy", 2]]})
        approx = _load(tmp_path)
        assert set(approx["dangerous_flows"]) == {2}
        text = _clean_check_flows(
            "a.c", "acl_worker", _evidence_index(approx),
        )
        assert text is not None
        assert "`n`" in text

    def test_malformed_flow_pairs_filtered(self, tmp_path):
        # Consumers tuple-unpack each pair as (callee, arg_index) —
        # wrong arity raises ValueError, wrong element types leak
        # non-(str, int) data into rendering.
        _write_cache(tmp_path, {
            "2": [
                "xxx",
                ["memcpy"],
                ["memcpy", "2"],
                [3, 2],
                ["memcpy", 2],
            ],
        })
        approx = _load(tmp_path)
        assert approx["dangerous_flows"] == {2: [["memcpy", 2]]}
        text = _clean_check_flows(
            "a.c", "acl_worker", _evidence_index(approx),
        )
        assert text is not None
        assert "memcpy" in text

    def test_malformed_params_fall_back_to_arg_naming(self, tmp_path):
        # Consumers call len(params) and index it — a non-list raises
        # TypeError. Replaced with [], so flows keep rendering with
        # the legible arg<N> fallback.
        _write_cache(tmp_path, {"2": [["memcpy", 2]]}, params=7)
        approx = _load(tmp_path)
        assert approx["params"] == []
        text = _clean_check_flows(
            "a.c", "acl_worker", _evidence_index(approx),
        )
        assert text is not None
        assert "arg2" in text

    def test_present_null_params_replaced(self, tmp_path):
        # An explicit JSON null must be replaced like any other
        # malformed shape — presence-keyed, not None-keyed. The
        # propagation resolver enumerates params with no None guard
        # (approx.get("params", []) does not default on present-null),
        # so a surviving null raised TypeError per constraint.
        from core.audit.constraints import Constraint
        from core.audit.propagation import (
            PropagationConfig,
            _try_taint_approx_resolve,
        )

        _write_cache(tmp_path, {"0": [["memcpy", 2]]}, params=None)
        approx = _load(tmp_path)
        assert approx["params"] == []
        constraint = Constraint(
            function="acl_worker",
            file="a.c",
            kind="parameter",
            target="buf",
            rule="buf must be bounded",
            violation="stack buffer overflow",
        )
        result = _try_taint_approx_resolve(
            constraint,
            PropagationConfig(evidence_index=_evidence_index(approx)),
        )
        # Empty params match no name — unresolved, and no crash.
        assert result is None

    def test_absent_params_key_stays_absent(self, tmp_path):
        cache = {
            _KEY: {
                "function": "acl_worker",
                "dangerous_flows": {"0": [["memcpy", 2]]},
            },
        }
        (tmp_path / "taint-approx.json").write_text(json.dumps(cache))
        approx = _load(tmp_path)
        assert "params" not in approx

    def test_params_with_non_str_element_replaced(self, tmp_path):
        # Element-wise filtering would shift positions, so a mixed
        # list is replaced wholesale — arg<N> naming for the function.
        _write_cache(
            tmp_path, {"1": [["memcpy", 2]]}, params=["buf", 3, "n"],
        )
        approx = _load(tmp_path)
        assert approx["params"] == []
        text = _clean_check_flows(
            "a.c", "acl_worker", _evidence_index(approx),
        )
        assert text is not None
        assert "arg1" in text
