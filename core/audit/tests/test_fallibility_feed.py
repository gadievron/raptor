"""Fallibility-contract feed → return-check contract witnesses.

The study loop's structured ``fallibility_contracts`` vocabulary
class (§2.2.2) binds through ``return_contracts`` into the census
verdict: mechanical tier (study-prep signals agreed) is
registry-grade and promote-capable; llm_summarized binds
detection-grade only; exception-borne and cannot-fail claims bind
nothing. No hidden vocabulary: a target-specific name with no learned
input stays contract-unresolved.
"""

from __future__ import annotations

import json
import textwrap

from core.audit.callsite_consistency import build_return_census
from core.audit.consistency_verify import census_verdict
from core.audit.fail_open_roles import RoleContext
from core.audit.return_contracts import bind_return_contract


def _write_model(tmp_path, entries) -> None:
    (tmp_path / "domain-model.json").write_text(json.dumps({
        "version": "1",
        "concepts": [],
        "invariants": [],
        "contracts": [],
        "bug_patterns": [],
        "fallibility_contracts": entries,
    }))


def _census(deviant_only: bool = False):
    parts = []
    if not deviant_only:
        for i in range(3):
            parts.append(textwrap.dedent(f"""\
                int user_{i}(void) {{
                    if (acquire_conn() < 0)
                        return -1;
                    return 0;
                }}
            """))
    parts.append(
        "int user_dev(void) {\n    acquire_conn();\n    return 0;\n}\n"
    )
    return build_return_census({"src/users.c": "\n".join(parts)})


class TestContractBinding:
    def test_mechanical_tier_is_registry_grade(self, tmp_path):
        _write_model(tmp_path, [{
            "name": "acquire_conn", "can_fail": True,
            "convention": "negative", "provenance": "mechanical",
        }])
        ev = bind_return_contract(
            "acquire_conn", context=RoleContext(out_dir=tmp_path),
        )
        assert ev is not None
        assert ev.source == "domain_model"
        assert ev.provenance == "domain_model:fallibility:mechanical"
        assert ev.registry_grade
        assert ev.detail == "negative"

    def test_llm_summarized_tier_is_detection_grade(self, tmp_path):
        _write_model(tmp_path, [{
            "name": "acquire_conn", "can_fail": True,
            "convention": "negative", "provenance": "llm_summarized",
        }])
        ev = bind_return_contract(
            "acquire_conn", context=RoleContext(out_dir=tmp_path),
        )
        assert ev is not None
        assert not ev.registry_grade
        assert ev.provenance == \
            "domain_model:fallibility:llm_summarized"

    def test_exception_convention_binds_nothing(self, tmp_path):
        _write_model(tmp_path, [{
            "name": "acquire_conn", "can_fail": True,
            "convention": "exception", "provenance": "mechanical",
        }])
        assert bind_return_contract(
            "acquire_conn", context=RoleContext(out_dir=tmp_path),
        ) is None

    def test_cannot_fail_claim_binds_nothing(self, tmp_path):
        _write_model(tmp_path, [{
            "name": "acquire_conn", "can_fail": False,
            "provenance": "mechanical",
        }])
        assert bind_return_contract(
            "acquire_conn", context=RoleContext(out_dir=tmp_path),
        ) is None

    def test_no_learned_input_stays_unresolved(self, tmp_path):
        """No hidden vocabulary: without the model entry the same
        target-specific name binds no contract at all."""
        _write_model(tmp_path, [])
        assert bind_return_contract(
            "acquire_conn", context=RoleContext(out_dir=tmp_path),
        ) is None


class TestCensusVerdict:
    def test_mechanical_fallibility_promotes_census_deviant(
        self, tmp_path,
    ):
        _write_model(tmp_path, [{
            "name": "acquire_conn", "can_fail": True,
            "convention": "negative", "provenance": "mechanical",
        }])
        census = _census()
        entry = census["acquire_conn"]
        res = census_verdict(
            entry, entry.deviants[0],
            context=RoleContext(out_dir=tmp_path),
        )
        assert res.outcome == "confirmed"
        assert res.rule_id == "consistency:return-check"
        assert res.contract["source"] == "domain_model"
        assert res.contract["provenance"] == \
            "domain_model:fallibility:mechanical"
        pe = res.peer_evidence
        assert pe.contract_source == "domain_model"
        assert pe.registry_grade

    def test_llm_tier_alone_cannot_promote(self, tmp_path):
        """Detection-grade fallibility falls to the strict majority
        leg (ratio >= 0.9) — an uncorroborated study claim never
        substitutes for a registry contract."""
        _write_model(tmp_path, [{
            "name": "acquire_conn", "can_fail": True,
            "convention": "negative", "provenance": "llm_summarized",
        }])
        census = _census()
        entry = census["acquire_conn"]
        res = census_verdict(
            entry, entry.deviants[0],
            context=RoleContext(out_dir=tmp_path),
        )
        assert res.outcome == "inconclusive"
        assert res.reason.startswith("ratio-below-threshold")

    def test_prepass_end_to_end(self, tmp_path):
        from core.audit.consistency_prepass import run_consistency_prepass

        _write_model(tmp_path, [{
            "name": "acquire_conn", "can_fail": True,
            "convention": "negative", "provenance": "mechanical",
        }])
        parts = []
        for i in range(3):
            parts.append(textwrap.dedent(f"""\
                int user_{i}(void) {{
                    if (acquire_conn() < 0)
                        return -1;
                    return 0;
                }}
            """))
        parts.append(
            "int user_dev(void) {\n"
            "    acquire_conn();\n    return 0;\n}\n"
        )
        res = run_consistency_prepass(
            {"src/users.c": "\n".join(parts)}, out_dir=tmp_path,
        )
        fallible = [
            f for f in res["findings"]
            if f["dimension"] == "return-check"
            and f["rule_id"] == "consistency:return-check"
        ]
        assert fallible, "mechanical fallibility contract must yield " \
            "the promote-capable rule-id"
        assert res["telemetry"]["contract_sources"].get(
            "domain_model", 0) >= 1
