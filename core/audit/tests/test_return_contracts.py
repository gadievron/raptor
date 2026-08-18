"""Failure-semantics binding for the return census (design §2.2).

Every source is exercised with a fixture pair; the vocabulary-policy
case (a target-specific name with no learned input binds nothing)
proves there is no hidden hardcoded list.
"""

from __future__ import annotations

import json
import textwrap

from core.audit.callsite_consistency import build_return_census
from core.audit.fail_open_roles import (
    GRADE_DETECTION,
    GRADE_REGISTRY,
    RoleContext,
)
from core.audit.return_contracts import (
    bind_return_contract,
    harvest_wur_declarations,
)


class TestWurFacts:
    def test_harvest_from_tu_declarations(self):
        header = textwrap.dedent("""\
            #define API extern

            __attribute__((warn_unused_result)) int do_auth(int uid);
            int __must_check drop_priv(void);
            int plain_helper(void);
        """)
        names = harvest_wur_declarations({"api.h": header})
        assert "do_auth" in names
        assert "drop_priv" in names
        assert "plain_helper" not in names

    def test_nodiscard_cpp_spelling(self):
        header = "[[nodiscard]] int verify_sig(const char *buf);\n"
        names = harvest_wur_declarations({"api.hpp": header})
        assert "verify_sig" in names

    def test_wur_fact_binds_registry_grade(self):
        ctx = RoleContext(wur_functions=frozenset({"do_auth"}))
        ev = bind_return_contract("do_auth", language="c", context=ctx)
        assert ev is not None
        assert ev.source == "wur"
        assert ev.grade == GRADE_REGISTRY
        assert ev.provenance == "wur:do_auth"


class TestLearnedSources:
    def test_domain_model_contract_binds(self, tmp_path):
        out = tmp_path / "out"
        out.mkdir()
        (out / "domain-model.json").write_text(json.dumps({
            "contracts": [{
                "function": "acquire_slot",
                "output_semantics": "returns NULL on failure",
            }],
        }))
        ctx = RoleContext(out_dir=out)
        ev = bind_return_contract("acquire_slot", language="c", context=ctx)
        assert ev is not None
        assert ev.source == "domain_model"
        assert ev.provenance == "domain_model:contract"
        assert ev.grade == GRADE_REGISTRY

    def test_annotation_prose_binds(self, tmp_path):
        from core.annotations.models import Annotation
        from core.annotations.storage import write_annotation

        base = tmp_path / "annotations"
        write_annotation(base, Annotation(
            file="src/db.c", function="db_reserve",
            body="Returns -1 on failure; the return value must be "
                 "checked before use.",
            metadata={"status": "suspicious", "source": "human"},
        ))
        ctx = RoleContext(annotations_dir=base)
        ev = bind_return_contract("db_reserve", language="c", context=ctx)
        assert ev is not None
        assert ev.source == "annotation"
        assert ev.grade == GRADE_REGISTRY

    def test_corroborated_iris_spec_is_registry_grade(self, tmp_path):
        out = tmp_path / "out"
        out.mkdir()
        (out / "iris-taint-specs.json").write_text(json.dumps([{
            "function": "sanitize_path",
            "file": "",
            "role": "sanitiser",
            "evidence_tier": "xref_backed",
        }]))
        ctx = RoleContext(out_dir=out)
        ev = bind_return_contract("sanitize_path", language="c", context=ctx)
        assert ev is not None
        assert ev.source == "iris_spec"
        assert ev.provenance == "iris_spec:xref_backed"
        assert ev.grade == GRADE_REGISTRY

    def test_heuristic_iris_spec_is_detection_grade(self, tmp_path):
        out = tmp_path / "out"
        out.mkdir()
        (out / "iris-taint-specs.json").write_text(json.dumps([{
            "function": "sanitize_path",
            "file": "",
            "role": "sanitiser",
            "evidence_tier": "heuristic",
        }]))
        ctx = RoleContext(out_dir=out)
        ev = bind_return_contract("sanitize_path", language="c", context=ctx)
        assert ev is not None
        assert ev.source == "iris_spec"
        assert ev.grade == GRADE_DETECTION


class TestTierA:
    def test_setuid_binds_from_shared_registry(self):
        ev = bind_return_contract("setuid", language="c")
        assert ev is not None
        assert ev.source == "tier_a"
        assert ev.detail == "zero_ok"
        assert ev.grade == GRADE_REGISTRY


class TestMajorityEvidence:
    def _census_entry(self, checked: int, unchecked: int):
        parts = []
        for i in range(checked):
            parts.append(
                f"int c{i}(void) {{\n"
                f"    if (do_work() != 0) return -1;\n"
                f"    return 0;\n}}\n"
            )
        for i in range(unchecked):
            parts.append(
                f"int u{i}(void) {{\n    do_work();\n    return 0;\n}}\n"
            )
        census = build_return_census({"a.c": "\n".join(parts)})
        return census["do_work"]

    def test_majority_binds_detection_grade(self):
        entry = self._census_entry(9, 1)
        ev = bind_return_contract(
            "do_work", language="c", census_entry=entry,
        )
        assert ev is not None
        assert ev.source == "majority"
        assert ev.grade == GRADE_DETECTION
        assert "9/10" in ev.provenance

    def test_below_ratio_binds_nothing(self):
        entry = self._census_entry(2, 2)
        ev = bind_return_contract(
            "do_work", language="c", census_entry=entry,
        )
        assert ev is None


class TestNoHiddenLists:
    def test_unknown_name_with_no_learned_inputs_binds_nothing(self):
        """The vocabulary-policy proof: a target-specific name with
        every learned surface absent resolves to no contract at all."""
        ev = bind_return_contract(
            "frobnicate_widget_checked", language="c",
            context=RoleContext(),
        )
        assert ev is None

    def test_strongest_source_wins(self, tmp_path):
        out = tmp_path / "out"
        out.mkdir()
        (out / "domain-model.json").write_text(json.dumps({
            "contracts": [{
                "function": "do_auth",
                "output_semantics": "returns NULL on failure",
            }],
        }))
        ctx = RoleContext(
            out_dir=out, wur_functions=frozenset({"do_auth"}),
        )
        ev = bind_return_contract("do_auth", language="c", context=ctx)
        assert ev is not None
        assert ev.source == "wur"
