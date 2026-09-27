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
            # Registry grade requires a human-grade note: source=human
            # with an interactive-TTY stamp (a fresh stamp-less note
            # cannot use the legacy grandfather clause).
            metadata={
                "status": "suspicious", "source": "human",
                "provenance": "interactive-tty", "tty": "stdin",
                "sid": "inherited", "envm": "trusted",
                "parents": "bash",
            },
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


class TestPerLookupReloadMemo:
    """Both learned contract sources were re-read and re-parsed on
    EVERY callee lookup — per-row-reload class. The stat-stamped
    caches serve unchanged files and reload on edit."""

    def test_iris_specs_parsed_once_across_lookups(
        self, tmp_path, monkeypatch,
    ):
        import core.audit.iris_specs as iris_specs
        import core.audit.return_contracts as rc

        out = tmp_path / "out"
        out.mkdir()
        (out / "iris-taint-specs.json").write_text(json.dumps([{
            "function": "sanitize_path", "file": "",
            "role": "sanitiser", "evidence_tier": "xref_backed",
        }]))
        rc._IRIS_SPEC_CACHE.clear()
        calls = {"n": 0}
        real = iris_specs.specs_from_json

        def counting(text):
            calls["n"] += 1
            return real(text)

        monkeypatch.setattr(iris_specs, "specs_from_json", counting)
        ctx = RoleContext(out_dir=out)
        for _ in range(3):
            ev = bind_return_contract(
                "sanitize_path", language="c", context=ctx)
            assert ev is not None
        assert calls["n"] == 1

    def test_iris_spec_edit_reloads(self, tmp_path):
        import core.audit.return_contracts as rc

        out = tmp_path / "out"
        out.mkdir()
        spec = out / "iris-taint-specs.json"
        spec.write_text(json.dumps([{
            "function": "sanitize_path", "file": "",
            "role": "sanitiser", "evidence_tier": "xref_backed",
        }]))
        rc._IRIS_SPEC_CACHE.clear()
        ctx = RoleContext(out_dir=out)
        assert bind_return_contract(
            "sanitize_path", language="c", context=ctx) is not None
        # Rewrite naming a different function: the old parse must not
        # be served (stamp changes with size/mtime).
        spec.write_text(json.dumps([{
            "function": "other_fn", "file": "",
            "role": "sanitiser", "evidence_tier": "xref_backed",
        }]))
        import os as _os
        _os.utime(spec, ns=(1, 1))
        ev = bind_return_contract(
            "sanitize_path", language="c", context=ctx)
        assert ev is None or ev.source != "iris_spec"

    def test_annotation_scan_parsed_once_across_lookups(
        self, tmp_path, monkeypatch,
    ):
        import core.annotations.storage as storage
        import core.audit.return_contracts as rc
        from core.annotations.models import Annotation
        from core.annotations.storage import write_annotation

        base = tmp_path / "annotations"
        write_annotation(base, Annotation(
            file="src/db.c", function="db_reserve",
            body="Returns -1 on failure; must be checked.",
            metadata={"status": "suspicious", "source": "human",
                      "provenance": "interactive-tty"},
        ))
        rc._ANNOTATION_SCAN_CACHE.clear()
        calls = {"n": 0}
        real = storage.iter_all_annotations

        def counting(b):
            calls["n"] += 1
            return real(b)

        monkeypatch.setattr(storage, "iter_all_annotations", counting)
        ctx = RoleContext(annotations_dir=base)
        for _ in range(3):
            ev = bind_return_contract(
                "db_reserve", language="c", context=ctx)
            assert ev is not None
        assert calls["n"] == 1


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


class TestWurWrappedDeclarator:
    def test_name_before_trailing_attribute_harvested(self):
        # Wrapped declarator: the name precedes the alias line — the
        # forward-only window never harvested this style.
        header = (
            "int foo(int a,\n"
            "        int b) __attribute__((warn_unused_result));\n"
        )
        names = harvest_wur_declarations({"api.h": header})
        assert "foo" in names

    def test_attribute_first_still_binds_forward(self):
        # Two-direction guard: attribute-on-its-own-line binds to the
        # FOLLOWING declaration, not a preceding unrelated one.
        header = (
            "int bar(int x);\n"
            "__attribute__((warn_unused_result))\n"
            "int foo(void);\n"
        )
        names = harvest_wur_declarations({"api.h": header})
        assert "foo" in names
        assert "bar" not in names


class TestAnnotationProvenanceGate:
    """Registry-grade contract authority requires a human-grade
    annotation (the consistency_prepass sibling gate) — agent-written
    prose is hint-tier by doctrine."""

    def _bind(self, tmp_path, metadata):
        from core.annotations.models import Annotation
        from core.annotations.storage import write_annotation

        base = tmp_path / "annotations"
        write_annotation(base, Annotation(
            file="src/db.c", function="db_reserve",
            body="Returns -1 on failure; the return value must be "
                 "checked before use.",
            metadata=metadata,
        ))
        ctx = RoleContext(annotations_dir=base)
        return bind_return_contract("db_reserve", language="c", context=ctx)

    def test_agent_annotation_is_detection_grade(self, tmp_path):
        ev = self._bind(tmp_path, {
            "status": "suspicious", "source": "agent",
        })
        assert ev is not None
        assert ev.source == "annotation"
        assert ev.grade == GRADE_DETECTION

    def test_non_tty_human_stamp_is_detection_grade(self, tmp_path):
        # The laundering shape: source=human contradicted by a
        # non-tty stamp demotes.
        ev = self._bind(tmp_path, {
            "status": "suspicious", "source": "human",
            "provenance": "non-tty",
        })
        assert ev is not None
        assert ev.grade == GRADE_DETECTION

    def test_stamped_human_annotation_is_registry_grade(self, tmp_path):
        ev = self._bind(tmp_path, {
            "status": "suspicious", "source": "human",
            "provenance": "interactive-tty", "tty": "stdin",
            "sid": "inherited", "envm": "trusted", "parents": "bash",
        })
        assert ev is not None
        assert ev.grade == GRADE_REGISTRY


class TestWurHarvestStride:
    """Two-direction pin on the header-count budget: an under-budget
    tree is scanned whole with no warning; an over-budget tree gets
    the budget spread EVENLY across the sorted paths (never the
    alphabetical prefix — on a kernel tree that reads one corner),
    the budget filled EXACTLY (a stride slice under-fills at
    non-divisible boundaries), and a loud selection-ratio
    disclosure."""

    def test_under_budget_scans_all_no_warning(self, tmp_path, caplog):
        import logging

        for i in range(5):
            (tmp_path / f"h{i}.h").write_text(
                f"__attribute__((warn_unused_result)) int f{i}(void);\n",
            )
        from core.audit.return_contracts import harvest_wur_from_target
        with caplog.at_level(
            logging.WARNING, logger="core.audit.return_contracts",
        ):
            names = harvest_wur_from_target(tmp_path)
        assert names == frozenset({f"f{i}" for i in range(5)})
        assert "harvest capped" not in caplog.text

    def test_over_budget_strides_and_warns(
        self, tmp_path, caplog, monkeypatch,
    ):
        import logging

        # 12 headers, budget 4: the sample must reach the END of the
        # sorted tree, not stop in the first third.
        monkeypatch.setattr(
            "core.audit.return_contracts._MAX_WUR_SCAN_FILES", 4,
        )
        for i in range(12):
            (tmp_path / f"h{i:02d}.h").write_text(
                f"__attribute__((warn_unused_result)) int f{i:02d}(void);\n",
            )
        from core.audit.return_contracts import harvest_wur_from_target
        with caplog.at_level(
            logging.WARNING, logger="core.audit.return_contracts",
        ):
            names = harvest_wur_from_target(tmp_path)
        assert len(names) == 4
        # Strided, not prefix: a name from the tree's last third made
        # the sample (the prefix slice would stop at f03).
        assert any(n >= "f06" for n in names), names
        hits = [r for r in caplog.records
                if "harvest capped" in r.getMessage()]
        assert len(hits) == 1
        assert "4 of 12" in hits[0].getMessage()

    def _harvest_n(self, tmp_path, caplog, monkeypatch, n, cap):
        import logging

        monkeypatch.setattr(
            "core.audit.return_contracts._MAX_WUR_SCAN_FILES", cap,
        )
        for i in range(n):
            (tmp_path / f"h{i:03d}.h").write_text(
                "__attribute__((warn_unused_result)) "
                f"int f{i:03d}(void);\n",
            )
        from core.audit.return_contracts import harvest_wur_from_target
        with caplog.at_level(
            logging.WARNING, logger="core.audit.return_contracts",
        ):
            return harvest_wur_from_target(tmp_path)

    def test_non_divisible_boundary_fills_budget(
        self, tmp_path, caplog, monkeypatch,
    ):
        # n = cap + 1: a stride slice (stride 2) selects only about
        # half the budget — HALF the coverage the prefix truncation it
        # replaced had. The sampler must fill the budget exactly.
        names = self._harvest_n(tmp_path, caplog, monkeypatch, 5, 4)
        assert len(names) == 4, names
        assert "f000" in names, "first file always included"
        assert max(names) >= "f003", "sample must reach the tree's end"

    def test_non_divisible_two_bands_fills_budget(
        self, tmp_path, caplog, monkeypatch,
    ):
        # n = 2*cap + 1: the other non-divisible band.
        names = self._harvest_n(tmp_path, caplog, monkeypatch, 9, 4)
        assert len(names) == 4, names
        assert "f000" in names
        assert max(names) >= "f006", "sample must reach the last region"

    def test_exact_multiple_control(self, tmp_path, caplog, monkeypatch):
        # Exact-multiple control: the divisible case keeps the same
        # contract (budget filled, ends covered).
        names = self._harvest_n(tmp_path, caplog, monkeypatch, 8, 4)
        assert len(names) == 4, names
        assert "f000" in names
        assert max(names) >= "f006"
