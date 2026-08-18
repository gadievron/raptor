"""Robustness tests for core.artifacts.provenance.

The provenance stamp is the mechanical carrier of docs/security.md
invariant I2-(b) ("LLM-derived artifacts are adversarial"), so these
tests pin the properties the raptor-validate-schema gate and the
artifact consumers rely on: stamps survive re-stamping without trust
downgrades, malformed stamps are detected with precise messages,
missing stamps read as untrusted, and free-text sanitisation is
idempotent and path-precise.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from core.artifacts.provenance import (
    ARTIFACT_TEXT_SCHEMAS,
    CONTEXT_MAP_TEXT_SCHEMA,
    FLOW_TRACE_TEXT_SCHEMA,
    PROVENANCE_KEY,
    PROVENANCE_SCHEMA_VERSION,
    SCHEMA_VERSION_KEY,
    STATUS_INVALID,
    STATUS_LEGACY,
    STATUS_OK,
    VARIANTS_TEXT_SCHEMA,
    check_free_text_idempotent,
    check_provenance,
    iter_free_text_fields,
    mark_schema_validated,
    provenance_of,
    sanitise_artifact_text,
    sanitise_free_text,
    stamp_provenance,
)


class TestStampProvenance(unittest.TestCase):

    def test_stamps_dict_with_generator_and_version(self):
        data = {"sources": []}
        stamp_provenance(data, "understand:map")
        self.assertEqual(data[PROVENANCE_KEY]["generator"], "understand:map")
        self.assertTrue(data[PROVENANCE_KEY]["untrusted"])
        self.assertFalse(data[PROVENANCE_KEY]["schema_validated"])
        self.assertEqual(data[SCHEMA_VERSION_KEY], PROVENANCE_SCHEMA_VERSION)

    def test_untrusted_never_downgrades(self):
        data = {PROVENANCE_KEY: {"generator": "llm", "untrusted": True,
                                 "schema_validated": False}}
        stamp_provenance(data, "mechanical", untrusted=False)
        self.assertTrue(data[PROVENANCE_KEY]["untrusted"])

    def test_untrusted_upgrades(self):
        data = {PROVENANCE_KEY: {"generator": "mech", "untrusted": False,
                                 "schema_validated": False}}
        stamp_provenance(data, "llm", untrusted=True)
        self.assertTrue(data[PROVENANCE_KEY]["untrusted"])

    def test_preserve_generator_of_original_writer(self):
        data = {PROVENANCE_KEY: {"generator": "binary-analysis",
                                 "untrusted": True,
                                 "schema_validated": False}}
        stamp_provenance(data, "understand:map", overwrite_generator=False)
        self.assertEqual(data[PROVENANCE_KEY]["generator"], "binary-analysis")

    def test_restamp_resets_schema_validated(self):
        data = {PROVENANCE_KEY: {"generator": "llm", "untrusted": True,
                                 "schema_validated": True}}
        stamp_provenance(data, "llm")
        self.assertFalse(data[PROVENANCE_KEY]["schema_validated"])

    def test_list_artifact_stamped_per_element(self):
        paths = [{"id": "AP-1"}, "not-a-dict", {"id": "AP-2"}]
        stamp_provenance(paths, "understand-bridge")
        self.assertIn(PROVENANCE_KEY, paths[0])
        self.assertIn(PROVENANCE_KEY, paths[2])
        self.assertEqual(paths[1], "not-a-dict")

    def test_non_container_untouched(self):
        self.assertEqual(stamp_provenance("scalar", "x"), "scalar")


class TestCheckProvenance(unittest.TestCase):

    def test_valid_stamp_is_ok(self):
        data = stamp_provenance({"a": 1}, "gen")
        status, msgs = check_provenance(data)
        self.assertEqual(status, STATUS_OK)
        self.assertEqual(msgs, [])

    def test_missing_stamp_and_marker_is_legacy(self):
        status, _ = check_provenance({"sources": []})
        self.assertEqual(status, STATUS_LEGACY)

    def test_version_marker_without_stamp_is_invalid(self):
        status, msgs = check_provenance({SCHEMA_VERSION_KEY: 2})
        self.assertEqual(status, STATUS_INVALID)
        self.assertTrue(any(PROVENANCE_KEY in m for m in msgs))

    def test_malformed_stamp_reports_field_paths(self):
        data = {PROVENANCE_KEY: {"generator": "", "untrusted": "yes"}}
        status, msgs = check_provenance(data)
        self.assertEqual(status, STATUS_INVALID)
        joined = "\n".join(msgs)
        self.assertIn("provenance.generator", joined)
        self.assertIn("provenance.untrusted", joined)
        self.assertIn("provenance.schema_validated", joined)

    def test_list_all_unstamped_is_legacy(self):
        status, _ = check_provenance([{"id": "AP-1"}])
        self.assertEqual(status, STATUS_LEGACY)

    def test_list_mixed_is_ok_with_note(self):
        paths = [stamp_provenance({"id": "AP-1"}, "g"), {"id": "AP-2"}]
        status, msgs = check_provenance(paths)
        self.assertEqual(status, STATUS_OK)
        self.assertTrue(any("without a provenance stamp" in m for m in msgs))

    def test_list_with_malformed_element_is_invalid(self):
        paths = [{"id": "AP-1", PROVENANCE_KEY: {"generator": 5}}]
        status, msgs = check_provenance(paths)
        self.assertEqual(status, STATUS_INVALID)
        self.assertTrue(any(m.startswith("[0].") for m in msgs))


class TestProvenanceOf(unittest.TestCase):

    def test_missing_stamp_reads_untrusted_legacy(self):
        prov = provenance_of({"sources": []})
        self.assertTrue(prov["untrusted"])
        self.assertTrue(prov["legacy"])
        self.assertEqual(prov["generator"], "unknown")

    def test_malformed_stamp_reads_untrusted_legacy(self):
        prov = provenance_of({PROVENANCE_KEY: {"generator": 5}})
        self.assertTrue(prov["untrusted"])
        self.assertTrue(prov["legacy"])

    def test_valid_stamp_round_trips(self):
        data = stamp_provenance({}, "gen", untrusted=False)
        prov = provenance_of(data)
        self.assertFalse(prov["untrusted"])
        self.assertFalse(prov["legacy"])
        self.assertEqual(prov["generator"], "gen")

    def test_list_aggregates_untrusted(self):
        paths = [stamp_provenance({"id": "a"}, "g", untrusted=False),
                 {"id": "b"}]
        prov = provenance_of(paths)
        self.assertTrue(prov["untrusted"])   # unstamped element wins
        self.assertFalse(prov["legacy"])

    def test_scalar_reads_untrusted(self):
        self.assertTrue(provenance_of(None)["untrusted"])


class TestMarkSchemaValidated(unittest.TestCase):

    def test_flips_valid_stamp(self):
        data = stamp_provenance({}, "gen")
        self.assertTrue(mark_schema_validated(data))
        self.assertTrue(data[PROVENANCE_KEY]["schema_validated"])
        # Second call is a no-op
        self.assertFalse(mark_schema_validated(data))

    def test_never_creates_a_stamp(self):
        data = {"a": 1}
        self.assertFalse(mark_schema_validated(data))
        self.assertNotIn(PROVENANCE_KEY, data)

    def test_ignores_malformed_stamp(self):
        data = {PROVENANCE_KEY: {"generator": 5}}
        self.assertFalse(mark_schema_validated(data))


class TestFreeText(unittest.TestCase):

    def test_sanitise_defangs_marked_fields_only(self):
        cm = {
            "sources": [{"trust": "# heading\nprose",
                         "entry": "# not-marked"}],
            "sink_details": [{"notes": "\x1b[31mred\x1b[0m",
                              "operation": "# code_marker(x)"}],
        }
        changed = sanitise_free_text(cm, CONTEXT_MAP_TEXT_SCHEMA)
        self.assertEqual(sorted(changed),
                         ["sink_details[0].notes", "sources[0].trust"])
        self.assertNotIn("\x1b", cm["sink_details"][0]["notes"])
        # Unmarked (identifier / code) fields untouched
        self.assertEqual(cm["sources"][0]["entry"], "# not-marked")
        self.assertEqual(cm["sink_details"][0]["operation"], "# code_marker(x)")

    def test_sanitise_is_idempotent(self):
        cm = {"sources": [{"trust": "* bullet\n`tick`"}]}
        sanitise_free_text(cm, CONTEXT_MAP_TEXT_SCHEMA)
        self.assertEqual(
            check_free_text_idempotent(cm, CONTEXT_MAP_TEXT_SCHEMA), [])

    def test_idempotence_check_pinpoints_field(self):
        trace = {"steps": [{"description": "clean"},
                           {"description": "# dirty"}]}
        offenders = check_free_text_idempotent(trace, FLOW_TRACE_TEXT_SCHEMA)
        self.assertEqual(offenders, ["steps[1].description"])

    def test_variants_schema_covers_nested_prose(self):
        variants = {
            "variants": [{"notes": "# md"}],
            "root_cause_groups": [{"description": "ok",
                                   "fix_strategy": "\x07bell"}],
            "validation_scope": {"note": "plain"},
        }
        offenders = check_free_text_idempotent(variants, VARIANTS_TEXT_SCHEMA)
        self.assertEqual(sorted(offenders),
                         ["root_cause_groups[0].fix_strategy",
                          "variants[0].notes"])

    def test_marked_string_items_in_arrays(self):
        # attack-path style: blockers is an array of marked strings
        schema = {"properties": {"blockers": {
            "items": {"x_free_text": True}}}}
        data = {"blockers": ["clean", "# dirty"]}
        offenders = check_free_text_idempotent(data, schema)
        self.assertEqual(offenders, ["blockers[1]"])
        sanitise_free_text(data, schema)
        self.assertEqual(data["blockers"][1], " dirty")

    def test_union_marked_items_recurse_into_objects(self):
        # steps: string or {action, result} — both forms covered
        schema = {"properties": {"steps": {"items": {
            "x_free_text": True,
            "properties": {"action": {"x_free_text": True}},
        }}}}
        data = {"steps": ["# str-form", {"action": "# obj-form"}]}
        offenders = check_free_text_idempotent(data, schema)
        self.assertEqual(sorted(offenders),
                         ["steps[0]", "steps[1].action"])

    def test_iter_yields_nothing_for_unmarked_schema(self):
        self.assertEqual(
            list(iter_free_text_fields({"a": "# x"}, {"properties": {
                "a": {"type": "string"}}})),
            [])

    def test_sanitise_caps_hostile_blob(self):
        blob = "A" * 100_000
        out = sanitise_artifact_text(blob)
        self.assertLessEqual(len(out), 20_000)

    def test_artifact_text_schemas_registry(self):
        self.assertEqual(
            set(ARTIFACT_TEXT_SCHEMAS),
            {"context-map", "flow-trace", "variants", "bug-report"})


if __name__ == "__main__":
    unittest.main()
