"""Token-enforcement map: projection pins, mutants, drift, adapters.

The fixture app (``fixtures/token_php_app``) carries one entry per
projection behaviour; every pin below has a mutant proving the
behaviour flips when the code shape flips (two-direction doctrine):

1. ENFORCED       — direct pre-output call (save_prefs.php); mutant:
   removing the call flips to not_enforced, moving it after output
   flips to not_enforced with the post-output note.
2. INDIRECT       — check reached through a wrapper (delete_item.php);
   mutant: emptying the wrapper flips to not_enforced.
3. NOT ENFORCED   — absence census (export_data.php); mutant: adding
   the call flips to enforced.
4. UNKNOWN        — dynamic dispatch (dispatch.php); mutant: replacing
   the dynamic call with the check flips to enforced (a positive
   witness beats the dynamic poison).
5. CONDITIONAL    — skip-path entry (options_save.php) maps enforced
   WITH the conditional flag; mutant: unwrapping the conditional
   drops the flag. This is the honesty pin behind "enforced never
   suppresses".
6. POST-OUTPUT    — late_check.php is not credited.
7. TRUNCATION     — every truncated search (call-depth cap, include
   depth cap, splice budget) degrades to unknown, never to a false
   absence; synthetic trees pin each bound in both directions.
8. TAG SEMANTICS  — ``<?=`` is an output event; a bare ``<?`` region
   is config-dependent and poisons to unknown in both directions.

Learned-not-hardcoded: the fixture's check function name carries no
token/csrf/nonce substring (seed_match False) while a minting decoy
does — identification comes from the study channel, never the seeds.
"""

from __future__ import annotations

import json
import re
import shutil
import time
from pathlib import Path

from core.concepts.token_map import (
    MAX_CALL_DEPTH,
    MAX_INCLUDE_DEPTH,
    TOKEN_SEED_RE,
    _inline_html_offsets,
    _php_code_spans,
    _strip_php,
    annotate_entry_points,
    build_token_map,
    entries_from_checklist,
    entries_from_context_map,
    learned_check_functions,
    load_token_map,
    project_token_map_for_run,
    save_token_map,
    token_map_drift,
)

FIXTURE = Path(__file__).parent / "fixtures" / "token_php_app"

MODEL = {
    "token_checks": [
        {"name": "om_verify_request_stamp", "kind": "csrf",
         "provenance": "mechanical"},
    ],
}


def _entries(root: Path) -> list[dict]:
    return [
        {"entry": p.name, "file": f"web/{p.name}"}
        for p in sorted((root / "web").glob("*.php"))
    ]


def _project(root: Path, model=None) -> dict:
    return build_token_map(model or MODEL, _entries(root), root)


def _by_file(payload: dict) -> dict:
    return {r["file"]: r for r in payload["entries"]}


def _mutant(tmp_path: Path) -> Path:
    root = tmp_path / "app"
    shutil.copytree(FIXTURE, root)
    return root


class TestFixtureProjection:
    def test_direct_call_is_enforced(self):
        rec = _by_file(_project(FIXTURE))["web/save_prefs.php"]
        assert rec["status"] == "enforced"
        assert rec["via"] == "om_verify_request_stamp"
        assert rec["call_path"] == [
            "web/save_prefs.php", "om_verify_request_stamp",
        ]
        assert "conditional" not in rec

    def test_wrapper_call_is_indirect_with_path(self):
        rec = _by_file(_project(FIXTURE))["web/delete_item.php"]
        assert rec["status"] == "indirect"
        assert rec["via"] == "om_verify_request_stamp"
        assert rec["call_path"] == [
            "web/delete_item.php", "om_require_valid_request",
            "om_verify_request_stamp",
        ]
        # Honesty: the record says what the projection did NOT check.
        assert "branch conditions not analysed" in rec["evidence"]

    def test_absence_is_not_enforced_with_census(self):
        rec = _by_file(_project(FIXTURE))["web/export_data.php"]
        assert rec["status"] == "not_enforced"
        assert "om_load_data" in rec["census_calls"]

    def test_dynamic_dispatch_is_unknown_never_not_enforced(self):
        rec = _by_file(_project(FIXTURE))["web/dispatch.php"]
        assert rec["status"] == "unknown"
        assert "dynamic dispatch" in rec["reason"]

    def test_skip_path_maps_enforced_but_conditional(self):
        rec = _by_file(_project(FIXTURE))["web/options_save.php"]
        assert rec["status"] == "enforced"
        assert rec["conditional"] is True
        assert "conditional branch" in rec["evidence"]

    def test_post_output_check_not_credited(self):
        rec = _by_file(_project(FIXTURE))["web/late_check.php"]
        assert rec["status"] == "not_enforced"
        assert "after output begins" in rec["evidence"]
        assert "om_verify_request_stamp" in rec["evidence"]

    def test_census_totals(self):
        payload = _project(FIXTURE)
        assert payload["census"] == {
            "enforced": 2, "indirect": 1, "not_enforced": 2, "unknown": 1,
        }

    def test_artifact_carries_honesty_contract(self):
        payload = _project(FIXTURE)
        assert "never bypass-freedom" in payload["honesty"]
        assert "no consumer may suppress" in payload["honesty"]

    def test_learned_name_needs_no_seed_match(self):
        checks = _project(FIXTURE)["check_functions"]
        assert checks[0]["seed_match"] is False
        # The decoy names DO match the discovery shape — proving the
        # seeds could not have picked the real check by themselves.
        assert TOKEN_SEED_RE.search("om_token_value")
        assert not TOKEN_SEED_RE.search("om_verify_request_stamp")


class TestMutants:
    def test_removed_check_flips_to_not_enforced(self, tmp_path):
        root = _mutant(tmp_path)
        f = root / "web" / "save_prefs.php"
        f.write_text(
            f.read_text().replace("om_verify_request_stamp();\n", ""),
        )
        rec = _by_file(_project(root))["web/save_prefs.php"]
        assert rec["status"] == "not_enforced"

    def test_check_moved_after_output_flips_to_not_enforced(self, tmp_path):
        root = _mutant(tmp_path)
        f = root / "web" / "save_prefs.php"
        text = f.read_text().replace("om_verify_request_stamp();\n", "")
        f.write_text(text + "\nom_verify_request_stamp();\n")
        rec = _by_file(_project(root))["web/save_prefs.php"]
        assert rec["status"] == "not_enforced"
        assert "after output begins" in rec["evidence"]

    def test_emptied_wrapper_flips_indirect_to_not_enforced(self, tmp_path):
        root = _mutant(tmp_path)
        f = root / "lib" / "guard.php"
        f.write_text(f.read_text().replace(
            "function om_require_valid_request() {\n"
            "    // Indirection layer: entries calling this are enforced one hop\n"
            "    // away from the check itself.\n"
            "    om_verify_request_stamp();\n"
            "}",
            "function om_require_valid_request() {\n    return true;\n}",
        ))
        rec = _by_file(_project(root))["web/delete_item.php"]
        assert rec["status"] == "not_enforced"

    def test_added_check_flips_not_enforced_to_enforced(self, tmp_path):
        root = _mutant(tmp_path)
        f = root / "web" / "export_data.php"
        f.write_text(f.read_text().replace(
            "$what =", "om_verify_request_stamp();\n$what =",
        ))
        rec = _by_file(_project(root))["web/export_data.php"]
        assert rec["status"] == "enforced"

    def test_direct_witness_beats_dynamic_poison(self, tmp_path):
        root = _mutant(tmp_path)
        f = root / "web" / "dispatch.php"
        f.write_text(f.read_text().replace(
            "$handler();", "$handler();\nom_verify_request_stamp();",
        ))
        rec = _by_file(_project(root))["web/dispatch.php"]
        assert rec["status"] == "enforced"

    def test_unwrapped_conditional_drops_the_flag(self, tmp_path):
        root = _mutant(tmp_path)
        f = root / "web" / "options_save.php"
        f.write_text(f.read_text().replace(
            "if (!isset($_GET['quick'])) {\n"
            "    om_verify_request_stamp();\n"
            "}",
            "om_verify_request_stamp();",
        ))
        rec = _by_file(_project(root))["web/options_save.php"]
        assert rec["status"] == "enforced"
        assert "conditional" not in rec

    def test_unbalanced_braces_are_unknown_parse_failure(self, tmp_path):
        root = _mutant(tmp_path)
        f = root / "web" / "save_prefs.php"
        f.write_text("<?php\nfunction broken() {\nom_load_data('x');\n")
        rec = _by_file(_project(root))["web/save_prefs.php"]
        assert rec["status"] == "unknown"
        assert "parse failure" in rec["reason"]

    def test_dynamic_include_is_unknown(self, tmp_path):
        root = _mutant(tmp_path)
        f = root / "web" / "export_data.php"
        f.write_text(f.read_text().replace(
            "require_once __DIR__ . '/../lib/guard.php';",
            "require_once $_GET['lib'];",
        ))
        rec = _by_file(_project(root))["web/export_data.php"]
        assert rec["status"] == "unknown"
        assert "include" in rec["evidence"]

    def test_depth_cap_two_directions(self, tmp_path):
        # Within the cap → indirect; one hop past it → the search is
        # TRUNCATED, so no absence claim: unknown, never not_enforced
        # (a deeper-than-cap real chain must not read as a false
        # absence). Both directions pin MAX_CALL_DEPTH exactly.
        for hops, expected in (
            (MAX_CALL_DEPTH, "indirect"),
            (MAX_CALL_DEPTH + 1, "unknown"),
        ):
            root = tmp_path / f"chain{hops}"
            (root / "web").mkdir(parents=True)
            chain = "<?php\n"
            for i in range(hops):
                callee = (
                    f"hop{i + 1}" if i + 1 < hops
                    else "om_verify_request_stamp"
                )
                chain += f"function hop{i}() {{ {callee}(); }}\n"
            chain += (
                "function om_verify_request_stamp() { die('no'); }\n"
            )
            (root / "web" / "guard.php").write_text(chain)
            (root / "web" / "entry.php").write_text(
                "<?php\nrequire_once __DIR__ . '/guard.php';\n"
                "hop0();\necho 'x';\n",
            )
            payload = build_token_map(
                MODEL, [{"entry": "entry", "file": "web/entry.php"}], root,
            )
            rec = payload["entries"][0]
            assert rec["status"] == expected, hops
            if expected == "unknown":
                assert "call-depth cap" in rec["reason"]
                assert "absence unproven" in rec["evidence"]


def _single_entry(root: Path, model=None) -> dict:
    payload = build_token_map(
        model or MODEL, [{"entry": "e", "file": "web/entry.php"}], root,
    )
    return payload["entries"][0]


class TestSpliceBudget:
    def _fanout(self, root: Path, k: int, depth: int) -> None:
        (root / "web").mkdir(parents=True)
        for lvl in range(depth):
            if lvl < depth - 1:
                body = "<?php\n" + f"require 'l{lvl + 1}.php';\n" * k
            else:
                body = "<?php\n$x = 1;\n"
            (root / "web" / f"l{lvl}.php").write_text(body)
        (root / "web" / "entry.php").write_text(
            "<?php\nrequire 'l0.php';\nom_do_write($_POST['id']);\n",
        )

    def test_within_budget_projects_normally(self, tmp_path):
        # Direction one of MAX_TOTAL_SPLICES: a legitimate linear
        # include chain (a handful of splices) still reaches a normal
        # absence census.
        root = tmp_path / "app"
        self._fanout(root, k=1, depth=5)
        rec = _single_entry(root)
        assert rec["status"] == "not_enforced"
        assert "om_do_write" in rec["census_calls"]

    def test_fanout_over_budget_is_unknown_and_bounded(self, tmp_path):
        # Direction two: K same-target requires per level x depth is
        # K^depth splices without the budget (5^6 = 15625 here — an
        # OOM-shaped hostile tree at larger K/file sizes). Over
        # budget: bounded work AND no absence claim.
        root = tmp_path / "app"
        self._fanout(root, k=5, depth=7)
        t0 = time.monotonic()
        rec = _single_entry(root)
        # Generous absolute bound (load-tolerant): the unbudgeted
        # shape took tens of seconds and hundreds of MB.
        assert time.monotonic() - t0 < 10.0
        assert rec["status"] == "unknown"
        assert "splice budget exhausted" in rec["evidence"]

    def test_budget_never_hides_an_earlier_witness(self, tmp_path):
        # The check call sits BEFORE the hostile fan-out: the direct
        # witness is real and survives the budget degradation (the
        # budget poisons absence claims only).
        root = tmp_path / "app"
        self._fanout(root, k=5, depth=7)
        (root / "web" / "entry.php").write_text(
            "<?php\nom_verify_request_stamp();\nrequire 'l0.php';\n",
        )
        assert _single_entry(root)["status"] == "enforced"

    def test_include_depth_cap_two_directions(self, tmp_path):
        # A check reached within MAX_INCLUDE_DEPTH splices is a
        # witness; one level past the cap the splice is refused and
        # the entry degrades to unknown (a silent skip would fabricate
        # absence).
        for depth, expected in (
            (MAX_INCLUDE_DEPTH, "enforced"),
            (MAX_INCLUDE_DEPTH + 1, "unknown"),
        ):
            root = tmp_path / f"d{depth}"
            (root / "web").mkdir(parents=True)
            for lvl in range(depth):
                if lvl < depth - 1:
                    body = f"<?php\nrequire 'l{lvl + 1}.php';\n"
                else:
                    body = "<?php\nom_verify_request_stamp();\n"
                (root / "web" / f"l{lvl}.php").write_text(body)
            (root / "web" / "entry.php").write_text(
                "<?php\nrequire 'l0.php';\n",
            )
            rec = _single_entry(root)
            assert rec["status"] == expected, depth
            if expected == "unknown":
                assert "include depth cap" in rec["evidence"]


class TestShortTags:
    def test_short_echo_tag_is_an_output_event(self, tmp_path):
        # <?= always emits — a check after it is post-output and must
        # not be credited as a pre-output witness.
        root = tmp_path / "app"
        (root / "web").mkdir(parents=True)
        (root / "web" / "entry.php").write_text(
            "<?= $greeting ?>\n<?php\nom_verify_request_stamp();\n"
            "om_do_write($_POST['id']);\n",
        )
        rec = _single_entry(root)
        assert rec["status"] == "not_enforced"
        assert "after output begins" in rec["evidence"]

    def test_without_short_echo_the_check_is_credited(self, tmp_path):
        # Direction two: drop the <?= and the same check is a normal
        # pre-output direct witness.
        root = tmp_path / "app"
        (root / "web").mkdir(parents=True)
        (root / "web" / "entry.php").write_text(
            "<?php\nom_verify_request_stamp();\n"
            "om_do_write($_POST['id']);\n",
        )
        assert _single_entry(root)["status"] == "enforced"

    def test_short_open_tag_region_is_unknown(self, tmp_path):
        # <? ... ?> is code under short_open_tag=On and literal output
        # under Off — statically undecidable. A check INSIDE the short
        # region is never credited, and the region poisons the entry's
        # absence claim to unknown (under On the region could hold the
        # check; claiming not_enforced would be a false absence).
        root = tmp_path / "app"
        (root / "web").mkdir(parents=True)
        (root / "web" / "entry.php").write_text(
            "<? om_verify_request_stamp(); ?>\n<?php\n"
            "om_do_write($_POST['id']);\n",
        )
        rec = _single_entry(root)
        assert rec["status"] == "unknown"
        assert "short open tag" in rec["evidence"]

    def test_full_tag_variant_is_a_normal_witness(self, tmp_path):
        # Direction two: the same code under a full <?php tag is a
        # plain direct witness.
        root = tmp_path / "app"
        (root / "web").mkdir(parents=True)
        (root / "web" / "entry.php").write_text(
            "<?php om_verify_request_stamp(); ?>\n<?php\n"
            "om_do_write($_POST['id']);\n",
        )
        assert _single_entry(root)["status"] == "enforced"


class TestLexerBounds:
    def test_include_argument_bound_two_directions(self, tmp_path):
        # Under the 512-char include-argument bound the statement is
        # SEEN (unresolvable literal → dynamic poison → unknown); over
        # the bound it produces no event at all and the entry falls to
        # the absence census — degradation toward fewer claims, never
        # toward unbounded scan cost.
        for arg_len, expected in ((400, "unknown"), (600, "not_enforced")):
            root = tmp_path / f"a{arg_len}"
            (root / "web").mkdir(parents=True)
            longpath = "'" + "x" * (arg_len - 2) + "'"
            (root / "web" / "entry.php").write_text(
                f"<?php\nrequire {longpath};\n"
                "om_do_write($_POST['id']);\n",
            )
            assert _single_entry(root)["status"] == expected, arg_len

    def test_identifier_bound_two_directions(self, tmp_path):
        # 128-char identifiers are captured as call events (witness
        # still earned); 129-char identifiers produce no event (no
        # claim minted, bounded scan cost).
        for length, expected in ((128, "enforced"), (129, "not_enforced")):
            name = "c" * length
            model = {"token_checks": [
                {"name": name, "kind": "csrf",
                 "provenance": "mechanical"},
            ]}
            root = tmp_path / f"n{length}"
            (root / "web").mkdir(parents=True)
            (root / "web" / "entry.php").write_text(
                f"<?php\n{name}();\nom_do_write($_POST['id']);\n",
            )
            assert _single_entry(root, model)["status"] == expected, length


class TestHostileInputPerformance:
    # Absolute generous bounds, not ratios: ratio-shaped timing tests
    # flake under CI load. Margins are wide in both directions — the
    # quadratic slice-pump shapes these pin against ran minutes-to-OOM
    # at these sizes, while the position-anchored implementations
    # finish in well under a second.

    def test_tag_dense_input_is_linear_shaped(self):
        text = "<? $a=1; ?>x" * 200_000
        t0 = time.monotonic()
        spans = _php_code_spans(text)
        _inline_html_offsets(text, spans)
        assert time.monotonic() - t0 < 5.0
        assert len(spans) == 200_000

    def test_shift_operator_dense_strip_is_linear_shaped(self):
        text = "<?php " + "$a=$b<<1;" * 200_000
        t0 = time.monotonic()
        stripped = _strip_php(text)
        assert time.monotonic() - t0 < 5.0
        assert len(stripped) == len(text)


class TestSourceDigest:
    def test_records_carry_content_digest(self):
        for rec in _project(FIXTURE)["entries"]:
            assert re.fullmatch(r"[0-9a-f]{16}", rec["source_sha256"])

    def test_digest_tracks_content_not_time(self, tmp_path):
        # Same content → same digest (the payload stays deterministic
        # — no timestamp); edited content → different digest, which is
        # what the audit-bridge staleness marker keys on.
        root = _mutant(tmp_path)
        a = _by_file(_project(root))["web/save_prefs.php"]["source_sha256"]
        b = _by_file(_project(root))["web/save_prefs.php"]["source_sha256"]
        assert a == b
        f = root / "web" / "save_prefs.php"
        f.write_text(f.read_text() + "\n$om_rev = 2;\n")
        c = _by_file(_project(root))["web/save_prefs.php"]["source_sha256"]
        assert c != a


class TestLearnedChecks:
    def test_invalid_names_dropped(self):
        model = {"token_checks": [
            {"name": "ok_name"},
            {"name": "bad name; rm -rf"},
            {"name": ""},
            "not-a-dict",
        ]}
        checks = learned_check_functions(model)
        assert [c["name"] for c in checks] == ["ok_name"]
        assert checks[0]["kind"] == "other"

    def test_no_learned_checks_projects_nothing(self):
        payload = build_token_map(
            {"token_checks": []}, _entries(FIXTURE), FIXTURE,
        )
        assert payload["entries"] == []
        assert "no token check function learned" in payload["note"]

    def test_entry_outside_root_is_unknown(self, tmp_path):
        outside = tmp_path / "elsewhere.php"
        outside.write_text("<?php echo 'x';\n")
        payload = build_token_map(
            MODEL, [{"entry": "e", "file": str(outside)}], FIXTURE,
        )
        assert payload["entries"][0]["status"] == "unknown"
        assert "outside source root" in payload["entries"][0]["reason"]


class TestAdapters:
    def test_entries_from_context_map(self):
        cm = {"entry_points": [
            {"id": "EP-001", "file": "web/save_prefs.php", "line": 5,
             "name": "save"},
            {"id": "EP-002", "location": "web/delete_item.php:6"},
            {"id": "EP-003"},          # no file — skipped
            "not-a-dict",
        ]}
        entries = entries_from_context_map(cm)
        assert {e["file"] for e in entries} == {
            "web/save_prefs.php", "web/delete_item.php",
        }

    def test_entries_from_checklist_needs_script_handler(self):
        cl = {"files": [
            {"path": "web/a.php",
             "items": [{"name": "interstitial:1-9",
                        "script_handler": True}]},
            {"path": "lib/wiring.php",
             "items": [{"name": "interstitial:1-3",
                        "script_handler": False}]},
            {"path": "src/main.c", "items": [{"script_handler": True}]},
        ]}
        entries = entries_from_checklist(cl)
        assert [e["file"] for e in entries] == ["web/a.php"]


class TestRunProjectionHook:
    def test_projects_when_context_map_colocated(self, tmp_path):
        cm = {"entry_points": [
            {"id": "EP-001", "file": "web/save_prefs.php", "line": 5},
        ]}
        (tmp_path / "context-map.json").write_text(json.dumps(cm))
        path = project_token_map_for_run(MODEL, tmp_path, FIXTURE)
        assert path is not None
        payload = load_token_map(tmp_path)
        assert payload["entries"][0]["status"] == "enforced"

    def test_no_checks_no_artifact(self, tmp_path):
        (tmp_path / "context-map.json").write_text(json.dumps(
            {"entry_points": [{"file": "web/save_prefs.php"}]},
        ))
        assert project_token_map_for_run(
            {"token_checks": []}, tmp_path, FIXTURE,
        ) is None
        assert load_token_map(tmp_path) is None

    def test_no_entry_source_no_artifact(self, tmp_path):
        assert project_token_map_for_run(MODEL, tmp_path, FIXTURE) is None


class TestDrift:
    def _payloads(self):
        prior = _project(FIXTURE)
        current = json.loads(json.dumps(prior))
        return prior, current

    def test_lost_enforcement(self):
        prior, current = self._payloads()
        _by_file(current)["web/save_prefs.php"]["status"] = "not_enforced"
        records = token_map_drift(prior, current)
        assert records == [{
            "entry": "save_prefs.php",
            "file": "web/save_prefs.php",
            "prior_status": "enforced",
            "current_status": "not_enforced",
            "change": "lost_enforcement",
        }]

    def test_lost_visibility_is_not_lost_enforcement(self):
        prior, current = self._payloads()
        _by_file(current)["web/delete_item.php"]["status"] = "unknown"
        (rec,) = token_map_drift(prior, current)
        assert rec["change"] == "lost_visibility"

    def test_gained_enforcement(self):
        prior, current = self._payloads()
        _by_file(current)["web/export_data.php"]["status"] = "indirect"
        (rec,) = token_map_drift(prior, current)
        assert rec["change"] == "gained_enforcement"

    def test_other_transitions_are_changed(self):
        prior, current = self._payloads()
        _by_file(current)["web/dispatch.php"]["status"] = "not_enforced"
        (rec,) = token_map_drift(prior, current)
        assert rec["change"] == "changed"

    def test_one_sided_entries_skipped(self):
        prior, current = self._payloads()
        current["entries"] = [
            r for r in current["entries"]
            if r["file"] != "web/save_prefs.php"
        ]
        assert token_map_drift(prior, current) == []

    def test_check_set_change_is_flagged(self):
        prior, current = self._payloads()
        current["check_functions"] = [{"name": "renamed_check"}]
        _by_file(current)["web/save_prefs.php"]["status"] = "not_enforced"
        (rec,) = token_map_drift(prior, current)
        assert rec["check_set_changed"] == {
            "prior": ["om_verify_request_stamp"],
            "current": ["renamed_check"],
        }

    def test_no_change_no_records(self):
        prior, current = self._payloads()
        assert token_map_drift(prior, current) == []


class TestAnnotateEntryPoints:
    def test_attaches_fact_without_touching_status(self, tmp_path):
        save_token_map(_project(FIXTURE), tmp_path)
        eps = [
            {"id": "EP-001", "file": "web/export_data.php",
             "auth_required": False},
            {"id": "EP-002", "file": "web/unrelated.php"},
            "not-a-dict",
        ]
        count = annotate_entry_points(eps, tmp_path)
        assert count == 1
        fact = eps[0]["token_enforcement"]
        assert fact["status"] == "not_enforced"
        # Advisory only: no other key was added or rewritten.
        assert set(eps[0]) == {"id", "file", "auth_required",
                               "token_enforcement"}
        assert "token_enforcement" not in eps[1]

    def test_hostile_evidence_is_escaped(self, tmp_path):
        payload = _project(FIXTURE)
        rec = _by_file(payload)["web/export_data.php"]
        rec["evidence"] = "bad\x1b]0;owned\x07text"
        rec["via"] = "evil\x1bname"
        save_token_map(payload, tmp_path)
        eps = [{"file": "web/export_data.php"}]
        annotate_entry_points(eps, tmp_path)
        fact = eps[0]["token_enforcement"]
        assert "\x1b" not in fact["evidence"]
        assert "\x1b" not in json.dumps(fact)

    def test_no_map_is_a_noop(self, tmp_path):
        eps = [{"file": "web/export_data.php"}]
        assert annotate_entry_points(eps, tmp_path) == 0
        assert "token_enforcement" not in eps[0]


class TestPersistence:
    def test_round_trip(self, tmp_path):
        payload = _project(FIXTURE)
        save_token_map(payload, tmp_path)
        assert load_token_map(tmp_path) == payload

    def test_wrong_artifact_kind_rejected(self, tmp_path):
        (tmp_path / "token-map.json").write_text(
            json.dumps({"artifact": "something-else"}),
        )
        assert load_token_map(tmp_path) is None
