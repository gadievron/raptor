"""token_checks vocabulary channel: elicitation, parsing, persistence.

The token-enforcement map's check idiom is LEARNED through the study
vocabulary (learn-vocab rule) — pinned here with the same shape as the
other channels (test_study_vocabulary conventions):

1. ELICITATION — prompt + response schema carry ``token_checks``, and
   the prompt demands behaviour-based classification (a minting decoy
   with a token-shaped name must not qualify; a validator without one
   must).
2. HONEST BOUNDARIES — names absent from the batch's study items are
   discarded and recorded.
3. PROVENANCE — gate_checks corroboration earns mechanical tier,
   otherwise llm_summarized.
4. PERSISTENCE — DomainModel round-trips ``token_checks``; pass-merge
   keeps it; the loader tolerates models that predate the field.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from core.concepts.model import DomainModel, StudyItem
from core.concepts.receipts import TIER_LLM_SUMMARIZED, TIER_MECHANICAL
from core.concepts.study import (
    _RESPONSE_SCHEMA,
    _SYSTEM_PROMPT,
    _assemble_vocabulary,
    _merge_domain_models,
    _parse_api_vocabulary,
)


def _items() -> list[StudyItem]:
    return [
        StudyItem(
            id="func_om_verify_request_stamp",
            kind="function",
            name="om_verify_request_stamp",
            file="lib/guard.php",
            line=21,
            definition=(
                "function om_verify_request_stamp() {\n"
                "    if (!hash_equals($_SESSION['om_stamp'], "
                "$_POST['om_stamp'])) { die('bad'); }\n}"
            ),
            gate_checks=["if (!om_verify_request_stamp())"],
        ),
        StudyItem(
            id="func_om_issue_stamp",
            kind="function",
            name="om_issue_stamp",
            file="lib/guard.php",
            line=8,
            definition=(
                "function om_issue_stamp() {\n"
                "    $_SESSION['om_stamp'] = bin2hex(random_bytes(16));\n}"
            ),
        ),
    ]


def _vocab(**over):
    base = {"token_checks": [
        {"name": "om_verify_request_stamp", "kind": "csrf",
         "when": "compares POST stamp to session; dies on mismatch"},
    ]}
    base.update(over)
    return {"api_vocabulary": base}


class TestElicitation:
    def test_prompt_carries_the_class_and_behaviour_rule(self):
        assert "`token_checks`" in _SYSTEM_PROMPT
        assert "anti-request-forgery" in _SYSTEM_PROMPT
        # Behaviour over name-shape: the seeds discover, never classify.
        assert "classify by the enforcement BEHAVIOUR" in _SYSTEM_PROMPT
        assert "MINTS or ECHOES a token never" in _SYSTEM_PROMPT

    def test_schema_carries_token_checks(self):
        vocab = _RESPONSE_SCHEMA["properties"]["api_vocabulary"]
        tc = vocab["properties"]["token_checks"]
        assert tc["items"]["required"] == ["name"]
        assert tc["items"]["properties"]["kind"]["enum"] == [
            "csrf", "nonce", "other",
        ]


class TestParsing:
    def test_verified_entry_kept_with_fields(self):
        entries = _parse_api_vocabulary(_vocab(), _items())
        (tc,) = [e for e in entries if e["class"] == "token_checks"]
        assert tc["name"] == "om_verify_request_stamp"
        assert tc["kind"] == "csrf"
        assert tc["when"].startswith("compares POST stamp")

    def test_hallucinated_name_discarded_and_recorded(self):
        sink: list = []
        entries = _parse_api_vocabulary(
            _vocab(token_checks=[{"name": "wp_verify_nonce"}]),
            _items(), discard_sink=sink,
        )
        assert not [e for e in entries if e["class"] == "token_checks"]
        assert sink and sink[0]["kind"] == "vocab:token_checks"
        assert sink[0]["id"] == "wp_verify_nonce"

    def test_gate_signal_corroboration_is_mechanical(self):
        entries = _parse_api_vocabulary(_vocab(), _items())
        (tc,) = [e for e in entries if e["class"] == "token_checks"]
        assert tc["provenance"] == TIER_MECHANICAL

    def test_uncorroborated_is_llm_summarized(self):
        entries = _parse_api_vocabulary(
            _vocab(token_checks=[{"name": "om_issue_stamp"}]), _items(),
        )
        (tc,) = [e for e in entries if e["class"] == "token_checks"]
        assert tc["provenance"] == TIER_LLM_SUMMARIZED

    def test_default_kind_is_other(self):
        entries = _parse_api_vocabulary(
            _vocab(token_checks=[{"name": "om_verify_request_stamp"}]),
            _items(),
        )
        (tc,) = [e for e in entries if e["class"] == "token_checks"]
        assert tc["kind"] == "other"


class TestAssemblyAndPersistence:
    def test_assembly_dedups_and_prefers_stronger_tier(self):
        (_, _, _, _, _, _, _, token_checks) = _assemble_vocabulary([
            {"class": "token_checks", "name": "om_verify_request_stamp",
             "kind": "csrf", "provenance": TIER_LLM_SUMMARIZED},
            {"class": "token_checks", "name": "om_verify_request_stamp",
             "kind": "csrf", "provenance": TIER_MECHANICAL},
        ])
        assert len(token_checks) == 1
        assert token_checks[0]["provenance"] == TIER_MECHANICAL

    def test_model_round_trips_token_checks(self, tmp_path):
        model = DomainModel(target="t", token_checks=[
            {"name": "om_verify_request_stamp", "kind": "csrf",
             "provenance": TIER_MECHANICAL},
        ])
        path = tmp_path / "domain-model.json"
        model.save(path)
        loaded = DomainModel.load(path)
        assert loaded.token_checks == model.token_checks
        assert "token_checks" in asdict(model)

    def test_loader_tolerates_pre_field_models(self, tmp_path):
        path = tmp_path / "domain-model.json"
        path.write_text(json.dumps({"version": "1", "concepts": []}))
        assert DomainModel.load(path).token_checks == []

    def test_loader_drops_non_dict_records(self, tmp_path):
        path = tmp_path / "domain-model.json"
        path.write_text(json.dumps({
            "token_checks": ["bare-string", {"name": "ok"}, 7],
        }))
        assert DomainModel.load(path).token_checks == [{"name": "ok"}]

    def test_merge_keeps_token_checks_across_passes(self):
        prior = DomainModel(token_checks=[
            {"name": "old_check", "kind": "csrf"},
        ])
        new = DomainModel(token_checks=[
            {"name": "new_check", "kind": "nonce"},
        ])
        merged = _merge_domain_models(prior, new)
        assert {t["name"] for t in merged.token_checks} == {
            "old_check", "new_check",
        }
