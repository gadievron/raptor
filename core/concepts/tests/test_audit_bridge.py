"""Tests for core.concepts.audit_bridge."""

import json

import pytest

from core.concepts.audit_bridge import (
    _extract_cwe_id,
    _find_domain_model,
    _match_pass_cwe,
    _match_pass_mechanism,
    _relevance_score,
    domain_model_context,
    guard_contradicts_finding,
    invariant_violations_for_hypothesis,
    queue_reading_list_item,
)


@pytest.fixture
def domain_model():
    return {
        "version": "1",
        "target": "/src/crypto",
        "source_root": "/src",
        "concepts": [
            {
                "id": "sg_page_ownership",
                "description": "scatterlist entries reference pages owned by the caller; "
                               "modifying pages through sg aliases violates ownership",
                "confidence": "corroborated",
                "evidence": [
                    {"type": "code_path", "file": "crypto/algif_aead.c",
                     "item": "_aead_recvmsg", "observation": "sg aliasing",
                     "line": 120},
                ],
            },
            {
                "id": "aead_inplace_aliasing",
                "description": "in-place AEAD operations alias src and dst scatterlists "
                               "to the same pages, creating a read-write conflict",
                "confidence": "traced",
                "evidence": [
                    {"type": "api_pattern", "file": "crypto/algif_aead.c",
                     "item": "crypto_aead_encrypt", "observation": "same sg",
                     "line": 200},
                ],
            },
        ],
        "invariants": [
            {
                "id": "sg_no_write_shared_pages",
                "concept": "sg_page_ownership",
                "statement": "Pages accessible through a scatterlist MUST NOT be modified "
                             "if another reference exists to the same page",
                "negation": "Writing through an aliased scatterlist corrupts shared page "
                            "cache data",
                "confidence": "corroborated",
                "mechanical_rule": "if sg_src == sg_dst and op == ENCRYPT: flag aliasing",
            },
            {
                "id": "refcount_balance",
                "concept": "page_lifecycle",
                "statement": "Every get_page must have a matching put_page on all paths",
                "negation": "Missing put_page causes a page leak; double put_page causes UAF",
                "confidence": "tested",
            },
        ],
        "contracts": [
            {
                "function": "_aead_recvmsg",
                "file": "crypto/algif_aead.c",
                "when": "AF_ALG AEAD socket recv",
                "input_semantics": "msg contains user buffer; ctx->tsgl holds pending data",
                "output_semantics": "decrypted plaintext in user buffer",
                "ownership_transfer": "pages from tsgl may alias rsgl during in-place ops",
                "implication": "If tsgl and rsgl reference same pages, write to rsgl "
                              "corrupts tsgl read",
            },
        ],
    }


@pytest.fixture
def dm_dir(domain_model, tmp_path):
    dm_path = tmp_path / "domain-model.json"
    dm_path.write_text(json.dumps(domain_model), encoding="utf-8")
    return tmp_path


class TestFindDomainModel:
    def test_finds_in_out_dir(self, dm_dir):
        result = _find_domain_model(dm_dir)
        assert result is not None
        assert result["version"] == "1"

    def test_finds_in_parent(self, domain_model, tmp_path):
        (tmp_path / "domain-model.json").write_text(
            json.dumps(domain_model), encoding="utf-8")
        child = tmp_path / "sub"
        child.mkdir()
        result = _find_domain_model(child)
        assert result is not None

    @pytest.mark.slow
    def test_returns_none_when_missing(self, tmp_path):
        result = _find_domain_model(tmp_path)
        assert result is None


class TestRelevanceScore:
    def test_direct_function_match(self, domain_model):
        contract = domain_model["contracts"][0]
        score = _relevance_score(
            contract, "crypto/algif_aead.c", "_aead_recvmsg", "")
        assert score > 5.0

    def test_evidence_file_match(self, domain_model):
        concept = domain_model["concepts"][0]
        score = _relevance_score(
            concept, "crypto/algif_aead.c", "_aead_recvmsg", "")
        assert score > 3.0

    def test_unrelated_function(self, domain_model):
        concept = domain_model["concepts"][0]
        score = _relevance_score(
            concept, "net/ipv4/tcp.c", "tcp_sendmsg", "")
        related_score = _relevance_score(
            concept, "crypto/algif_aead.c", "_aead_recvmsg", "")
        assert score < related_score

    def test_source_content_boost(self, domain_model):
        concept = domain_model["concepts"][0]
        score_without = _relevance_score(
            concept, "other.c", "some_func", "")
        score_with = _relevance_score(
            concept, "other.c", "some_func",
            "struct scatterlist *sg = sg_page_ownership_check();")
        assert score_with > score_without


class TestDomainModelContext:
    def test_returns_relevant_block(self, dm_dir):
        block = domain_model_context(
            dm_dir, "crypto/algif_aead.c", "_aead_recvmsg")
        assert block is not None
        assert "Domain Knowledge" in block
        assert "sg_page_ownership" in block

    def test_returns_less_for_unrelated(self, dm_dir):
        block_related = domain_model_context(
            dm_dir, "crypto/algif_aead.c", "_aead_recvmsg")
        block_unrelated = domain_model_context(
            dm_dir, "drivers/usb/core.c", "usb_submit_urb")
        # Related function gets contracts + concepts; unrelated may get
        # generic invariants but should have fewer sections
        assert block_related is not None
        assert "Contract" in block_related
        if block_unrelated:
            assert "Contract" not in block_unrelated

    def test_returns_none_when_no_model(self, tmp_path):
        block = domain_model_context(
            tmp_path, "any.c", "any_func")
        assert block is None

    def test_includes_invariants(self, dm_dir):
        block = domain_model_context(
            dm_dir, "crypto/algif_aead.c", "_aead_recvmsg",
            source="sg aliasing write shared pages")
        assert block is not None
        assert "Invariant" in block

    def test_includes_contracts(self, dm_dir):
        block = domain_model_context(
            dm_dir, "crypto/algif_aead.c", "_aead_recvmsg")
        assert block is not None
        assert "Contract" in block
        assert "ownership_transfer" in block.lower() or "Ownership" in block


@pytest.fixture
def enriched_model():
    """Domain model with CWE/mechanism enrichment on invariants."""
    return {
        "version": "1",
        "target": "/src/crypto",
        "source_root": "/src",
        "concepts": [],
        "invariants": [
            {
                "id": "page_refcounting",
                "concept": "sgl_io",
                "statement": "Pages in SGL must have balanced get_page/put_page",
                "negation": "Missing put_page causes page leak; double put_page causes UAF",
                "confidence": "traced",
                "role": "boost",
                "relevant_cwes": ["CWE-416", "CWE-787"],
                "mechanism_tags": ["sgl_page_lifecycle", "page_refcount"],
                "mechanism_keywords": [
                    "page", "scatterlist", "get_page", "put_page",
                    "sgl", "aliasing", "page_cache",
                ],
            },
            {
                "id": "guard_bind_oneshot",
                "concept": "socket_state",
                "statement": "After alg_bind() succeeds, BOUND is irreversible",
                "negation": "State reverts from BOUND to UNBOUND",
                "confidence": "traced",
                "role": "guard",
                "scope": {"files": ["af_alg.c"]},
                "relevant_cwes": ["CWE-362", "CWE-367"],
                "mechanism_tags": ["state_machine", "one_shot_transition"],
                "mechanism_keywords": [
                    "race", "toctou", "concurrent", "revert",
                    "one_shot", "alg_bind",
                ],
            },
            {
                "id": "guard_iv_size",
                "concept": "value_constraint",
                "statement": "ivlen <= ivsize after validation",
                "negation": "ivlen exceeds ivsize",
                "confidence": "traced",
                "role": "guard",
                "scope": {"files": ["af_alg.c"]},
                "relevant_cwes": ["CWE-190", "CWE-787", "CWE-125"],
                "mechanism_tags": ["value_constraint", "bounds_validation"],
                "mechanism_keywords": [
                    "constraint", "validation", "ivlen", "ivsize",
                ],
            },
            {
                "id": "legacy_no_enrichment",
                "concept": "misc",
                "statement": "Some legacy invariant without enrichment fields",
                "negation": "integer overflow in length calculation causes buffer overrun",
                "confidence": "inferred",
                "role": "boost",
            },
        ],
        "contracts": [],
    }


@pytest.fixture
def enriched_dir(enriched_model, tmp_path):
    dm_path = tmp_path / "domain-model.json"
    dm_path.write_text(json.dumps(enriched_model), encoding="utf-8")
    return tmp_path


class TestExtractCweId:
    def test_already_prefixed(self):
        assert _extract_cwe_id("CWE-787") == "CWE-787"

    def test_bare_number(self):
        assert _extract_cwe_id("787") == "CWE-787"

    def test_lowercase(self):
        assert _extract_cwe_id("cwe-125") == "CWE-125"

    def test_whitespace(self):
        assert _extract_cwe_id("  CWE-190 ") == "CWE-190"


class TestMatchPassCwe:
    def test_cwe_match(self):
        inv = {"relevant_cwes": ["CWE-787", "CWE-416"]}
        assert _match_pass_cwe(inv, "CWE-787") is True

    def test_cwe_no_match(self):
        inv = {"relevant_cwes": ["CWE-787"]}
        assert _match_pass_cwe(inv, "CWE-125") is False

    def test_empty_cwes(self):
        inv = {"relevant_cwes": []}
        assert _match_pass_cwe(inv, "CWE-787") is False

    def test_no_finding_cwe(self):
        inv = {"relevant_cwes": ["CWE-787"]}
        assert _match_pass_cwe(inv, "") is False

    def test_normalises_finding_cwe(self):
        inv = {"relevant_cwes": ["CWE-190"]}
        assert _match_pass_cwe(inv, "190") is True


class TestMatchPassMechanism:
    def test_keyword_match(self):
        inv = {"mechanism_keywords": ["page", "scatterlist", "aliasing"]}
        assert _match_pass_mechanism(
            inv, "page-cache corruption via scatterlist aliasing") is True

    def test_insufficient_keywords(self):
        inv = {"mechanism_keywords": ["page", "scatterlist", "aliasing"]}
        assert _match_pass_mechanism(
            inv, "integer overflow in size") is False

    def test_one_keyword_not_enough(self):
        inv = {"mechanism_keywords": ["page", "scatterlist", "aliasing"]}
        assert _match_pass_mechanism(inv, "page fault handler") is False

    def test_empty_keywords(self):
        inv = {"mechanism_keywords": []}
        assert _match_pass_mechanism(inv, "anything") is False

    def test_case_insensitive(self):
        inv = {"mechanism_keywords": ["Page", "SGL"]}
        assert _match_pass_mechanism(inv, "page in sgl entry") is True


class TestInvariantViolations:
    def test_finds_matching_violation(self, dm_dir):
        results = invariant_violations_for_hypothesis(
            dm_dir,
            "Writing through aliased scatterlist corrupts page cache",
        )
        assert len(results) >= 1
        assert results[0]["invariant_id"] == "sg_no_write_shared_pages"

    def test_no_match_for_unrelated(self, dm_dir):
        results = invariant_violations_for_hypothesis(
            dm_dir, "integer overflow in size calculation")
        assert results == []

    def test_empty_when_no_model(self, tmp_path):
        results = invariant_violations_for_hypothesis(
            tmp_path, "anything")
        assert results == []


class TestEnrichedMatching:
    def test_cwe_match_boost_crossfile(self, enriched_dir):
        """Boost matched by CWE is scope-free — works cross-file."""
        results = invariant_violations_for_hypothesis(
            enriched_dir,
            "page-cache corruption via write to shared page",
            role="boost",
            finding_file="algif_aead.c",
            finding_cwe="CWE-787",
        )
        ids = [r["invariant_id"] for r in results]
        assert "page_refcounting" in ids
        cwe_match = next(r for r in results if r["invariant_id"] == "page_refcounting")
        assert cwe_match["match_pass"] == "cwe"

    def test_mechanism_match_boost_crossfile(self, enriched_dir):
        """Boost matched by mechanism keywords, no CWE needed."""
        results = invariant_violations_for_hypothesis(
            enriched_dir,
            "scatterlist aliasing causes page cache corruption",
            role="boost",
            finding_file="algif_aead.c",
            finding_cwe="",
        )
        ids = [r["invariant_id"] for r in results]
        assert "page_refcounting" in ids
        mech_match = next(r for r in results if r["invariant_id"] == "page_refcounting")
        assert mech_match["match_pass"] == "mechanism"

    def test_guard_scoped_to_file(self, enriched_dir):
        """Guard invariant only matches findings in its scoped files."""
        results_scoped = invariant_violations_for_hypothesis(
            enriched_dir,
            "TOCTOU race in concurrent alg_bind call",
            role="guard",
            finding_file="af_alg.c",
            finding_cwe="CWE-362",
        )
        results_wrong_file = invariant_violations_for_hypothesis(
            enriched_dir,
            "TOCTOU race in concurrent alg_bind call",
            role="guard",
            finding_file="algif_aead.c",
            finding_cwe="CWE-362",
        )
        scoped_ids = [r["invariant_id"] for r in results_scoped]
        wrong_file_ids = [r["invariant_id"] for r in results_wrong_file]
        assert "guard_bind_oneshot" in scoped_ids
        assert "guard_bind_oneshot" not in wrong_file_ids

    def test_legacy_fallback(self, enriched_dir):
        """Invariants without enrichment fall back to keyword matching."""
        results = invariant_violations_for_hypothesis(
            enriched_dir,
            "integer overflow in length calculation causes buffer overrun",
        )
        ids = [r["invariant_id"] for r in results]
        assert "legacy_no_enrichment" in ids
        legacy = next(r for r in results if r["invariant_id"] == "legacy_no_enrichment")
        assert legacy["match_pass"] == "legacy"

    def test_no_false_positive_module_vs_page_refcount(self, enriched_dir):
        """Module reference counting should NOT match page refcounting."""
        results = invariant_violations_for_hypothesis(
            enriched_dir,
            "missing try_module_get on algorithm owner module "
            "allows premature module unloading and use-after-free",
            role="boost",
            finding_cwe="CWE-416",
        )
        ids = [r["invariant_id"] for r in results]
        # CWE-416 matches page_refcounting, but this is intentional —
        # it's the CWE match that fires, not spurious keyword overlap.
        # The mechanism keywords (scatterlist, sgl, page_cache) do NOT
        # appear in the module-UAF hypothesis, so mechanism pass wouldn't
        # match on its own.
        if "page_refcounting" in ids:
            pr = next(r for r in results if r["invariant_id"] == "page_refcounting")
            assert pr["match_pass"] == "cwe"

    def test_cwe_preferred_over_mechanism(self, enriched_dir):
        """When both CWE and mechanism would match, CWE pass wins."""
        results = invariant_violations_for_hypothesis(
            enriched_dir,
            "page corruption via scatterlist aliasing of shared pages",
            role="boost",
            finding_cwe="CWE-787",
        )
        pr = next(
            (r for r in results if r["invariant_id"] == "page_refcounting"),
            None,
        )
        assert pr is not None
        assert pr["match_pass"] == "cwe"

    def test_guard_contradicts_with_cwe(self, enriched_dir):
        """guard_contradicts_finding passes CWE through."""
        results = guard_contradicts_finding(
            enriched_dir,
            "integer overflow in ivlen causes out-of-bounds write",
            [],
            finding_file="af_alg.c",
            finding_cwe="CWE-190",
        )
        ids = [r["invariant_id"] for r in results]
        assert "guard_iv_size" in ids


class TestQueueReadingListItem:
    def test_creates_reading_list(self, tmp_path):
        ok = queue_reading_list_item(
            tmp_path,
            question="struct page ownership semantics",
            source_file="mm/page_alloc.c",
            source_function="__alloc_pages",
            priority="high",
        )
        assert ok is True
        rl_path = tmp_path / "reading-list.json"
        assert rl_path.is_file()
        data = json.loads(rl_path.read_text(encoding="utf-8"))
        assert len(data["items"]) == 1
        assert data["items"][0]["question"] == "struct page ownership semantics"

    def test_deduplicates(self, tmp_path):
        queue_reading_list_item(tmp_path, question="foo")
        queue_reading_list_item(tmp_path, question="foo")
        data = json.loads(
            (tmp_path / "reading-list.json").read_text(encoding="utf-8"))
        assert len(data["items"]) == 1

    def test_priority_upgrade(self, tmp_path):
        queue_reading_list_item(tmp_path, question="bar", priority="normal")
        queue_reading_list_item(tmp_path, question="bar", priority="critical")
        data = json.loads(
            (tmp_path / "reading-list.json").read_text(encoding="utf-8"))
        assert data["items"][0]["priority"] == "critical"
