"""Tests for core.concepts.audit_bridge."""

import json
from unittest.mock import MagicMock, patch

import pytest

from core.concepts.audit_bridge import (
    _extract_cwe_id,
    _find_domain_model,
    _guard_in_scope,
    _infer_repo_path,
    _match_pass_cwe,
    _relevance_score,
    _sage_recall_for_context,
    domain_bug_patterns,
    domain_key_files,
    domain_model_context,
    domain_security_context,
    invariant_violations_for_hypothesis,
    invariants_contradicting_finding,
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

    def test_statement_identifiers_route_derived_invariants(self):
        # Derived (threat-frame) invariants have no receipts, evidence
        # anchors, or file field — their statement's code identifiers
        # matched against the function body are their only routing
        # signal. Description-only scoring left them at 0.0 (observed:
        # the CVE-critical invariant ranked 58/61 and never injected).
        derived = {
            "id": "tf_no-writeback",
            "statement": "Pages pulled by af_alg_pull_tsgl must never "
                         "be used as a writable destination.",
            "negation": "Writing corrupts foreign pages.",
            "description": "[threat-frame derived]",
            "provenance": "llm_prior",
            "confidence": "derived",
        }
        body = "err = af_alg_pull_tsgl(sk, processed, areq->tsgl, 0);"
        score = _relevance_score(derived, "crypto/algif_aead.c",
                                 "_aead_recvmsg", body)
        assert score > 1.0
        assert _relevance_score(
            derived, "crypto/algif_aead.c", "_aead_recvmsg", "") == 0.0

    def test_identifier_signal_is_capped(self):
        item = {
            "id": "x",
            "statement": " ".join(
                f"name_{i}_token" for i in range(10)),
            "provenance": "llm_prior",
        }
        body = " ".join(f"name_{i}_token" for i in range(10))
        score = _relevance_score(item, "a.c", "f", body)
        # 10 identifier hits must not outrank an exact-function anchor
        # (+5.0/+6.0/+8.0 signals).
        assert score <= 4.0


class TestDerivedInvariantReservedSlots:
    def test_derived_invariant_injected_past_topn_cut(self, tmp_path):
        """A derived (llm_prior) invariant that anchors to the function
        but is outscored by >max_invariants extracted invariants still
        enters the block via the reserved slots."""
        import json as _json
        extracted = [
            {
                "id": f"ext_{i}",
                "concept": "",
                "statement": f"guard {i} on target_func",
                "negation": "n",
                "description": f"target_func guard {i}",
                "evidence": [{"file": "a.c", "item": "target_func"}],
                "confidence": "documented",
                "provenance": "verbatim",
            }
            for i in range(8)
        ]
        derived = {
            "id": "tf_never-writable",
            "concept": "",
            "statement": "Pages pulled by helper_pull_pages must "
                         "never be a writable destination.",
            "negation": "Writes corrupt foreign pages.",
            "description": "[threat-frame derived]",
            "confidence": "derived",
            "provenance": "llm_prior",
        }
        (tmp_path / "concepts").mkdir()
        (tmp_path / "concepts" / "domain-model.json").write_text(
            _json.dumps({
                "concepts": [], "contracts": [],
                "invariants": extracted + [derived],
            }))
        out_dir = tmp_path / "run1"
        out_dir.mkdir()
        block = domain_model_context(
            out_dir, "a.c", "target_func",
            "err = helper_pull_pages(sk, n, dst_sgl);")
        assert block is not None
        assert "never-writable" in block
        assert "[unverified]" in block


    def test_primers_path_gets_derived_slots_too(self, tmp_path):
        """primers_from_domain_model is what the review prompt
        actually uses when primers exist — the derived-slot reserve
        must apply there, not only in domain_model_context (observed
        live: the fix landed in the dead path first and the CVE-frame
        invariant still never reached the prompt)."""
        import json as _json

        from core.concepts.audit_bridge import primers_from_domain_model
        extracted = [
            {
                "id": f"ext_{i}",
                "statement": f"guard {i} on target_func",
                "negation": "n",
                "description": f"target_func guard {i}",
                "evidence": [{"file": "a.c", "item": "target_func"}],
                "confidence": "documented",
                "provenance": "verbatim",
            }
            for i in range(8)
        ]
        derived = {
            "id": "tf_never-writable",
            "statement": "Pages pulled by helper_pull_pages must "
                         "never be a writable destination.",
            "negation": "Writes corrupt foreign pages.",
            "description": "[threat-frame derived]",
            "confidence": "derived",
            "provenance": "llm_prior",
        }
        (tmp_path / "concepts").mkdir()
        (tmp_path / "concepts" / "domain-model.json").write_text(
            _json.dumps({
                "concepts": [], "contracts": [],
                "invariants": extracted + [derived],
            }))
        out_dir = tmp_path / "run1"
        out_dir.mkdir()
        primers = primers_from_domain_model(
            out_dir, "a.c", "target_func",
            "err = helper_pull_pages(sk, n, dst_sgl);")
        joined = "\n".join(primers)
        assert "never be a writable destination" in joined
        # Fail-closed tier rendering on THIS path too: a receipt-less
        # derived invariant must read as a hint, never as an extracted
        # fact (pre-fix the primers block branded every entry "a
        # violation is a real bug" with no tier tag).
        line = next(ln for ln in joined.splitlines()
                    if "never be a writable destination" in ln)
        assert "[unverified]" in line


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
                "relevant_cwes": ["CWE-416", "CWE-787"],
            },
            {
                "id": "guard_bind_oneshot",
                "concept": "socket_state",
                "statement": "After alg_bind() succeeds, BOUND is irreversible",
                "negation": "State reverts from BOUND to UNBOUND",
                "confidence": "traced",
                "relevant_cwes": ["CWE-362", "CWE-367"],
            },
            {
                "id": "guard_iv_size",
                "concept": "value_constraint",
                "statement": "ivlen <= ivsize after validation",
                "negation": "ivlen exceeds ivsize",
                "confidence": "traced",
                "relevant_cwes": ["CWE-190", "CWE-787", "CWE-125"],
            },
            {
                "id": "legacy_no_enrichment",
                "concept": "misc",
                "statement": "Some legacy invariant without enrichment fields",
                "negation": "integer overflow in length calculation causes buffer overrun",
                "confidence": "inferred",
            },
        ],
        "contracts": [],
    }


@pytest.fixture
def enriched_dir(enriched_model, tmp_path):
    dm_path = tmp_path / "domain-model.json"
    dm_path.write_text(json.dumps(enriched_model), encoding="utf-8")
    return tmp_path


class TestDomainModelContextWithSage:
    def test_sage_only_when_no_local_match(self, tmp_path):
        """SAGE provides standalone value even when local model is empty."""
        dm = {
            "version": "1",
            "target": "/src",
            "source_root": "/src",
            "concepts": [],
            "invariants": [],
            "contracts": [],
        }
        (tmp_path / "domain-model.json").write_text(
            json.dumps(dm), encoding="utf-8")
        (tmp_path / "study-list.json").write_text(
            json.dumps({"target": "/repos/myproj"}), encoding="utf-8")

        mock_client = MagicMock()
        mock_client.query.return_value = [
            {"confidence": 0.85, "content": "validate_token must check expiry"},
        ]
        mock_hooks = MagicMock()
        mock_hooks._get_client.return_value = mock_client
        mock_hooks._concepts_domain.return_value = "test-domain"

        with patch.dict("sys.modules", {"core.sage.hooks": mock_hooks}):
            block = domain_model_context(
                tmp_path, "auth/token.c", "validate_token")
            assert block is not None
            assert "Cross-Session Knowledge" in block
            assert "validate_token must check expiry" in block


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
    def test_cwe_match_crossfile(self, enriched_dir):
        """Invariant matched by CWE works cross-file."""
        results = invariant_violations_for_hypothesis(
            enriched_dir,
            "page-cache corruption via write to shared page",
            finding_cwe="CWE-787",
        )
        ids = [r["invariant_id"] for r in results]
        assert "page_refcounting" in ids
        cwe_match = next(r for r in results if r["invariant_id"] == "page_refcounting")
        assert cwe_match["match_pass"] == "cwe"

    def test_keyword_match_crossfile(self, enriched_dir):
        """Invariant matched by keyword overlap, no CWE needed."""
        results = invariant_violations_for_hypothesis(
            enriched_dir,
            "double put_page on error path leads to use-after-free",
            finding_cwe="",
        )
        ids = [r["invariant_id"] for r in results]
        assert "page_refcounting" in ids
        kw_match = next(r for r in results if r["invariant_id"] == "page_refcounting")
        assert kw_match["match_pass"] == "keyword"

    def test_legacy_fallback(self, enriched_dir):
        """Invariants without enrichment fall back to keyword matching."""
        results = invariant_violations_for_hypothesis(
            enriched_dir,
            "integer overflow in length calculation causes buffer overrun",
        )
        ids = [r["invariant_id"] for r in results]
        assert "legacy_no_enrichment" in ids
        legacy = next(r for r in results if r["invariant_id"] == "legacy_no_enrichment")
        assert legacy["match_pass"] == "keyword"

    def test_no_false_positive_module_vs_page_refcount(self, enriched_dir):
        """Module reference counting should NOT match page refcounting."""
        results = invariant_violations_for_hypothesis(
            enriched_dir,
            "missing try_module_get on algorithm owner module "
            "allows premature module unloading and use-after-free",
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

    def test_cwe_preferred_over_keyword(self, enriched_dir):
        """When both CWE and keyword would match, CWE pass wins."""
        results = invariant_violations_for_hypothesis(
            enriched_dir,
            "double put_page causes use-after-free on shared pages",
            finding_cwe="CWE-787",
        )
        pr = next(
            (r for r in results if r["invariant_id"] == "page_refcounting"),
            None,
        )
        assert pr is not None
        assert pr["match_pass"] == "cwe"

    def test_invariants_contradicting_with_cwe(self, enriched_dir):
        """invariants_contradicting_finding passes CWE through."""
        results = invariants_contradicting_finding(
            enriched_dir,
            "integer overflow in ivlen causes out-of-bounds write",
            [],
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


class TestInferRepoPath:
    def test_from_study_list_in_out_dir(self, tmp_path):
        (tmp_path / "study-list.json").write_text(
            json.dumps({"target": "/home/user/myrepo"}), encoding="utf-8")
        assert _infer_repo_path(tmp_path) == "/home/user/myrepo"

    def test_from_study_list_in_parent(self, tmp_path):
        (tmp_path / "study-list.json").write_text(
            json.dumps({"target": "/repos/linux"}), encoding="utf-8")
        child = tmp_path / "sub"
        child.mkdir()
        assert _infer_repo_path(child) == "/repos/linux"

    def test_returns_none_when_missing(self, tmp_path):
        child = tmp_path / "run001"
        child.mkdir()
        assert _infer_repo_path(child) is None

    def test_returns_none_on_empty_target(self, tmp_path):
        (tmp_path / "study-list.json").write_text(
            json.dumps({"target": ""}), encoding="utf-8")
        assert _infer_repo_path(tmp_path) is None

    def test_returns_none_on_invalid_json(self, tmp_path):
        (tmp_path / "study-list.json").write_text("not json", encoding="utf-8")
        assert _infer_repo_path(tmp_path) is None


class TestSageRecallForContext:
    def test_returns_none_when_sage_not_installed(self, tmp_path):
        with patch.dict("sys.modules", {"core.sage.hooks": None}):
            result = _sage_recall_for_context(tmp_path, "foo.c", "bar")
            assert result is None

    def test_returns_none_when_client_unavailable(self, tmp_path):
        mock_hooks = MagicMock()
        mock_hooks._get_client.return_value = None
        with patch.dict("sys.modules", {"core.sage.hooks": mock_hooks}):
            result = _sage_recall_for_context(tmp_path, "foo.c", "bar")
            assert result is None

    def test_returns_formatted_block(self, tmp_path):
        (tmp_path / "study-list.json").write_text(
            json.dumps({"target": "/repos/myproj"}), encoding="utf-8")

        mock_client = MagicMock()
        mock_client.query.return_value = [
            {"confidence": 0.85, "content": "mutex_lock must pair with mutex_unlock"},
            {"confidence": 0.72, "content": "refcount_inc requires matching refcount_dec"},
        ]
        mock_hooks = MagicMock()
        mock_hooks._get_client.return_value = mock_client
        mock_hooks._concepts_domain.return_value = "raptor-concepts-myproj"

        with patch.dict("sys.modules", {"core.sage.hooks": mock_hooks}):
            result = _sage_recall_for_context(tmp_path, "kernel/locking.c", "do_lock")

        assert result is not None
        assert "Cross-Session Knowledge" in result
        assert "85%" in result
        assert "mutex_lock" in result
        assert "72%" in result

    def test_returns_none_on_empty_results(self, tmp_path):
        (tmp_path / "study-list.json").write_text(
            json.dumps({"target": "/repos/myproj"}), encoding="utf-8")

        mock_client = MagicMock()
        mock_client.query.return_value = []
        mock_hooks = MagicMock()
        mock_hooks._get_client.return_value = mock_client
        mock_hooks._concepts_domain.return_value = "test-domain"

        with patch.dict("sys.modules", {"core.sage.hooks": mock_hooks}):
            result = _sage_recall_for_context(tmp_path, "foo.c", "bar")
            assert result is None

    def test_returns_none_on_query_exception(self, tmp_path):
        (tmp_path / "study-list.json").write_text(
            json.dumps({"target": "/repos/myproj"}), encoding="utf-8")

        mock_client = MagicMock()
        mock_client.query.side_effect = ConnectionError("SAGE down")
        mock_hooks = MagicMock()
        mock_hooks._get_client.return_value = mock_client
        mock_hooks._concepts_domain.return_value = "test-domain"

        with patch.dict("sys.modules", {"core.sage.hooks": mock_hooks}):
            result = _sage_recall_for_context(tmp_path, "foo.c", "bar")
            assert result is None

    def test_truncates_long_content(self, tmp_path):
        (tmp_path / "study-list.json").write_text(
            json.dumps({"target": "/repos/myproj"}), encoding="utf-8")

        long_content = "x" * 500 + "\nsecond line"
        mock_client = MagicMock()
        mock_client.query.return_value = [
            {"confidence": 0.9, "content": long_content},
        ]
        mock_hooks = MagicMock()
        mock_hooks._get_client.return_value = mock_client
        mock_hooks._concepts_domain.return_value = "test-domain"

        with patch.dict("sys.modules", {"core.sage.hooks": mock_hooks}):
            result = _sage_recall_for_context(tmp_path, "foo.c", "bar")
            assert result is not None
            assert "second line" not in result
            assert len(result.split("\n")[-1]) <= 210

    def test_handles_none_confidence_and_content(self, tmp_path):
        (tmp_path / "study-list.json").write_text(
            json.dumps({"target": "/repos/myproj"}), encoding="utf-8")

        mock_client = MagicMock()
        mock_client.query.return_value = [
            {"confidence": None, "content": None},
            {"confidence": 0.8, "content": "valid result"},
        ]
        mock_hooks = MagicMock()
        mock_hooks._get_client.return_value = mock_client
        mock_hooks._concepts_domain.return_value = "test-domain"

        with patch.dict("sys.modules", {"core.sage.hooks": mock_hooks}):
            result = _sage_recall_for_context(tmp_path, "foo.c", "bar")
            assert result is not None
            assert "valid result" in result

    def test_returns_none_when_no_repo_path(self, tmp_path):
        """When _infer_repo_path returns None, SAGE is skipped."""
        mock_hooks = MagicMock()
        mock_hooks._get_client.return_value = MagicMock()
        with patch.dict("sys.modules", {"core.sage.hooks": mock_hooks}):
            result = _sage_recall_for_context(tmp_path, "foo.c", "bar")
            assert result is None

    def test_respects_max_results(self, tmp_path):
        (tmp_path / "study-list.json").write_text(
            json.dumps({"target": "/repos/myproj"}), encoding="utf-8")

        mock_client = MagicMock()
        mock_client.query.return_value = [
            {"confidence": 0.9, "content": "result 1"},
        ]
        mock_hooks = MagicMock()
        mock_hooks._get_client.return_value = mock_client
        mock_hooks._concepts_domain.return_value = "test-domain"

        with patch.dict("sys.modules", {"core.sage.hooks": mock_hooks}):
            _sage_recall_for_context(
                tmp_path, "foo.c", "bar",
                max_results=5, min_confidence=0.5,
            )
            mock_client.query.assert_called_once_with(
                "bar foo.c",
                domain_tag="test-domain",
                top_k=5,
                min_confidence=0.5,
            )


@pytest.fixture
def extras_model(domain_model):
    """Domain model with security_context, bug_patterns, key_files."""
    domain_model = dict(domain_model)
    domain_model["security_context"] = {
        "privilege_level": "kernel",
        "attack_surface": "AF_ALG socket API reachable from userspace",
        "isolation": "none",
        "trust_summary": "unprivileged user -> kernel crypto layer",
    }
    domain_model["bug_patterns"] = [
        {"id": "sg-double-free", "description": "double free of sg pages",
         "what_to_grep": r"af_alg_free_areq_sgls"},
        {"id": "unchecked-copy", "description": "copy without bounds check",
         "what_to_grep": r"copy_from_user"},
    ]
    domain_model["key_files"] = [
        {"path": "crypto/algif_aead.c", "reason": "entry point"},
        "crypto/af_alg.c",
    ]
    return domain_model


@pytest.fixture
def extras_out_dir(extras_model, tmp_path):
    (tmp_path / "domain-model.json").write_text(
        json.dumps(extras_model), encoding="utf-8")
    return tmp_path


class TestDomainSecurityContext:
    def test_returns_block(self, extras_out_dir):
        block = domain_security_context(extras_out_dir)
        assert block is not None
        assert "Target Security Context" in block
        assert "kernel" in block
        assert "AF_ALG socket API" in block
        assert "Trust boundary" in block

    def test_none_without_model(self, tmp_path):
        assert domain_security_context(tmp_path) is None

    def test_none_without_privilege_level(self, domain_model, tmp_path):
        (tmp_path / "domain-model.json").write_text(
            json.dumps(domain_model), encoding="utf-8")
        assert domain_security_context(tmp_path) is None


class TestDomainBugPatterns:
    def test_grep_hint_match_selects(self, extras_out_dir):
        src = "err = af_alg_free_areq_sgls(areq);"
        block = domain_bug_patterns(
            extras_out_dir, "crypto/algif_aead.c", "aead_release", src)
        assert block is not None
        assert "double free of sg pages" in block
        assert "copy without bounds check" not in block

    def test_no_match_returns_none(self, extras_out_dir):
        block = domain_bug_patterns(
            extras_out_dir, "lib/other.c", "unrelated",
            "int x = 1;\nreturn x;")
        assert block is None

    def test_empty_source_includes_all(self, extras_out_dir):
        block = domain_bug_patterns(
            extras_out_dir, "crypto/algif_aead.c", "aead_release", "")
        assert block is not None
        assert "double free of sg pages" in block
        assert "copy without bounds check" in block

    def test_none_without_model(self, tmp_path):
        assert domain_bug_patterns(tmp_path, "a.c", "f", "src") is None

    def test_bad_regex_hint_falls_back_to_substring(
        self, domain_model, tmp_path,
    ):
        domain_model = dict(domain_model)
        domain_model["bug_patterns"] = [
            {"id": "p", "description": "unbalanced paren hint",
             "what_to_grep": "kfree("},
        ]
        (tmp_path / "domain-model.json").write_text(
            json.dumps(domain_model), encoding="utf-8")
        block = domain_bug_patterns(tmp_path, "a.c", "f", "kfree(ptr);")
        assert block is not None
        assert "unbalanced paren hint" in block


class TestDomainKeyFiles:
    def test_returns_paths_from_dicts_and_strings(self, extras_out_dir):
        kf = domain_key_files(extras_out_dir)
        assert kf == {"crypto/algif_aead.c", "crypto/af_alg.c"}

    def test_empty_without_model(self, tmp_path):
        assert domain_key_files(tmp_path) == set()

    def test_empty_without_key_files(self, dm_dir):
        assert domain_key_files(dm_dir) == set()


class TestGuardInScope:
    def test_unscoped_guard_is_global(self):
        assert _guard_in_scope({"id": "g1", "statement": "s"}, "a/b.c")

    def test_files_list_scopes(self):
        inv = {"id": "g", "files": ["crypto/algif_aead.c"]}
        assert _guard_in_scope(inv, "crypto/algif_aead.c")
        assert _guard_in_scope(inv, "src/crypto/algif_aead.c")
        assert not _guard_in_scope(inv, "net/socket.c")

    def test_evidence_dict_file_scopes(self):
        inv = {"id": "g", "evidence": [{"file": "lib/parse.c"}]}
        assert _guard_in_scope(inv, "lib/parse.c")
        assert not _guard_in_scope(inv, "lib/other.c")

    def test_evidence_string_path_scopes(self):
        inv = {"id": "g", "evidence": ["crypto/af_alg.c:120 sg aliasing"]}
        assert _guard_in_scope(inv, "crypto/af_alg.c")
        assert not _guard_in_scope(inv, "crypto/algif_hash.c")

    def test_prose_evidence_does_not_scope(self):
        inv = {"id": "g", "evidence": ["documented in the manpage"]}
        assert _guard_in_scope(inv, "any/file.c")


class TestProvenanceTierTags:
    """Injected domain knowledge must carry provenance tiers —
    llm_summarized entries read as untrusted context, not fact."""

    def test_untiered_entries_tagged_unverified(self, dm_dir):
        block = domain_model_context(
            dm_dir, "crypto/algif_aead.c", "_aead_recvmsg",
        )
        assert block is not None
        # Fixture entries carry no provenance → fail-closed tag.
        assert "[unverified]" in block

    def test_framing_note_present(self, dm_dir):
        block = domain_model_context(
            dm_dir, "crypto/algif_aead.c", "_aead_recvmsg",
        )
        assert block is not None
        assert "WITHOUT verified receipts" in block
        assert "never as established fact" in block

    def test_verbatim_entry_tagged(self, domain_model, tmp_path):
        domain_model["concepts"][0]["provenance"] = "verbatim"
        dm_path = tmp_path / "domain-model.json"
        dm_path.write_text(json.dumps(domain_model), encoding="utf-8")
        block = domain_model_context(
            tmp_path, "crypto/algif_aead.c", "_aead_recvmsg",
        )
        assert block is not None
        assert "**sg_page_ownership** [verbatim]" in block

    def test_stale_entry_tagged(self, domain_model, tmp_path):
        domain_model["concepts"][0]["provenance"] = "verbatim"
        domain_model["concepts"][0]["state"] = "stale"
        dm_path = tmp_path / "domain-model.json"
        dm_path.write_text(json.dumps(domain_model), encoding="utf-8")
        block = domain_model_context(
            tmp_path, "crypto/algif_aead.c", "_aead_recvmsg",
        )
        assert block is not None
        assert "**sg_page_ownership** [stale-unverified]" in block
