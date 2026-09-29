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

    def test_injection_survives_poisoned_study_artifacts(self, dm_dir):
        """Briefing-side injection is a pure disk read of
        domain-model.json — a broken study SUBSYSTEM (here: the run's
        reading-list.json poisoned with present-but-null fields, the
        shape that crashed study-prep and disabled the study consumer)
        must not starve reviews of the already-extracted model."""
        (dm_dir / "reading-list.json").write_text(json.dumps({
            "items": [{
                "id": "study_unresolved_x.deadbeef1234",
                "question": "q?", "source_command": "/understand --study",
                "source_file": None, "context": None,
                "resolved": False, "resolution": "identifier",
            }],
        }), encoding="utf-8")
        block = domain_model_context(
            dm_dir, "crypto/algif_aead.c", "_aead_recvmsg")
        assert block is not None
        assert "sg_page_ownership" in block

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

    def test_queue_writes_under_the_shared_lock(self, tmp_path, monkeypatch):
        """The load-modify-save cycle must hold the reading-list
        module's shared writer lock — a queue racing another
        in-process writer's cycle silently drops items."""
        from core.concepts import reading_list as rl_mod

        held: list[bool] = []
        real_save = rl_mod.ReadingList.save

        def checking_save(self, path=None):
            held.append(rl_mod.READING_LIST_WRITE_LOCK.locked())
            return real_save(self, path)

        monkeypatch.setattr(rl_mod.ReadingList, "save", checking_save)
        assert queue_reading_list_item(tmp_path, question="locked?")
        assert held == [True]

    def test_concurrent_queuers_drop_nothing(self, tmp_path):
        import threading

        def queue_one(i: int) -> None:
            queue_reading_list_item(tmp_path, question=f"q{i}")

        threads = [
            threading.Thread(target=queue_one, args=(i,))
            for i in range(16)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        data = json.loads(
            (tmp_path / "reading-list.json").read_text(encoding="utf-8"))
        assert {i["question"] for i in data["items"]} == {
            f"q{i}" for i in range(16)
        }


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

    @staticmethod
    def _write_hint_model(tmp_path, hint):
        (tmp_path / "domain-model.json").write_text(json.dumps({
            "bug_patterns": [
                {"id": "p", "description": "hinted pattern",
                 "what_to_grep": hint},
            ],
        }), encoding="utf-8")

    def test_redos_shaped_hint_not_compiled(self, tmp_path):
        """A nested-quantifier hint (LLM output, steerable by hostile
        repo content) must degrade to substring matching instead of
        compiling into a super-linear matcher that runs per-function."""
        self._write_hint_model(tmp_path, r"(a+)+$")
        # Would take effectively forever under backtracking; the
        # substring fallback returns instantly (no literal match).
        src = "a" * 40 + "b"
        block = domain_bug_patterns(tmp_path, "a.c", "f", src)
        assert block is None

    def test_starred_overlap_alternation_hint_not_compiled(self, tmp_path):
        """`(a|aa)*b` is the `)*` twin of overlap alternation — it
        backtracks exponentially just like `(a|aa)+` and must hit the
        same substring fallback."""
        self._write_hint_model(tmp_path, r"(a|aa)*b$")
        src = "a" * 40 + "c"
        block = domain_bug_patterns(tmp_path, "a.c", "f", src)
        assert block is None

    def test_overlong_hint_falls_back_to_substring(self, tmp_path):
        from core.concepts.audit_bridge import _MAX_GREP_HINT_CHARS
        hint = "kfree_" + "x" * _MAX_GREP_HINT_CHARS
        self._write_hint_model(tmp_path, hint)
        # Substring semantics: the literal hint text present in source
        # still selects the pattern.
        block = domain_bug_patterns(tmp_path, "a.c", "f",
                                    f"call {hint} done")
        assert block is not None
        assert "hinted pattern" in block

    def test_hint_under_cap_keeps_regex_semantics(self, tmp_path):
        from core.concepts.audit_bridge import _MAX_GREP_HINT_CHARS
        # Other direction of the cap: a legitimate alternation hint
        # under the limit must still match as a REGEX (no literal
        # "kfree|kzalloc" appears in the source).
        hint = "kfree|kzalloc"
        assert len(hint) <= _MAX_GREP_HINT_CHARS
        self._write_hint_model(tmp_path, hint)
        block = domain_bug_patterns(tmp_path, "a.c", "f", "kzalloc(8);")
        assert block is not None
        assert "hinted pattern" in block

    def test_ungrouped_star_chain_hint_not_compiled(self, tmp_path):
        """`a*a*a*...b` has no group or alternation for any shape
        rule to anchor on, yet backtracks combinatorially — the
        repeat budget must route it to the substring fallback. The
        source is sized so a compiled match attempt would effectively
        never return (the test hanging IS the red direction)."""
        self._write_hint_model(tmp_path, "a*" * 20 + "b")
        src = "a" * 60 + "c"
        block = domain_bug_patterns(tmp_path, "a.c", "f", src)
        assert block is None

    def test_refused_hint_keeps_substring_semantics(self, tmp_path):
        """A budget-refused hint still selects when its LITERAL text
        appears in source — demotion means substring matching, not
        no matching at all."""
        hint = "a*a*a*b"
        self._write_hint_model(tmp_path, hint)
        block = domain_bug_patterns(tmp_path, "a.c", "f",
                                    f"lex table row: {hint} end")
        assert block is not None
        assert "hinted pattern" in block

    def test_backreference_hint_not_compiled(self, tmp_path):
        r"""`(a*)\1b` carries ONE repeat token and no quantified-group
        shape, yet the backreference re-matches the captured span —
        super-linear backtracking. The source is sized so a compiled
        match attempt would effectively never return (the test
        hanging IS the red direction)."""
        self._write_hint_model(tmp_path, r"(a*)\1b")
        src = "a" * 4000 + "c"
        block = domain_bug_patterns(tmp_path, "a.c", "f", src)
        assert block is None

    def test_source_clamp_two_directions(self, tmp_path):
        # Both directions of _MAX_REGEX_SOURCE_CHARS: at the clamp an
        # admitted hint keeps REGEX semantics (matches with no literal
        # occurrence); one char past it the same hint drops to
        # substring semantics (same source content, no literal -> no
        # selection). The decision depends only on len(source).
        from core.concepts.audit_bridge import _MAX_REGEX_SOURCE_CHARS
        self._write_hint_model(tmp_path, "memcpy.*len")
        head = "memcpy(dst, src, len);\n"
        at_clamp = head + "x" * (_MAX_REGEX_SOURCE_CHARS - len(head))
        assert len(at_clamp) == _MAX_REGEX_SOURCE_CHARS
        block = domain_bug_patterns(tmp_path, "a.c", "f", at_clamp)
        assert block is not None
        assert "hinted pattern" in block
        over_clamp = at_clamp + "x"
        assert len(over_clamp) == _MAX_REGEX_SOURCE_CHARS + 1
        block = domain_bug_patterns(tmp_path, "a.c", "f", over_clamp)
        assert block is None

    def test_source_clamp_substring_scans_full_source(self, tmp_path):
        # Past the clamp the hint is a substring over the FULL source
        # — the literal is planted beyond the clamp offset to prove
        # the source is not truncated for the fallback.
        from core.concepts.audit_bridge import _MAX_REGEX_SOURCE_CHARS
        hint = "memcpy.*len"
        self._write_hint_model(tmp_path, hint)
        src = "x" * (_MAX_REGEX_SOURCE_CHARS + 10) + hint
        block = domain_bug_patterns(tmp_path, "a.c", "f", src)
        assert block is not None
        assert "hinted pattern" in block

    def test_admitted_hint_bounded_on_quadratic_source(self, tmp_path):
        """The clamp's reason to exist: an ADMITTED single-span hint
        is quadratic on a failing search when its leading literal
        recurs through the source. This source size hangs the regex
        path for minutes pre-clamp (the test hanging IS the red
        direction); the substring fallback returns instantly."""
        self._write_hint_model(tmp_path, "memcpy.*len")
        src = "memcpy" * 100_000  # ~600 KB, no "len" anywhere
        block = domain_bug_patterns(tmp_path, "a.c", "f", src)
        assert block is None

    def test_legit_leading_literal_hint_stays_regex_selected(
        self, tmp_path,
    ):
        # Other direction of the shape rules: the common
        # leading-literal single-span hint keeps REGEX semantics —
        # the literal "memcpy.*len" appears nowhere in this source,
        # so only a compiled match can select the pattern (the
        # relevance fallback scores nothing here). Over-refusal by
        # any rule turns this selection off.
        self._write_hint_model(tmp_path, "memcpy.*len")
        block = domain_bug_patterns(
            tmp_path, "a.c", "f", "memcpy(dst, src, length);")
        assert block is not None
        assert "hinted pattern" in block

    def test_worst_admitted_shape_cost_bounded(self, tmp_path):
        """Cost pin for the worst shapes the guard ADMITS, CONSTRUCTED
        from the cost model's own bounds (the model at
        ``_MAX_REGEX_SOURCE_CHARS``) — and an arithmetic pin of each
        shape's weight over those bounds. The weighted walk is
        (1 + branch bars) x continuation chars, capped at 13 — an
        odd number, so among shapes whose only weight-counted bars
        are path-splitting ones the cap is reachable only bar-free:
        the bar-free arithmetic maximum is a minimum-period prefix
        + the atom cap + a BAR-FREE prefix-periodic continuation of
        exactly the cap, while the path-splitting-bar constructions
        max out one weighted element lower. (Mixed raw+grouped-bar
        shapes reach weight 13 with the grouped bar present and
        score 15 restart-floor units, but only at continuation
        <= 1 char, and measure below this family — figures and
        both spellings at the clamp comment; boundary pinned in
        ``test_repeat_continuation_walk_two_directions``.) W alone
        is NOT a strict cost ranking at the top: in restart-floor
        units the full-walk admitted maxima TIE at 14 (bar-free:
        1 + 13; each path-splitting-bar family: 2 + 12), and
        measurement discriminates — the (1+g) path factor also
        multiplies the walk-INDEPENDENT per-restart base cost
        (~60% of bar-free wall clock at the clamp), so the MEASURED
        admitted ceiling belongs to the matching-alternative
        pre-token family (its constructed "[a-z0-9]" representative
        ~1.4 s light-load at the clamp; within the family the cost
        is atom-spelling-dependent and sampled spellings are
        samples with no stated supremum — figures at the clamp
        comment), above
        the post-token runner-up (~1.1 s — the raw char-count walk
        over-prices a literal continuation, which usually fails at
        its first char, against a grouped one whose alternatives
        are always both tried) and the bar-free arithmetic maximum
        (~0.9 s). All three tying shapes are built here from the
        constants, each weight is asserted as arithmetic over those
        constants, and all three are evaluated against an at-clamp
        source saturated with the prefix (every third position
        restarts the span; the match always fails; the pre-token
        group's alternatives are drawn from the prefix so they
        MATCH the saturated source — non-matching alternatives fail
        at the group and would hide the family's cost). Measures
        ~3.4 s total single-threaded light-load; the wall-clock
        bound leaves headroom for loaded hosts while staying far
        below the shapes the bounds exist to refuse (the 246-char
        literal-tail reproducer measured ~8.7 s here; the
        pre-token-bar shape at the saturated walk, refused,
        ~1.8 s), and the alarm turns a cost regression into a
        failure instead of a hang."""
        import signal
        import time

        from core.concepts.audit_bridge import (
            _MAX_HINT_GROUPED_ALTERNATION_BARS,
            _MAX_HINT_REPEAT_ATOM_CHARS,
            _MAX_HINT_REPEAT_CONTINUATION_WALK,
            _MAX_REGEX_SOURCE_CHARS,
            _MIN_HINT_PREFIX_PERIOD,
            _engine_fold,
            _grep_hint_compilable,
            _string_period,
        )

        prefix = "aab"
        assert len(prefix) == _MIN_HINT_PREFIX_PERIOD
        assert (
            _string_period(_engine_fold(prefix)) == _MIN_HINT_PREFIX_PERIOD
        )
        atom = "[a-z0-9]"
        assert len(atom) == _MAX_HINT_REPEAT_ATOM_CHARS
        walk = _MAX_HINT_REPEAT_CONTINUATION_WALK
        bars = _MAX_HINT_GROUPED_ALTERNATION_BARS
        # Arithmetic-worst: bar-free continuation of exactly the walk
        # cap, prefix-periodic so the source's period never breaks it.
        cont_worst = (prefix * walk)[: walk - 1] + "z"
        assert len(cont_worst) == walk
        assert cont_worst.count("|") == 0
        worst = prefix + atom + "*" + cont_worst
        # Runner-up: the walk spent through the one admitted grouped
        # bar — (1 + bars) x chars <= walk caps the chars at
        # walk // (1 + bars).
        runner_chars = walk // (1 + bars)
        runner_cont = "(" + "a" * (runner_chars - 5) + "z|q)"
        assert len(runner_cont) == runner_chars
        assert runner_cont.count("|") == bars
        runner = prefix + atom + "*" + runner_cont
        # Measured-worst: the one admitted grouped bar spent BEFORE
        # the token (the weight counts bars over the WHOLE branch, so
        # a pre-token bar halves the continuation allowance exactly
        # like a post-token one), with the group's alternatives drawn
        # from the prefix so they MATCH the saturated source — the
        # engine walks the group on every restart instead of
        # short-circuiting, which is what makes this family the
        # measured ceiling.
        pre_group = "(" + prefix[:1] + "|" + prefix[:1] + ")"
        pre_cont = (prefix * walk)[: runner_chars - 1] + "z"
        assert len(pre_cont) == runner_chars
        assert pre_cont.count("|") == 0
        pretoken = prefix + pre_group + atom + "*" + pre_cont
        # Weight arithmetic over the constants — NOT a cost ranking:
        # the bar-free construction reaches the walk cap exactly and
        # every admitted shape whose only weight-counted bars are
        # path-splitting ones sits one weighted element lower (13 is
        # not divisible by 1 + bars = 2; mixed raw+grouped-bar
        # shapes do reach weight 13, at continuation <= 1 char —
        # figures at the clamp comment), but in full cost units
        # these three shapes TIE and the pre-token family carries
        # the MEASURED ceiling (docstring; clamp comment at
        # ``_MAX_REGEX_SOURCE_CHARS``). Each shape here is
        # a single top-level branch, so counting bars over the whole
        # hint IS the branch-wide count the shipped rule uses.
        worst_weighted = (1 + worst.count("|")) * len(cont_worst)
        runner_weighted = (1 + runner.count("|")) * len(runner_cont)
        pretoken_weighted = (1 + pretoken.count("|")) * len(pre_cont)
        assert worst_weighted == walk
        assert runner_weighted == (1 + bars) * (walk // (1 + bars))
        assert pretoken_weighted == (1 + bars) * (walk // (1 + bars))
        assert pretoken_weighted <= walk
        assert runner_weighted < worst_weighted
        assert _grep_hint_compilable(worst), worst
        assert _grep_hint_compilable(runner), runner
        assert _grep_hint_compilable(pretoken), pretoken

        (tmp_path / "domain-model.json").write_text(json.dumps({
            "bug_patterns": [
                {"id": "w", "description": "arithmetic-worst shape",
                 "what_to_grep": worst},
                {"id": "r", "description": "bar-carrying runner-up",
                 "what_to_grep": runner},
                {"id": "m", "description": "measured-worst pre-token",
                 "what_to_grep": pretoken},
            ],
        }), encoding="utf-8")
        n = _MAX_REGEX_SOURCE_CHARS
        src = ("aab" * (n // 3 + 1))[:n]  # no "z" or "q" anywhere

        def _on_alarm(signum: int, frame: object) -> None:
            msg = "admitted-hint evaluation exceeded the alarm bound"
            raise AssertionError(msg)

        old = signal.signal(signal.SIGALRM, _on_alarm)
        signal.alarm(60)
        try:
            t0 = time.perf_counter()
            block = domain_bug_patterns(tmp_path, "a.c", "f", src)
            dt = time.perf_counter() - t0
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old)
        assert block is None  # regex fails; relevance finds nothing
        assert dt < 8.0, f"worst admitted shapes took {dt:.3f}s at clamp"

    def test_milder_admitted_shapes_cost_bounded(self, tmp_path):
        """Regression net for the milder shapes that stressed the
        superseded ceiling claim: each is refused or admitted WITH a
        pinned cost. "aab(x|.*)(y|w)" is refused (two grouped bars);
        the big-but-bounded brace span "aab[ab]{0,9999}z" and the
        escape-atom span "aab\\D*z" are admitted and measure
        ~0.3-0.4 s each at the clamp (bare-engine best-of-5 on one
        host) — both under the constructed admitted worst."""
        import signal
        import time

        from core.concepts.audit_bridge import (
            _MAX_REGEX_SOURCE_CHARS,
            _grep_hint_compilable,
        )

        assert not _grep_hint_compilable("aab(x|.*)(y|w)")
        (tmp_path / "domain-model.json").write_text(json.dumps({
            "bug_patterns": [
                {"id": "p0", "description": "brace span",
                 "what_to_grep": "aab[ab]{0,9999}z"},
                {"id": "p1", "description": "escape-atom span",
                 "what_to_grep": r"aab\D*z"},
            ],
        }), encoding="utf-8")
        n = _MAX_REGEX_SOURCE_CHARS
        src = ("aab" * (n // 3 + 1))[:n]  # no "z" anywhere

        def _on_alarm(signum: int, frame: object) -> None:
            msg = "milder-shape evaluation exceeded the alarm bound"
            raise AssertionError(msg)

        old = signal.signal(signal.SIGALRM, _on_alarm)
        signal.alarm(30)
        try:
            t0 = time.perf_counter()
            block = domain_bug_patterns(tmp_path, "a.c", "f", src)
            dt = time.perf_counter() - t0
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old)
        assert block is None
        assert dt < 5.0, f"milder admitted shapes took {dt:.3f}s at clamp"

    def test_hostile_pattern_list_slice_hash_bounded(
        self, tmp_path, monkeypatch,
    ):
        """One fold-row slice recompute against a whole hostile
        pattern LIST: forty quantified-group hints — each measured
        in the seconds regime per evaluation when compiled — against
        an at-clamp adversarial source. The guard demotes every one
        to a substring scan, so the single ``domain_slice_hash`` call
        the staleness gate makes per journal row returns promptly
        (pre-refusal this call outlived a 15 s bound)."""
        import signal
        import time

        from core.concepts import audit_bridge as ab

        monkeypatch.setattr(ab, "_demoted_hints_logged", set())
        (tmp_path / "domain-model.json").write_text(json.dumps({
            "bug_patterns": [
                {"id": f"p{i}", "description": f"pattern {i}",
                 "what_to_grep": f"([ab][ba])*qqx{i}"}
                for i in range(40)
            ],
        }), encoding="utf-8")
        n = ab._MAX_REGEX_SOURCE_CHARS
        src = ("ab" * (n // 2 + 1))[:n]

        def _on_alarm(signum: int, frame: object) -> None:
            msg = "hostile-list slice recompute exceeded the alarm"
            raise AssertionError(msg)

        old = signal.signal(signal.SIGALRM, _on_alarm)
        signal.alarm(30)
        try:
            t0 = time.perf_counter()
            digest = ab.domain_slice_hash(tmp_path, "a.c", "f", src)
            dt = time.perf_counter() - t0
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old)
        assert digest is not None
        assert dt < 5.0, f"40-hint slice recompute took {dt:.3f}s"

    def test_group_split_bypass_list_slice_hash_bounded(
        self, tmp_path, monkeypatch,
    ):
        """The split-artifact shape at LIST scale: forty distinct
        "(a|aab).*z"-family hints against an at-clamp saturated
        source. Under the raw "|" branch split these were ADMITTED
        (each ~0.9 s per evaluation, ~15-25 s per fold-row slice
        recompute measured on one host); the structure-aware split
        demotes every one, so the single ``domain_slice_hash`` call
        returns promptly. Red if the top-level scanner is neutralized
        back to a raw split."""
        import signal
        import time

        from core.concepts import audit_bridge as ab

        monkeypatch.setattr(ab, "_demoted_hints_logged", set())
        (tmp_path / "domain-model.json").write_text(json.dumps({
            "bug_patterns": [
                {"id": f"p{i}", "description": f"pattern {i}",
                 "what_to_grep": f"(a|aab).*zx{i}"}
                for i in range(40)
            ],
        }), encoding="utf-8")
        n = ab._MAX_REGEX_SOURCE_CHARS
        src = ("aab" * (n // 3 + 1))[:n]

        def _on_alarm(signum: int, frame: object) -> None:
            msg = "bypass-list slice recompute exceeded the alarm"
            raise AssertionError(msg)

        old = signal.signal(signal.SIGALRM, _on_alarm)
        signal.alarm(30)
        try:
            t0 = time.perf_counter()
            digest = ab.domain_slice_hash(tmp_path, "a.c", "f", src)
            dt = time.perf_counter() - t0
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old)
        assert digest is not None
        assert dt < 5.0, f"bypass-list slice recompute took {dt:.3f}s"


class TestGrepHintGuard:
    """Decision-level pins for ``_grep_hint_compilable`` — assert on
    the guard's verdict, never on wall-clock."""

    @pytest.fixture(autouse=True)
    def _fresh_demotion_log(self, monkeypatch):
        # The guard's verdict cache would swallow the demotion-log
        # side effect for hints another test already scored — clear
        # it around every test so log assertions see cache misses.
        from core.concepts import audit_bridge as ab
        monkeypatch.setattr(ab, "_demoted_hints_logged", set())
        ab._grep_hint_compilable.cache_clear()
        yield
        ab._grep_hint_compilable.cache_clear()

    def test_plain_literal_hint_compiles(self):
        from core.concepts.audit_bridge import _grep_hint_compilable
        assert _grep_hint_compilable("sg->length after dma_map_sg")

    def test_multi_alternation_hint_compiles(self):
        from core.concepts.audit_bridge import _grep_hint_compilable
        assert _grep_hint_compilable("memcpy|memmove|strcpy|sprintf")

    def test_repeat_budget_two_directions(self):
        # Both directions of _MAX_GREP_HINT_REPEATS (1): exactly at
        # the budget keeps regex power (the common single-span hint);
        # one over is refused (the smallest chain the shape scans
        # cannot see).
        from core.concepts.audit_bridge import (
            _MAX_GREP_HINT_REPEATS,
            _grep_hint_compilable,
        )
        at_budget = "memcpy" + ".*len" * _MAX_GREP_HINT_REPEATS
        over_budget = "memcpy" + ".*len" * (_MAX_GREP_HINT_REPEATS + 1)
        assert _grep_hint_compilable(at_budget)
        assert not _grep_hint_compilable(over_budget)

    def test_star_chain_refused(self):
        from core.concepts.audit_bridge import _grep_hint_compilable
        assert not _grep_hint_compilable("a*" * 20 + "b")

    def test_optional_chain_refused(self):
        # The a?a?...a{n} classic — only the repeat budget sees it.
        from core.concepts.audit_bridge import _grep_hint_compilable
        assert not _grep_hint_compilable("a?" * 12 + "a" * 12)

    def test_consecutive_quantifiers_refused(self):
        from core.concepts.audit_bridge import _grep_hint_compilable
        assert not _grep_hint_compilable("ab**c")

    def test_nested_counted_group_refused(self):
        from core.concepts.audit_bridge import _grep_hint_compilable
        assert not _grep_hint_compilable("(a{1,9}){1,9}")

    def test_demotion_logged_once_per_hint(self, caplog):
        from core.concepts.audit_bridge import _grep_hint_compilable
        hint = ".*alloc.*free"
        with caplog.at_level("WARNING", "core.concepts.audit_bridge"):
            assert not _grep_hint_compilable(hint)
            assert not _grep_hint_compilable(hint)
        demotions = [
            r for r in caplog.records
            if "demoted to substring matching" in r.getMessage()
        ]
        assert len(demotions) == 1
        assert "alloc" in demotions[0].getMessage()

    def test_demotion_log_escapes_hostile_bytes(self, caplog):
        # Hint text is target-derived LLM output — control bytes must
        # land escaped, never raw, in the operator log.
        from core.concepts.audit_bridge import _grep_hint_compilable
        hint = ".*\x1b]0;pwn\x07.*x"
        with caplog.at_level("WARNING", "core.concepts.audit_bridge"):
            assert not _grep_hint_compilable(hint)
        demotions = [
            r for r in caplog.records
            if "demoted to substring matching" in r.getMessage()
        ]
        assert len(demotions) == 1
        assert "\x1b" not in demotions[0].getMessage()
        assert "\\x1b" in demotions[0].getMessage()

    def test_demotion_log_cap_two_directions(self, caplog, monkeypatch):
        # Both directions of _MAX_DEMOTED_HINTS_LOGGED: under the cap
        # a NEW distinct offender warns; at the cap it does not — and
        # the refusal decision is identical either way (the cap gates
        # only the log line).
        from core.concepts import audit_bridge as ab
        with caplog.at_level("WARNING", "core.concepts.audit_bridge"):
            assert not ab._grep_hint_compilable(".*under.*cap")
        assert any(
            "demoted to substring matching" in r.getMessage()
            for r in caplog.records
        )
        caplog.clear()
        monkeypatch.setattr(
            ab, "_demoted_hints_logged",
            {f"filler-{i}" for i in range(ab._MAX_DEMOTED_HINTS_LOGGED)},
        )
        with caplog.at_level("WARNING", "core.concepts.audit_bridge"):
            assert not ab._grep_hint_compilable(".*over.*cap")
        assert not any(
            "demoted to substring matching" in r.getMessage()
            for r in caplog.records
        )
        # The seen-set stays at the cap — a hostile model minting
        # unlimited distinct hints cannot grow it further.
        assert len(ab._demoted_hints_logged) == ab._MAX_DEMOTED_HINTS_LOGGED

    def test_plus_plus_code_phrase_refused_on_every_interpreter(self):
        # "sg++ without sg_next" is a documented legit hint shape
        # whose compile fate is version-dependent (re.error on 3.10,
        # possessive quantifier on 3.11+). The guard's refusal must
        # be shape-based and identical everywhere — substring is the
        # faithful matcher for a literal code phrase either way.
        from core.concepts.audit_bridge import _grep_hint_compilable
        assert not _grep_hint_compilable("sg++ without sg_next")

    @pytest.mark.parametrize("hint", [
        r"(a*)\1b",
        r"(a*)\1\1b",
        r"(.*)\1b",
        r"(\w*)\1b",
        r"(a{99})\1b",
    ])
    def test_backreference_hints_refused(self, hint):
        # Each carries a single repeat token and no quantified-group
        # shape — invisible to every other layer — yet re-matching the
        # captured span backtracks super-linearly.
        from core.concepts.audit_bridge import _grep_hint_compilable
        assert not _grep_hint_compilable(hint)

    def test_named_backref_and_conditional_refused(self):
        # Named backrefs and conditional groups happen to be refused
        # by the repeat-token budget too (the "?" in "(?" counts), so
        # pin the backref rule itself as well — budget drift must not
        # be the only thing keeping these re-match forms out.
        from core.concepts.audit_bridge import (
            _HINT_BACKREF_RE,
            _grep_hint_compilable,
        )
        for hint in (r"(?P<g>a*)(?P=g)b", r"(a)(?(1)b*|c)"):
            assert _HINT_BACKREF_RE.search(hint) is not None
            assert not _grep_hint_compilable(hint)

    def test_demotion_log_truncation_never_splits_escape(self, caplog):
        # Two directions of the excerpt cut: an escape sequence
        # SPLIT by the cut is dropped whole; an escape sequence that
        # ENDS exactly at the cut is kept whole. Either way the
        # excerpt carries the elision marker and never a partial
        # escape.
        from core.concepts import audit_bridge as ab

        def demotion_msgs():
            return [
                r.getMessage() for r in caplog.records
                if "demoted to substring matching" in r.getMessage()
            ]

        cut = ab._MAX_DEMOTED_HINT_EXCERPT_CHARS
        # Escaped form: "a"*117 + "\x1b" (chars 118-121) + ".*x.*y";
        # the cut at 120 lands inside the escape.
        split_hint = "a" * (cut - 3) + "\x1b.*x.*y"
        with caplog.at_level("WARNING", "core.concepts.audit_bridge"):
            assert not ab._grep_hint_compilable(split_hint)
        (msg,) = demotion_msgs()
        assert msg.endswith("…")
        assert "\\x1" not in msg  # the partial escape was dropped whole
        caplog.clear()
        # Escaped form: "a"*116 + "\x1b" ends exactly AT the cut — a
        # complete escape is not over-trimmed.
        kept_hint = "a" * (cut - 4) + "\x1b.*x.*y"
        with caplog.at_level("WARNING", "core.concepts.audit_bridge"):
            assert not ab._grep_hint_compilable(kept_hint)
        (msg,) = demotion_msgs()
        assert msg.endswith("\\x1b…")

    @pytest.mark.parametrize("hint", [
        r"(ab)*c",
        r"([ab][ba])*x",
        r"(x.)*y",
        r"([^x][^y])*z",
        r"(..)*xy",
        r"(a){60000}",
        r"(abab){9000}",
        r"kfree(ab)*x",
        r"kfree(ab){2000}x",
    ])
    def test_quantified_group_hints_refused(self, hint):
        # Body-blind group refusal: a plain-literal or class group
        # body passes the body-inspecting shape rules, yet every
        # iteration boundary backtracks — these measure 0.8-1.8 s
        # per evaluation when compiled (bare re.search IGNORECASE at
        # the source clamp, saturated failing source, best-of-5 wall
        # clock on one host). The kfree-prefixed pair isolates
        # _HINT_QUANTIFIED_GROUP_RE: their long literal prefix
        # satisfies the restart-density gate, so only the group rule
        # keeps them out.
        from core.concepts.audit_bridge import _grep_hint_compilable
        assert not _grep_hint_compilable(hint)

    def test_group_hint_without_group_repeat_stays_admitted(self):
        # Other direction of the quantified-group rule: a group whose
        # repeat sits INSIDE it ("kfree(.*) double free") is a legit
        # hint shape — mandatory "kfree" prefix, span cost bounded by
        # the source clamp — and must stay a regex.
        from core.concepts.audit_bridge import _grep_hint_compilable
        assert _grep_hint_compilable("kfree(.*) double free")

    def test_span_prefix_period_two_directions(self):
        # Both directions of _MIN_HINT_PREFIX_PERIOD (3): the
        # shortest common C-identifier prefix keeps regex power; a
        # shorter or self-overlapping prefix lets a failing search
        # restart the span at up to every source position — the
        # density-1 shapes measure ~3-4x the tail-free period-3
        # baseline at the source clamp ("aab.*z" 0.22 s vs "x.*y"
        # 0.68 s / "aa.*z"
        # 0.88 s; bare re.search IGNORECASE, saturated failing
        # source, best-of-5 wall clock on one host).
        from core.concepts.audit_bridge import _grep_hint_compilable
        # At the floor: period-3 prefixes stay regexes.
        assert _grep_hint_compilable("len.*memcpy")
        assert _grep_hint_compilable("aab.*z")
        # Below the floor: demoted to substring matching.
        assert not _grep_hint_compilable("ab.*z")    # period 2
        assert not _grep_hint_compilable("aa.*z")    # period 1
        assert not _grep_hint_compilable("aaaa.*z")  # long, period 1
        assert not _grep_hint_compilable("x.*y")     # 1-char prefix
        assert not _grep_hint_compilable(".*z")      # no prefix
        assert not _grep_hint_compilable("a*z")      # span atom only

    def test_span_prefix_period_engine_folded(self):
        # Matching is IGNORECASE, so the period is computed under the
        # ENGINE's character equivalence (_engine_fold), not any
        # plain string fold. Same-letter case: "aAA" (raw period 3)
        # folds to period-1 "aaa"; "kKK" needs the lower() layer
        # (KELVIN SIGN lowercases to "k"). Cross-codepoint orbits:
        # "ſsss" hides period-1 "ssss" behind the long s, and the
        # i/ı orbit is the one where casefold() DISAGREES with the
        # engine — "iıı" casefolds to period-3 "iıı" yet the engine
        # matches i <-> ı at every position (true restart density 1;
        # 0.81 s at the clamp, bare-engine best-of-5, vs the 0.22 s
        # tail-free "aab.*z" baseline). Expansion traps: casefold
        # blows "İ" and
        # "ﬃ" up to multi-char strings ("i"+dot, "ffi") with fake
        # period 3, while the engine matches each 1:1 (İ <-> i by
        # simple lowercase; ﬃ only to itself) — density 1 again
        # (0.76 s / 0.92 s in the same venue). Every one must refuse.
        from core.concepts.audit_bridge import _grep_hint_compilable
        assert not _grep_hint_compilable("aAA.*z")
        assert not _grep_hint_compilable("kKK.*z")
        assert not _grep_hint_compilable("ſsss.*z")
        assert not _grep_hint_compilable("iıı.*z")
        assert not _grep_hint_compilable("ıii.*z")
        assert not _grep_hint_compilable("İii.*z")
        assert not _grep_hint_compilable("ﬃﬃﬃ.*z")

    def test_engine_fold_admits_what_the_engine_distinguishes(self):
        # Direction pin for the fold itself: ß is NOT in any engine
        # orbit with "s" (re.IGNORECASE matches ß only against ß/ẞ),
        # so "ssß" is a true period-3 prefix and keeps regex power.
        # casefold() expands ß to "ss" (period-1 "ssss") — a fold
        # regression back to casefold turns this admission off.
        import re as _re

        from core.concepts.audit_bridge import _grep_hint_compilable
        assert _re.fullmatch("s", "ß", _re.IGNORECASE) is None
        assert _grep_hint_compilable("ssß.*z")

    def test_engine_fold_covers_interpreter_orbits(self):
        # Drift pin for the HARDCODED orbit table: re-derive the
        # engine's extra-case pairs from the RUNNING interpreter and
        # assert the fold unifies every one (the admission-risk
        # direction — a pair the fold misses is a period the rule
        # overstates). The table is hardcoded so the verdict feeding
        # domain_slice_hash never varies by interpreter; this test is
        # the loud failure that demands a table update when a new
        # interpreter widens re._casefix.
        from re import _casefix

        from core.concepts.audit_bridge import _engine_fold
        for k, vals in _casefix._EXTRA_CASES.items():
            for v in vals:
                assert _engine_fold(chr(k)) == _engine_fold(chr(v)), (
                    f"engine orbit pair not unified by _engine_fold: "
                    f"{hex(k)} vs {hex(v)}"
                )
        # The one character whose full lowercase EXPANDS: the engine
        # simple-lowercases İ to "i", and the fold must too (1:1).
        assert _engine_fold("İ") == "i"

    def test_span_prefix_checked_per_alternation_branch(self):
        # A literal first branch must not vouch for a bare span in a
        # later branch; alternations made only of plain literals keep
        # regex power (no unbounded repeat in any branch).
        from core.concepts.audit_bridge import _grep_hint_compilable
        assert not _grep_hint_compilable("memcpy|.*z")
        assert _grep_hint_compilable("memcpy|memmove|strcpy|sprintf")

    @pytest.mark.parametrize("hint", [
        "(a|aab).*z",        # the split-artifact bypass itself
        "(aab|a).*z",        # branch order must not matter
        "aabX|(a|aab).*z",   # benign top-level branch in front
        "aab|[]|aab]*z",     # bar hidden in a class ("]" first member)
        "[q|aab]*z",         # class-star rebuild of the same shape
        "(memcpy|memmove).*len",  # group alternation, no whole-branch
                                  # prefix before the span
    ])
    def test_group_internal_alternation_never_vouches(self, hint):
        # The restart-density rule takes its branches from the
        # structure-aware top-level split: a bar INSIDE a group or
        # class is not an alternative of the whole pattern, so a
        # strong literal fragment there must never vouch for a span
        # whose real branch has no mandatory prefix. A raw "|" split
        # admitted every one of these (true engine restart density 1;
        # 0.72-1.8 s per evaluation at the source clamp, bare
        # re.search IGNORECASE best-of-5 on one host, vs the 0.22 s
        # tail-free "aab.*z" baseline).
        from core.concepts.audit_bridge import _grep_hint_compilable
        assert not _grep_hint_compilable(hint)

    def test_group_after_admissible_prefix_stays_admitted(self):
        # Other direction of the top-level split: when the mandatory
        # whole-branch prefix DOES clear the period floor, a
        # group-internal alternation after it is fine — the prefix,
        # not the group, bounds the restart density (same class as
        # the admitted "memcpy.*len" baseline). A raw "|" split
        # over-refused this shape on its "b.*z)" fragment.
        from core.concepts.audit_bridge import _grep_hint_compilable
        assert _grep_hint_compilable("memcpy(a|b.*z)")

    def test_top_level_branch_scanner_structure(self):
        # Unit pins for _hint_top_level_branches: bars split only at
        # depth 0 outside classes; escapes and the leading
        # "]"-as-member rule are honoured; unbalanced structure
        # returns None (refusal at the caller).
        from core.concepts.audit_bridge import _hint_top_level_branches
        assert _hint_top_level_branches("a|b") == ["a", "b"]
        assert _hint_top_level_branches("(a|aab).*z") == ["(a|aab).*z"]
        assert _hint_top_level_branches("ab[|]c") == ["ab[|]c"]
        assert _hint_top_level_branches(r"a\|b") == [r"a\|b"]
        assert _hint_top_level_branches("aab|[]|aab]*z") == [
            "aab", "[]|aab]*z",
        ]
        assert _hint_top_level_branches("[^]a|b]c") == ["[^]a|b]c"]
        assert _hint_top_level_branches("(a") is None
        assert _hint_top_level_branches("a)") is None
        assert _hint_top_level_branches("[ab") is None

    def test_unbalanced_structure_two_directions(self):
        # Unbalanced structure WITH an unbounded repeat refuses (the
        # scanner cannot attribute the repeat to a true branch, and
        # re.error would demote such a hint anyway); unbalanced
        # structure with NO repeat token anywhere is exempt before
        # any structure scan — truncated identifier hints like
        # "(frame_checksum" keep their historical verdict.
        from core.concepts.audit_bridge import _grep_hint_compilable
        assert not _grep_hint_compilable("(a.*z")
        assert _grep_hint_compilable("(frame_checksum")

    def test_repeat_continuation_walk_two_directions(self):
        # Both directions of _MAX_HINT_REPEAT_CONTINUATION_WALK (13):
        # at the budget the longest legit continuation keeps regex
        # power ("kfree(.*) double free" — ") double free" is exactly
        # 13 chars — and its 13-char prefix-periodic analogue); one
        # char over is refused. The walk is bar-WEIGHTED by the WHOLE
        # branch, (1 + branch bars) * continuation chars: a grouped
        # bar doubles what each backtracked position walks whether it
        # sits after the token (the alternation is re-walked per
        # backtrack) or before it (the span and its walk are re-run
        # per alternative). So 13 continuation chars with a bar weigh
        # 26 and refuse while 6 chars with a bar weigh 12 and stay
        # admitted — on BOTH sides of the token (rationale and
        # measurements at the constant).
        from core.concepts.audit_bridge import (
            _MAX_HINT_REPEAT_CONTINUATION_WALK,
            _grep_hint_compilable,
        )
        walk = _MAX_HINT_REPEAT_CONTINUATION_WALK
        at_budget = ("aab" * walk)[: walk - 1] + "z"     # 13 chars
        over_budget = ("aab" * walk)[:walk] + "z"        # 14 chars
        assert _grep_hint_compilable("kfree(.*) double free")
        assert _grep_hint_compilable("aab.*" + at_budget)
        assert not _grep_hint_compilable("aab.*" + over_budget)
        # bar AFTER the token
        assert _grep_hint_compilable("aab.*(az|q)")            # 2*6=12
        assert not _grep_hint_compilable("aab.*(aabaabaaz|q)")  # 2*13
        # bar BEFORE the token — same weight, same boundary
        assert _grep_hint_compilable("aab(x|y)[a-z0-9]*aabaaz")      # 2*6
        assert not _grep_hint_compilable("aab(x|y)[a-z0-9]*aabaabz")  # 2*7
        # ... and with alternatives that MATCH a prefix-saturated
        # source — the measured-worst admitted family (the (x|y)
        # spelling above short-circuits on such a source and hides
        # the family's cost; figures at the constant). Same weight,
        # same boundary.
        assert _grep_hint_compilable("aab(a|a)[a-z0-9]*aabaaz")      # 2*6
        assert not _grep_hint_compilable("aab(a|a)[a-z0-9]*aabaabz")  # 2*7
        # ... and the family's atom spelling is free within the atom
        # cap: a multi-member negated class spells 6 and keeps the
        # same weight-12/14 boundary — the family's costliest
        # sampled spelling AXIS, its range+literal mixes at the
        # sampled top (spelling-dependent, no stated supremum;
        # figures at the clamp comment).
        assert _grep_hint_compilable("aab(a|a)[^c-z]*aabaaz")        # 2*6
        assert not _grep_hint_compilable("aab(a|a)[^c-z]*aabaazz")   # 2*7
        # ... and a range+literal MIX inside that axis spells 7 —
        # still within the atom cap — and keeps the same boundary
        # (the mix defeats the single-RANGE charset compilation;
        # figures at the clamp comment).
        assert _grep_hint_compilable("aab(a|a)[^c-e9]*aabaaz")       # 2*6
        assert not _grep_hint_compilable("aab(a|a)[^c-e9]*aabaazz")  # 2*7
        # Raw (escaped or class-member) bars split no paths but are
        # weight-counted anyway (demote-only, asymmetry note at the
        # constant): raw-bar weight-13 admitted shapes exist and
        # are strictly cheap (~0.000 s: the mandatory literal bars
        # kill every match attempt immediately).
        assert _grep_hint_compilable("aab" + r"\|" * 12 + "[ab]*z")   # 13*1
        assert not _grep_hint_compilable(
            "aab" + r"\|" * 13 + "[ab]*z"                             # 14*1
        )
        # ... and raw bars MIX with the one grouped bar in the raw
        # branch count, so weight 13 is reachable WITH a
        # path-splitting bar present — one grouped bar + 11 raw
        # bars over a 1-char continuation, (1+12)*1 = 13 (the bar
        # BUDGET counts only the grouped bar) — in both raw
        # spellings; one more raw bar weighs (1+13)*1 = 14 and
        # refuses. Measured figures for both spellings at the clamp
        # comment (escaped ~0.000 s; class-member ~1.0 s — its
        # classes match a prefix-saturated source, so the doubled
        # span work is real — both below the measured-worst family).
        assert _grep_hint_compilable(
            "aab(a|a)" + r"\|" * 11 + "[ab]*z"                        # 13*1
        )
        assert not _grep_hint_compilable(
            "aab(a|a)" + r"\|" * 12 + "[ab]*z"                        # 14*1
        )
        assert _grep_hint_compilable(
            "aab(a|a)" + "[a|b]" * 11 + "[a-z0-9]*z"                  # 13*1
        )
        assert not _grep_hint_compilable(
            "aab(a|a)" + "[a|b]" * 12 + "[a-z0-9]*z"                  # 14*1
        )
        # Top-level bars are additive, not multiplicative: a grouped
        # bar in a SIBLING top-level branch is priced only against
        # its own branch's (empty) continuation, so the repeat
        # branch keeps the full walk 13 — while the same bar moved
        # INTO the repeat branch weighs (1 + 1) * 13 = 26 and
        # refuses.
        assert _grep_hint_compilable("x(a|a)y|aab[a-z0-9]*" + at_budget)
        assert not _grep_hint_compilable("aab(a|a)[a-z0-9]*" + at_budget)

    def test_literal_tail_continuation_refused(self):
        # Red-if-neutralized pin for the literal-tail family: a
        # minimum-period prefix, ONE repeat token, and a long
        # self-overlapping literal tail — every guard layer before
        # the continuation walk admits it, and per-backtrack tail
        # cost multiplies the quadratic term ~linearly in tail
        # length (L30 ~1.0 s, L90 ~3.0 s, L240 ~7.4 s at the source
        # clamp; venue at the constant). Removing or unbounding the
        # walk turns every one of these back into an admission.
        from core.concepts.audit_bridge import _grep_hint_compilable
        for repeats in (10, 30, 80):
            hint = "aab.*" + "aab" * repeats + "z"
            assert not _grep_hint_compilable(hint), hint

    def test_pre_token_grouped_bar_saturated_walk_refused(self):
        # Red-if-neutralized pin for the pre-token-bar family: the
        # one admitted grouped bar spent BEFORE the repeat token,
        # riding in front of a walk-saturated bar-free continuation.
        # sre re-runs the span AND its backtrack walk once per group
        # alternative, so this shape costs (1 + bars) x the bar-free
        # twin (~1.8 s vs ~0.9 s at the source clamp; venue at the
        # constant) — the branch-wide bar weight prices it at
        # (1 + 1) * 13 = 26 > 13 and refuses. Weighting only the
        # continuation's own bars would admit every one of these;
        # the bar-free twin stays admitted.
        from core.concepts.audit_bridge import _grep_hint_compilable
        tail13 = ("aab" * 5)[:12] + "z"  # aabaabaabaabz
        assert _grep_hint_compilable("aab[a-z0-9]*" + tail13)  # twin
        for hint in (
            "aab(a|a)[a-z0-9]*" + tail13,
            "aab(a|a).*" + tail13,
            "aab(x|y).*" + tail13,
            "memcpy(a|b).*" + tail13,
        ):
            assert not _grep_hint_compilable(hint), hint

    def test_repeat_atom_spelling_two_directions(self):
        # Both directions of _MAX_HINT_REPEAT_ATOM_CHARS (8): the
        # common range class "[a-z0-9]" spells exactly 8 and keeps
        # regex power (so do the golden "abc[)]*x" at 3 and the
        # escape atom "\D" at 2); one char over is refused, as is an
        # escape-heavy member zoo whose per-span-char cost the model
        # cannot state. The spelled span is located by the branch
        # splitter's forward class scan: a class-member "[" must not
        # fake a short spelling.
        from core.concepts.audit_bridge import _grep_hint_compilable
        assert _grep_hint_compilable("aab[a-z0-9]*z")       # spells 8
        assert _grep_hint_compilable("abc[)]*x")            # spells 3
        assert _grep_hint_compilable(r"aab\D*z")            # spells 2
        assert not _grep_hint_compilable("aab[a-z0-9_]*z")  # spells 9
        assert not _grep_hint_compilable(r"aab[ab\x63\x64]*z")
        # class-member "[": true opener is index 3, spelling 11
        assert not _grep_hint_compilable("aab[qwerty[ab]*z")

    def test_repeat_atom_chars_structure(self):
        # Unit pins for _hint_repeat_atom_chars: literal / escape /
        # class atoms; the class span is measured from its TRUE
        # opener (a nearest-"[" backward scan would credit the
        # class-member "[" instead); token at position 0 spells 0.
        from core.concepts.audit_bridge import _hint_repeat_atom_chars
        assert _hint_repeat_atom_chars("aab.*z", 4) == 1
        assert _hint_repeat_atom_chars(r"aab\D*z", 5) == 2
        assert _hint_repeat_atom_chars("abc[)]*x", 6) == 3
        assert _hint_repeat_atom_chars("aab[a-z0-9]*z", 11) == 8
        assert _hint_repeat_atom_chars("aab[qwerty[ab]*z", 14) == 11
        assert _hint_repeat_atom_chars("*z", 0) == 0

    def test_grouped_alternation_bar_budget_two_directions(self):
        # Both directions of _MAX_HINT_GROUPED_ALTERNATION_BARS (1):
        # one grouped bar keeps the legit
        # group-alternation-after-prefix class admitted
        # ("memcpy(a|b.*z)"); a second grouped bar refuses — every
        # allowed bar doubles the paths one match attempt explores
        # through the pattern suffix (rationale and the exponential
        # stack measurements at the constant).
        from core.concepts.audit_bridge import _grep_hint_compilable
        assert _grep_hint_compilable("memcpy(a|b.*z)")
        assert not _grep_hint_compilable("aab(x|.*)(y|w)")
        assert not _grep_hint_compilable("(a|b|c)x")
        # Top-level bars stay additive, not multiplicative — budget
        # does not touch them.
        assert _grep_hint_compilable("memcpy|memmove|strcpy|sprintf")

    def test_alternation_stack_refused(self):
        # Red-if-neutralized pin for the repeat-free exponential:
        # "(a|a)(a|a)...b" carries ZERO repeat tokens — invisible to
        # every repeat-anchored rule — yet sre memoises nothing, so
        # each group doubles the paths per start position (measured
        # x~1.9 per group; 0.93 s at 22 groups over a 32-char source,
        # venue at the constant). Only the grouped-bar budget stands
        # between this family and an effective hang at the clamp.
        from core.concepts.audit_bridge import _grep_hint_compilable
        assert not _grep_hint_compilable("(a|a)(a|a)b")
        assert not _grep_hint_compilable("(a|a)" * 10 + "b")
        assert not _grep_hint_compilable("(a|a)" * 24 + "b")

    def test_grouped_bar_counter_structure(self):
        # Unit pins for _hint_grouped_alternation_bars: depth moves
        # only on TRUE group parens — an escaped or class-member ")"
        # must not close the depth and hide the bars behind it (each
        # rebuilds the exponential stack if it does) — while escaped
        # and class-member bars are literal members and never count.
        # Counting never fails: unterminated structure still yields
        # a defined count (refusal-on-unbalance stays the splitter's,
        # for repeat-bearing hints only).
        from core.concepts.audit_bridge import (
            _hint_grouped_alternation_bars,
        )
        assert _hint_grouped_alternation_bars("a|b") == 0
        assert _hint_grouped_alternation_bars("(a|b)") == 1
        assert _hint_grouped_alternation_bars("(a|b|c)") == 2
        assert _hint_grouped_alternation_bars(r"a\|b(c)") == 0
        assert _hint_grouped_alternation_bars("[(]a|b") == 0
        assert _hint_grouped_alternation_bars("(a[|]b)") == 0
        assert _hint_grouped_alternation_bars(r"(a\)x|a)") == 1
        assert _hint_grouped_alternation_bars("([)]|x)") == 1
        assert _hint_grouped_alternation_bars("(a|b") == 1
        assert _hint_grouped_alternation_bars("a)b|c") == 0


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

    def test_whitespace_evidence_does_not_crash(self):
        # LLM-authored models can carry whitespace-only string
        # evidence — split()[0] on it raised IndexError, aborting one
        # consumer mid-run and failing another open.
        inv = {"id": "g", "evidence": ["  ", "\t"]}
        assert _guard_in_scope(inv, "any/file.c")

    def test_whitespace_evidence_ignored_beside_real_scope(self):
        inv = {"id": "g", "evidence": ["  ", "lib/parse.c:12 note"]}
        assert _guard_in_scope(inv, "lib/parse.c")
        assert not _guard_in_scope(inv, "lib/other.c")


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

    def test_stale_invariant_tagged_in_primers(self, domain_model, tmp_path):
        """A quarantined invariant must read as [stale-unverified] on
        the primers path — never as receipt-backed ground truth."""
        from core.concepts.audit_bridge import primers_from_domain_model
        domain_model["invariants"][0]["provenance"] = "verbatim"
        domain_model["invariants"][0]["state"] = "stale"
        dm_path = tmp_path / "domain-model.json"
        dm_path.write_text(json.dumps(domain_model), encoding="utf-8")
        primers = primers_from_domain_model(
            tmp_path, "crypto/algif_aead.c", "_aead_recvmsg",
            source="scatterlist page aliasing",
        )
        joined = "\n".join(primers)
        assert "[stale-unverified]" in joined
        assert "[verbatim] Pages accessible" not in joined

    def test_stale_contract_dropped_from_primers(
        self, domain_model, tmp_path,
    ):
        """The contract primer carries no tier tag — a stale contract
        (source drifted since study) must not be served at all."""
        from core.concepts.audit_bridge import (
            _load_cached,
            primers_from_domain_model,
        )
        dm_path = tmp_path / "domain-model.json"

        dm_path.write_text(json.dumps(domain_model), encoding="utf-8")
        fresh = primers_from_domain_model(
            tmp_path, "crypto/algif_aead.c", "_aead_recvmsg",
        )
        assert any("CONTRACT FOR _aead_recvmsg" in p for p in fresh)

        domain_model["contracts"][0]["state"] = "stale"
        dm_path.write_text(json.dumps(domain_model), encoding="utf-8")
        # The model loader caches by path for the process lifetime —
        # drop it so the rewritten fixture is re-read.
        _load_cached.cache_clear()
        stale = primers_from_domain_model(
            tmp_path, "crypto/algif_aead.c", "_aead_recvmsg",
        )
        assert not any("CONTRACT FOR _aead_recvmsg" in p for p in stale)


class TestNameVariantJoin:
    """Binary audits key functions with r2 decoration; source
    inventories legitimately emit dotted names. Matching considers
    BOTH forms — an in-place strip regressed source exact joins."""

    def test_source_dotted_name_keeps_exact_join(self):
        from core.concepts.audit_bridge import _relevance_score
        contract = {"function": "sym.lookup", "file": "src/symtab.lua"}
        assert _relevance_score(
            contract, "src/symtab.lua", "sym.lookup", "") >= 10.0

    def test_r2_decorated_name_joins_bare_contract(self):
        from core.concepts.audit_bridge import _relevance_score
        contract = {"function": "parse_header", "file": "g1.c"}
        for decorated in ("sym.parse_header", "sym.imp.parse_header",
                          "fcn.parse_header"):
            assert _relevance_score(
                contract, "binary:/x", decorated, "") >= 8.0

    def test_primers_contract_loop_joins_decorated_names(
        self, tmp_path,
    ):
        import json

        from core.concepts.audit_bridge import (
            _load_cached,
            primers_from_domain_model,
        )
        (tmp_path / "domain-model.json").write_text(json.dumps({
            "concepts": [], "invariants": [],
            "contracts": [{
                "function": "parse_header", "file": "g1.c",
                "input_semantics": "len bounds data",
            }],
        }))
        _load_cached.cache_clear()
        primers = primers_from_domain_model(
            tmp_path, "binary:/x", "sym.parse_header")
        assert primers, "decorated name found no contract primer"
        assert any("parse_header" in p for p in primers)

    def test_concept_primer_joins_top_level_invariants(self, tmp_path):
        """The DOMAIN-SPECIFIC concept primer must render from the
        schema study writers actually produce: Concept.to_dict rows
        (id/description/evidence) with invariants in the model's
        top-level list, joined by concept id."""
        import json

        from core.concepts.audit_bridge import (
            _load_cached,
            primers_from_domain_model,
        )
        (tmp_path / "domain-model.json").write_text(json.dumps({
            "version": "1",
            "concepts": [{
                "id": "buf_ownership",
                "description": "caller owns buf until release",
                "confidence": "traced",
                "evidence": [{
                    "type": "code_path", "file": "h.c",
                    "item": "consume_buf", "observation": "takes buf",
                }],
            }],
            "invariants": [{
                "id": "inv_release_once",
                "concept": "buf_ownership",
                "statement": "buf must be released exactly once",
                "negation": "double release corrupts the pool",
            }],
            "contracts": [],
        }), encoding="utf-8")
        _load_cached.cache_clear()
        primers = primers_from_domain_model(
            tmp_path, "h.c", "consume_buf",
        )
        concept_primers = [
            p for p in primers if "CONCEPT — buf ownership" in p
        ]
        assert concept_primers, "expected a concept primer"
        assert "buf must be released exactly once" in concept_primers[0]
        assert "caller owns buf until release" in concept_primers[0]
        # No provenance stamp on the invariant → fail-closed hint tier.
        assert "[unverified]" in concept_primers[0]

    def test_concept_primer_accepts_inline_string_invariants(
        self, tmp_path,
    ):
        """Inline concept["invariants"] entries (plain strings) are a
        supported consumer shape and must keep producing a primer."""
        import json

        from core.concepts.audit_bridge import (
            _load_cached,
            primers_from_domain_model,
        )
        (tmp_path / "domain-model.json").write_text(json.dumps({
            "version": "1",
            "concepts": [{
                "id": "buf_ownership",
                "description": "caller owns buf",
                "invariants": ["callers must own buf"],
                "evidence": [{"file": "h.c", "item": "f"}],
            }],
        }), encoding="utf-8")
        _load_cached.cache_clear()
        primers = primers_from_domain_model(tmp_path, "h.c", "f")
        assert any(
            "callers must own buf" in p and "[unverified]" in p
            for p in primers
        )

    def test_bare_prefix_name_yields_no_empty_variant(self):
        """A name that IS a bare r2 prefix must not produce an
        empty-string variant — "" substring-matches every item (+5
        noise) and joins a contract missing its function key
        (KeyError swallowed into silent primer loss)."""
        from core.concepts.audit_bridge import (
            _name_variants,
            _relevance_score,
        )
        assert _name_variants("sym.") == ("sym.",)
        unrelated = {"id": "x", "description": "nothing related"}
        assert _relevance_score(unrelated, "f.c", "sym.", "") < 5.0


class TestContractQualifiedIdentity:
    """Contracts are (function, file) authority — never name-only."""

    @staticmethod
    def _model_with_contract(**overrides):
        contract = {
            "function": "parse_header",
            "file": "driver_a/proto.c",
            "input_semantics": "hdr is pre-validated by caller; "
                               "len <= 64 guaranteed",
            "provenance": "verbatim",
        }
        contract.update(overrides)
        return {
            "version": "1", "target": "t", "source_root": "s",
            "concepts": [], "invariants": [],
            "contracts": [contract],
        }

    def _write(self, tmp_path, model):
        (tmp_path / "domain-model.json").write_text(
            json.dumps(model), encoding="utf-8")
        return tmp_path

    def test_primer_not_served_across_files(self, tmp_path):
        from core.concepts.audit_bridge import primers_from_domain_model
        out = self._write(tmp_path, self._model_with_contract())
        primers = primers_from_domain_model(
            out, "driver_b/other.c", "parse_header")
        assert not any("pre-validated" in p for p in primers), (
            "another file's contract served as authority for a "
            "same-named function"
        )

    def test_primer_served_for_matching_file(self, tmp_path):
        from core.concepts.audit_bridge import primers_from_domain_model
        out = self._write(tmp_path, self._model_with_contract())
        primers = primers_from_domain_model(
            out, "driver_a/proto.c", "parse_header")
        served = [p for p in primers if "pre-validated" in p]
        assert served, "same-file contract must still be served"

    def test_served_contract_carries_tier_tag(self, tmp_path):
        from core.concepts.audit_bridge import primers_from_domain_model
        out = self._write(tmp_path, self._model_with_contract())
        primers = primers_from_domain_model(
            out, "driver_a/proto.c", "parse_header")
        header = next(p for p in primers if "CONTRACT FOR" in p)
        assert "[verbatim]" in header.splitlines()[0]

    def test_unstamped_contract_reads_unverified(self, tmp_path):
        from core.concepts.audit_bridge import primers_from_domain_model
        model = self._model_with_contract()
        del model["contracts"][0]["provenance"]
        out = self._write(tmp_path, model)
        primers = primers_from_domain_model(
            out, "driver_a/proto.c", "parse_header")
        header = next(p for p in primers if "CONTRACT FOR" in p)
        assert "[unverified]" in header.splitlines()[0]

    def test_fileless_contract_served_with_caution(self, tmp_path):
        from core.concepts.audit_bridge import primers_from_domain_model
        out = self._write(tmp_path, self._model_with_contract(file=""))
        primers = primers_from_domain_model(
            out, "driver_b/other.c", "parse_header")
        served = next(p for p in primers if "CONTRACT FOR" in p)
        assert "function name only" in served

    def test_context_block_not_served_across_files(self, tmp_path):
        model = self._model_with_contract()
        # Give the contract a description naming the function so the
        # relevance score clears the threshold on name alone.
        model["contracts"][0]["description"] = (
            "parse_header contract: caller pre-validates hdr")
        out = self._write(tmp_path, model)
        block = domain_model_context(
            out, "driver_b/other.c", "parse_header")
        assert block is None or "pre-validated" not in block

    def test_binary_pseudo_path_falls_back_to_name_match(self, tmp_path):
        """Binary audits key items by the binary: pseudo-path; study
        contract files are decompile units — incomparable shapes must
        not drop every contract."""
        from core.concepts.audit_bridge import primers_from_domain_model
        out = self._write(tmp_path, self._model_with_contract(file="g1.c"))
        primers = primers_from_domain_model(
            out, "binary:/x", "parse_header")
        assert any("CONTRACT FOR" in p for p in primers)

    def test_fallback_serve_carries_caution_exact_serve_does_not(
        self, tmp_path,
    ):
        """A pseudo-path fallback serve is a name-only match and must
        carry the same caution as the fileless path; an exact-keyed
        (file-matched) serve must not."""
        from core.concepts.audit_bridge import primers_from_domain_model
        out = self._write(tmp_path, self._model_with_contract(file="g1.c"))
        fallback = next(
            p for p in primers_from_domain_model(
                out, "binary:/x", "parse_header")
            if "CONTRACT FOR" in p
        )
        assert "function name only" in fallback
        exact = next(
            p for p in primers_from_domain_model(
                out, "g1.c", "parse_header")
            if "CONTRACT FOR" in p
        )
        assert "function name only" not in exact

class TestDriftedModelDegradesPerEntry:
    """One schema-drifted record must cost one logged gap, never the
    whole domain-knowledge block (consumers catch-all at DEBUG, so an
    escaped KeyError is silent total loss)."""

    @staticmethod
    def _drifted_model():
        return {
            "version": "1", "target": "t", "source_root": "s",
            "concepts": [
                # id missing: the drifted record (description still
                # names the function so it scores as relevant).
                {"description": "checksum_verify validates the frame"},
                {"id": "frame_layout",
                 "description": "checksum_verify frames carry a "
                                "trailing CRC"},
                "just a string",
            ],
            "invariants": [
                {"concept": "frame_layout",
                 "statement": "checksum_verify must run before use"},
                {"id": "crc_before_use", "concept": "frame_layout",
                 "statement": "checksum_verify precedes any field "
                              "read"},
            ],
            "contracts": [
                {"file": "net/frame.c",
                 "input_semantics": "drifted: no function key"},
                {"function": "checksum_verify", "file": "net/frame.c",
                 "input_semantics": "buf holds >= 4 bytes"},
            ],
        }

    def test_block_survives_drifted_records(self, tmp_path, caplog):
        import logging

        (tmp_path / "domain-model.json").write_text(
            json.dumps(self._drifted_model()), encoding="utf-8")
        with caplog.at_level(
            logging.WARNING, logger="core.concepts.audit_bridge",
        ):
            block = domain_model_context(
                tmp_path, "net/frame.c", "checksum_verify")
        assert block is not None, "drifted record killed the block"
        # The intact records still render.
        assert "frame_layout" in block
        assert "crc_before_use" in block
        assert "buf holds >= 4 bytes" in block
        # The gap is recorded, both in the log and in the block.
        assert any("schema drift" in r.message for r in caplog.records)
        assert "schema-drifted" in block

    def test_primers_survive_drifted_records(self, tmp_path):
        from core.concepts.audit_bridge import primers_from_domain_model
        (tmp_path / "domain-model.json").write_text(
            json.dumps(self._drifted_model()), encoding="utf-8")
        primers = primers_from_domain_model(
            tmp_path, "net/frame.c", "checksum_verify")
        assert any("CONTRACT FOR checksum_verify" in p for p in primers)

    def test_non_list_key_degrades_to_empty(self, tmp_path):
        model = self._drifted_model()
        model["invariants"] = "corrupted"
        (tmp_path / "domain-model.json").write_text(
            json.dumps(model), encoding="utf-8")
        block = domain_model_context(
            tmp_path, "net/frame.c", "checksum_verify")
        assert block is not None
        assert "frame_layout" in block


class TestDomainSliceHash:
    """Per-function prompt-slice fingerprint (verdict-reuse key)."""

    _SOURCE = (
        "int check_pw(const char *pw) {\n"
        "    return strcmp(pw, stored) == 0;\n"
        "}\n"
    )

    @staticmethod
    def _write(tmp_path, model: dict) -> None:
        from core.concepts.audit_bridge import _load_cached
        (tmp_path / "domain-model.json").write_text(
            json.dumps(model), encoding="utf-8")
        # The loader caches by resolved path for the process lifetime;
        # tests that rewrite the same file must drop the cache like a
        # fresh audit process would.
        _load_cached.cache_clear()

    def _hash(self, tmp_path) -> str | None:
        from core.concepts.audit_bridge import domain_slice_hash
        return domain_slice_hash(
            tmp_path, "auth.c", "check_pw", self._SOURCE)

    def test_no_model_yields_none(self, tmp_path):
        from core.concepts.audit_bridge import domain_slice_hash
        assert domain_slice_hash(tmp_path, "auth.c", "check_pw") is None

    def test_deterministic_full_sha256(self, dm_dir):
        from core.concepts.audit_bridge import domain_slice_hash
        h1 = domain_slice_hash(
            dm_dir, "crypto/algif_aead.c", "_aead_recvmsg", "sg aliasing")
        h2 = domain_slice_hash(
            dm_dir, "crypto/algif_aead.c", "_aead_recvmsg", "sg aliasing")
        assert h1 is not None
        assert h1 == h2
        # Full digest, not the whole-model hash's 8-char prefix: the
        # stamp is compared for byte-identity across model rewrites,
        # so it gets the full collision margin.
        assert len(h1) == 64
        int(h1, 16)

    def test_empty_selection_still_stamps(self, tmp_path):
        self._write(
            tmp_path, {"concepts": [], "invariants": [], "contracts": []})
        h = self._hash(tmp_path)
        # "Nothing injected for this function" is a real, comparable
        # prompt state — only a MISSING model refuses to stamp.
        assert h is not None
        assert len(h) == 64

    def test_irrelevant_model_growth_keeps_hash(self, tmp_path):
        self._write(
            tmp_path, {"concepts": [], "invariants": [], "contracts": []})
        before = self._hash(tmp_path)
        self._write(tmp_path, {
            "concepts": [{
                "id": "cred_cache_rules",
                "description": "credential cache invalidation rules",
                "related_strategies": ["auth"],
            }],
            "invariants": [],
            "contracts": [],
        })
        after = self._hash(tmp_path)
        # The new concept never selects for check_pw (relevance 0), so
        # the function's injected slice — and its fingerprint — is
        # unchanged even though the whole model grew.
        assert before == after

    def test_relevant_model_growth_changes_hash(self, tmp_path):
        self._write(
            tmp_path, {"concepts": [], "invariants": [], "contracts": []})
        before = self._hash(tmp_path)
        self._write(tmp_path, {
            "concepts": [{
                "id": "pw_compare_rules",
                "description": "check_pw must compare in constant time",
            }],
            "invariants": [],
            "contracts": [],
        })
        after = self._hash(tmp_path)
        assert before != after

    def test_sage_recall_excluded_from_fingerprint(
        self, tmp_path, monkeypatch,
    ):
        import core.concepts.audit_bridge as ab
        # A concept that selects for check_pw but yields no primer
        # (no invariants), so the fingerprint includes the
        # domain-knowledge block — the one place SAGE recall renders.
        self._write(tmp_path, {
            "concepts": [{
                "id": "pw_compare_rules",
                "description": "check_pw must compare in constant time",
            }],
            "invariants": [],
            "contracts": [],
        })
        calls = {"n": 0}

        def _volatile_sage(out_dir, file_path, function_name, **kw):
            calls["n"] += 1
            return (
                "\n### Cross-Session Knowledge (SAGE)\n"
                f"- [90%] volatile recall #{calls['n']}"
            )

        monkeypatch.setattr(
            ab, "_sage_recall_for_context", _volatile_sage)
        # The prompt block DOES vary with SAGE recall...
        block = ab.domain_model_context(
            tmp_path, "auth.c", "check_pw", self._SOURCE)
        assert block is not None and "volatile recall" in block
        # ...its include_sage=False rendering does not...
        bare = ab.domain_model_context(
            tmp_path, "auth.c", "check_pw", self._SOURCE,
            include_sage=False)
        assert bare is not None and "volatile recall" not in bare
        # ...and the fingerprint is stable call-to-call.
        assert self._hash(tmp_path) == self._hash(tmp_path)

    def test_primer_presence_mirrors_prompt_assembly(self, tmp_path):
        # When dynamic primers render, build_context skips the
        # domain-knowledge block — so a concept visible ONLY through
        # that block must not move the fingerprint either.
        contract = {
            "function": "check_pw",
            "file": "auth.c",
            "when": "login",
            "implication": "reject on mismatch",
        }
        self._write(tmp_path, {
            "concepts": [],
            "invariants": [],
            "contracts": [contract],
        })
        before = self._hash(tmp_path)
        self._write(tmp_path, {
            "concepts": [{
                "id": "pw_compare_rules",
                "description": "check_pw must compare in constant time",
            }],
            "invariants": [],
            "contracts": [contract],
        })
        after = self._hash(tmp_path)
        assert before is not None
        assert before == after

    def test_primer_content_change_changes_hash(self, tmp_path):
        base = {
            "function": "check_pw",
            "file": "auth.c",
            "when": "login",
            "implication": "reject on mismatch",
        }
        self._write(tmp_path, {
            "concepts": [], "invariants": [], "contracts": [base],
        })
        before = self._hash(tmp_path)
        changed = dict(base, implication="lock the account on mismatch")
        self._write(tmp_path, {
            "concepts": [], "invariants": [], "contracts": [changed],
        })
        after = self._hash(tmp_path)
        assert before != after
