"""Release-order channel tests (design §2.7) — hermetic, EFAIL-anchored
fixture pairs asserting full receipts on the deviant and the exact
enumerated reason on the twin."""

from __future__ import annotations

import pytest

from core.audit.fail_open_roles import SEED_SET_CAP, RoleContext
from core.audit.release_order import (
    _SEED_FINALIZER_NAMES,
    _SEED_RELEASE_NAMES,
    DETECTION_VARIANT_SUFFIX,
    INCONCLUSIVE_REASONS,
    REASON_ENGINES_DISAGREE,
    REASON_FINALIZER_UNRESOLVED,
    REASON_HYPOTHESIS_UNBINDABLE,
    REASON_LANGUAGE_UNSUPPORTED,
    REASON_SINK_ALIAS_UNRESOLVED,
    RELEASE_ORDER_CWES,
    RULE_RELEASE_BEFORE_VERIFY,
    is_detection_rule_id,
    is_release_order_hypothesis,
    learned_verify_release_pairs,
    release_order_applicable,
    run_release_order_check,
    run_release_order_prepass,
    seed_budget_violations,
)
from core.audit.sweep import SweepResult

pytest.importorskip("tree_sitter_c", reason="CFG leg needs tree-sitter")

HYP = ("decrypted chunks are written to `out` before the cipher "
       "status is verified")

# EFAIL anchor (CVE-2017-17688/17689 class; code shape =
# cms_smime.c cms_copy_content): in-loop BIO_write to the out BIO,
# BIO_get_cipher_status consulted only at end-of-stream.
EFAIL = """\
int cms_copy_content(BIO *out, BIO *cms, unsigned char *buf)
{
    int i;
    for (;;) {
        i = BIO_read(cms, buf, 1024);
        if (i <= 0) {
            if (BIO_get_cipher_status(cms) <= 0)
                return -1;
            break;
        }
        BIO_write(out, buf, i);
    }
    return 1;
}
"""

EFAIL_BUFFERED_TWIN = """\
int cms_copy_buffered(BIO *out, BIO *cms, unsigned char *buf)
{
    int total = collect_all(cms, buf);
    if (BIO_get_cipher_status(cms) <= 0)
        return -1;
    BIO_write(out, buf, total);
    return 1;
}
"""

# tmpout != out: CMS_TEXT intermediary flushed post-check.
TMPOUT_INTERNAL = """\
int cms_text(BIO *out, BIO *cms, unsigned char *buf, int n)
{
    BIO *tmpout = BIO_new(BIO_s_mem());
    BIO_write(tmpout, buf, n);
    if (BIO_get_cipher_status(cms) <= 0)
        return -1;
    flush_to(out, tmpout);
    return 1;
}
"""

TMPOUT_ALIAS_UNRESOLVED = """\
int cms_text_alias(BIO *out, BIO *cms, unsigned char *buf, int n,
                   int clear)
{
    BIO *tmpout = clear ? out : BIO_new(BIO_s_mem());
    BIO_write(tmpout, buf, n);
    if (BIO_get_cipher_status(cms) <= 0)
        return -1;
    return 1;
}
"""

# Plain-CBC pipeline without a MAC — not this channel's claim.
PLAIN_CBC = """\
int cbc_stream(BIO *out, BIO *cms, unsigned char *buf)
{
    int i = BIO_read(cms, buf, 1024);
    while (i > 0) {
        BIO_write(out, buf, i);
        i = BIO_read(cms, buf, 1024);
    }
    return 1;
}
"""

LEARNED_PAIR = """\
int relay_frame(struct conn *c, struct frame *f)
{
    int ok;
    conn_send(c, f->payload, f->len);
    ok = my_mac_check(c, f);
    if (ok <= 0)
        return -1;
    return 0;
}
"""


def _write(tmp_path, rel, text):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


class TestClassifier:
    def test_positive_shapes(self):
        for text in (
            HYP,
            "output is delivered prior to signature verification",
            "the plaintext is flushed without integrity verification",
            "cipher status verified only at EOF",
            "the EFAIL class applies here",
            "MAC verified only after the data is emitted",
        ):
            assert is_release_order_hypothesis(text), text

    def test_negative_shapes(self):
        for text in (
            "unchecked memcpy overflow of `dst`",
            "the session list grows without limit",
            "9/10 callers check do_auth()'s return",
            "",
        ):
            assert not is_release_order_hypothesis(text), text

    def test_cwe_membership(self):
        assert RELEASE_ORDER_CWES == {"CWE-354", "CWE-347"}
        assert release_order_applicable("CWE-354")
        assert release_order_applicable("CWE-347")
        # Joins the CWE-345 authenticity chain additively.
        assert release_order_applicable("CWE-345")
        assert not release_order_applicable("CWE-770")

    def test_detection_rule_id(self):
        assert is_detection_rule_id(
            RULE_RELEASE_BEFORE_VERIFY + DETECTION_VARIANT_SUFFIX,
        )
        assert not is_detection_rule_id(RULE_RELEASE_BEFORE_VERIFY)
        assert not is_detection_rule_id(
            "resource_bounds:unbounded-accumulation-naming",
        )


class TestVocabPolicy:
    def test_seed_budget(self):
        assert seed_budget_violations() == []
        assert len(_SEED_FINALIZER_NAMES) <= SEED_SET_CAP
        assert len(_SEED_RELEASE_NAMES) <= SEED_SET_CAP

    def test_learned_pairs_exclude_llm_prior(self):
        dm = {"paired_operations": [
            {"acquire": "my_mac_check", "release": "conn_send",
             "kind": "verify_release", "provenance": "mechanical"},
            {"acquire": "bad", "release": "worse",
             "kind": "verify_release", "provenance": "llm_prior"},
        ]}
        pairs = learned_verify_release_pairs(dm)
        assert [p["finalizer"] for p in pairs] == ["my_mac_check"]


class TestAnchorPairs:
    def test_efail_confirmed_names_the_inloop_write(self, tmp_path):
        _write(tmp_path, "src/cms_smime.c", EFAIL)
        res = run_release_order_check(
            tmp_path, "src/cms_smime.c", "cms_copy_content", HYP,
        )
        assert res.outcome == "confirmed"
        assert res.finalizer["name"] == "BIO_get_cipher_status"
        undominated = [r for r in res.releases if not r["dominated"]]
        assert len(undominated) == 1
        assert undominated[0]["callee"] == "BIO_write"
        assert undominated[0]["destination"] == "out"
        assert undominated[0]["engine"] == "cfg"
        assert str(undominated[0]["line"]) in res.reason

    def test_buffered_twin_refuted_with_dominator(self, tmp_path):
        _write(tmp_path, "src/cms_smime.c", EFAIL_BUFFERED_TWIN)
        res = run_release_order_check(
            tmp_path, "src/cms_smime.c", "cms_copy_buffered", HYP,
        )
        assert res.outcome == "refuted"
        assert all(r["dominated"] for r in res.releases)
        assert "BIO_get_cipher_status" in res.releases[0]["dominator"]

    def test_tmpout_internal_refuted(self, tmp_path):
        _write(tmp_path, "src/cms_smime.c", TMPOUT_INTERNAL)
        res = run_release_order_check(
            tmp_path, "src/cms_smime.c", "cms_text", HYP,
        )
        assert res.outcome == "refuted"
        assert "internal buffer" in res.reason
        assert res.releases[0]["destination_class"] == "internal"

    def test_tmpout_alias_unresolved(self, tmp_path):
        _write(tmp_path, "src/cms_smime.c", TMPOUT_ALIAS_UNRESOLVED)
        res = run_release_order_check(
            tmp_path, "src/cms_smime.c", "cms_text_alias", HYP,
        )
        assert res.outcome == "inconclusive"
        assert REASON_SINK_ALIAS_UNRESOLVED in res.reason

    def test_plain_cbc_is_finalizer_unresolved(self, tmp_path):
        # Proves the channel does not claim unauthenticated pipelines.
        _write(tmp_path, "src/cbc.c", PLAIN_CBC)
        res = run_release_order_check(
            tmp_path, "src/cbc.c", "cbc_stream", HYP,
        )
        assert res.outcome == "inconclusive"
        assert res.reason.startswith(REASON_FINALIZER_UNRESOLVED)

    def test_learned_pair_registry_seed_only_naming(self, tmp_path):
        _write(tmp_path, "src/relay.c", LEARNED_PAIR)
        dm = {"paired_operations": [
            {"acquire": "my_mac_check", "release": "conn_send",
             "kind": "verify_release", "provenance": "mechanical"},
        ]}
        res = run_release_order_check(
            tmp_path, "src/relay.c", "relay_frame",
            "payload sent before MAC verification", domain_model=dm,
        )
        assert res.outcome == "confirmed"
        assert res.rule_id == RULE_RELEASE_BEFORE_VERIFY

        _write(tmp_path, "src/cms.c", EFAIL)
        res2 = run_release_order_check(
            tmp_path, "src/cms.c", "cms_copy_content", HYP,
        )
        assert res2.outcome == "confirmed"
        assert res2.rule_id == (
            RULE_RELEASE_BEFORE_VERIFY + DETECTION_VARIANT_SUFFIX
        )
        assert is_detection_rule_id(res2.rule_id)


class TestJoernLeg:
    def _mk(self, outcome):
        return SweepResult(
            tool="joern", file_path="src/cms_smime.c",
            function_name="cms_copy_content", outcome=outcome,
            rule_id="joern:guard-dominance",
        )

    def test_agreement_upgrades_engine(self, tmp_path, monkeypatch):
        import core.audit.joern_verify as jv
        # Joern also finds an unguarded sink → agrees with CFG.
        monkeypatch.setattr(
            jv, "run_guard_dominance_check",
            lambda **kw: self._mk("confirmed"),
        )
        _write(tmp_path, "src/cms_smime.c", EFAIL)
        res = run_release_order_check(
            tmp_path, "src/cms_smime.c", "cms_copy_content", HYP,
            joern_server=object(),
        )
        assert res.outcome == "confirmed"
        undominated = [r for r in res.releases if not r["dominated"]]
        assert undominated[0]["engine"] == "cfg+joern"

    def test_disagreement_is_engines_disagree(self, tmp_path, monkeypatch):
        import core.audit.joern_verify as jv
        # Joern claims every sink is dominated → disagrees with CFG.
        monkeypatch.setattr(
            jv, "run_guard_dominance_check",
            lambda **kw: self._mk("refuted"),
        )
        _write(tmp_path, "src/cms_smime.c", EFAIL)
        res = run_release_order_check(
            tmp_path, "src/cms_smime.c", "cms_copy_content", HYP,
            joern_server=object(),
        )
        assert res.outcome == "inconclusive"
        assert REASON_ENGINES_DISAGREE in res.reason

    def test_joern_error_keeps_single_engine_verdict(
        self, tmp_path, monkeypatch,
    ):
        import core.audit.joern_verify as jv

        def _boom(**kw):
            raise RuntimeError("server down")

        monkeypatch.setattr(jv, "run_guard_dominance_check", _boom)
        _write(tmp_path, "src/cms_smime.c", EFAIL)
        res = run_release_order_check(
            tmp_path, "src/cms_smime.c", "cms_copy_content", HYP,
            joern_server=object(),
        )
        assert res.outcome == "confirmed"
        undominated = [r for r in res.releases if not r["dominated"]]
        assert undominated[0]["engine"] == "cfg"


class TestEnumeratedReasons:
    def test_language_unsupported(self, tmp_path):
        _write(tmp_path, "src/a.py", "def f():\n    pass\n")
        res = run_release_order_check(tmp_path, "src/a.py", "f", HYP)
        assert res.reason.startswith(REASON_LANGUAGE_UNSUPPORTED)

    def test_hypothesis_unbindable(self, tmp_path):
        src = """\
int f(BIO *cms)
{
    if (BIO_get_cipher_status(cms) <= 0)
        return -1;
    return 0;
}
"""
        _write(tmp_path, "src/a.c", src)
        res = run_release_order_check(tmp_path, "src/a.c", "f", HYP)
        assert res.outcome == "inconclusive"
        assert res.reason.startswith(REASON_HYPOTHESIS_UNBINDABLE)

    def test_all_reasons_enumerated(self):
        assert len(INCONCLUSIVE_REASONS) == 7


class TestPrepass:
    def test_prepass_pairs(self, tmp_path):
        texts = {
            "src/cms_smime.c": EFAIL,
            "src/buffered.c": EFAIL_BUFFERED_TWIN,
        }
        out = run_release_order_prepass(texts, out_dir=tmp_path)
        tele = out["telemetry"]
        assert tele["confirmed"] == 1
        assert tele["refuted"] == 1
        assert out["findings"][0]["file"] == "src/cms_smime.c"
        assert out["findings"][0]["cwe"] == "CWE-354"
        assert (tmp_path / "release-order.json").is_file()

    def test_prepass_budget(self, tmp_path):
        out = run_release_order_prepass(
            {"src/cms_smime.c": EFAIL}, budget_s=0.0,
        )
        assert out["telemetry"]["budget_exceeded"] is True

    def test_reachability_escalator_wired(self, tmp_path):
        _write(tmp_path, "src/cms_smime.c", EFAIL)
        ctx = RoleContext(context_map={
            "entry_points": [
                {"file": "src/cms_smime.c",
                 "function": "cms_copy_content"},
            ],
        })
        res = run_release_order_check(
            tmp_path, "src/cms_smime.c", "cms_copy_content", HYP,
            context=ctx,
        )
        assert res.outcome == "confirmed"
        assert res.reachability["status"] == "entry_reachable"
