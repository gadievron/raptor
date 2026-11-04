"""Fixture tests for the scatterlist_frag_undersize detection rule.

A scatterlist table sized from the bare top-level fragment count
(skb_shinfo(skb)->nr_frags [+ constant]) and mapped from the same skb
via skb_to_sgvec()/skb_to_sgvec_nomark() into a crypto request is
undersized whenever the skb carries a frag_list: skb_to_sgvec() walks
frag_list segments recursively and needs one entry per segment. The
correct idiom sizes from skb_cow_data()'s return value or proves the
absence of a frag_list first. Functions that test skb_has_frag_list(),
call skb_cow_data()/skb_linearize()/skb_linearize_cow(), or write
skb_shinfo(skb)->nr_frags establish the very geometry they size for
and must not fire; non-crypto consumers (DMA-mapping transmit paths)
are out of scope by design.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1]
    / "rules"
    / "scatterlist_frag_undersize.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(tmp_path: Path, source: str) -> list[dict]:
    return run_rule(tmp_path, source, _RULE)


# The in-place decrypt shape: bare-count sizing, map, crypto binding,
# no geometry witness.
_DECRYPT_BUG = """\
    static int verify_pkt(struct call *call, struct sk_buff *skb,
                          struct skcipher_request *req)
    {
        struct scatterlist _sg[4], *sg;
        struct crypt_iv iv;
        int nsg, ret;

        sg = _sg;
        nsg = skb_shinfo(skb)->nr_frags + 1;
        if (nsg <= 4) {
            nsg = 4;
        } else {
            sg = kmalloc_array(nsg, sizeof(*sg), GFP_NOIO);
            if (!sg)
                return -ENOMEM;
        }

        sg_init_table(sg, nsg);
        ret = skb_to_sgvec(skb, sg, sp->offset, sp->len);
        if (ret < 0)
            return ret;

        skcipher_request_set_crypt(req, sg, sg, sp->len, iv.x);
        crypto_skcipher_decrypt(req);
        return 0;
    }
"""


class TestPositives:
    def test_bare_count_map_crypt_fires(self, tmp_path):
        results = _run_rule(tmp_path, _DECRYPT_BUG)
        assert len(results) == 1
        r = results[0]
        assert r["rule"] == "scatterlist_frag_undersize"
        assert "frag_list" in r["message"]
        # The finding sits on the sizing line, inside the function.
        assert r["line"] == 9

    def test_declaration_initializer_count_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            static int decrypt(struct sk_buff *skb, struct aead_request *req)
            {
                int nsg = skb_shinfo(skb)->nr_frags + 2;
                struct scatterlist *sg;

                sg = kmalloc_array(nsg, sizeof(*sg), GFP_ATOMIC);
                if (!sg)
                    return -ENOMEM;
                sg_init_table(sg, nsg);
                if (skb_to_sgvec(skb, sg, 0, skb->len) < 0)
                    return -EINVAL;
                aead_request_set_crypt(req, sg, sg, skb->len, iv);
                return 0;
            }
        """)
        assert len(results) == 1
        assert results[0]["line"] == 3

    def test_inline_sg_init_table_count_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            static int decrypt(struct sk_buff *skb, struct aead_request *req)
            {
                struct scatterlist sg[MAX_SG];

                sg_init_table(sg, skb_shinfo(skb)->nr_frags + 1);
                if (skb_to_sgvec(skb, sg, 0, skb->len) < 0)
                    return -EINVAL;
                aead_request_set_crypt(req, sg, sg, skb->len, iv);
                return 0;
            }
        """)
        assert len(results) == 1

    def test_nomark_sink_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            static int decrypt(struct sk_buff *skb, struct aead_request *req)
            {
                struct scatterlist *sg;
                int nsg;

                nsg = skb_shinfo(skb)->nr_frags + 1;
                sg = kmalloc_array(nsg, sizeof(*sg), GFP_ATOMIC);
                if (!sg)
                    return -ENOMEM;
                sg_init_table(sg, nsg);
                if (skb_to_sgvec_nomark(skb, sg, 0, skb->len) < 0)
                    return -EINVAL;
                aead_request_set_crypt(req, sg, sg, skb->len, iv);
                return 0;
            }
        """)
        assert len(results) == 1

    def test_witness_in_other_function_does_not_suppress(self, tmp_path):
        # Per-function discipline: a geometry witness in a NEIGHBOUR
        # function must not clear the buggy one (per-file suppression
        # is the missing_bounds_check anti-pattern).
        results = _run_rule(tmp_path, """\
            static int other_path(struct sk_buff *skb)
            {
                struct sk_buff *trailer;

                return skb_cow_data(skb, 0, &trailer);
            }

        """ + _DECRYPT_BUG)
        assert len(results) == 1
        assert results[0]["rule"] == "scatterlist_frag_undersize"


class TestNegatives:
    def test_cow_data_sized_table_does_not_fire(self, tmp_path):
        # The correct idiom: skb_cow_data() counts every segment
        # (including frag_list) and the table is sized from its
        # return value.
        results = _run_rule(tmp_path, """\
            static int decrypt(struct sk_buff *skb, struct aead_request *req)
            {
                struct sk_buff *trailer;
                struct scatterlist *sg;
                int nsg;

                nsg = skb_cow_data(skb, 0, &trailer);
                if (nsg < 0)
                    return nsg;
                sg = kmalloc_array(nsg, sizeof(*sg), GFP_ATOMIC);
                if (!sg)
                    return -ENOMEM;
                sg_init_table(sg, nsg);
                if (skb_to_sgvec(skb, sg, 0, skb->len) < 0)
                    return -EINVAL;
                aead_request_set_crypt(req, sg, sg, skb->len, iv);
                return 0;
            }
        """)
        assert results == []

    def test_rebuilt_frag_geometry_does_not_fire(self, tmp_path):
        # The esp_output_tail() shape: the function rewrites
        # skb_shinfo(skb)->nr_frags to a single private frag right
        # before sizing the destination table from nr_frags + 1 — the
        # count reads back geometry the function itself established.
        results = _run_rule(tmp_path, """\
            static int output_tail(struct sk_buff *skb,
                                   struct aead_request *req)
            {
                struct scatterlist *sg, *dsg;
                int err;

                sg = req_sg(aead, req);
                dsg = &sg[esp->nfrags];
                sg_init_table(sg, esp->nfrags);
                err = skb_to_sgvec(skb, sg, 0, esp->clen);
                if (err < 0)
                    return err;

                skb_shinfo(skb)->nr_frags = 1;
                __skb_fill_page_desc(skb, 0, page, pfrag->offset,
                                     skb->data_len);

                sg_init_table(dsg, skb_shinfo(skb)->nr_frags + 1);
                err = skb_to_sgvec(skb, dsg, 0, esp->clen);
                if (err < 0)
                    return err;

                aead_request_set_crypt(req, sg, dsg, esp->clen, iv);
                return 0;
            }
        """)
        assert results == []

    def test_frag_list_test_does_not_fire(self, tmp_path):
        # A function that branches on skb_has_frag_list() accounts
        # for the geometry (hns3/iwlwifi TX shape).
        results = _run_rule(tmp_path, """\
            static int xmit_crypt(struct sk_buff *skb,
                                  struct aead_request *req)
            {
                struct scatterlist *sg;
                int nsg = skb_shinfo(skb)->nr_frags + 1;

                if (skb_has_frag_list(skb))
                    nsg = MAX_BD_NUM;
                sg = kmalloc_array(nsg, sizeof(*sg), GFP_ATOMIC);
                if (!sg)
                    return -ENOMEM;
                sg_init_table(sg, nsg);
                if (skb_to_sgvec(skb, sg, 0, skb->len) < 0)
                    return -EINVAL;
                aead_request_set_crypt(req, sg, sg, skb->len, iv);
                return 0;
            }
        """)
        assert results == []

    def test_dunder_linearize_does_not_fire(self, tmp_path):
        # __skb_linearize() (net/core, tls, tcp spelling) linearizes
        # the skb, so the bare count afterwards is correct.
        results = _run_rule(tmp_path, """\
            static int decrypt(struct sk_buff *skb, struct aead_request *req)
            {
                struct scatterlist *sg;
                int nsg;

                if (skb_is_nonlinear(skb) && __skb_linearize(skb))
                    return -ENOMEM;
                nsg = skb_shinfo(skb)->nr_frags + 1;
                sg = kmalloc_array(nsg, sizeof(*sg), GFP_ATOMIC);
                if (!sg)
                    return -ENOMEM;
                sg_init_table(sg, nsg);
                if (skb_to_sgvec(skb, sg, 0, skb->len) < 0)
                    return -EINVAL;
                aead_request_set_crypt(req, sg, sg, skb->len, iv);
                return 0;
            }
        """)
        assert results == []

    def test_nonlinear_bail_does_not_fire(self, tmp_path):
        # A function that refuses non-linear skbs up front proves the
        # skb linear (no paged frags, no frag_list) before sizing.
        results = _run_rule(tmp_path, """\
            static int decrypt(struct sk_buff *skb, struct aead_request *req)
            {
                struct scatterlist *sg;
                int nsg;

                if (skb_is_nonlinear(skb))
                    return -EINVAL;
                nsg = skb_shinfo(skb)->nr_frags + 1;
                sg = kmalloc_array(nsg, sizeof(*sg), GFP_ATOMIC);
                if (!sg)
                    return -ENOMEM;
                sg_init_table(sg, nsg);
                if (skb_to_sgvec(skb, sg, 0, skb->len) < 0)
                    return -EINVAL;
                aead_request_set_crypt(req, sg, sg, skb->len, iv);
                return 0;
            }
        """)
        assert results == []

    def test_linearize_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            static int decrypt(struct sk_buff *skb, struct aead_request *req)
            {
                struct scatterlist *sg;
                int nsg = skb_shinfo(skb)->nr_frags + 1;

                if (skb_linearize(skb))
                    return -ENOMEM;
                sg = kmalloc_array(nsg, sizeof(*sg), GFP_ATOMIC);
                if (!sg)
                    return -ENOMEM;
                sg_init_table(sg, nsg);
                if (skb_to_sgvec(skb, sg, 0, skb->len) < 0)
                    return -EINVAL;
                aead_request_set_crypt(req, sg, sg, skb->len, iv);
                return 0;
            }
        """)
        assert results == []

    def test_non_crypto_consumer_does_not_fire(self, tmp_path):
        # DMA-mapping transmit path (dpaa2/axienet shape): whether a
        # frag-listed skb can reach it is a netdev feature contract
        # the rule cannot see — out of scope by design.
        results = _run_rule(tmp_path, """\
            static int build_sg_fd(struct sk_buff *skb, struct fd *fd)
            {
                int nr_frags = skb_shinfo(skb)->nr_frags;
                struct scatterlist *scl;
                int num_sg;

                scl = kmalloc_array(nr_frags + 1, sizeof(*scl), GFP_ATOMIC);
                if (!scl)
                    return -ENOMEM;
                sg_init_table(scl, nr_frags + 1);
                num_sg = skb_to_sgvec(skb, scl, 0, skb->len);
                if (num_sg < 0)
                    return -ENOMEM;
                return dma_map_sg(dev, scl, num_sg, DMA_TO_DEVICE);
            }
        """)
        assert results == []

    def test_count_for_different_skb_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            static int decrypt(struct sk_buff *skb, struct sk_buff *other,
                               struct aead_request *req)
            {
                struct scatterlist *sg;
                int nsg;

                nsg = skb_shinfo(other)->nr_frags + 1;
                sg = kmalloc_array(nsg, sizeof(*sg), GFP_ATOMIC);
                if (!sg)
                    return -ENOMEM;
                sg_init_table(sg, nsg);
                if (skb_to_sgvec(skb, sg, 0, skb->len) < 0)
                    return -EINVAL;
                aead_request_set_crypt(req, sg, sg, skb->len, iv);
                return 0;
            }
        """)
        assert results == []

    def test_crypt_on_different_table_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            static int decrypt(struct sk_buff *skb, struct aead_request *req)
            {
                struct scatterlist *sg;
                int nsg;

                nsg = skb_shinfo(skb)->nr_frags + 1;
                sg = kmalloc_array(nsg, sizeof(*sg), GFP_ATOMIC);
                if (!sg)
                    return -ENOMEM;
                sg_init_table(sg, nsg);
                if (skb_to_sgvec(skb, sg, 0, skb->len) < 0)
                    return -EINVAL;
                aead_request_set_crypt(req, other_sg, other_sg,
                                       skb->len, iv);
                return 0;
            }
        """)
        assert results == []

    def test_unlinked_count_does_not_fire(self, tmp_path):
        # The frag count is read for unrelated arithmetic (statistics)
        # and never feeds the table that gets mapped — no sizing
        # relationship exists, so no receipt may be minted.
        results = _run_rule(tmp_path, """\
            static int decrypt(struct sk_buff *skb, struct aead_request *req)
            {
                struct scatterlist sg[MAX_SKB_FRAGS + 2];
                int frags;

                frags = skb_shinfo(skb)->nr_frags + 1;
                pr_debug("mapping %d frags", frags);
                sg_init_table(sg, MAX_SKB_FRAGS + 2);
                if (skb_to_sgvec(skb, sg, 0, skb->len) < 0)
                    return -EINVAL;
                aead_request_set_crypt(req, sg, sg, skb->len, iv);
                return 0;
            }
        """)
        assert results == []

    def test_map_before_count_does_not_fire(self, tmp_path):
        # The sizing must precede the map it undersizes.
        results = _run_rule(tmp_path, """\
            static int decrypt(struct sk_buff *skb, struct aead_request *req)
            {
                int nsg;

                if (skb_to_sgvec(skb, sg, 0, skb->len) < 0)
                    return -EINVAL;
                aead_request_set_crypt(req, sg, sg, skb->len, iv);
                nsg = skb_shinfo(skb)->nr_frags + 1;
                return nsg;
            }
        """)
        assert results == []
