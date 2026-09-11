"""Lifetime witness family — unit tests.

The witness corroborates dismissed CWE-415/416 claims with proofs over
a goto-resolved CFG.  These tests pin both sides of the contract: the
shapes each arm must PROVE (path-exclusive frees, no-use-after-release,
acquire-release brackets, delegation bodies, sentinel handoff paths)
and — more importantly — the red-team shapes where the claimed bug is
REAL and the witness must REFUSE (shared-path double frees, actual
use-after-free through aliases and retaining co-arguments, unpaired
puts, non-trivial delegation bodies, handoff paths that touch the
object), plus the macro-certification refusals that keep hidden
control flow, hidden releases and tracked-name rebinding out of the
CFG's blind spot.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_c")

from core.audit.lifetime_witness import (
    LifetimeClaimResult,
    check_lifetime_claim,
)

REL = "src/mod.c"


def _target(tmp_path: Path, func_source: str, prelude: str = "") -> Path:
    """A minimal analysed tree: the anchor file carries *prelude*
    (macro definitions) above the function."""
    f = tmp_path / REL
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(prelude + "\n" + func_source + "\n")
    return tmp_path


def _check(
    tmp_path: Path,
    func_source: str,
    mechanism: str,
    cwes: set[str],
    *,
    prelude: str = "",
    vocab=None,
) -> LifetimeClaimResult:
    root = _target(tmp_path, func_source, prelude)
    return check_lifetime_claim(
        func_source, mechanism, frozenset(cwes),
        target_path=root, rel_file=REL, vocab=vocab,
    )


# ---------------------------------------------------------------------------
# W-FREEPATH: proofs
# ---------------------------------------------------------------------------

_EXCLUSIVE_FREES = """
static int copy_all(struct sock *sk, int n, struct src *list)
{
\tstruct filt *p;
\tint err, i;

\tp = kmalloc(64, GFP_KERNEL);
\tif (!p)
\t\treturn -ENOBUFS;
\tfor (i = 0; i < n; ++i) {
\t\tif (list[i].bad)
\t\t\tgoto bad_addr;
\t\tp->slot[i] = list[i].v;
\t}
\terr = consume(sk, p, 0);
\tkfree(p);
\treturn err;

bad_addr:
\tkfree(p);
\treturn -EADDRNOTAVAIL;
}
"""

_DF_CLAIM = (
    "Double-free of p: type-state detector claims p freed at line 12 "
    "then again at line 16"
)


class TestFreepathProofs:
    def test_goto_exclusive_frees_discharge(self, tmp_path):
        r = _check(tmp_path, _EXCLUSIVE_FREES, _DF_CLAIM, {"CWE-415"})
        assert r.discharged
        assert r.covered_cwes == frozenset({"CWE-415"})
        assert r.proofs[0].arm == "freepath"
        assert r.proofs[0].pointer == "p"

    def test_switch_break_exclusive_frees_discharge(self, tmp_path):
        src = """
static void h(int mode, char *p)
{
\tswitch (mode) {
\tcase 1:
\t\tkfree(p);
\t\tbreak;
\tcase 2:
\t\tkfree(p);
\t\tbreak;
\tdefault:
\t\tbreak;
\t}
}
"""
        r = _check(
            tmp_path, src,
            "Double-free: p freed at line 5 then again at line 8",
            {"CWE-415"},
        )
        assert r.discharged and r.proofs[0].arm == "freepath"


# ---------------------------------------------------------------------------
# W-FREEPATH: red-team refusals (the claimed bug is REAL)
# ---------------------------------------------------------------------------


class TestFreepathRefusals:
    def test_sequential_double_free_refuses(self, tmp_path):
        src = """
static void h(char *p)
{
\tkfree(p);
\tkfree(p);
}
"""
        r = _check(
            tmp_path, src,
            "Double-free of p: freed at line 3 then again at line 4",
            {"CWE-415"},
        )
        assert not r.discharged
        assert "one path" in r.reason

    def test_loop_enclosed_free_refuses(self, tmp_path):
        src = """
static void h(char *p, int n)
{
\tint i;
\tfor (i = 0; i < n; ++i) {
\t\tif (i == 2)
\t\t\tkfree(p);
\t}
\tkfree(p);
}
"""
        r = _check(
            tmp_path, src,
            "Double-free of p: freed at line 6 then again at line 8",
            {"CWE-415"},
        )
        assert not r.discharged

    def test_goto_joining_paths_refuses(self, tmp_path):
        src = """
static void h(char *p, int a)
{
\tif (a)
\t\tgoto second;
\tkfree(p);
\tgoto second;
second:
\tkfree(p);
}
"""
        r = _check(
            tmp_path, src,
            "Double-free of p: freed at line 5 then again at line 8",
            {"CWE-415"},
        )
        assert not r.discharged

    def test_switch_fallthrough_double_free_refuses(self, tmp_path):
        src = """
static void h(int mode, char *p)
{
\tswitch (mode) {
\tcase 1:
\t\tkfree(p);
\tcase 2:
\t\tkfree(p);
\t\tbreak;
\t}
}
"""
        r = _check(
            tmp_path, src,
            "Double-free: p freed at line 5 then again at line 7",
            {"CWE-415"},
        )
        assert not r.discharged

    def test_single_site_two_site_claim_refuses(self, tmp_path):
        src = """
static void h(char *p)
{
\tkfree(p);
}
"""
        r = _check(
            tmp_path, src,
            "Double-free of p: freed at line 3 then again at line 9",
            {"CWE-415"},
        )
        assert not r.discharged
        assert "fewer than two" in r.reason

    def test_alias_free_counts_as_site(self, tmp_path):
        # q = p makes kfree(q) a site of p; the pair is sequential.
        src = """
static void h(char *p)
{
\tchar *q = p;
\tkfree(p);
\tkfree(q);
}
"""
        r = _check(
            tmp_path, src,
            "Double-free of p: freed at line 4 then again at line 5",
            {"CWE-415"},
        )
        assert not r.discharged

    def test_mixed_uaf_df_phrasing_out_of_family(self, tmp_path):
        # Path-exclusive frees, but the claim ALSO alleges a use —
        # W-FREEPATH must not examine mixed phrasings.
        r = _check(
            tmp_path, _EXCLUSIVE_FREES,
            "UAF/double-free of p: p freed at line 12 and again "
            "used/freed later",
            {"CWE-415"},
        )
        assert not r.discharged

    def test_concurrent_actor_phrasing_out_of_family(self, tmp_path):
        r = _check(
            tmp_path, _EXCLUSIVE_FREES,
            "Double-free of p: another thread could free p "
            "concurrently, then line 12 frees it again",
            {"CWE-415"},
        )
        assert not r.discharged


# ---------------------------------------------------------------------------
# W-NOUSE: proofs
# ---------------------------------------------------------------------------

_THAW_SHAPE = """
static int drop_last(struct sb *sb, int who)
{
\tint error = -EINVAL;

\tif (sb->frozen != 2)
\t\tgoto out_unlock;
\tif (freeze_dec(sb, who))
\t\tgoto out_unlock;
\tsb->frozen = 0;
\twake_all(&sb->waiters);
\tdeactivate_locked_super(sb);
\treturn 0;

out_unlock:
\tsuper_unlock(sb);
\treturn error;
}
"""

_UAF_CLAIM = (
    "Use-after-free: deactivate_locked_super(sb) at line 11 may free "
    "sb (drops the last reference); sb is dereferenced after "
    "deactivate_locked_super"
)


class TestNouseProofs:
    def test_release_then_return_discharges(self, tmp_path):
        r = _check(tmp_path, _THAW_SHAPE, _UAF_CLAIM, {"CWE-416"})
        assert r.discharged
        assert r.covered_cwes == frozenset({"CWE-416"})
        assert r.proofs[0].arm == "nouse"

    def test_kfree_then_disjoint_label_discharges(self, tmp_path):
        src = """
static int h(struct ctx *c, int a)
{
\tchar *buf;
\tbuf = kmalloc(16, GFP_KERNEL);
\tif (!buf)
\t\treturn -ENOMEM;
\tif (a < 0)
\t\tgoto err;
\tfill(buf, a);
\tkfree(buf);
\treturn 0;
err:
\tkfree(buf);
\treturn -EINVAL;
}
"""
        r = _check(
            tmp_path, src,
            "Use-after-free: buf freed at line 10 and then used later",
            {"CWE-416"},
        )
        assert r.discharged and r.proofs[0].arm == "nouse"

    def test_learned_release_verb_via_vocab(self, tmp_path):
        src = """
static void h(struct obj *o)
{
\tprep(o);
\tobj_dispose(o);
}
"""
        claim = (
            "Use-after-free: obj_dispose(o) frees o and o is "
            "dereferenced after obj_dispose returns"
        )
        r = _check(tmp_path, src, claim, {"CWE-416"})
        assert not r.discharged  # obj_dispose is not a seed verb

        class _V:
            deallocators = frozenset({"obj_dispose"})
            refcount_gets = frozenset()
            refcount_puts = frozenset()

        r2 = _check(tmp_path, src, claim, {"CWE-416"}, vocab=_V())
        assert r2.discharged and r2.proofs[0].arm == "nouse"


# ---------------------------------------------------------------------------
# W-NOUSE: red-team refusals
# ---------------------------------------------------------------------------


class TestNouseRefusals:
    def test_actual_use_after_free_refuses(self, tmp_path):
        src = """
static int h(struct req *p)
{
\tkfree(p);
\treturn p->len;
}
"""
        r = _check(
            tmp_path, src,
            "Use-after-free: p freed at line 3 and then used at line 4",
            {"CWE-416"},
        )
        assert not r.discharged

    def test_alias_use_after_free_refuses(self, tmp_path):
        src = """
static void h(struct req *p)
{
\tstruct req *q = p;
\tkfree(p);
\tnotify(q);
}
"""
        r = _check(
            tmp_path, src,
            "Use-after-free: p freed at line 4 and then used later",
            {"CWE-416"},
        )
        assert not r.discharged

    def test_retaining_co_argument_use_refuses(self, tmp_path):
        # The rxkad shape in miniature: sg escapes into a call that
        # also takes skb; skb is used after the free.
        src = """
static int h(struct skb *skb, int n)
{
\tstruct sg *sg;
\tsg = kmalloc(n, GFP_NOIO);
\tif (!sg)
\t\treturn -ENOMEM;
\tskb_to_sgvec(skb, sg, n);
\tkfree(sg);
\treturn skb_copy_bits(skb, 0);
}
"""
        r = _check(
            tmp_path, src,
            "Use-after-free: sg freed at line 8 and then used later "
            "in the function",
            {"CWE-416"},
        )
        assert not r.discharged
        assert "possibly-retaining" in r.reason

    def test_store_escape_refuses(self, tmp_path):
        src = """
static void h(struct ctx *c)
{
\tchar *p = kmalloc(8, GFP_KERNEL);
\tc->stash = p;
\tkfree(p);
}
"""
        r = _check(
            tmp_path, src,
            "Use-after-free: p freed at line 5 and used after through "
            "the stash",
            {"CWE-416"},
        )
        assert not r.discharged
        assert "stored into memory" in r.reason

    def test_address_of_pointer_refuses(self, tmp_path):
        src = """
static void h(char *p)
{
\treap(&p);
\tkfree(p);
}
"""
        r = _check(
            tmp_path, src,
            "Use-after-free: p freed at line 4 and used after the free",
            {"CWE-416"},
        )
        assert not r.discharged

    def test_release_in_loop_refuses(self, tmp_path):
        src = """
static void h(char *p, int n)
{
\tint i;
\tfor (i = 0; i < n; ++i)
\t\tkfree(p);
}
"""
        r = _check(
            tmp_path, src,
            "Use-after-free: p freed at line 5 and used after the free",
            {"CWE-416"},
        )
        assert not r.discharged

    def test_two_pointer_claim_needs_both_proven(self, tmp_path):
        # q's claim cannot be examined (no visible release site), so
        # naming it alongside p refuses the whole discharge.
        src = """
static void h(char *p, char *q)
{
\tkfree(p);
}
"""
        r = _check(
            tmp_path, src,
            "Use-after-free: p freed at line 3, q dangling and used "
            "after the free",
            {"CWE-416"},
        )
        assert not r.discharged

    def test_derived_pointer_deref_after_free_refuses(self, tmp_path):
        src = """
static int h(struct box *b)
{
\tstruct inner *d = unwrap(b);
\tkfree(b);
\treturn d->len;
}
"""
        r = _check(
            tmp_path, src,
            "Use-after-free: b freed at line 4 then used at line 5",
            {"CWE-416"},
        )
        assert not r.discharged


# ---------------------------------------------------------------------------
# W-BRACKET
# ---------------------------------------------------------------------------

_BRACKET_SHAPE = """
static int inherit_all(struct task *t)
{
\tstruct pctx *ctx;
\tint ret = 0;

\tctx = perf_pin_task_context(t);
\tif (!ctx)
\t\treturn 0;
\tmutex_lock(&ctx->mutex);
\tif (scan(t, ctx))
\t\tgoto out;
\tctx->rotate = 0;
out:
\tmutex_unlock(&ctx->mutex);
\tperf_unpin_context(ctx);
\tput_ctx(ctx);
\treturn ret;
}
"""

_BRACKET_CLAIM = (
    "Typestate tool claims use-after-free of ctx: ctx freed at "
    "line 16 (put_ctx), used at line 17"
)


class TestBracket:
    def test_pin_put_bracket_discharges(self, tmp_path):
        r = _check(tmp_path, _BRACKET_SHAPE, _BRACKET_CLAIM, {"CWE-416"})
        assert r.discharged
        assert r.proofs[0].arm == "bracket"
        assert r.covered_cwes == frozenset({"CWE-415", "CWE-416"})

    def test_store_with_get_is_permitted(self, tmp_path):
        src = """
static int adopt(struct task *t, struct child *ch)
{
\tstruct pctx *ctx;
\tctx = get_task_ctx(t);
\tif (!ctx)
\t\treturn 0;
\tch->parent = ctx;
\tget_ctx(ch->parent);
\tput_ctx(ctx);
\treturn 1;
}
"""
        r = _check(
            tmp_path, src,
            "Use-after-free: ctx freed by put_ctx at line 9 and used "
            "after the put",
            {"CWE-416"},
        )
        assert r.discharged and r.proofs[0].arm == "bracket"

    def test_unpaired_put_refuses(self, tmp_path):
        src = """
static void h(struct pctx *ctx)
{
\ttouch(ctx);
\tput_ctx(ctx);
}
"""
        r = _check(
            tmp_path, src,
            "Use-after-free: ctx freed by put_ctx at line 4 and used "
            "after the put",
            {"CWE-416"},
        )
        assert not r.discharged

    def test_double_put_same_callee_refuses(self, tmp_path):
        src = """
static void h(struct task *t)
{
\tstruct pctx *ctx;
\tctx = perf_pin_task_context(t);
\tput_ctx(ctx);
\tput_ctx(ctx);
}
"""
        r = _check(
            tmp_path, src,
            "Use-after-free: ctx freed by put_ctx at line 5 and used "
            "after the put at line 6",
            {"CWE-416"},
        )
        assert not r.discharged

    def test_use_after_final_put_refuses(self, tmp_path):
        src = """
static int h(struct task *t)
{
\tstruct pctx *ctx;
\tctx = perf_pin_task_context(t);
\tput_ctx(ctx);
\treturn ctx->gen;
}
"""
        r = _check(
            tmp_path, src,
            "Use-after-free: ctx freed by put_ctx at line 5 and used "
            "at line 6",
            {"CWE-416"},
        )
        assert not r.discharged

    def test_reassigned_pointer_refuses(self, tmp_path):
        src = """
static void h(struct task *t, struct pctx *alt)
{
\tstruct pctx *ctx;
\tctx = perf_pin_task_context(t);
\tif (!ctx)
\t\tctx = alt;
\tput_ctx(ctx);
}
"""
        r = _check(
            tmp_path, src,
            "Use-after-free: ctx freed by put_ctx at line 7 and used "
            "after the put",
            {"CWE-416"},
        )
        assert not r.discharged

    def test_put_in_loop_refuses(self, tmp_path):
        src = """
static void h(struct task *t, int n)
{
\tstruct pctx *ctx;
\tint i;
\tctx = perf_pin_task_context(t);
\tfor (i = 0; i < n; ++i)
\t\tput_ctx(ctx);
}
"""
        r = _check(
            tmp_path, src,
            "Use-after-free: ctx freed by put_ctx at line 7 and used "
            "after the put",
            {"CWE-416"},
        )
        assert not r.discharged

    def test_release_reachable_without_acquire_refuses(self, tmp_path):
        src = """
static void h(struct task *t, int fast)
{
\tstruct pctx *ctx;
\tif (fast)
\t\tgoto out;
\tctx = perf_pin_task_context(t);
out:
\tput_ctx(ctx);
}
"""
        r = _check(
            tmp_path, src,
            "Use-after-free: ctx freed by put_ctx at line 8 and used "
            "after the put",
            {"CWE-416"},
        )
        assert not r.discharged


# ---------------------------------------------------------------------------
# Async-handoff sub-arm
# ---------------------------------------------------------------------------

_ASYNC_SHAPE = """
static int send_all(struct st *x, struct skb *skb)
{
\tvoid *tmp;
\tint err = -ENOMEM;

\ttmp = alloc_tmp(x, 2);
\tif (!tmp)
\t\tgoto error;
\tstash(skb, tmp);
\terr = crypto_encrypt(x, skb);
\tswitch (err) {
\tcase -EINPROGRESS:
\t\tgoto error;
\tcase -ENOSPC:
\t\terr = 1;
\t\tbreak;
\t}
error_free:
\tkfree(tmp);
error:
\treturn err;
}
"""

_ASYNC_CLAIM = (
    "Async completion bug: -EINPROGRESS could double-free tmp, or "
    "the error path uses freed memory"
)


class TestAsyncHandoff:
    def test_sentinel_path_past_free_discharges(self, tmp_path):
        r = _check(tmp_path, _ASYNC_SHAPE, _ASYNC_CLAIM, {"CWE-416"})
        assert r.discharged
        assert r.proofs[0].arm == "async_handoff"
        assert r.covered_cwes == frozenset({"CWE-415", "CWE-416"})

    def test_sentinel_if_shape_discharges(self, tmp_path):
        src = """
static int h(struct st *x, char *tmp)
{
\tint err;
\terr = fire(x, tmp);
\tif (err == -EINPROGRESS)
\t\treturn 0;
\tkfree(tmp);
\treturn err;
}
"""
        r = _check(
            tmp_path, src,
            "Async handoff: on -EINPROGRESS the function returns while "
            "tmp is freed by the completion handler; the error path "
            "could double-free tmp",
            {"CWE-415", "CWE-416"},
        )
        assert r.discharged

    def test_sentinel_path_with_free_refuses(self, tmp_path):
        src = """
static int h(struct st *x, char *tmp)
{
\tint err;
\terr = fire(x, tmp);
\tswitch (err) {
\tcase -EINPROGRESS:
\t\tkfree(tmp);
\t\treturn 0;
\t}
\tkfree(tmp);
\treturn err;
}
"""
        r = _check(
            tmp_path, src,
            "Async completion bug: -EINPROGRESS path could double-free "
            "tmp",
            {"CWE-415", "CWE-416"},
        )
        assert not r.discharged

    def test_sentinel_path_touching_object_refuses(self, tmp_path):
        src = """
static int h(struct st *x, struct hdr *tmp)
{
\tint err;
\terr = fire(x, tmp);
\tif (err == -EINPROGRESS) {
\t\ttmp->flag = 1;
\t\treturn 0;
\t}
\tkfree(tmp);
\treturn err;
}
"""
        r = _check(
            tmp_path, src,
            "Async completion UAF: on -EINPROGRESS the error path uses "
            "tmp after the completion handler frees it",
            {"CWE-416"},
        )
        assert not r.discharged

    def test_sentinel_path_rejoining_free_refuses(self, tmp_path):
        src = """
static int h(struct st *x, char *tmp)
{
\tint err;
\terr = fire(x, tmp);
\tswitch (err) {
\tcase -EINPROGRESS:
\t\terr = 0;
\t\tbreak;
\t}
\tkfree(tmp);
\treturn err;
}
"""
        r = _check(
            tmp_path, src,
            "Async completion bug: the -EINPROGRESS path double-frees "
            "tmp",
            {"CWE-415", "CWE-416"},
        )
        assert not r.discharged

    def test_no_sentinel_refuses(self, tmp_path):
        src = """
static int h(struct st *x, char *tmp)
{
\tint err;
\terr = fire(x, tmp);
\tkfree(tmp);
\treturn err;
}
"""
        r = _check(
            tmp_path, src,
            "Async completion bug: -EINPROGRESS could double-free tmp",
            {"CWE-415", "CWE-416"},
        )
        assert not r.discharged


# ---------------------------------------------------------------------------
# W-DELEG
# ---------------------------------------------------------------------------

_DELEG_SHAPE = """
static void aead_release(void *private)
{
\tcrypto_free_aead(private);
}
"""

_DELEG_CLAIM = (
    "Double-free: crypto_free_aead(private) could be called twice if "
    "the framework invokes release twice on the same private pointer"
)


class TestDeleg:
    def test_single_forwarding_call_discharges(self, tmp_path):
        r = _check(tmp_path, _DELEG_SHAPE, _DELEG_CLAIM, {"CWE-415"})
        assert r.discharged
        assert r.proofs[0].arm == "deleg"
        assert r.covered_cwes == frozenset({"CWE-415"})

    def test_extra_statement_refuses(self, tmp_path):
        src = """
static void rel(void *private)
{
\tlog_release(private);
\tcrypto_free_aead(private);
}
"""
        r = _check(
            tmp_path, src,
            "Double-free: crypto_free_aead(private) could be called "
            "twice by the framework",
            {"CWE-415"},
        )
        assert not r.discharged

    def test_non_parameter_argument_refuses(self, tmp_path):
        src = """
static void rel(void *private)
{
\tcrypto_free_aead(global_tfm);
}
"""
        r = _check(
            tmp_path, src,
            "Double-free: crypto_free_aead could be called twice by "
            "the framework on the same pointer",
            {"CWE-415"},
        )
        assert not r.discharged

    def test_non_free_callee_refuses(self, tmp_path):
        src = """
static void rel(void *private)
{
\tcrypto_shutdown(private);
}
"""
        r = _check(
            tmp_path, src,
            "Double-free: crypto_shutdown(private) could be called "
            "twice by the framework",
            {"CWE-415"},
        )
        assert not r.discharged

    def test_without_caller_twice_phrasing_refuses(self, tmp_path):
        r = _check(
            tmp_path, _DELEG_SHAPE,
            "Double-free of private somewhere in the release path",
            {"CWE-415"},
        )
        assert not r.discharged


# ---------------------------------------------------------------------------
# Fences and preconditions
# ---------------------------------------------------------------------------


class TestFences:
    def test_no_lifetime_cwe_refuses(self, tmp_path):
        r = _check(
            tmp_path, _THAW_SHAPE, _UAF_CLAIM, {"CWE-362"},
        )
        assert not r.discharged

    def test_claim_naming_no_local_refuses(self, tmp_path):
        r = _check(
            tmp_path, _THAW_SHAPE,
            "Use-after-free: the superblock is freed and then used "
            "after the release",
            {"CWE-416"},
        )
        assert not r.discharged

    def test_missing_target_refuses(self, tmp_path):
        r = check_lifetime_claim(
            _THAW_SHAPE, _UAF_CLAIM, frozenset({"CWE-416"}),
            target_path=None, rel_file=None,
        )
        assert not r.discharged

    def test_concurrent_actor_uaf_out_of_family(self, tmp_path):
        r = _check(
            tmp_path, _THAW_SHAPE,
            "Use-after-free: another thread frees sb concurrently "
            "while this function runs, then sb is used",
            {"CWE-416"},
        )
        assert not r.discharged


# ---------------------------------------------------------------------------
# Macro certification
# ---------------------------------------------------------------------------


class TestMacroCertification:
    def test_macro_hidden_free_refuses(self, tmp_path):
        src = """
static void h(char *p, int a)
{
\tif (a)
\t\tgoto out;
\tRELEASE(p);
\treturn;
out:
\tkfree(p);
}
"""
        r = _check(
            tmp_path, src,
            "Double-free of p: freed at line 5 then again at line 8",
            {"CWE-415"},
            prelude="#define RELEASE(x) kfree(x)\n",
        )
        assert not r.discharged
        assert "release-family" in r.reason

    def test_macro_rebinding_tracked_name_refuses(self, tmp_path):
        src = """
static void h(char *p, char *q)
{
\tSWAPIN(p, q);
\tkfree(p);
\tuse(q);
}
"""
        r = _check(
            tmp_path, src,
            "Use-after-free: p freed at line 4 and used after the free",
            {"CWE-416"},
            prelude="#define SWAPIN(a, b) ((a) = (b))\n",
        )
        assert not r.discharged

    def test_macro_addressing_declaration_initialized_alias_refuses(
        self, tmp_path,
    ):
        # The alias is born in a declaration initializer — invisible
        # to the token-level tracked superset (its ``*`` reads as an
        # operator).  The second certification pass over the
        # tree-sitter closure must still refuse the macro that takes
        # the alias's address (a callee reached through ``&q`` can
        # free or rewrite what it points at invisibly).
        src = """
static int h(struct ctx *c)
{
\tchar *p = kmalloc(64, GFP_KERNEL);
\tstruct s *q = p;
\tif (!p)
\t\treturn -ENOMEM;
\tREG(q);
\tif (c->flag) {
\t\tkfree(p);
\t\treturn 0;
\t}
\tkfree(p);
\treturn 1;
}
"""
        r = _check(
            tmp_path, src,
            "Double-free of p: freed at line 9 then again at line 12",
            {"CWE-415"},
            prelude="#define REG(x) register_ptr(&x)\n",
        )
        assert not r.discharged
        assert "rebinds, addresses or invokes" in r.reason

    def test_macro_addressing_unrelated_name_still_certifies(
        self, tmp_path,
    ):
        # Control for the second certification pass: the same macro
        # on a name outside the alias/derived closure stays inert and
        # the freepath proof goes through.
        src = """
static int h(struct ctx *c)
{
\tint tick = 0;
\tchar *p = kmalloc(64, GFP_KERNEL);
\tif (!p)
\t\treturn -ENOMEM;
\tREG(tick);
\tif (c->flag) {
\t\tkfree(p);
\t\treturn 0;
\t}
\tkfree(p);
\treturn 1;
}
"""
        r = _check(
            tmp_path, src,
            "Double-free of p: freed at line 9 then again at line 12",
            {"CWE-415"},
            prelude="#define REG(x) register_ptr(&x)\n",
        )
        assert r.discharged

    def test_macro_with_goto_refuses(self, tmp_path):
        src = """
static void h(char *p)
{
\tBAIL_IF(!p);
\tkfree(p);
}
"""
        r = _check(
            tmp_path, src,
            "Use-after-free: p freed at line 4 and used after the free",
            {"CWE-416"},
            prelude="#define BAIL_IF(c) do { if (c) goto out; } while (0)\n",
        )
        assert not r.discharged

    def test_macro_naming_function_local_refuses(self, tmp_path):
        src = """
static int h(char *p)
{
\tint err = 0;
\tTICK();
\tkfree(p);
\treturn err;
}
"""
        r = _check(
            tmp_path, src,
            "Use-after-free: p freed at line 5 and used after the free",
            {"CWE-416"},
            prelude="#define TICK() (err++)\n",
        )
        assert not r.discharged

    def test_paste_synthesizing_free_name_refuses(self, tmp_path):
        src = """
static void h(char *p)
{
\tKILL(p);
\tkfree(p);
}
"""
        r = _check(
            tmp_path, src,
            "Use-after-free: p freed at line 4 and used after the free",
            {"CWE-416"},
            prelude="#define KILL(x) k ## free(x)\n",
        )
        assert not r.discharged

    def test_inert_conflicting_definitions_proceed(self, tmp_path):
        src = """
static void h(char *p, int a)
{
\tif (CHECKED(a))
\t\tkfree(p);
}
"""
        r = _check(
            tmp_path, src,
            "Use-after-free: p freed at line 4 and used after the free",
            {"CWE-416"},
            prelude=(
                "#define CHECKED(x) (x)\n"
                "#define CHECKED(x) __builtin_expect(!!(x), 1)\n"
            ),
        )
        assert r.discharged

    def test_conflicting_definition_with_goto_refuses(self, tmp_path):
        src = """
static void h(char *p, int a)
{
\tif (CHECKED(a))
\t\tkfree(p);
}
"""
        r = _check(
            tmp_path, src,
            "Use-after-free: p freed at line 4 and used after the free",
            {"CWE-416"},
            prelude=(
                "#define CHECKED(x) (x)\n"
                "#define CHECKED(x) ({ if (!(x)) goto bad; 1; })\n"
            ),
        )
        assert not r.discharged

    def test_named_variadic_definition_vets(self, tmp_path):
        src = """
static void h(char *p)
{
\twarn_all("boom", 1, 2);
\tkfree(p);
}
"""
        r = _check(
            tmp_path, src,
            "Use-after-free: p freed at line 4 and used after the free",
            {"CWE-416"},
            prelude="#define warn_all(fmt, args...) do_warn(fmt, ##args)\n",
        )
        assert r.discharged

    def test_claimed_pointer_is_macro_refuses(self, tmp_path):
        r = _check(
            tmp_path, _THAW_SHAPE, _UAF_CLAIM, {"CWE-416"},
            prelude="#define sb global_sb\n",
        )
        assert not r.discharged

    def test_loop_macro_transform_joins_cfg(self, tmp_path):
        # A kernel-style iteration macro at statement position: the
        # free inside its block is loop-enclosed → FREEPATH refuses.
        src = """
static void h(struct list *head, char *p)
{
\tstruct item *it;
\tfor_each_item(it, head) {
\t\tif (it->bad)
\t\t\tkfree(p);
\t}
\tkfree(p);
}
"""
        r = _check(
            tmp_path, src,
            "Double-free of p: freed at line 6 then again at line 8",
            {"CWE-415"},
            prelude=(
                "#define for_each_item(pos, head) "
                "for (pos = first(head); pos; pos = next(pos))\n"
            ),
        )
        assert not r.discharged

    def test_unresolvable_block_macro_refuses(self, tmp_path):
        src = """
static void h(struct list *head, char *p, char *q)
{
\tstruct item *it;
\tmystery_walk(it, head) {
\t\ttouch(it);
\t}
\tif (q)
\t\tkfree(p);
\telse
\t\tkfree(p);
}
"""
        r = _check(
            tmp_path, src,
            "Double-free of p: freed at line 9 then again at line 11",
            {"CWE-415"},
        )
        assert not r.discharged


# ---------------------------------------------------------------------------
# CFG robustness
# ---------------------------------------------------------------------------


class TestCfgRobustness:
    def test_trailing_export_symbol_is_trimmed(self, tmp_path):
        src = _THAW_SHAPE + "EXPORT_SYMBOL_GPL(drop_last);\n"
        r = _check(tmp_path, src, _UAF_CLAIM, {"CWE-416"})
        assert r.discharged

    def test_goto_unknown_label_refuses(self, tmp_path):
        src = """
static void h(char *p, int a)
{
\tif (a)
\t\tgoto missing;
\tkfree(p);
}
"""
        r = _check(
            tmp_path, src,
            "Use-after-free: p freed at line 5 and used after the free",
            {"CWE-416"},
        )
        assert not r.discharged

    def test_statement_expression_refuses(self, tmp_path):
        src = """
static void h(char *p)
{
\tint v = ({ int t = probe(p); t + 1; });
\tkfree(p);
}
"""
        r = _check(
            tmp_path, src,
            "Use-after-free: p freed at line 4 and used after the free",
            {"CWE-416"},
        )
        assert not r.discharged

    def test_release_not_statement_pure_refuses(self, tmp_path):
        src = """
static int h(char *p)
{
\tint r = (kfree(p), 1);
\treturn r;
}
"""
        r = _check(
            tmp_path, src,
            "Use-after-free: p freed at line 3 and used after the free",
            {"CWE-416"},
        )
        assert not r.discharged

    def test_do_while_back_edge_seen(self, tmp_path):
        src = """
static void h(char *p, int n)
{
\tdo {
\t\tkfree(p);
\t} while (n--);
}
"""
        r = _check(
            tmp_path, src,
            "Use-after-free: p freed at line 4 and used after the free",
            {"CWE-416"},
        )
        assert not r.discharged

# ---------------------------------------------------------------------------
# Laundering and hidden-hazard refusals: every fixture here carries a
# REAL reachable bug (or an uncertifiable construct) dressed in a shape
# that once looked provable — each must refuse.
# ---------------------------------------------------------------------------


class TestLaunderingRefusals:
    def test_ternary_alias_free_refuses(self, tmp_path):
        # q is a real copy of p laundered through a ternary; kfree(q)
        # plus kfree(p) is a genuine double free on the else path.
        src = """
static int h(struct sock *sk, int flag)
{
\tstruct filt *p;
\tstruct filt *q;
\tp = kmalloc(64, GFP_KERNEL);
\tif (!p)
\t\treturn -ENOMEM;
\tq = flag ? p : p;
\tif (flag) {
\t\tkfree(p);
\t\treturn 0;
\t}
\tkfree(q);
\tkfree(p);
\treturn 1;
}
"""
        r = _check(
            tmp_path, src,
            "Double-free of p: p freed at line 11 then again at line 15",
            {"CWE-415"},
        )
        assert not r.discharged
        assert "possibly-aliasing" in r.reason

    def test_comma_alias_free_refuses(self, tmp_path):
        src = """
static int h(struct sock *sk, int flag)
{
\tstruct filt *p;
\tstruct filt *q;
\tp = kmalloc(64, GFP_KERNEL);
\tq = (0, p);
\tif (flag) {
\t\tkfree(p);
\t\treturn 0;
\t}
\tkfree(q);
\tkfree(p);
\treturn 1;
}
"""
        r = _check(
            tmp_path, src,
            "Double-free of p: p freed at line 9 then again at line 13",
            {"CWE-415"},
        )
        assert not r.discharged

    def test_cast_laundered_deref_after_free_refuses(self, tmp_path):
        # The write goes through ((struct filt *)q)->cnt — a genuine
        # use of the freed object behind a cast wrapper.
        src = """
static int h(struct sock *sk, int flag)
{
\tstruct filt *p;
\tstruct filt *q;
\tp = kmalloc(64, GFP_KERNEL);
\tif (!p)
\t\treturn -ENOMEM;
\tq = flag ? p : p;
\tkfree(p);
\t((struct filt *)q)->cnt = 1;
\treturn 0;
}
"""
        r = _check(
            tmp_path, src,
            "Use-after-free of p: p freed at line 10 and the object is "
            "then written through a stale copy at line 11",
            {"CWE-416"},
        )
        assert not r.discharged

    def test_arith_laundered_deref_after_free_refuses(self, tmp_path):
        src = """
static int h(struct sock *sk, int flag)
{
\tstruct filt *p;
\tstruct filt *q;
\tp = kmalloc(64, GFP_KERNEL);
\tif (!p)
\t\treturn -ENOMEM;
\tq = flag ? p : p;
\tkfree(p);
\t*(q + 0) = *(q + 0);
\treturn 0;
}
"""
        r = _check(
            tmp_path, src,
            "Use-after-free of p: p freed at line 10 and then written "
            "through pointer arithmetic at line 11",
            {"CWE-416"},
        )
        assert not r.discharged

    def test_retainer_cast_deref_after_free_refuses(self, tmp_path):
        src = """
static int h(struct ctx *ctx)
{
\tstruct filt *p;
\tp = kmalloc(64, GFP_KERNEL);
\tif (!p)
\t\treturn -ENOMEM;
\tlink_into(ctx, p);
\tkfree(p);
\t((struct ctx *)ctx)->last->cnt = 1;
\treturn 0;
}
"""
        r = _check(
            tmp_path, src,
            "Use-after-free of p: p is stored into the context, freed "
            "at line 8, then the stale object is written through the "
            "context pointer at line 9",
            {"CWE-416"},
        )
        assert not r.discharged

    def test_paren_laundered_free_in_macro_refuses(self, tmp_path):
        # (kfree)(x) has no NAME( adjacency; the release verb in ANY
        # body position must refuse.
        src = """
static void h(char *p, int a)
{
\tif (a)
\t\tgoto out;
\tREL(p);
\treturn;
out:
\tkfree(p);
}
"""
        r = _check(
            tmp_path, src,
            "Double-free of p: freed at line 5 then again at line 8",
            {"CWE-415"},
            prelude="#define REL(x) (kfree)(x)\n",
        )
        assert not r.discharged
        assert "release-family" in r.reason

    def test_comma_laundered_callee_in_source_refuses(self, tmp_path):
        src = """
static int h(char *p, int c)
{
\tif (c) {
\t\tkfree(p);
\t\treturn 0;
\t}
\t(0, kfree)(p);
\tkfree(p);
\treturn 1;
}
"""
        r = _check(
            tmp_path, src,
            "Double-free of p: freed at line 4 then again at line 8",
            {"CWE-415"},
        )
        assert not r.discharged
        assert "outside a direct call" in r.reason

    def test_addr_of_laundered_free_refuses(self, tmp_path):
        # kfree(*pp) with pp = &p really frees p on the else path.
        src = """
static int h(struct sock *sk, int c)
{
\tstruct filt *p = sk_filter(sk);
\tstruct filt **pp = &p;
\tif (c) {
\t\tkfree(p);
\t\treturn 0;
\t}
\tkfree(*pp);
\tkfree(p);
\treturn 1;
}
"""
        r = _check(
            tmp_path, src,
            "Double-free of p: p freed at line 6 then again at line 10",
            {"CWE-415"},
        )
        assert not r.discharged

    def test_unbalanced_macro_pair_hiding_loop_refuses(self, tmp_path):
        # do { / } while(...) split across two object-like macros
        # splices a back edge the raw CFG cannot see: each "exclusive"
        # site really runs once per retry iteration.
        src = """
static int h(struct sock *sk, int flag)
{
\tstruct filt *p;
\tp = kmalloc(64, GFP_KERNEL);
\tif (!p)
\t\treturn -ENOMEM;
\tBEGIN_RETRY;
\tif (flag)
\t\tkfree(p);
\telse
\t\tkfree(p);
\tEND_RETRY;
\treturn 1;
}
"""
        r = _check(
            tmp_path, src,
            "Double-free of p: p freed at line 8 then again at line 10 "
            "on the retry iteration",
            {"CWE-415"},
            prelude=(
                "#define BEGIN_RETRY do {\n"
                "#define END_RETRY } while (should_retry())\n"
            ),
        )
        assert not r.discharged
        assert "unbalanced" in r.reason

    def test_multi_line_comment_inside_define_is_joined(self, tmp_path):
        # Newlines inside a block comment do not end a #define; the
        # table must parse the full balanced body, not a truncated one.
        src = """
static void h(char *p)
{
\tLOGIT(p != 0);
\tkfree(p);
}
"""
        r = _check(
            tmp_path, src,
            "Use-after-free: p freed at line 4 and used after the free",
            {"CWE-416"},
            prelude=(
                "#define LOGIT(c) do { \\\n"
                "\tif (c) { /*\n"
                "\t * commentary spanning lines\n"
                "\t * without continuations\n"
                "\t */ \\\n"
                "\t\tnote(); \\\n"
                "\t} \\\n"
                "} while (0)\n"
            ),
        )
        assert r.discharged

    def test_bracket_derived_deref_after_put_refuses(self, tmp_path):
        src = """
static int h(struct dev *dev, int flag)
{
\tstruct page *pg;
\tstruct page *d;
\tpg = page_get(dev);
\tif (!pg)
\t\treturn -EIO;
\td = flag ? pg : pg;
\tpage_put(pg);
\treturn d->val;
}
"""
        r = _check(
            tmp_path, src,
            "Use-after-free of pg: the reference is dropped by "
            "page_put and the page is then dereferenced through a "
            "stale copy",
            {"CWE-416"},
        )
        assert not r.discharged

    def test_two_distinct_drops_one_path_refuses(self, tmp_path):
        # A get-family acquisition grants ONE reference; put + unpin on
        # the same path is a double drop even with different callees.
        src = """
static int h(struct dev *dev)
{
\tstruct page *pg;
\tpg = page_get(dev);
\tif (!pg)
\t\treturn -EIO;
\tpage_put(pg);
\tpage_unpin(pg);
\treturn 0;
}
"""
        r = _check(
            tmp_path, src,
            "Use-after-free / double release of pg: the single "
            "page_get reference is dropped by page_put at line 7 and "
            "dropped again by page_unpin at line 8",
            {"CWE-415", "CWE-416"},
        )
        assert not r.discharged

    def test_pin_acquire_permits_unpin_put_pair(self, tmp_path):
        # Positive control for the rule above: a pin-stem acquisition
        # grants a pin AND a reference, so unpin followed by put is
        # the correct bracket close.
        r = _check(tmp_path, _BRACKET_SHAPE, _BRACKET_CLAIM, {"CWE-416"})
        assert r.discharged and r.proofs[0].arm == "bracket"

    def test_thread_letter_phrasings_out_of_family(self, tmp_path):
        for mech in (
            "Double-free of p: thread A frees p at line 9 and thread "
            "B frees p again at line 12",
            "Double-free of p: two threads enter h and p is freed "
            "twice, at line 9 and at line 12",
            "Double-free of p: the softirq re-enters h and p is freed "
            "again at line 12",
            "Double-free of p: a second CPU frees p at line 12 after "
            "line 9 already freed it",
        ):
            r = _check(tmp_path, _EXCLUSIVE_FREES, mech, {"CWE-415"})
            assert not r.discharged, mech

    def test_multi_function_source_refuses(self, tmp_path):
        # A second definition after the first balanced body must not
        # silently displace the analysed function.
        src = """
static void helper(struct sock *sk, int flag)
{
\tstruct filt *p;
\tp = sk_filter(sk);
\tif (flag) {
\t\tkfree(p);
\t\treturn;
\t}
\tkfree(p);
}

static int h(struct sock *sk)
{
\tstruct filt *p;
\tp = sk_filter(sk);
\tkfree(p);
\tkfree(p);
\treturn 0;
}
"""
        r = _check(
            tmp_path, src,
            "Double-free of p in h: p freed at line 17 then again at "
            "line 18",
            {"CWE-415"},
        )
        assert not r.discharged
        assert "additional definitions" in r.reason

    def test_async_sentinel_path_cast_touch_refuses(self, tmp_path):
        src = """
static int h(struct ctx *ctx)
{
\tstruct req *req;
\tstruct req *stash;
\tint err;
\treq = make_req(ctx);
\tstash = ctx->fast ? req : req;
\terr = fire(ctx, req);
\tif (err == -EINPROGRESS) {
\t\t((struct req *)stash)->flag = 1;
\t\treturn 0;
\t}
\tkfree(req);
\treturn err;
}
"""
        r = _check(
            tmp_path, src,
            "Use-after-free of req on the asynchronous EINPROGRESS "
            "path: the completion handler owns and frees req, yet the "
            "in-progress path still writes the request afterwards",
            {"CWE-416"},
        )
        assert not r.discharged

    def test_substitution_size_bomb_refuses_fast(self, tmp_path):
        import time

        n, m = 2000, 20000
        prelude = (
            "#define BIG(x) " + " ".join(["x"] * n) + "\n"
            "#define BOMB() BIG(" + " ".join(["a"] * m) + ")\n"
        )
        src = """
static int h(struct sock *sk)
{
\tstruct filt *p;
\tp = sk_filter(sk);
\tif (sk->err) {
\t\tkfree(p);
\t\treturn 0;
\t}
\tkfree(p);
\tBOMB();
\treturn 1;
}
"""
        t0 = time.time()
        r = _check(
            tmp_path, src,
            "Double-free of p: p freed at line 6 then again at line 9",
            {"CWE-415"},
            prelude=prelude,
        )
        assert not r.discharged
        assert "token budget" in r.reason
        assert time.time() - t0 < 10

# ---------------------------------------------------------------------------
# Path-shape refusals beyond the laundering set: releases that reach
# the sentinel test, recursion, declarator stashes, paren-wrapped
# macro hazards, combined-stem drops.
# ---------------------------------------------------------------------------


class TestPathShapeRefusals:
    def test_release_reaching_sentinel_refuses(self, tmp_path):
        # The textbook in-flight free: the object is freed BEFORE the
        # -EINPROGRESS test on the same execution path, so the async
        # completion still owns memory that is already gone.  The
        # sentinel region alone cannot see it.
        src = """
static int h(struct st *x, struct req *r)
{
\tint err;
\terr = submit(x, r);
\tkfree(r);
\tif (err == -EINPROGRESS)
\t\treturn 0;
\treturn err;
}
"""
        r = _check(
            tmp_path, src,
            "Async completion UAF: r is freed before the -EINPROGRESS "
            "check, so the in-flight completion touches freed memory",
            {"CWE-416"},
        )
        assert not r.discharged
        assert "reach the handoff-sentinel" in r.reason

    def test_release_after_sentinel_still_discharges(self, tmp_path):
        # Control: the correct idiom — the free is only reachable on
        # the non-sentinel continuation, never before the test.
        src = """
static int h(struct st *x, struct req *r)
{
\tint err;
\terr = submit(x, r);
\tswitch (err) {
\tcase -EINPROGRESS:
\t\tgoto out;
\t}
\tkfree(r);
out:
\treturn err;
}
"""
        res = _check(
            tmp_path, src,
            "Async completion bug: -EINPROGRESS could double-free r "
            "or the error path uses freed memory",
            {"CWE-415", "CWE-416"},
        )
        assert res.discharged
        assert res.proofs[0].arm == "async_handoff"

    def test_self_recursive_function_refuses(self, tmp_path):
        # One invocation executes both "path-exclusive" sites at two
        # recursion depths: a real double free with no CFG back edge.
        src = """
static void retire_node(struct buf *p, int depth)
{
\tif (depth) {
\t\tkfree(p);
\t\tretire_node(p, 0);
\t\treturn;
\t}
\tkfree(p);
}
"""
        r = _check(
            tmp_path, src,
            "Double-free of p: p freed at line 4 then again at line 8",
            {"CWE-415"},
        )
        assert not r.discharged
        assert "refers to itself" in r.reason

    def test_array_initializer_stash_refuses(self, tmp_path):
        # The stash rides a declaration initializer on an ARRAY
        # declarator — no assignment expression exists for the store
        # rule, and the declared name never resolves to an identifier.
        src = """
static int h(struct dev *d)
{
\tstruct buf *p;
\tp = kmalloc(64, GFP_KERNEL);
\tif (!p)
\t\treturn -ENOMEM;
\tstruct buf *arr[1] = { p };
\tkfree(p);
\treturn arr[0]->len;
}
"""
        r = _check(
            tmp_path, src,
            "Use-after-free of p: p freed at line 8 and then read "
            "through the stashed copy at line 9",
            {"CWE-416"},
        )
        assert not r.discharged
        assert "non-identifier declarator" in r.reason

    def test_paren_wrapped_macro_address_refuses(self, tmp_path):
        # &(x) is the same hazard as &x — adjacency must see through
        # balanced parenthesis wraps.
        src = """
static int h(struct sock *sk, int c)
{
\tstruct filt *p = sk_filter(sk);
\tREG3(p);
\tif (c) {
\t\tkfree(p);
\t\treturn 0;
\t}
\tkfree(p);
\treturn 1;
}
"""
        r = _check(
            tmp_path, src,
            "Double-free of p: p freed at line 6 then again at line 9",
            {"CWE-415"},
            prelude="#define REG3(x) reg_helper(&(x))\n",
        )
        assert not r.discharged
        assert "rebinds, addresses or invokes" in r.reason

    def test_paren_wrapped_macro_rebind_refuses(self, tmp_path):
        src = """
static void h(char *p, char *q)
{
\tSET((p), (q));
\tkfree(p);
\tuse(q);
}
"""
        r = _check(
            tmp_path, src,
            "Use-after-free: p freed at line 4 and used after the free",
            {"CWE-416"},
            prelude="#define SET(a, b) ((a) = (b))\n",
        )
        assert not r.discharged

    def test_combined_stem_release_refuses(self, tmp_path):
        # folio_unpin_put drops BOTH grants of the pin acquisition by
        # itself; a further put is an over-drop the pin-idiom pair
        # exception must never type as the legitimate close.
        src = """
static int h(struct dev *dev)
{
\tstruct page *pg;
\tpg = folio_pin(dev);
\tif (!pg)
\t\treturn -EIO;
\tfolio_unpin_put(pg);
\tfolio_put(pg);
\treturn 0;
}
"""
        r = _check(
            tmp_path, src,
            "Use-after-free / double release of pg: the pin grant is "
            "fully dropped by folio_unpin_put at line 7 and dropped "
            "again by folio_put at line 8",
            {"CWE-415", "CWE-416"},
        )
        assert not r.discharged
        assert "combines unpin and put stems" in r.reason


# ---------------------------------------------------------------------------
# Refusal gaps: shapes the witness previously discharged while
# the claimed bug was real. Every fix fails toward refusal (claim
# stays alive), never toward discharge.
# ---------------------------------------------------------------------------


class TestMemberCalleeRelease:
    def test_ops_table_free_refuses_nouse(self, tmp_path):
        # ``r->ops->free(p)`` was invisible to release_sites (member
        # callee) AND the verb fallback (_idents yields identifiers
        # only) — nouse discharged over a function whose real free
        # happened through the ops table.
        src = """
static void f(struct req *r)
{
\tchar *p = r->buf;
\tr->ops->free(p);
\tsink(*p);
\tkfree(p);
}
"""
        r = _check(
            tmp_path, src,
            "Use-after-free: p freed then dereferenced",
            {"CWE-416"},
        )
        assert not r.discharged

    def test_plain_release_still_discharges(self, tmp_path):
        # Two-direction guard: the field_identifier scan must not
        # refuse functions with only ordinary direct releases.
        src = """
static void f(char *p)
{
\tsink(*p);
\tkfree(p);
}
"""
        r = _check(
            tmp_path, src,
            "Use-after-free: p freed at line 5 then used",
            {"CWE-416"},
        )
        assert r.discharged


class TestDerivedAndGlobalStores:
    def test_derived_pointer_store_refuses(self, tmp_path):
        # q = p + 8 still points into p's allocation; storing it into
        # a struct field escapes the freed memory into a name the
        # tracker cannot see (consume(s->stash) after the free).
        src = """
static void g(struct s *s, char *p)
{
\tchar *q = p + 8;
\ts->stash = q;
\tkfree(p);
\tconsume(s->stash);
}
"""
        r = _check(
            tmp_path, src,
            "Use-after-free of p through the stashed derived pointer",
            {"CWE-416"},
        )
        assert not r.discharged

    def test_global_identifier_store_refuses(self, tmp_path):
        # A file-scope global is an identifier too: ``g_saved = p;``
        # is a store into memory a callee reads after the free.
        src = """
static void h(char *p)
{
\tg_saved = p;
\tkfree(p);
\thelper();
}
"""
        r = _check(
            tmp_path, src,
            "Use-after-free: p escapes through g_saved and helper() "
            "dereferences it after the kfree",
            {"CWE-416"},
        )
        assert not r.discharged

    def test_local_alias_copy_still_permitted(self, tmp_path):
        # Two-direction guard: local alias propagation stays exempt
        # (it is tracked by _compute_sets, not an escape).
        src = """
static void k(char *p)
{
\tchar *q;
\tq = p;
\tsink(*q);
\tkfree(p);
}
"""
        r = _check(
            tmp_path, src,
            "Use-after-free: p freed at line 6 then used",
            {"CWE-416"},
        )
        assert r.discharged


class TestBracketRebindGaps:
    def test_update_expression_refuses(self, tmp_path):
        # ``p++`` rebinds the pointer between acquire and release —
        # put_obj receives p+1, not the acquired object.
        src = """
static void m(struct task *t)
{
\tstruct pctx *ctx;
\tctx = get_task_ctx(t);
\tctx++;
\tput_ctx(ctx);
}
"""
        r = _check(
            tmp_path, src,
            "Use-after-free: ctx freed by put_ctx and used after",
            {"CWE-416"},
        )
        assert not r.discharged

    def test_parenthesized_lhs_counts_as_definition(self, tmp_path):
        # ``(ctx) = o;`` is the same rebinding as ``ctx = o;`` — it
        # must count toward the single-definition premise (two defs
        # -> refusal).
        src = """
static void m2(struct task *t, struct pctx *o)
{
\tstruct pctx *ctx;
\tctx = get_task_ctx(t);
\t(ctx) = o;
\tput_ctx(ctx);
}
"""
        r = _check(
            tmp_path, src,
            "Use-after-free: ctx freed by put_ctx and used after",
            {"CWE-416"},
        )
        assert not r.discharged


class TestChainedAssignmentMacro:
    def test_chained_assignment_macro_refuses(self, tmp_path):
        # ``#define CHAIN(x) chain_tmp = x = g_other`` assigns THROUGH
        # the parameter; the old comparison exemption certified it
        # inert (maximal-munch tokenizing makes a bare `=` on both
        # sides of the marker impossible for real comparisons).
        src = """
static void m3(struct task *t)
{
\tstruct pctx *ctx;
\tctx = get_task_ctx(t);
\tCHAIN(ctx);
\tput_ctx(ctx);
}
"""
        r = _check(
            tmp_path, src,
            "Use-after-free: ctx freed by put_ctx and used after",
            {"CWE-416"},
            prelude="#define CHAIN(x) chain_tmp = x = g_other\n",
        )
        assert not r.discharged
