// scatterlist_frag_undersize.cocci — Find scatterlist tables sized from
// a bare skb fragment count (skb_shinfo(skb)->nr_frags [+ constant]) and
// mapped from the same skb via skb_to_sgvec()/skb_to_sgvec_nomark() in a
// crypto-transform function, with no frag_list accounting in that
// function.
//
// skb_shinfo(skb)->nr_frags counts only the top-level paged fragments.
// A fragmented socket buffer additionally chains whole sk_buffs on
// skb_shinfo(skb)->frag_list, and skb_to_sgvec() walks those
// recursively, consuming one scatterlist entry per segment. A table
// sized from the bare frag count is short by every frag_list segment:
// historically an out-of-bounds write of scatterlist entries (macsec,
// fixed by 4d6fa57b4dab "macsec: avoid heap overflow in skb_to_sgvec"
// and 5294b83086cc "macsec: dynamically allocate space for sglist");
// since 48a1df65334b ("skbuff: return -EMSGSIZE in skb_to_sgvec to
// prevent overflow") an overrun of a properly end-marked table is
// converted to -EMSGSIZE, so callers sized this way instead hard-fail
// on exactly the fragmented packets the transform exists to handle
// (sockmap, fixed by 4363023d2668; rxrpc rxkad, bare-count sizing
// introduced by d0d5c0cd1e71, removed by d2bc90cf6c75 which extracts
// to a linear bounce buffer). The correct idiom sizes the table from
// skb_cow_data()'s return value — it counts every segment and
// linearizes clones — or proves the absence of a frag_list first.
//
// Scope (deliberately narrow — in-place crypto transform paths only):
//   fire = bare-frag-count size expression
//        + the count feeding the mapped table (sg_init_table /
//          kmalloc_array link, or the count spelled inline in one)
//        + skb_to_sgvec-family map of the same skb into that table
//        + the mapped table bound into a skcipher/aead crypto request
//   all in ONE function, and no geometry witness (below) in it.
// DMA-mapping transmit paths are out of scope by construction: whether
// a frag-listed skb can reach a driver's xmit path is a netdev feature
// contract (NETIF_F_FRAGLIST absent => no frag_list) that a
// single-file semantic patch cannot see, so a bare-count sizing there
// is only a defect for FRAGLIST-advertising devices. Known misses,
// accepted for precision: counts computed in a different function
// than the map (helper-split callers); counts held in struct fields
// (ctx->nsg = ... — the count and link metavariables bind plain
// identifiers only); counts built by incremental nfrags++ arithmetic;
// count-to-table links spelled other than sg_init_table(sg, n) /
// sg = kmalloc_array(n, ...); tables aliased between the map and the
// crypto binding; non-crypto consumers of an undersized table.
// Known FALSE-FIRE residuals (correct code the rule cannot prove
// correct — detection grade, receipt never promotes alone): linearity
// established by non-witness means, i.e. a fresh skb_copy() (always
// linear), a locally-built skb (alloc_skb + skb_fill_page_desc — the
// nr_frags write hides inside a skbuff.h static inline), GSO segments
// with FRAGLIST features masked off, a checked skb_to_sgvec return
// with a correct linear-fallback path, or a full-length
// pskb_may_pull(skb, skb->len). Geometry witnesses are recognised
// anywhere in the function without skb- or order-correlation, so a
// witness taken on a DIFFERENT skb, or one issued only after the map,
// still suppresses — conservative toward silence, never toward a
// false receipt.
// Known conflation residual: candidates correlate per
// (file, function-name) via position.current_element, so two
// same-named function definitions in one file (#ifdef arms) can
// cross-satisfy or cross-suppress each other; kernel style makes this
// rare, and the fabricated-fire direction additionally requires the
// arms to share identifier names end-to-end.
//
// Geometry witnesses that suppress every candidate in a function: a
// skb_has_frag_list() or skb_is_nonlinear() test, a skb_cow_data() /
// skb_linearize() / __skb_linearize() / skb_linearize_cow() call, or
// a write to skb_shinfo(skb)->nr_frags. Each one means the function
// checks, rebuilds, linearizes, or owns the fragment geometry it
// sizes for — esp_output_tail() rebuilds the skb to a single private
// frag (skb_shinfo(skb)->nr_frags = 1) immediately before sizing its
// destination table from nr_frags + 1, which is why its spelling of
// the count is correct and must not fire.
//
// Covers CWE-787: scatterlist table overrun on fragmented skbs.
// @role: detection
// raptor: confirm-only

@initialize:python@
@@
_sfu_guarded = set()
_sfu_counts = []
_sfu_links = []
_sfu_maps = []
_sfu_crypts = []

// Geometry witnesses — collect the enclosing functions; every
// candidate inside one is suppressed in the finalize block.
@sfu_guard exists@
expression skb, E;
position p;
@@

(
  skb_has_frag_list@p(...)
|
  skb_is_nonlinear@p(...)
|
  skb_cow_data@p(...)
|
  skb_linearize@p(...)
|
  __skb_linearize@p(...)
|
  skb_linearize_cow@p(...)
|
  skb_shinfo(skb)->nr_frags =@p E
)

@script:python@
p << sfu_guard.p;
@@

for _pu in p:
    _sfu_guarded.add((_pu.file, _pu.current_element))

// Bare-frag-count sizing bound to a variable (assignment and
// declaration-initializer spellings).
@sfu_count exists@
identifier nsg;
expression skb;
constant C;
type T;
position p;
@@

(
  nsg =@p skb_shinfo(skb)->nr_frags + C;
|
  nsg =@p C + skb_shinfo(skb)->nr_frags;
|
  nsg =@p skb_shinfo(skb)->nr_frags;
|
  T nsg =@p skb_shinfo(skb)->nr_frags + C;
|
  T nsg =@p C + skb_shinfo(skb)->nr_frags;
|
  T nsg =@p skb_shinfo(skb)->nr_frags;
)

@script:python@
p << sfu_count.p;
skb << sfu_count.skb;
nsg << sfu_count.nsg;
@@

for _pu in p:
    _sfu_counts.append((_pu.file, _pu.current_element, int(_pu.line),
                        str(skb), str(nsg)))

// The count variable feeding a table: sg_init_table(sg, nsg) or a
// kmalloc_array allocation into the table pointer. Without this link
// a frag count read for unrelated arithmetic (statistics, logging)
// must never mint a sizing receipt.
@sfu_link exists@
identifier nsg;
expression sg;
position p;
@@

(
  sg_init_table@p(sg, nsg)
|
  sg =@p kmalloc_array(nsg, ...)
)

@script:python@
p << sfu_link.p;
sg << sfu_link.sg;
nsg << sfu_link.nsg;
@@

for _pu in p:
    _sfu_links.append((_pu.file, _pu.current_element, str(sg), str(nsg)))

// Bare-frag-count sizing spelled inline in the table allocation /
// init — the count-to-table link is the site itself.
@sfu_counti exists@
expression skb, sg;
constant C;
position p;
@@

(
  sg_init_table@p(sg, skb_shinfo(skb)->nr_frags + C)
|
  sg =@p kmalloc_array(skb_shinfo(skb)->nr_frags + C, ...)
)

@script:python@
p << sfu_counti.p;
skb << sfu_counti.skb;
sg << sfu_counti.sg;
@@

for _pu in p:
    _sfu_counts.append((_pu.file, _pu.current_element, int(_pu.line),
                        str(skb), "<inline:%s>" % str(sg)))

// The skb-to-scatterlist map.
@sfu_map exists@
expression skb, sg;
position p;
@@

(
  skb_to_sgvec@p(skb, sg, ...)
|
  skb_to_sgvec_nomark@p(skb, sg, ...)
)

@script:python@
p << sfu_map.p;
skb << sfu_map.skb;
sg << sfu_map.sg;
@@

for _pu in p:
    _sfu_maps.append((_pu.file, _pu.current_element, int(_pu.line),
                      str(skb), str(sg)))

// The mapped table bound into a crypto request (source or
// destination operand).
@sfu_crypt exists@
expression E1, E2, sg;
position p;
@@

(
  skcipher_request_set_crypt@p(E1, sg, ...)
|
  skcipher_request_set_crypt@p(E1, E2, sg, ...)
|
  aead_request_set_crypt@p(E1, sg, ...)
|
  aead_request_set_crypt@p(E1, E2, sg, ...)
)

@script:python@
p << sfu_crypt.p;
sg << sfu_crypt.sg;
@@

for _pu in p:
    _sfu_crypts.append((_pu.file, _pu.current_element, str(sg)))

@finalize:python@
@@
import json, sys
_seen = set()
for _cf, _cfn, _cl, _cskb, _cvar in _sfu_counts:
    if (_cf, _cfn) in _sfu_guarded:
        continue
    if _cvar.startswith("<inline:"):
        _tables = {_cvar[len("<inline:"):-1]}
    else:
        # The count variable must feed a table; collect the tables it
        # sizes in this function.
        _tables = {_lsg for _lf, _lfn, _lsg, _lnsg in _sfu_links
                   if (_lf, _lfn) == (_cf, _cfn) and _lnsg == _cvar}
    if not _tables:
        continue
    for _mf, _mfn, _ml, _mskb, _msg_ in _sfu_maps:
        if (_mf, _mfn) != (_cf, _cfn) or _mskb != _cskb or _ml < _cl:
            continue
        if _msg_ not in _tables:
            continue
        if not any(_rf == _cf and _rfn == _cfn and _rsg == _msg_
                   for _rf, _rfn, _rsg in _sfu_crypts):
            continue
        if (_cf, _cl) in _seen:
            continue
        _seen.add((_cf, _cl))
        _m = {"file": _cf, "line": _cl, "col": 0,
              "line_end": _cl, "col_end": 0,
              "rule": "scatterlist_frag_undersize",
              "message": "scatterlist sized from bare fragment count "
                         "'skb_shinfo(%s)->nr_frags' at line %s but "
                         "'%s' is mapped via skb_to_sgvec at line %s: "
                         "frag_list segments of a fragmented skb are "
                         "not counted, so the table is undersized for "
                         "non-linear buffers (out-of-bounds "
                         "scatterlist write / hard failure; size from "
                         "skb_cow_data() instead)"
                         % (_cskb, _cl, _mskb, _ml)}
        sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
