// resource_leak_err.cocci — Find allocations not freed on error paths.
//
// The pattern: a function allocates memory (kmalloc, kzalloc, etc.)
// into a local variable, then a later error check returns without
// freeing it. Classic error-path resource leak.
//
// Allocation and error return are matched in ONE rule so both sit in
// the same function: a name-only join across two rules let an
// allocation in one function pair with a same-named pointer's error
// return in a completely different function.
//
// The allocation-failure check itself (`if (!ptr) return -ENOMEM;`)
// is not a leak — nothing was allocated on that path — so it is
// excluded via the unstarred first disjunction branch below (leftmost
// branch takes priority in SmPL, the standard exception idiom).
// `when any` keeps the dots from stopping at that first matching if:
// the common real-bug shape is a leaky error return AFTER the
// failure check, and shortest-path dots would never reach it.
//
// Covers CWE-401: missing free on error path.
// @role: detection
// raptor: confirm-only
// Missing this error-path shape does not rule out other allocation leaks.

@initialize:python@
@@
_rl_safe = {}
_rl_bypass = set()
_rl_changed = set()
_rl_addressed = set()
_rl_bindings = {}
_rl_seen = set()

def _rl_location(position):
    return (position.file, int(position.line), int(position.column))

def _rl_pairs(allocations, returns):
    for allocation in allocations:
        for returned in returns:
            yield (*_rl_location(allocation), int(returned.line), int(returned.column))

def _rl_proven_cleanup(key, pointer):
    # C++ references can rebind a pointer without an address-of expression.
    # Keep those warnings conservative (including headers and uppercase .C).
    if not key[0].endswith(".c"):
        return False
    proof = _rl_safe.get(key)
    if proof is None or key in _rl_bypass or key in _rl_changed:
        return False
    function, array, declaration = proof
    if (*function, str(pointer)) in _rl_addressed:
        return False
    return not (_rl_bindings.get((*function, array), set()) - {declaration})

@leak exists@
identifier ptr;
type T;
// @vocab: allocators
identifier alloc = {kmalloc, kzalloc, kcalloc, kmalloc_array, vmalloc, kvmalloc};
expression E, E2;
statement S;
position p_alloc, p_ret;
@@

(
  ptr =@p_alloc alloc(...);
|
  T ptr =@p_alloc alloc(...);
)
// A free or reassignment between the allocation and the error check
// ends this allocation's liability for the path — without these
// guards a function that frees eagerly and then takes an unrelated
// error return was still flagged. Learned deallocators must extend
// this guard in lockstep with the inner one below.
// @vocab: deallocators
... when != \(kfree\|kvfree\|vfree\|kfree_sensitive\)(ptr)
    when != ptr = E2
    when any
(
// Exception branch: the mandatory allocation-failure check — the
// pointer is NULL (or an error cookie) on this path, there is
// nothing to free.
if (\(!ptr\|ptr == NULL\|NULL == ptr\|unlikely(!ptr)\|unlikely(ptr == NULL)\|IS_ERR(ptr)\|IS_ERR_OR_NULL(ptr)\)) S
|
if (...) {
  // @vocab: deallocators
  ... when != \(kfree\|kvfree\|vfree\|kfree_sensitive\)(ptr)
  return@p_ret E;
}
)

// A heap pointer cannot equal an actual local array. This is only a
// candidate proof: a bypass, pointer mutation/address escape or a shadowed
// array binding vetoes it below. No other conditional free is promoted to
// an unconditional cleanup.
@stack_cleanup exists@
identifier leak.ptr, leak.alloc;
position leak.p_alloc, leak.p_ret;
position safe_alloc, safe_ret, cleanup_guard;
type T, U;
identifier backing, fn;
position function_start, local_declaration;
expression E, E2;
// @vocab: deallocators
identifier release = {kfree, kvfree, vfree, kfree_sensitive};
@@

fn@function_start(...) {
<...
T backing@local_declaration[...];
... when exists
(
  ptr =@p_alloc@safe_alloc alloc(...);
|
  U ptr =@p_alloc@safe_alloc alloc(...);
)
... when != ptr = E2
    when exists
if (\(ptr != backing@cleanup_guard\|backing@cleanup_guard != ptr\)) { release(ptr); }
... when != ptr = E2
    when exists
return@p_ret@safe_ret E;
...>
}

// Bind positions from the SAME cleanup proof. A reachable path avoiding
// its exact comparison is a real bypass, even if another branch frees.
@stack_bypass exists@
identifier leak.ptr, leak.alloc;
position stack_cleanup.safe_alloc, stack_cleanup.safe_ret;
position unsafe_alloc, unsafe_ret;
identifier stack_cleanup.backing;
position stack_cleanup.cleanup_guard;
expression E, E2;
type T;
@@
(
  ptr =@safe_alloc@unsafe_alloc alloc(...);
|
  T ptr =@safe_alloc@unsafe_alloc alloc(...);
)
... when != ptr = E2
    when != \(ptr != backing@cleanup_guard\|backing@cleanup_guard != ptr\)
    when any
return@safe_ret@unsafe_ret E;

// An address-taken pointer may be changed through an alias created even
// before the allocation. Keep these warnings rather than guessing.
@stack_address exists@
identifier stack_cleanup.fn;
identifier ptr;
position stack_cleanup.function_start;
position address_fn, p_address;
@@
fn@function_start@address_fn(...) {
<+...
 (&ptr@p_address)
...+>
}

@script:python@
f << stack_address.address_fn;
ptr << stack_address.ptr;
@@
for _f in f:
    _rl_addressed.add((*_rl_location(_f), str(ptr)))

// A same-spelled pointer declaration/parameter must not be mistaken for
// the array. Facts are keyed by function position as well as variable name.
@local_binding exists@
identifier stack_cleanup.fn, stack_cleanup.backing;
position stack_cleanup.function_start;
type T;
position f, p_decl;
expression E;
@@
fn@function_start@f(...) {
<+...
(
 T backing@p_decl;
|
 T backing@p_decl = E;
)
...+>
}

@script:python@
f << local_binding.f;
array << stack_cleanup.backing;
d << local_binding.p_decl;
@@
for _f in f:
    _key = (*_rl_location(_f), str(array))
    _rl_bindings.setdefault(_key, set()).update(
        (int(_d.line), int(_d.column)) for _d in d
    )

@local_parameter exists@
identifier stack_cleanup.fn, stack_cleanup.backing;
position stack_cleanup.function_start;
type T;
position f, p_decl;
@@
fn@function_start@f(..., T backing@p_decl, ...) { ... }

@script:python@
f << local_parameter.f;
array << stack_cleanup.backing;
d << local_parameter.p_decl;
@@
for _f in f:
    _key = (*_rl_location(_f), str(array))
    _rl_bindings.setdefault(_key, set()).update(
        (int(_d.line), int(_d.column)) for _d in d
    )

// Any reachable reassignment/arithmetic before this return invalidates
// the proof, including a modification on a different conditional path.
@stack_rebound exists@
identifier leak.ptr, leak.alloc;
position leak.p_alloc, leak.p_ret;
position changed_alloc, changed_ret;
expression E, E2;
type T;
@@
(
  ptr =@p_alloc@changed_alloc alloc(...);
|
  T ptr =@p_alloc@changed_alloc alloc(...);
)
... when exists
(
   (ptr = E2)
|
   (ptr += E2)
|
   (ptr -= E2)
|
   (ptr++)
|
   (++ptr)
|
   (ptr--)
|
   (--ptr)
)
... when exists
return@p_ret@changed_ret E;

@script:python@
p_alloc << stack_rebound.changed_alloc;
p_ret << stack_rebound.changed_ret;
@@
_rl_changed.update(_rl_pairs(p_alloc, p_ret))

@script:python@
p_alloc << stack_bypass.unsafe_alloc;
p_ret << stack_bypass.unsafe_ret;
@@
_rl_bypass.update(_rl_pairs(p_alloc, p_ret))

@script:python@
p_alloc << stack_cleanup.safe_alloc;
p_ret << stack_cleanup.safe_ret;
f << stack_cleanup.function_start;
array << stack_cleanup.backing;
d << stack_cleanup.local_declaration;
@@
for _key in _rl_pairs(p_alloc, p_ret):
    _rl_safe[_key] = (
        _rl_location(f[0]), str(array), (int(d[0].line), int(d[0].column))
    )

@script:python@
p_alloc << leak.p_alloc;
p_ret << leak.p_ret;
ptr << leak.ptr;
@@

import json, sys
# One record per report site: multi-path matches bind several
# allocation positions to the same error return (both branches of an
# if allocate — one match environment each), and the cross product
# emitted near-identical duplicates that only consumer-side dedup
# absorbed. The seen-set lives in module globals because coccinelle
# re-executes this block once per match environment within one
# persistent interpreter; the key carries the file so state never
# leaks across targets.
_first = min(int(_a.line) for _a in p_alloc)
for _p in p_ret:
    _alloc_keys = list(_rl_pairs(p_alloc, [_p]))
    if _alloc_keys and all(_rl_proven_cleanup(_key, ptr) for _key in _alloc_keys):
        continue
    _key = (_p.file, int(_p.line), int(_p.column))
    if _key in _rl_seen:
        continue
    _rl_seen.add(_key)
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
          "line_end": int(_p.line_end), "col_end": int(_p.column_end),
          "rule": "resource_leak_err",
          "message": "'%s' allocated at line %s not freed before return on error path" % (ptr, _first)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
