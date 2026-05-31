// lock_sites.cocci — enumerate lock acquire/release sites for the
// Phase B `shared_state` /understand --map section.
//
// NOT a bug detector — that's lock_imbalance.cocci's job. Pure
// enumeration. One COCCIRESULT per call:
//
//   lock_site:<op>:<kind>:<fn>:<lock_var>
//
// op       ∈ acquire | release
// kind     ∈ spin | mutex | rw | pthread_mutex
// fn       = the concrete function name matched
// lock_var = the expression in the first arg position, rendered by
//            spatch (may contain whitespace, e.g. ``& sl``). Consumers
//            should normalise (e.g. collapse ``& `` → ``&``).
//
// Coverage:
//   * Kernel spinlock variants (incl. irq/bh/irqsave/trylock)
//   * Kernel mutex (lock/lock_interruptible/lock_killable/trylock/unlock)
//   * Kernel rwlock (read/write variants + irq/bh)
//   * POSIX pthread mutex (lock/trylock/unlock)
//
// Out of scope (deferred): atomic_*, READ_ONCE/WRITE_ONCE, RCU,
// futex, std::mutex / std::lock_guard (C++ scope-based). Each has
// distinct semantics worth its own evidence shape.
//
// Known limitations consumers should be aware of:
//
//   * trylock variants (`spin_trylock`, `mutex_trylock`,
//     `pthread_mutex_trylock`, `read_trylock`, `write_trylock`) emit
//     ``op=acquire`` because that's the *intent*, but the lock is
//     only HELD when the return value is checked-zero. Pure
//     enumeration is correct; pairing/imbalance reasoning must
//     account for the failure path.
//
//   * Identifier matching is name-only. A non-kernel project that
//     defines `void read_lock(int fd)` (e.g. file-lock wrapper) WILL
//     fire as kind=`rw`. Short names like `read_lock` / `write_lock`
//     are the highest collision risk. The shared_state section is
//     informational; downstream LLM analysis can disambiguate from
//     surrounding code. Match by signature/header file would tighten
//     this but isn't worth the complexity for v1.
//
// Consumed by packages/source_intel/analyze.py:_collect_lock_sites
// → LockSiteEvidence tuples → SourceIntelResult.lock_sites →
// context_map_sites.build_shared_state → cmap["shared_state"].


// === Kernel spinlocks ===

@spin_acq@
position p;
expression L;
identifier fn = {
    spin_lock, spin_lock_irq, spin_lock_bh, spin_lock_irqsave,
    spin_trylock, spin_trylock_irq, spin_trylock_bh, spin_trylock_irqsave,
    raw_spin_lock, raw_spin_lock_irq, raw_spin_lock_bh, raw_spin_lock_irqsave,
    raw_spin_trylock
};
@@
fn@p(L, ...)

@script:python depends on spin_acq@
p << spin_acq.p;
fn << spin_acq.fn;
L << spin_acq.L;
@@
import json, sys
for _p in p:
    sys.stderr.write("COCCIRESULT:" + json.dumps({
        "file": _p.file, "line": int(_p.line),
        "rule": "lock_sites",
        "message": "lock_site:acquire:spin:" + str(fn) + ":" + str(L),
    }) + "\n")


@spin_rel@
position p;
expression L;
identifier fn = {
    spin_unlock, spin_unlock_irq, spin_unlock_bh, spin_unlock_irqrestore,
    raw_spin_unlock, raw_spin_unlock_irq, raw_spin_unlock_bh, raw_spin_unlock_irqrestore
};
@@
fn@p(L, ...)

@script:python depends on spin_rel@
p << spin_rel.p;
fn << spin_rel.fn;
L << spin_rel.L;
@@
import json, sys
for _p in p:
    sys.stderr.write("COCCIRESULT:" + json.dumps({
        "file": _p.file, "line": int(_p.line),
        "rule": "lock_sites",
        "message": "lock_site:release:spin:" + str(fn) + ":" + str(L),
    }) + "\n")


// === Kernel mutex ===

@mutex_acq@
position p;
expression L;
identifier fn = {
    mutex_lock, mutex_lock_interruptible, mutex_lock_killable,
    mutex_trylock
};
@@
fn@p(L, ...)

@script:python depends on mutex_acq@
p << mutex_acq.p;
fn << mutex_acq.fn;
L << mutex_acq.L;
@@
import json, sys
for _p in p:
    sys.stderr.write("COCCIRESULT:" + json.dumps({
        "file": _p.file, "line": int(_p.line),
        "rule": "lock_sites",
        "message": "lock_site:acquire:mutex:" + str(fn) + ":" + str(L),
    }) + "\n")


@mutex_rel@
position p;
expression L;
identifier fn = { mutex_unlock };
@@
fn@p(L, ...)

@script:python depends on mutex_rel@
p << mutex_rel.p;
fn << mutex_rel.fn;
L << mutex_rel.L;
@@
import json, sys
for _p in p:
    sys.stderr.write("COCCIRESULT:" + json.dumps({
        "file": _p.file, "line": int(_p.line),
        "rule": "lock_sites",
        "message": "lock_site:release:mutex:" + str(fn) + ":" + str(L),
    }) + "\n")


// === Kernel rwlock ===

@rw_acq@
position p;
expression L;
identifier fn = {
    read_lock, read_lock_irq, read_lock_bh, read_lock_irqsave,
    write_lock, write_lock_irq, write_lock_bh, write_lock_irqsave,
    read_trylock, write_trylock
};
@@
fn@p(L, ...)

@script:python depends on rw_acq@
p << rw_acq.p;
fn << rw_acq.fn;
L << rw_acq.L;
@@
import json, sys
for _p in p:
    sys.stderr.write("COCCIRESULT:" + json.dumps({
        "file": _p.file, "line": int(_p.line),
        "rule": "lock_sites",
        "message": "lock_site:acquire:rw:" + str(fn) + ":" + str(L),
    }) + "\n")


@rw_rel@
position p;
expression L;
identifier fn = {
    read_unlock, read_unlock_irq, read_unlock_bh, read_unlock_irqrestore,
    write_unlock, write_unlock_irq, write_unlock_bh, write_unlock_irqrestore
};
@@
fn@p(L, ...)

@script:python depends on rw_rel@
p << rw_rel.p;
fn << rw_rel.fn;
L << rw_rel.L;
@@
import json, sys
for _p in p:
    sys.stderr.write("COCCIRESULT:" + json.dumps({
        "file": _p.file, "line": int(_p.line),
        "rule": "lock_sites",
        "message": "lock_site:release:rw:" + str(fn) + ":" + str(L),
    }) + "\n")


// === POSIX pthread mutex (userspace) ===

@pthread_acq@
position p;
expression L;
identifier fn = { pthread_mutex_lock, pthread_mutex_trylock };
@@
fn@p(L, ...)

@script:python depends on pthread_acq@
p << pthread_acq.p;
fn << pthread_acq.fn;
L << pthread_acq.L;
@@
import json, sys
for _p in p:
    sys.stderr.write("COCCIRESULT:" + json.dumps({
        "file": _p.file, "line": int(_p.line),
        "rule": "lock_sites",
        "message": "lock_site:acquire:pthread_mutex:" + str(fn) + ":" + str(L),
    }) + "\n")


@pthread_rel@
position p;
expression L;
identifier fn = { pthread_mutex_unlock };
@@
fn@p(L, ...)

@script:python depends on pthread_rel@
p << pthread_rel.p;
fn << pthread_rel.fn;
L << pthread_rel.L;
@@
import json, sys
for _p in p:
    sys.stderr.write("COCCIRESULT:" + json.dumps({
        "file": _p.file, "line": int(_p.line),
        "rule": "lock_sites",
        "message": "lock_site:release:pthread_mutex:" + str(fn) + ":" + str(L),
    }) + "\n")
