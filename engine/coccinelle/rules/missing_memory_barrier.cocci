// missing_memory_barrier.cocci — Find stores to shared struct fields
// followed by loads from different fields of the same struct through
// the same pointer, without an intervening memory barrier.
//
// On weakly-ordered architectures (ARM, RISC-V, PowerPC), the CPU
// may reorder the store after the load, causing another CPU to see
// stale data. The Linux kernel requires explicit barriers (smp_wmb,
// smp_rmb, smp_mb, barrier) or ordered accessors (WRITE_ONCE,
// READ_ONCE) between such accesses.
//
// Conservative: only matches when BOTH accesses go through the same
// pointer to struct fields, suggesting shared state that needs ordering.
//
// Covers CWE-362 / CWE-667: race condition from missing synchronisation.
// @role: detection

// Store to ptr->fldA then load from ptr->fldB without barrier
@missing_barrier@
expression ptr;
expression E;
identifier fldA, fldB;
position p_load;
@@

ptr->fldA = E;
... when != \(smp_wmb\|smp_rmb\|smp_mb\|smp_store_mb\|barrier\)()
    when != WRITE_ONCE(...)
    when != READ_ONCE(...)
    when != \(spin_lock\|spin_unlock\|mutex_lock\|mutex_unlock\|spin_lock_irq\|spin_unlock_irq\|spin_lock_bh\|spin_unlock_bh\)(...)
    when != return ...;
* ptr->fldB@p_load

@script:python@
p_load << missing_barrier.p_load;
ptr << missing_barrier.ptr;
fldA << missing_barrier.fldA;
fldB << missing_barrier.fldB;
@@

import json, sys
if fldA != fldB:
    for _p in p_load:
        _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
              "line_end": int(_p.line_end), "col_end": int(_p.column_end),
              "rule": "missing_memory_barrier",
              "message": "Store to '%s->%s' then load from '%s->%s' without memory barrier" % (ptr, fldA, ptr, fldB)}
        sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
