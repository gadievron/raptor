// init_after_register.cocci — Review field writes after registration calls.
//
// Ordering alone does not establish a race. Review registration success,
// actual publication, object identity, field purpose and synchronisation.
// A write can be an intentional update rather than missing initialisation.
// The generic chrdev leg does not link the written object to a registration
// argument, so unrelated field writes can also be candidates.
//
// CWE-908 / CWE-362 hypotheses require independent evidence of a consumer
// observing incompletely initialised state.
//
// Common in Linux kernel drivers: cdev_add, register_netdev,
// register_chrdev, platform_device_register, misc_register, etc.
// @role: detection

// cdev_add then field assignment
@cdev_late_init@
expression dev;
identifier fld;
position p_reg, p_init;
@@

cdev_add(&dev@p_reg, ...)
...
* dev.fld@p_init = ...;

@script:python@
p_reg << cdev_late_init.p_reg;
p_init << cdev_late_init.p_init;
dev << cdev_late_init.dev;
fld << cdev_late_init.fld;
@@

import json, sys
for _pr, _pi in zip(p_reg, p_init):
    _m = {"file": _pi.file, "line": int(_pi.line), "col": int(_pi.column),
          "line_end": int(_pi.line_end), "col_end": int(_pi.column_end),
          "rule": "init_after_register",
          "message": "Candidate: '%s.%s' written after cdev_add at line %s; review object identity, registration success, publication and synchronisation before claiming a race (CWE-908/CWE-362)" % (dev, fld, _pr.line)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

// register_netdev then field assignment
@netdev_late_init@
expression dev;
identifier fld;
position p_reg, p_init;
@@

register_netdev(dev@p_reg)
...
* dev->fld@p_init = ...;

@script:python@
p_reg << netdev_late_init.p_reg;
p_init << netdev_late_init.p_init;
dev << netdev_late_init.dev;
fld << netdev_late_init.fld;
@@

import json, sys
for _pr, _pi in zip(p_reg, p_init):
    _m = {"file": _pi.file, "line": int(_pi.line), "col": int(_pi.column),
          "line_end": int(_pi.line_end), "col_end": int(_pi.column_end),
          "rule": "init_after_register",
          "message": "Candidate: '%s->%s' written after register_netdev at line %s; review object identity, registration success, publication and synchronisation before claiming a race (CWE-908/CWE-362)" % (dev, fld, _pr.line)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

// misc_register then field assignment
@misc_late_init@
expression dev;
identifier fld;
position p_reg, p_init;
@@

misc_register(&dev@p_reg)
...
* dev.fld@p_init = ...;

@script:python@
p_reg << misc_late_init.p_reg;
p_init << misc_late_init.p_init;
dev << misc_late_init.dev;
fld << misc_late_init.fld;
@@

import json, sys
for _pr, _pi in zip(p_reg, p_init):
    _m = {"file": _pi.file, "line": int(_pi.line), "col": int(_pi.column),
          "line_end": int(_pi.line_end), "col_end": int(_pi.column_end),
          "rule": "init_after_register",
          "message": "Candidate: '%s.%s' written after misc_register at line %s; review object identity, registration success, publication and synchronisation before claiming a race (CWE-908/CWE-362)" % (dev, fld, _pr.line)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

// platform_device_register then field assignment (pointer variant)
@platform_late_init@
expression pdev;
identifier fld;
position p_reg, p_init;
@@

\(platform_device_register\|platform_device_add\)(pdev@p_reg)
...
* pdev->fld@p_init = ...;

@script:python@
p_reg << platform_late_init.p_reg;
p_init << platform_late_init.p_init;
pdev << platform_late_init.pdev;
fld << platform_late_init.fld;
@@

import json, sys
for _pr, _pi in zip(p_reg, p_init):
    _m = {"file": _pi.file, "line": int(_pi.line), "col": int(_pi.column),
          "line_end": int(_pi.line_end), "col_end": int(_pi.column_end),
          "rule": "init_after_register",
          "message": "Candidate: '%s->%s' written after platform_device_register at line %s; review object identity, registration success, publication and synchronisation before claiming a race (CWE-908/CWE-362)" % (pdev, fld, _pr.line)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

// Generic: register_chrdev_region / alloc_chrdev_region then field init
// The position binds to the first argument expression (mirroring the
// platform leg above) — attaching it to the argument dots
// (`(...@p_reg)`) never binds, which left this whole leg silently
// dead (U12-F205).
@chrdev_late_init@
expression dev, REGARG;
identifier fld;
position p_reg, p_init;
@@

\(register_chrdev\|register_chrdev_region\|alloc_chrdev_region\)(REGARG@p_reg, ...)
...
* dev.fld@p_init = ...;

@script:python@
p_reg << chrdev_late_init.p_reg;
p_init << chrdev_late_init.p_init;
dev << chrdev_late_init.dev;
fld << chrdev_late_init.fld;
@@

import json, sys
for _pr, _pi in zip(p_reg, p_init):
    _m = {"file": _pi.file, "line": int(_pi.line), "col": int(_pi.column),
          "line_end": int(_pi.line_end), "col_end": int(_pi.column_end),
          "rule": "init_after_register",
          "message": "Candidate: '%s.%s' written after chrdev registration at line %s; review object identity, registration success, publication and synchronisation before claiming a race (CWE-908/CWE-362)" % (dev, fld, _pr.line)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
