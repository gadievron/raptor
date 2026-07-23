// init_after_register.cocci — Find device/handler registration where
// struct fields are initialized AFTER the registration call.
//
// The pattern: a struct is registered with a subsystem (making it
// visible to other threads / interrupt handlers), then fields of that
// struct are assigned. Between registration and the late init, another
// thread can access the partially-initialized object.
//
// Covers CWE-908 (use of uninitialized resource) + CWE-362 (race
// condition): the registration creates a race window where the object
// is accessible but not fully initialized.
//
// Common in Linux kernel drivers: cdev_add, register_netdev,
// register_chrdev, platform_device_register, misc_register, etc.

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
          "message": "'%s.%s' initialized after cdev_add at line %s — race window" % (dev, fld, _pr.line)}
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
          "message": "'%s->%s' initialized after register_netdev at line %s — race window" % (dev, fld, _pr.line)}
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
          "message": "'%s.%s' initialized after misc_register at line %s — race window" % (dev, fld, _pr.line)}
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
          "message": "'%s->%s' initialized after platform_device_register at line %s — race window" % (pdev, fld, _pr.line)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

// Generic: register_chrdev_region / alloc_chrdev_region then field init
@chrdev_late_init@
expression dev;
identifier fld;
position p_reg, p_init;
@@

\(register_chrdev\|register_chrdev_region\|alloc_chrdev_region\)(...@p_reg)
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
          "message": "'%s.%s' initialized after chrdev registration at line %s — race window" % (dev, fld, _pr.line)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
