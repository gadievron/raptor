// uninitialized_return.cocci — Find local variables that can reach a
// return statement without guaranteed initialization on all paths.
//
// Covers the kernel IPC pattern where `int err;` is declared, only
// assigned inside a switch/if branch, and returned on the fallthrough.
//
// This is NOT parametric (-D func= not needed) — it matches any
// function in the target. The consistency_check runner can still
// pass -D func= but the rule ignores it.
// @role: detection

// Pattern 1: int declared without init, returned without assignment
// on at least one path (goto-error or direct return)
@uninit_assign@
identifier err;
position p_decl, p_ret;
type T;
@@

  T err@p_decl;
<... when != err = ...;
     when != &err
     when any
(
* return@p_ret err;
)
...>

@script:python@
p_decl << uninit_assign.p_decl;
p_ret << uninit_assign.p_ret;
err << uninit_assign.err;
@@

import json, sys
for _pd in p_decl:
    for _pr in p_ret:
        if int(_pr.line) > int(_pd.line):
            _m = {"file": _pr.file, "line": int(_pr.line), "col": int(_pr.column),
                   "line_end": int(_pr.line_end), "col_end": int(_pr.column_end),
                   "rule": "uninitialized_return",
                   "message": "Variable '%s' (declared line %s) may be returned uninitialized" % (err, _pd.line)}
            sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

// Pattern 2: uninitialised variable assigned inside a switch that
// lacks a default case, then returned.  Catches the common kernel
// pattern where ret is set in some case arms but not all.
// SmPL matches decl → return broadly; the Python script scans the
// source range for a switch-without-default that assigns the variable.
@uninit_switch exists@
identifier err;
position p_decl, p_ret;
type T;
@@

T err@p_decl;
... when any
return@p_ret err;

@script:python depends on uninit_switch@
p_decl << uninit_switch.p_decl;
p_ret << uninit_switch.p_ret;
err << uninit_switch.err;
@@

import json, sys, re

def _find_switch_no_default(filepath, decl_line, ret_line, var_name):
    """Find a switch-without-default that assigns var_name between decl and ret."""
    try:
        with open(filepath) as fh:
            lines = fh.readlines()
    except Exception:
        return None
    assign_re = re.compile(r'\b' + re.escape(var_name) + r'\s*=[^=]')
    switch_re = re.compile(r'\bswitch\s*\(')
    i = decl_line  # 0-based index after decl_line (1-based)
    while i < ret_line - 1 and i < len(lines):
        if switch_re.search(lines[i]):
            sw_line = i + 1  # 1-based
            depth = 0
            has_default = False
            assigns_var = False
            switch_end_idx = None
            for j in range(i, len(lines)):
                line = lines[j]
                for ch in line:
                    if ch == '{':
                        depth += 1
                    elif ch == '}':
                        depth -= 1
                        if depth == 0:
                            switch_end_idx = j
                            if not has_default and assigns_var:
                                pass
                            i = j
                            break
                else:
                    if depth == 1:
                        stripped = line.lstrip()
                        if stripped.startswith('default'):
                            rest = stripped[7:].lstrip()
                            if rest.startswith(':'):
                                has_default = True
                        if assign_re.search(line):
                            assigns_var = True
                    continue
                break
            if not has_default and assigns_var and switch_end_idx is not None:
                dominated = False
                brace_depth = 0
                for k in range(switch_end_idx + 1, ret_line - 1):
                    if k >= len(lines):
                        break
                    kline = lines[k]
                    for ch in kline:
                        if ch == '{':
                            brace_depth += 1
                        elif ch == '}':
                            brace_depth -= 1
                    if brace_depth == 0 and assign_re.search(kline):
                        dominated = True
                        break
                if not dominated:
                    return sw_line
        i += 1
    return None

for _pd in p_decl:
    for _pr in p_ret:
        dl = int(_pd.line)
        rl = int(_pr.line)
        if rl <= dl:
            continue
        sw = _find_switch_no_default(_pr.file, dl, rl, err)
        if sw is None:
            continue
        _m = {"file": _pr.file, "line": rl, "col": int(_pr.column),
               "line_end": int(_pr.line_end), "col_end": int(_pr.column_end),
               "rule": "uninitialized_return",
               "message": "Variable '%s' (declared line %s) may be returned uninitialized — switch without default at line %d" % (err, _pd.line, sw)}
        sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
