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

// Kernel iterator models are applied only to their first cursor, inside a
// supported body, with its declaration before the iterator. Keep the native
// matching unchanged: annotating iterator names changes spatch's C parser.
// These model conventional Linux APIs. Local overrides disable the model;
// header-only redefinitions are not resolved by the no-includes scan.
@initialize:python@
@@

from bisect import bisect_right

iterator_names = frozenset((
    "list_for_each_entry", "list_for_each_entry_reverse",
    "list_for_each_entry_safe", "hlist_for_each_entry",
    "hlist_for_each_entry_safe",
))
iterator_cache = {}

def iterator_statement_end(view, start, pairs, depth=0):
    # Delimiter pairing handles compounds without re-scanning their bodies.
    # Refuse unsupported control shapes instead of extending into later code.
    if depth >= 64:
        return None
    size = len(view)
    while start < size and view[start].isspace():
        start += 1
    if start == size or view[start] == chr(35):
        return None
    if view[start] == "{":
        return pairs.get(start, -2) + 1 if start in pairs else None
    end = start
    while end < size and (view[end].isalnum() or view[end] == "_"):
        end += 1
    word = view[start:end]
    if word == "if" or word in iterator_names:
        opening = end
        while opening < size and view[opening].isspace():
            opening += 1
        if opening not in pairs or view[opening] != "(":
            return None
        body_end = iterator_statement_end(view, pairs[opening] + 1, pairs, depth + 1)
        if body_end is None:
            return None
        if word == "if":
            following = body_end
            while following < size and view[following].isspace():
                following += 1
            if view.startswith("else", following) and (
                    following + 4 == size or not (
                        view[following + 4].isalnum() or view[following + 4] == "_")):
                return iterator_statement_end(view, following + 4, pairs, depth + 1)
        return body_end
    if word in ("for", "while", "do", "switch"):
        return None
    i = start
    while i < size:
        if view[i] == ";":
            return i + 1
        if view[i] in ":}" or view[i] == chr(35):
            return None
        if view[i] == "{":
            return None
        if view[i] == "(":
            if i not in pairs:
                return None
            i = pairs[i] + 1
        else:
            i += 1
    return None

def iterator_regions(path):
    if path in iterator_cache:
        return iterator_cache[path]
    empty = ([], [], [], [], [], [])
    if len(iterator_cache) >= 8:
        iterator_cache.pop(next(iter(iterator_cache)))
    iterator_cache[path] = empty
    try:
        with open(path, "rb") as fh:
            data = fh.read(4 * 1024 * 1024 + 1)
    except OSError:
        return empty
    if len(data) > 4 * 1024 * 1024:
        return empty
    # One character per byte keeps native columns aligned. Record physical
    # line starts and removed splice lengths before masking comments/literals.
    text = data.decode("latin-1")
    if not any(name in text for name in iterator_names):
        # A spliced spelling is ambiguous until preprocessing is complete.
        if chr(92) not in text:
            return empty
    newline, carriage, backslash = chr(10), chr(13), chr(92)
    if "?" + "?/" in text or text.count(newline) > 100000:
        return empty
    line_starts = [0] + [i + 1 for i, ch in enumerate(text) if ch == newline]
    pieces, splice_ends, removed = [], [], []
    start, search, total_removed = 0, 0, 0
    while True:
        escape = text.find(backslash, search)
        if escape < 0:
            break
        end = escape + 1
        if text.startswith(carriage + newline, end):
            end += 2
        elif text.startswith(newline, end):
            end += 1
        else:
            search = end
            continue
        if len(splice_ends) >= 10000:
            return empty
        pieces.append(text[start:escape])
        total_removed += end - escape
        splice_ends.append(end)
        removed.append(total_removed)
        start = search = end
    pieces.append(text[start:])
    text = "".join(pieces)
    if not any(name in text for name in iterator_names):
        return empty
    view = list(text)
    state = "code"
    i = 0
    while i < len(text):
        ch = text[i]
        if state == "code":
            if text.startswith("/" + "*", i) or text.startswith("/" + "/", i):
                state = "block" if text[i + 1] == "*" else "line"
                view[i:i + 2] = "  "
                i += 2
                continue
            if ch in (chr(34), chr(39)):
                state = ch
                view[i] = " "
        elif state == "block":
            if text.startswith("*" + "/", i):
                view[i:i + 2] = "  "
                state = "code"
                i += 2
                continue
            if ch not in (carriage, newline):
                view[i] = " "
        elif state == "line":
            if ch in (carriage, newline):
                state = "code"
            else:
                view[i] = " "
        else:
            if ch == backslash and i + 1 < len(text):
                view[i:i + 2] = "  "
                i += 2
                continue
            if ch == state:
                state = "code"
            if ch not in (carriage, newline):
                view[i] = " "
        i += 1
    if state not in ("code", "line"):
        return empty
    view = "".join(view)
    for line in view.split(newline):
        line = line.lstrip()
        if not line.startswith(chr(35)):
            continue
        parts = line[1:].lstrip().split(None, 1)
        if len(parts) != 2 or parts[0] not in ("define", "undef"):
            continue
        name = parts[1]
        end = 0
        while end < len(name) and (name[end].isalnum() or name[end] == "_"):
            end += 1
        if name[:end] in iterator_names:
            return empty
    # Pair delimiters once: nested loops must not re-scan their whole bodies.
    pairs, stack = {}, []
    for i, ch in enumerate(view):
        if ch in "({":
            stack.append(i)
        elif ch in ")}":
            if not stack or view[stack[-1]] != (
                    "(" if ch == ")" else "{"):
                return empty
            pairs[stack.pop()] = i
    if stack:
        return empty
    regions = []
    i = 0
    while i < len(view):
        if not (view[i].isalpha() or view[i] == "_"):
            i += 1
            continue
        start = i
        while i < len(view) and (view[i].isalnum() or view[i] == "_"):
            i += 1
        if view[start:i] not in iterator_names:
            continue
        j = i
        while j < len(view) and view[j].isspace():
            j += 1
        if j not in pairs or view[j] != "(":
            continue
        closing = pairs[j]
        k = j + 1
        while k < closing and view[k].isspace():
            k += 1
        arg_start = k
        while k < closing and (view[k].isalnum() or view[k] == "_"):
            k += 1
        cursor = view[arg_start:k]
        while k < closing and view[k].isspace():
            k += 1
        if not cursor or k == closing or view[k] != ",":
            continue
        body = closing + 1
        while body < len(view) and view[body].isspace():
            body += 1
        body_end = iterator_statement_end(view, body, pairs)
        if body_end is not None:
            regions.append((body, body_end, start, cursor))
    if not regions:
        return empty
    regions.sort()
    parents, active = [], []
    for index, region in enumerate(regions):
        while active and regions[active[-1]][1] < region[0]:
            active.pop()
        parents.append(active[-1] if active else -1)
        active.append(index)
    result = (line_starts, regions, [r[0] for r in regions], parents, splice_ends, removed)
    iterator_cache[path] = result
    return result

def initialized_iterator_return(path, decl_line, decl_column,
                                ret_line, ret_column, var_name):
    lines, regions, starts, parents, splices, removed = iterator_regions(path)
    if not (1 <= decl_line <= len(lines) and 1 <= ret_line <= len(lines)):
        return False
    declaration = lines[decl_line - 1] + decl_column
    returned = lines[ret_line - 1] + ret_column
    before_decl = bisect_right(splices, declaration)
    before_return = bisect_right(splices, returned)
    declaration -= removed[before_decl - 1] if before_decl else 0
    returned -= removed[before_return - 1] if before_return else 0
    index = bisect_right(starts, returned) - 1
    while index >= 0:
        body, end, call, cursor = regions[index]
        if body <= returned < end and declaration < call and cursor == var_name:
            return True
        index = parents[index]
    return False

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
        if initialized_iterator_return(_pr.file, int(_pd.line), int(_pd.column),
                                       int(_pr.line), int(_pr.column), err):
            continue
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
    pre_depth = 0
    while i < ret_line - 1 and i < len(lines):
        if not switch_re.search(lines[i]):
            # An assignment at nesting depth 0 before the switch is an
            # unconditional initialisation that dominates the return —
            # whatever the switch does, the variable is already set.
            # (Same depth-0 heuristic as the after-switch scan below.)
            if pre_depth == 0 and assign_re.search(lines[i]):
                return None
            for ch in lines[i]:
                if ch == '{':
                    pre_depth += 1
                elif ch == '}':
                    pre_depth -= 1
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
        if initialized_iterator_return(_pr.file, int(_pd.line), int(_pd.column),
                                       int(_pr.line), int(_pr.column), err):
            continue
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
