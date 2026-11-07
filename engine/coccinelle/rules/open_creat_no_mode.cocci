// open_creat_no_mode.cocci — Find missing mode arguments on open-family calls.
//
// O_CREAT and O_TMPFILE require an explicit mode. Recognize exact flag
// identifiers in bounded expressions whose OR/AND structure proves a flag
// survives. Do not infer flag values from similarly named identifiers,
// numeric constants, calls, casts or other unsupported expressions.
// Keep analysis report-local so this rule can share a production batch.
// CWE-732: Incorrect Permission Assignment for Critical Resource
// @role: verification

@open_creat_no_mode@
expression DIRFD, PATH, FLAGS;
position p;
@@

(
* \(open\|open64\)(PATH, FLAGS)@p
|
* \(openat\|openat64\)(DIRFD, PATH, FLAGS)@p
)

@script:python check_open depends on open_creat_no_mode@
p << open_creat_no_mode.p;
FLAGS << open_creat_no_mode.FLAGS;
@@
import ast
import json
import re


def _open_mode_required(node):
    if isinstance(node, ast.Name):
        return {"O_CREAT": 1, "O_TMPFILE": 2}.get(node.id, 0)
    if isinstance(node, ast.BinOp):
        left = _open_mode_required(node.left)
        right = _open_mode_required(node.right)
        if isinstance(node.op, ast.BitOr):
            return left | right
        if isinstance(node.op, ast.BitAnd):
            return left & right
    return 0


_open_flags = str(FLAGS)
_open_requires_mode = 0
if len(_open_flags) <= 512 and _open_flags.isascii():
    # Numeric leaves establish no symbolic flag. Normalize C integer suffixes
    # and octal syntax for parsing without assuming platform-specific values.
    _open_flags = re.sub(
        r"\b(?:0[xX][0-9a-fA-F]+|0[bB][01]+|[0-9]+)[uUlL]*\b", "0", _open_flags,
    )
    try:
        _open_requires_mode = _open_mode_required(ast.parse(_open_flags, mode="eval").body)
    except (SyntaxError, ValueError, RecursionError):
        _open_requires_mode = 0
if _open_requires_mode:
    msg = {
      "rule": "open_creat_no_mode",
      "file": p[0].file,
      "line": int(p[0].line),
      "col": int(p[0].column),
      "message": "open-family call with O_CREAT/O_TMPFILE but no mode argument — missing creation permissions (CWE-732). Add the mode parameter."
    }
    print("COCCIRESULT:" + json.dumps(msg))
