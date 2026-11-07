// fcntl_flag_domain.cocci — Detect descriptor/status flag domain confusion.
//
// F_SETFD takes descriptor flags; F_SETFL takes file-status flags.
// Check exact identifiers whose bits survive supported OR/AND expressions.
// A correct-domain flag alongside a wrong-domain flag does not repair it.
// Numeric values, casts and unsupported expressions establish no flag facts.
// Keep parsing bounded and report-local to preserve production batching.
// CWE-688: Function Call With Incorrect Variable or Reference as Argument
// @role: verification

@fcntl_flag_domain@
expression FD, COMMAND, FLAGS;
position p;
@@

* \(fcntl\|fcntl64\)(FD, COMMAND, FLAGS)@p

@script:python check_domain depends on fcntl_flag_domain@
p << fcntl_flag_domain.p;
COMMAND << fcntl_flag_domain.COMMAND;
FLAGS << fcntl_flag_domain.FLAGS;
@@
import ast
import json
import re


def _fcntl_surviving_flags(node):
    if isinstance(node, ast.Name):
        # Abstract identity bits, not operating-system flag values.
        return {
            "FD_CLOEXEC": 1,
            "O_NONBLOCK": 2,
            "O_APPEND": 4,
            "O_ASYNC": 8,
            "O_DIRECT": 16,
            "O_NOATIME": 32,
        }.get(node.id, 0)
    if isinstance(node, ast.BinOp):
        left = _fcntl_surviving_flags(node.left)
        right = _fcntl_surviving_flags(node.right)
        if isinstance(node.op, ast.BitOr):
            return left | right
        if isinstance(node.op, ast.BitAnd):
            return left & right
    return 0


_fcntl_command = str(COMMAND).strip()
_fcntl_flags = str(FLAGS)
_fcntl_wrong = 0
if len(_fcntl_flags) <= 512 and _fcntl_flags.isascii() and len(_fcntl_command) <= 64 and _fcntl_command.isascii():
    try:
        _fcntl_command_node = ast.parse(_fcntl_command, mode="eval").body
        _fcntl_command_name = (
            _fcntl_command_node.id if isinstance(_fcntl_command_node, ast.Name) else ""
        )
        _fcntl_wrong_mask = {"F_SETFL": 1, "F_SETFD": 62}.get(_fcntl_command_name, 0)
        if _fcntl_wrong_mask:
            # Numeric leaves prove no symbolic flags; normalize C integer
            # spelling without assigning platform-specific numeric values.
            _fcntl_flags = re.sub(
                r"\b(?:0[xX][0-9a-fA-F]+|0[bB][01]+|[0-9]+)[uUlL]*\b", "0", _fcntl_flags,
            )
            _fcntl_wrong = _fcntl_surviving_flags(
                ast.parse(_fcntl_flags, mode="eval").body,
            ) & _fcntl_wrong_mask
    except (SyntaxError, ValueError, RecursionError):
        _fcntl_wrong = 0
if _fcntl_wrong:
    msg = {
      "rule": "fcntl_flag_domain",
      "file": p[0].file,
      "line": int(p[0].line),
      "col": int(p[0].column),
      "message": "fcntl-family call mixes file-descriptor and file-status flag domains (CWE-688). Use F_SETFD for FD_CLOEXEC and F_SETFL for file-status flags."
    }
    print("COCCIRESULT:" + json.dumps(msg))
