"""Conditional slice-model observations; never source safety certificates."""
from __future__ import annotations

import ast
from hashlib import sha256


def _constant_index(node: ast.expr | None) -> int | None:
    if node is None:
        return None
    sign = 1
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        sign, node = -1, node.operand
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return sign * node.value
    raise ValueError("nonconstant slice index")


def slice_model_diagnostic(
    source_text: str, validator_line: int, sink_line: int, variable: str,
    intervals: tuple[tuple[int, int], ...], *, allows_empty: bool,
    optional_final_lf: bool, forbidden: tuple[int, ...],
) -> dict | None:
    """Model one observed bound and edge slice, retaining every source gap.

    These observations do not establish canonical len/re identities,
    exact builtin str, value epochs, or a complete sink property. Even
    excluded results cannot authorise suppression. No scanned code runs.
    """
    from core.dataflow.smt_barrier import _block_always_exits, _function_containing
    from core.smt_solver.string_slice import (
        AsciiRepeatDomain, PythonEdgeSlice, prove_slice_property,
    )

    if type(allows_empty) is not bool or type(optional_final_lf) is not bool:
        return None
    try:
        tree = ast.parse(source_text)
        function = _function_containing(tree, validator_line)
        if (not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef))
                or function is not _function_containing(tree, sink_line)):
            return None
        statements = function.body
        validators = [s for s in statements if s.lineno == validator_line]
        sinks = [s for s in statements if s.lineno == sink_line]
        if len(validators) != 1 or len(sinks) != 1:
            return None
        sink = sinks[0]
        expression = sink.value if isinstance(sink, (ast.Return, ast.Expr)) else None
        if (not isinstance(expression, ast.Call) or expression.keywords
                or len(expression.args) != 1 or not isinstance(expression.args[0], ast.Name)):
            return None
        sink_index = statements.index(sink)
        if sink_index == 0:
            return None
        transfer = statements[sink_index - 1]
        if (not isinstance(transfer, ast.Assign) or len(transfer.targets) != 1
                or not isinstance(transfer.targets[0], ast.Name)
                or transfer.targets[0].id != expression.args[0].id
                or not isinstance(transfer.value, ast.Subscript)
                or not isinstance(transfer.value.value, ast.Name)
                or transfer.value.value.id != variable
                or not isinstance(transfer.value.slice, ast.Slice)
                or transfer.value.slice.step is not None
                or transfer.lineno <= validator_line):
            return None
        operation = transfer.value.slice
        start, stop = _constant_index(operation.lower), _constant_index(operation.upper)
        if (start is not None and start < 0) or (stop is not None and stop > 0):
            return None
        bounds: list[tuple[int, int]] = []
        for statement in statements[:sink_index - 1]:
            if (not isinstance(statement, ast.If) or statement.orelse
                    or not _block_always_exits(statement.body)):
                continue
            test = statement.test
            if (not isinstance(test, ast.Compare) or len(test.ops) != 1
                    or not isinstance(test.ops[0], ast.Gt) or len(test.comparators) != 1
                    or not isinstance(test.left, ast.Call)
                    or not isinstance(test.left.func, ast.Name) or test.left.func.id != "len"
                    or test.left.keywords or len(test.left.args) != 1
                    or not isinstance(test.left.args[0], ast.Name)
                    or test.left.args[0].id != variable):
                continue
            limit = test.comparators[0]
            if isinstance(limit, ast.Constant) and type(limit.value) is int and limit.value >= 0:
                bounds.append((statement.lineno, limit.value))
        if len(bounds) != 1:
            return None
        bound_line, maximum = bounds[0]
        result = prove_slice_property(
            AsciiRepeatDomain(intervals, 0 if allows_empty else 1, optional_final_lf, maximum),
            PythonEdgeSlice(start, stop), forbidden,
        )
    except (SyntaxError, RecursionError, ValueError):
        return None
    return {
        "mechanism": "smt-bounded-ascii-edge-slice",
        "scope": "conditional-untyped-string-model",
        "source_bound": False,
        "status": result.status,
        "reason": result.reason,
        "assumptions": list(result.assumptions),
        "unverified_source_premises": [
            "canonical regex and length callable identities and runtime origin",
            "exact builtin str rather than an overloaded subclass",
            "one value epoch satisfying the observed regex and length bound",
            "complete sink argument and vulnerability-property contract",
        ],
        "source_digest": sha256(source_text.encode("utf-8", errors="surrogatepass")).hexdigest(),
        "validator_line": validator_line,
        "bound_line": bound_line,
        "source_max_length": maximum,
        "model_domain": {
            "intervals": [list(interval) for interval in intervals],
            "minimum_repetitions": 0 if allows_empty else 1,
            "optional_final_lf": optional_final_lf,
            "source_max_length": maximum,
        },
        "model_operation": {"start": start, "stop": stop},
        "model_property": {"forbidden_codepoints": list(forbidden)},
        "slice_span": [transfer.lineno, transfer.col_offset,
                       transfer.end_lineno, transfer.end_col_offset],
        "sink_line": sink_line,
        "input_value": result.input_value,
        "output_value": result.output_value,
    }
