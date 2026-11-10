"""Bounded QUALITY integer and fixed-array source review obligations.

These are leads, never findings or proof receipts. The source-bound oracle
must still establish defined-prefix satisfiability and replay its witness.
Enumeration neither executes target code nor asks the solver/model provider.
"""

from hashlib import sha256
import operator
from pathlib import PurePosixPath

from .arithmetic_operation import _select_arithmetic_site, _select_comparison_site, _unwrap
from .arithmetic_types import common_integer_type, integer_type, model_for_integer_terms
from .condition_extraction import _get_parser
from .integer_abi import integer_abi_record
from .integer_comparison_types import comparison_frame, converted_interval
from .integer_literals import integer_literal_value, source_integer_atom

SEED_SOURCE = "source_arithmetic"
MAX_SEEDS_PER_GAP = 4
MAX_SEEDS_PER_RUN = 40
_MAX_NODES = 2048
_MAX_SOURCE_CHARS = 65536
_MAX_CANDIDATES = 16
_COMPARISONS = {"<": operator.lt, "<=": operator.le, ">": operator.gt, ">=": operator.ge,
                "==": operator.eq, "!=": operator.ne}


def _range_constant(atoms, op, types, abi, frame):
    """A cheap candidate filter, never an oracle receipt or intent claim."""
    if atoms[0] == atoms[1]:
        return _COMPARISONS[op](0, 0)
    ranges = []
    declared = dict(types)
    for atom in atoms:
        value = integer_literal_value(atom)
        if value is not None:
            ranges.append((value, value))
            continue
        kind = integer_type(declared.get(atom), abi)
        if kind is None:
            return None
        ranges.append((-(1 << (kind.width - 1)) if kind.signed else 0,
                       (1 << (kind.width - (1 if kind.signed else 0))) - 1))
    ranges = [converted_interval(low, high, frame) for low, high in ranges]
    if any(bounds is None for bounds in ranges):
        return None
    (al, ah), (bl, bh) = ranges
    if op in {">", ">="}:
        al, ah, bl, bh = bl, bh, al, ah
        op = "<" if op == ">" else "<="
    if op == "<":
        return True if ah < bl else False if al >= bh else None
    if op == "<=":
        return True if ah <= bl else False if al > bh else None
    if ah < bl or bh < al:
        return op == "!="
    if al == ah == bl == bh:
        return op == "=="
    return None


def _operations(source, language, abi):
    parser = _get_parser(language)
    if parser is None:
        return []
    data = source.encode("utf-8")
    root = parser.parse(data).root_node
    if root.has_error:
        return []

    def atom(node):
        node = _unwrap(node)
        if node is not None and node.type == "identifier":
            return data[node.start_byte:node.end_byte].decode("utf-8")
        return source_integer_atom(node, data)

    pending, candidates, comparisons, accesses, visited = [root], [], [], [], 0
    while pending:
        node = pending.pop()
        visited += 1
        if visited > _MAX_NODES:
            return []
        if node.type == "subscript_expression" and len(accesses) < _MAX_CANDIDATES:
            array = _unwrap(node.child_by_field_name("argument"))
            index = _unwrap(node.child_by_field_name("index"))
            if language == "cpp":
                indices = node.child_by_field_name("indices")
                index = _unwrap(indices.named_children[0]) if indices is not None and len(indices.named_children) == 1 else None
            if array is not None and index is not None and array.type == index.type == "identifier":
                accesses.append((node, data[array.start_byte:array.end_byte].decode(),
                                 data[index.start_byte:index.end_byte].decode()))
        if node.type == "binary_expression":
            op_node = node.child_by_field_name("operator")
            op = data[op_node.start_byte:op_node.end_byte].decode() if op_node else ""
            if op in {"/", "%", "<<", ">>"} or op in _COMPARISONS:
                atoms = tuple(atom(node.child_by_field_name(side))
                              for side in ("left", "right"))
                if None not in atoms:
                    if op in _COMPARISONS:
                        if len(comparisons) < _MAX_CANDIDATES:
                            comparisons.append((op, atoms))
                    else:
                        candidates.append((op, atoms))
                        if len(candidates) > _MAX_CANDIDATES:
                            return []
        pending.extend(reversed(node.named_children))
    result = []
    # Preserve the arithmetic intake and prompt budget even when a function
    # has many ordinary comparisons. New hints cannot evict old candidates.
    for op, atoms in dict.fromkeys(candidates + comparisons):
        select = _select_comparison_site if op in _COMPARISONS else _select_arithmetic_site
        status, selected_data, _, target = select(source, atoms, op, language=language)
        if status != "bound":
            continue
        # Per-operand typing preserves shifts' independent promotions and
        # excludes C++ overloaded operators. This is not a reaching proof.
        operand_types, operand_kinds = {}, []
        for atom in atoms:
            if integer_literal_value(atom) is not None:
                kind = common_integer_type([atom], (), abi)
            else:
                model = model_for_integer_terms(target, selected_data, [atom], (), abi, language=language)
                operand_types.update(model.types)
                kind = integer_type(operand_types.get(atom), abi) if model.status == "bound" else None
            if kind is None:
                break
            operand_kinds.append(kind)
        if len(operand_kinds) != 2:
            continue
        kinds = [("invalid-shift-count", "Potential invalid shift count")]
        if op in _COMPARISONS:
            if not operand_types:
                continue  # retain the oracle's entry-parameter fragment
            frame = comparison_frame(*operand_kinds)
            truth = _range_constant(atoms, op, operand_types, abi, frame)
            if truth is None:
                continue
            truth_text = "true" if truth else "false"
            kinds = [(f"constant-comparison-{truth_text}", f"Comparison is always {truth_text}")]
        elif op in {"/", "%"}:
            model = model_for_integer_terms(target, selected_data, atoms, (), abi, language=language)
            frame = common_integer_type(atoms, model.types, abi)
            if model.status != "bound" or frame is None:
                continue
            kinds = [("zero-divisor", "Potential zero divisor")]
            if frame.signed:
                kinds.append(("signed-division-overflow", "Potential division overflow"))
        for claim_kind, subject in kinds:
            mechanism = f"{subject} in `{atoms[0]} {op} {atoms[1]}`."
            if len(mechanism) <= 300:
                result.append((target, op, atoms, claim_kind, mechanism, {}))
    for target, array, index in accesses:
        from .array_bounds import array_access_candidate
        mechanism = f"Potential out-of-bounds read at `{array}[{index}]`."
        if len(mechanism) > 300:
            continue
        access = array_access_candidate(source, mechanism, language=language, integer_abi=abi)
        if access.status == "candidate":
            result.append((target, "[]", (array, index), "fixed-array-read", mechanism,
                           {"object_extent": access.extent, "access_kind": "read", "binding_status": "candidate"}))
    return result


def seed_arithmetic_hypotheses(gaps, source_texts, *, mode, integer_abi=None):
    """Attach bounded source-identity-bearing leads to live QUALITY gaps."""
    abi = integer_abi_record(integer_abi)
    if mode != "quality" or abi is None:
        return 0
    seeded = 0
    # Reserve all existing rows before discovery, including later gaps.
    # Re-entry may prepend newly inventoried gaps ahead of populated ones.
    total = sum(1 for gap in gaps
                for h in (gap.get("injected_hypotheses") or [])
                if isinstance(h, dict) and h.get("source") == SEED_SOURCE)
    file_lines = {}
    for gap in gaps:
        if gap.get("dead"):
            continue
        file = gap.get("file")
        if not isinstance(file, str):
            continue
        language = {".c": "c", ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp"}.get(PurePosixPath(file).suffix.lower())
        text = source_texts.get(file)
        lo, hi = gap.get("line_start"), gap.get("line_end")
        if (language is None or not isinstance(text, str)
                or type(lo) is not int or type(hi) is not int or lo < 1 or hi < lo):
            continue
        # Check bounds before materialising a possibly huge slice.
        if hi - lo > _MAX_SOURCE_CHARS:
            continue
        if file not in file_lines:
            file_lines[file] = text.splitlines()
        lines = file_lines[file]
        if hi > len(lines):
            continue
        source = "\n".join(lines[lo - 1:hi])
        if len(source) > _MAX_SOURCE_CHARS:
            continue
        digest = sha256(source.encode()).hexdigest()
        existing = gap.get("injected_hypotheses", [])
        if not isinstance(existing, list):
            continue
        # Re-entrant prep must not retain a lead from a different slice or
        # target layout. Other seed producers keep ownership of their rows.
        stale = [h for h in existing if isinstance(h, dict) and h.get("source") == SEED_SOURCE
                 and (not isinstance(h.get("arithmetic_site"), dict)
                      or h["arithmetic_site"].get("source_sha256") != digest
                      or h["arithmetic_site"].get("integer_abi") != abi
                      or h["arithmetic_site"].get("file") != file
                      or h["arithmetic_site"].get("function") != gap.get("name", "")
                      or h["arithmetic_site"].get("function_line_start") != lo
                      or h["arithmetic_site"].get("function_line_end") != hi)]
        if stale:
            existing[:] = [h for h in existing if not any(h is old for old in stale)]
            total -= len(stale)
        own = [h for h in existing if isinstance(h, dict) and h.get("source") == SEED_SOURCE]
        if total >= MAX_SEEDS_PER_RUN or len(own) >= MAX_SEEDS_PER_GAP:
            continue
        for target, op, atoms, claim_kind, mechanism, extra in _operations(source, language, integer_abi):
            site = {
                "file": file, "function": gap.get("name", ""),
                "function_line_start": lo, "function_line_end": hi,
                "source_sha256": digest, "line": lo + target.start_point[0],
                "column": target.start_point[1] + 1,
                "byte_start": target.start_byte, "byte_end": target.end_byte,
                "operator": op, "operands": list(atoms), "claim_kind": claim_kind,
                "integer_abi": abi,
                **extra,
            }
            if any(h.get("arithmetic_site") == site for h in own):
                continue
            if len(own) >= MAX_SEEDS_PER_GAP or total >= MAX_SEEDS_PER_RUN:
                break
            seed = {"mechanism": mechanism, "confidence": "low", "source": SEED_SOURCE,
                    "arithmetic_site": site}
            gap.setdefault("injected_hypotheses", []).append(seed)
            own.append(seed)
            seeded += 1
            total += 1
    return seeded
