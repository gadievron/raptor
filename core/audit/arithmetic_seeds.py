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


def _range_constant(atoms, op, types, abi, frame, *, bounds=None):
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
    if bounds is not None:
        ranges = [bounds.get(atom, interval) for atom, interval in zip(atoms, ranges)]
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


def _guard_range_constant(target, data, atoms, op, types, abi, frame):
    """A syntactic candidate range, never a reaching-path or SSA proof.

    Consume only value-preserving parameter/literal comparisons controlling
    a branch, or a preceding direct early return. The native oracle must
    independently admit every prefix, input identity and reaching predicate.
    """
    declared = dict(types)
    bounds = {}
    for atom in atoms:
        kind = integer_type(declared.get(atom), abi)
        if kind is not None:
            bounds[atom] = (-(1 << (kind.width - 1)) if kind.signed else 0,
                            (1 << (kind.width - (1 if kind.signed else 0))) - 1)
    if not bounds:
        return None

    def contains(node):
        return node is not None and node.start_byte <= target.start_byte < node.end_byte

    def text(node):
        return data[node.start_byte:node.end_byte].decode() if node is not None else ''

    facts, current, work = [], target.parent, 0
    while current is not None and current.type != 'function_definition':
        work += 1
        if work > 64:
            return None
        if current.type == 'if_statement':
            yes, no = (current.child_by_field_name(field) for field in ('consequence', 'alternative'))
            if contains(yes) or contains(no):
                facts.append((current.child_by_field_name('condition'), contains(yes)))
        if current.type == 'compound_statement':
            for child in current.named_children:
                if child.end_byte > target.start_byte:
                    break
                if (child.type == 'if_statement' and child.child_by_field_name('alternative') is None
                        and child.child_by_field_name('consequence') is not None
                        and child.child_by_field_name('consequence').type == 'return_statement'):
                    facts.append((child.child_by_field_name('condition'), False))
        if len(facts) > 8:
            return None
        current = current.parent
    used = False
    inverse = {'<': '>=', '<=': '>', '>': '<=', '>=': '<', '==': '!=', '!=': '=='}
    reverse = {'<': '>', '<=': '>=', '>': '<', '>=': '<=', '==': '==', '!=': '!='}
    for node, truth in facts:
        node = _unwrap(node)
        if node is not None and node.type == 'condition_clause':
            node = _unwrap(node.child_by_field_name('value'))
        for _ in range(8):
            if node is None or node.type != 'unary_expression' or text(node.child_by_field_name('operator')) != '!':
                break
            truth, node = not truth, _unwrap(node.child_by_field_name('argument'))
        if node is None or node.type != 'binary_expression':
            continue
        guard_op = text(node.child_by_field_name('operator'))
        if guard_op not in inverse:
            continue
        left, right = (_unwrap(node.child_by_field_name(field)) for field in ('left', 'right'))
        if left is None or right is None:
            continue
        if left.type == 'identifier' and text(left) in bounds:
            variable, literal = text(left), source_integer_atom(right, data)
        elif right.type == 'identifier' and text(right) in bounds:
            variable, literal, guard_op = text(right), source_integer_atom(left, data), reverse[guard_op]
        else:
            continue
        value = integer_literal_value(literal)
        if value is None or common_integer_type([variable, literal], types, abi) is None:
            continue  # no guessed literal width or modular sign-change refinement
        guard_op = guard_op if truth else inverse[guard_op]
        low, high = bounds[variable]
        if guard_op == '<':
            high = min(high, value - 1)
        elif guard_op == '<=':
            high = min(high, value)
        elif guard_op == '>':
            low = max(low, value + 1)
        elif guard_op == '>=':
            low = max(low, value)
        elif guard_op == '==':
            low, high = max(low, value), min(high, value)
        else:
            continue
        if low > high:
            return None  # no vacuous constant lead from an empty candidate range
        bounds[variable], used = (low, high), True
    return _range_constant(atoms, op, types, abi, frame, bounds=bounds) if used else None


def _range_can_wrap(atoms, op, types, abi, frame):
    """A pure storage-range candidate filter for value-preserving frames."""
    if op == "-" and atoms[0] == atoms[1]:
        return False
    ranges = []
    declared = dict(types)
    for atom in atoms:
        value = integer_literal_value(atom)
        if value is not None:
            ranges.append((value, value))
            continue
        kind = integer_type(declared.get(atom), abi)
        if kind is None:
            return False
        ranges.append((-(1 << (kind.width - 1)) if kind.signed else 0,
                       (1 << (kind.width - (1 if kind.signed else 0))) - 1))
    (al, ah), (bl, bh) = ranges
    if op == "+":
        low, high = al + bl, ah + bh
    elif op == "-":
        low, high = al - bh, ah - bl
    else:
        corners = [a * b for a in (al, ah) for b in (bl, bh)]
        low, high = min(corners), max(corners)
    minimum = -(1 << (frame.width - 1)) if frame.signed else 0
    maximum = (1 << (frame.width - (1 if frame.signed else 0))) - 1
    return low < minimum or high > maximum


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

    pending, candidates, comparisons, accesses, wraps, visited = [root], [], [], [], [], 0
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
            if op in {"/", "%", "<<", ">>", "+", "-", "*"} or op in _COMPARISONS:
                atoms = tuple(atom(node.child_by_field_name(side))
                              for side in ("left", "right"))
                if None not in atoms:
                    if op in _COMPARISONS:
                        if len(comparisons) < _MAX_CANDIDATES:
                            comparisons.append((op, atoms))
                    elif op in {"+", "-", "*"}:
                        if len(wraps) < _MAX_CANDIDATES:
                            wraps.append((op, atoms))
                    else:
                        candidates.append((op, atoms))
                        if len(candidates) > _MAX_CANDIDATES:
                            return []
        pending.extend(reversed(node.named_children))
    result, deferred_wraps, deferred_guards = [], [], []
    # Preserve the arithmetic intake and prompt budget even when a function
    # has many ordinary comparisons. New hints cannot evict old candidates.
    for op, atoms in dict.fromkeys(candidates + comparisons + wraps):
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
        guard_implied = False
        kinds = [("invalid-shift-count", "Potential invalid shift count")]
        if op in _COMPARISONS:
            if not operand_types:
                continue  # retain the oracle's entry-parameter fragment
            frame = comparison_frame(*operand_kinds)
            truth = _range_constant(atoms, op, operand_types, abi, frame)
            if truth is None:
                truth = _guard_range_constant(target, selected_data, atoms, op, operand_types, abi, frame)
                if truth is None:
                    continue
                guard_implied = True
            truth_text = "true" if truth else "false"
            kinds = [(f"constant-comparison-{truth_text}", f"Comparison is always {truth_text}")]
        elif op in {"+", "-", "*"}:
            model = model_for_integer_terms(target, selected_data, atoms, (), abi, language=language)
            frame = common_integer_type(atoms, model.types, abi)
            if (model.status != "bound" or frame is None
                    or not _range_can_wrap(atoms, op, model.types, abi, frame)):
                continue
            kinds = [("integer-wrap", "Potential integer overflow")]
        elif op in {"/", "%"}:
            model = model_for_integer_terms(target, selected_data, atoms, (), abi, language=language)
            frame = common_integer_type(atoms, model.types, abi)
            if model.status != "bound" or frame is None:
                continue
            divisor = integer_literal_value(atoms[1])
            kinds = [("zero-divisor", "Potential zero divisor")] if divisor is None or divisor == 0 else []
            if frame.signed:
                minimum = -(1 << (frame.width - 1))
                numerator = integer_literal_value(atoms[0])
                if numerator is None:
                    kind = operand_kinds[0]
                    low = -(1 << (kind.width - 1)) if kind.signed else 0
                    high = (1 << (kind.width - (1 if kind.signed else 0))) - 1
                    can_reach_minimum = low <= minimum <= high
                else:
                    can_reach_minimum = numerator == minimum
                # Admitted promotions preserve values. Unsigned storage
                # cannot supply -1 even when promoted to a signed int.
                can_reach_minus_one = operand_kinds[1].signed if divisor is None else divisor == -1
                if can_reach_minimum and can_reach_minus_one:
                    kinds.append(("signed-division-overflow", "Potential division overflow"))
        for claim_kind, subject in kinds:
            mechanism = f"{subject} in `{atoms[0]} {op} {atoms[1]}`."
            if len(mechanism) <= 300:
                destination = deferred_guards if guard_implied else deferred_wraps if op in {"+", "-", "*"} else result
                extra = {"binding_status": "candidate", "candidate_basis": "controlling-comparison-range"} if guard_implied else {}
                destination.append((target, op, atoms, claim_kind, mechanism, extra))
    for target, array, index in accesses:
        from .array_bounds import array_access_candidate
        mechanism = f"Potential out-of-bounds read at `{array}[{index}]`."
        if len(mechanism) > 300:
            continue
        access = array_access_candidate(source, mechanism, language=language, integer_abi=abi)
        if access.status == "candidate":
            result.append((target, "[]", (array, index), "fixed-array-read", mechanism,
                           {"object_extent": access.extent, "access_kind": "read", "binding_status": "candidate"}))
    # Existing source leads retain their ordering and finite prompt budget.
    result.extend(deferred_wraps)
    from .integer_conversion import conversion_candidates
    for conversion in conversion_candidates(source, language=language, integer_abi=abi):
        incoming, destination = conversion["incoming"], conversion["destination"]
        mechanism = f"Potential non-representable unsigned conversion in `{destination} = {incoming}`."
        if len(mechanism) <= 300:
            result.append((conversion["target"], "=", (destination, incoming), "unsigned-conversion-loss", mechanism,
                           {"binding_status": "candidate", "source_type": conversion["source_type"],
                            "destination_type": conversion["destination_type"]}))
    return result + deferred_guards


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
