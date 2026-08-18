"""Mechanical (non-LLM) gates that eliminate FP categories A-E.

Each gate produces structured annotations injected into the per-function
context before the LLM review.  When a gate is definitive (all entry
points trusted, all callee args literal), the prefilter can skip LLM
entirely.

A — input provenance: which entry points reach this function, and their
    trust classification (trusted/untrusted from the threat model).
B — callee defense: when a callee validates/guards a parameter the
    reviewed function passes to it, surface that as a defense signal.
C — security-decision reachability: whether this function's output
    feeds a security-sensitive callee (auth, crypto, access control).
D — constant arguments: whether a dangerous API call uses only
    literal/constant arguments.
E — caller constraint sorting: reorder callers so the most
    constraining (those with preconditions/guards) appear first.
"""

from __future__ import annotations

import ast
import logging
import re
from collections import deque
from typing import Any

logger = logging.getLogger(__name__)


# ── A: Entry-point provenance ──────────────────────────────────────


def build_provenance_map(
    context_map: dict[str, Any],
    threat_model: dict[str, Any] | None = None,
) -> dict[str, list[dict[str, str]]]:
    """BFS from entry points through call edges.

    Returns ``{file:function: [{ep_id, ep_name, trust, ep_type}]}``
    showing which entry points can reach each function.
    """
    entries = context_map.get("entry_points") or []
    edges = context_map.get("call_edges") or []
    if not entries or not edges:
        return {}

    ep_trust = _classify_entry_points(entries, threat_model)

    adj: dict[str, list[str]] = {}
    for edge in edges:
        caller_key = f"{edge.get('caller_file', '')}:{edge.get('caller', '')}"
        callee_name = edge.get("callee", "")
        callee_file = edge.get("callee_file") or edge.get("caller_file", "")
        if callee_name:
            adj.setdefault(caller_key, []).append(f"{callee_file}:{callee_name}")

    result: dict[str, list[dict[str, str]]] = {}
    for ep in entries:
        if not isinstance(ep, dict):
            continue
        ep_id = str(ep.get("id") or "")
        ep_name = str(ep.get("name") or "")
        ep_file = str(ep.get("file") or "")
        ep_key = f"{ep_file}:{ep_name}"
        trust_info = ep_trust.get(ep_id, {"trust": "untrusted", "type": ""})
        tag = {
            "ep_id": ep_id,
            "ep_name": ep_name,
            "trust": trust_info["trust"],
            "ep_type": trust_info["type"],
        }

        visited: set[str] = set()
        queue = deque([ep_key])
        while queue:
            current = queue.popleft()
            if current in visited:
                continue
            visited.add(current)
            result.setdefault(current, []).append(tag)
            for neighbor in adj.get(current, []):
                if neighbor not in visited:
                    queue.append(neighbor)

    return result


def format_provenance_for_context(
    provenance: list[dict[str, str]],
) -> str:
    """Format provenance annotations for LLM context injection."""
    if not provenance:
        return ""
    trusted = [p for p in provenance if p["trust"] == "trusted"]
    untrusted = [p for p in provenance if p["trust"] != "trusted"]

    if not untrusted:
        ep_list = ", ".join(
            f"{p['ep_id']} {p['ep_name']} ({p['ep_type']})"
            for p in trusted[:5]
        )
        return (
            f"INPUT PROVENANCE: This function is reachable ONLY from "
            f"trusted (operator-controlled) entry points: {ep_list}. "
            f"Parameters originating from these paths are NOT "
            f"attacker-controlled. Do not flag operator-controlled inputs "
            f"reaching sinks."
        )

    lines = ["INPUT PROVENANCE (mechanical):"]
    if untrusted:
        for p in untrusted[:5]:
            lines.append(
                f"- UNTRUSTED: reachable from {p['ep_id']} "
                f"{p['ep_name']} ({p['ep_type']})"
            )
    if trusted:
        for p in trusted[:3]:
            lines.append(
                f"- trusted: also reachable from {p['ep_id']} "
                f"{p['ep_name']} ({p['ep_type']})"
            )
    return "\n".join(lines)


def _classify_entry_points(
    entries: list[Any],
    threat_model: dict[str, Any] | None,
) -> dict[str, dict[str, str]]:
    """Classify entry points as trusted/untrusted.

    Uses threat model trusted/untrusted lists when available,
    falls back to type-based heuristic.
    """
    trusted_names: set[str] = set()
    untrusted_names: set[str] = set()
    if threat_model:
        for item in threat_model.get("trusted_inputs") or []:
            for word in str(item).split():
                if "(" in word:
                    word = word.split("(")[0]
                if word and not word.startswith("—"):
                    trusted_names.add(word.lower())
        for item in threat_model.get("untrusted_inputs") or []:
            for word in str(item).split():
                if "(" in word:
                    word = word.split("(")[0]
                if word and not word.startswith("—"):
                    untrusted_names.add(word.lower())

    _UNTRUSTED_TYPES = {
        "socket", "http", "https", "rpc", "grpc", "graphql",
        "websocket", "message_queue", "file_parser", "upload",
        "webhook", "public_api",
    }
    _TRUSTED_TYPES = {
        "cli", "config", "cron", "migration", "internal_api",
        "admin", "management_command",
    }

    result: dict[str, dict[str, str]] = {}
    for ep in entries:
        if not isinstance(ep, dict):
            continue
        ep_id = str(ep.get("id") or "")
        ep_name = str(ep.get("name") or "").lower()
        ep_type = str(ep.get("type") or "").lower()
        trust_level = str(ep.get("trust_level") or "").lower()

        if trust_level in ("internal_value", "runtime_constant"):
            trust = "trusted"
        elif trust_level in ("attacker_controlled", "persistent_store"):
            trust = "untrusted"
        elif ep_name in trusted_names:
            trust = "trusted"
        elif ep_name in untrusted_names:
            trust = "untrusted"
        elif ep_type in _TRUSTED_TYPES:
            trust = "trusted"
        elif ep_type in _UNTRUSTED_TYPES:
            trust = "untrusted"
        else:
            trust = "untrusted"

        result[ep_id] = {"trust": trust, "type": ep_type}
    return result


# ── B: Callee defense annotation ──────────────────────────────────


def format_callee_defenses(
    callee_summaries: list[Any],
    callees: list[dict[str, Any]] | None = None,
) -> str:
    """Surface callee preconditions/guards as explicit defense signals.

    When a callee has preconditions on a parameter, that parameter is
    validated before reaching any dangerous sink inside the callee.
    """
    if not callee_summaries:
        return ""
    defenses: list[str] = []
    for summary in callee_summaries:
        preconditions = getattr(summary, "preconditions", None) or []
        func_name = getattr(summary, "function", "?")
        if not preconditions:
            continue
        for pre in preconditions:
            param = getattr(pre, "param", "?")
            conditions = getattr(pre, "conditions", [])
            if conditions:
                cond_str = ", ".join(str(c)[:80] for c in conditions[:3])
                defenses.append(
                    f"CALLEE DEFENSE: `{func_name}()` validates param "
                    f"`{param}` with: {cond_str} — flow through this "
                    f"callee is defended."
                )
    if not defenses:
        return ""
    return "\n".join(defenses[:10])


# ── C: Security-decision reachability ─────────────────────────────

_SECURITY_DECISION_PATTERNS = re.compile(
    r"(?:^|_)(?:auth|authn|authz|authenticate|authorize|check_perm|"
    r"is_allowed|has_permission|verify_token|validate_token|"
    r"check_access|access_control|rbac|acl|can_access|"
    r"encrypt|decrypt|sign|verify_signature|hmac|hash_password|"
    r"check_password|compare_digest|constant_time|"
    r"sanitize|escape|validate_input|is_safe|is_valid|"
    r"rate_limit|throttle|check_csrf|verify_csrf)(?:$|_)",
    re.IGNORECASE,
)


def build_security_decision_set(
    context_map: dict[str, Any],
) -> frozenset[str]:
    """Identify functions that are security-decision points.

    Returns ``frozenset`` of ``file:function`` keys for functions whose
    names match security-decision patterns.
    """
    edges = context_map.get("call_edges") or []

    sec_keys: set[str] = set()
    all_keys: set[str] = set()
    for edge in edges:
        for prefix in ("caller", "callee"):
            name = edge.get(prefix, "")
            file = edge.get(f"{prefix}_file") or edge.get("caller_file", "")
            key = f"{file}:{name}"
            all_keys.add(key)
            if name and _SECURITY_DECISION_PATTERNS.search(name):
                sec_keys.add(key)

    return frozenset(sec_keys)


def build_feeds_security_map(
    context_map: dict[str, Any],
    security_keys: frozenset[str] | None = None,
) -> frozenset[str]:
    """Find functions whose output feeds a security-decision function.

    Returns ``frozenset`` of ``file:function`` keys for functions that
    are direct callers of security-decision functions.
    """
    if security_keys is None:
        security_keys = build_security_decision_set(context_map)
    if not security_keys:
        return frozenset()

    edges = context_map.get("call_edges") or []
    feeds: set[str] = set()
    for edge in edges:
        callee_name = edge.get("callee", "")
        callee_file = edge.get("callee_file") or edge.get("caller_file", "")
        callee_key = f"{callee_file}:{callee_name}"
        if callee_key in security_keys:
            caller_key = f"{edge.get('caller_file', '')}:{edge.get('caller', '')}"
            feeds.add(caller_key)

    return frozenset(feeds)


def format_security_decision_for_context(
    feeds_security: bool,
    security_callees: list[str] | None = None,
) -> str:
    """Format security-decision annotation for LLM context."""
    if not feeds_security:
        return ""
    if security_callees:
        callee_list = ", ".join(f"`{c}`" for c in security_callees[:5])
        return (
            f"SECURITY CONSEQUENCE: This function's output feeds "
            f"security-decision functions: {callee_list}. A correctness "
            f"bug here has SECURITY impact — do not dismiss as "
            f"non-security."
        )
    return (
        "SECURITY CONSEQUENCE: This function's output feeds a "
        "security-decision function. A correctness bug here has "
        "SECURITY impact."
    )


# ── D: Constant argument detection ───────────────────────────────

_DANGEROUS_CALLS_PYTHON = frozenset({
    "eval", "exec", "compile",
    "subprocess.run", "subprocess.call", "subprocess.Popen",
    "subprocess.check_output", "subprocess.check_call",
    "os.system", "os.popen", "os.exec", "os.execvp",
    "importlib.import_module", "__import__",
    "pickle.loads", "pickle.load",
    "yaml.load", "yaml.unsafe_load",
    "marshal.loads",
    "shutil.rmtree",
    "open",
})


def detect_constant_dangerous_calls(
    source: str,
    file_path: str,
) -> list[dict[str, Any]]:
    """Detect dangerous API calls where ALL arguments are literals.

    Returns list of ``{call, line, args}`` for calls with only constant
    arguments.  These are definitively not attacker-controllable.
    """
    if not file_path.endswith(".py"):
        return []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    module_constants = _collect_module_constants(tree)
    results: list[dict[str, Any]] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        call_name = _call_name(node)
        if not call_name:
            continue
        if call_name not in _DANGEROUS_CALLS_PYTHON:
            short = call_name.rsplit(".", 1)[-1]
            if short not in _DANGEROUS_CALLS_PYTHON:
                continue
        if not node.args and not node.keywords:
            continue
        all_args = list(node.args) + [kw.value for kw in node.keywords]
        if all(_is_constant(arg, module_constants) for arg in all_args):
            arg_strs = []
            for arg in node.args:
                arg_strs.append(_const_repr(arg, module_constants))
            for kw in node.keywords:
                arg_strs.append(_const_repr(kw.value, module_constants))
            results.append({
                "call": call_name,
                "line": getattr(node, "lineno", 0),
                "args": arg_strs,
            })

    return results


def _collect_module_constants(tree: ast.Module) -> dict[str, Any]:
    """Collect module-level constant assignments (NAME = literal)."""
    constants: dict[str, Any] = {}
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name) and target.id.isupper():
                if isinstance(node.value, ast.Constant):
                    constants[target.id] = node.value.value
    return constants


def _is_constant(node: ast.AST, module_constants: dict[str, Any]) -> bool:
    """Check if an AST node is a constant (literal or module-level const)."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.Name) and node.id in module_constants:
        return True
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return all(_is_constant(elt, module_constants) for elt in node.elts)
    if isinstance(node, ast.Dict):
        return (
            all(_is_constant(k, module_constants) for k in node.keys if k)
            and all(_is_constant(v, module_constants) for v in node.values)
        )
    if isinstance(node, ast.UnaryOp) and isinstance(
        node.op, (ast.Not, ast.USub, ast.UAdd, ast.Invert),
    ):
        return _is_constant(node.operand, module_constants)
    return False


def _const_repr(node: ast.AST, module_constants: dict[str, Any]) -> str:
    if isinstance(node, ast.Constant):
        return repr(node.value)
    if isinstance(node, ast.Name) and node.id in module_constants:
        return f"{node.id}={module_constants[node.id]!r}"
    return "..."


def _call_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        parts = []
        obj = node.func
        while isinstance(obj, ast.Attribute):
            parts.append(obj.attr)
            obj = obj.value
        if isinstance(obj, ast.Name):
            parts.append(obj.id)
        return ".".join(reversed(parts))
    return ""


# ── E: Caller constraint sorting ─────────────────────────────────


def sort_callers_by_constraint(
    callers: list[dict[str, Any]],
    taint_summaries: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Sort callers so those with preconditions/guards appear first.

    Callers that validate inputs are more informative for the LLM —
    they show structural constraints that may make a hypothesis
    impossible.
    """
    if not callers or not taint_summaries:
        return callers

    def _constraint_score(caller: dict[str, Any]) -> tuple[int, str]:
        key = f"{caller.get('file', '')}:{caller.get('name', '')}"
        summary = taint_summaries.get(key)
        if summary is None:
            return (0, key)
        n_pre = len(getattr(summary, "preconditions", []) or [])
        n_guards = len(getattr(summary, "error_paths", []) or [])
        return (-(n_pre + n_guards), key)

    return sorted(callers, key=_constraint_score)


# ── E-2: Caller dedup by call-site pattern ──────────────────────────


def dedup_callers(
    callers: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Group callers by normalised call-site pattern, keep one representative.

    Callers with identical argument patterns (after stripping variable
    names to positional placeholders) are collapsed into one entry with
    a ``same_pattern_count`` field.  Callers without a ``call_site`` are
    each treated as unique.
    """
    if not callers:
        return callers

    groups: dict[str, list[dict[str, Any]]] = {}
    ungrouped: list[dict[str, Any]] = []

    for c in callers:
        site = c.get("call_site", "")
        if not site:
            ungrouped.append(c)
            continue
        key = _normalise_call_site(site)
        groups.setdefault(key, []).append(c)

    result: list[dict[str, Any]] = []
    for _key, group in groups.items():
        rep = dict(group[0])
        if len(group) > 1:
            rep["same_pattern_count"] = len(group)
            rep["same_pattern_callers"] = [
                f"{c.get('file', '')}:{c.get('name', '')}" for c in group[1:]
            ]
        result.append(rep)

    result.extend(ungrouped)
    return result


def _normalise_call_site(site: str) -> str:
    """Reduce a call-site snippet to its structural pattern.

    Strips line numbers, replaces variable names with ``_``, keeps
    literals and structure so that calls with identical argument
    shapes hash together.
    """
    text = re.sub(r"^\s*\d+\s+", "", site, flags=re.MULTILINE)
    text = re.sub(r"#.*$", "", text, flags=re.MULTILINE)
    text = re.sub(r'("(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\')', r"\1", text)
    text = re.sub(
        r'(?<!["\'])(?<!\w)([a-zA-Z_]\w*)(?=\s*[,\)\]\s])',
        "_",
        text,
    )
    return re.sub(r"\s+", " ", text).strip()


# ── E-3: Universal precondition detection ───────────────────────────


def detect_universal_preconditions(
    callers: list[dict[str, Any]],
    taint_summaries: dict[str, Any] | None = None,
) -> list[dict[str, str]]:
    """Detect when ALL callers guard the same parameter.

    Returns a list of ``{param, conditions, n_callers}`` for parameters
    where every caller with a taint summary enforces at least one
    precondition.  This is a definitive structural constraint — the LLM
    should not hypothesise unguarded input on these parameters.
    """
    if not callers or not taint_summaries:
        return []

    param_guards: dict[str, list[set[str]]] = {}
    n_with_summary = 0

    for c in callers:
        key = f"{c.get('file', '')}:{c.get('name', '')}"
        summary = taint_summaries.get(key)
        if summary is None:
            continue
        n_with_summary += 1
        caller_params: set[str] = set()
        for pre in getattr(summary, "preconditions", []) or []:
            param = getattr(pre, "param", "")
            if param and param not in caller_params:
                caller_params.add(param)
                conds = {str(c)[:80] for c in (getattr(pre, "conditions", []) or [])}
                param_guards.setdefault(param, []).append(conds)

    if n_with_summary < 2:
        return []

    results: list[dict[str, str]] = []
    for param, guard_sets in param_guards.items():
        if len(guard_sets) == n_with_summary:
            all_conds = set()
            for gs in guard_sets:
                all_conds.update(gs)
            results.append({
                "param": param,
                "conditions": ", ".join(sorted(all_conds)[:5]),
                "n_callers": str(n_with_summary),
            })

    return results


def format_universal_preconditions(
    preconditions: list[dict[str, str]],
) -> str:
    """Format universal precondition annotations for LLM context."""
    if not preconditions:
        return ""
    lines = ["UNIVERSAL CALLER CONSTRAINT (mechanical):"]
    for p in preconditions:
        lines.append(
            f"- ALL {p['n_callers']} callers validate param `{p['param']}` "
            f"with: {p['conditions']}. This parameter CANNOT reach this "
            f"function unvalidated."
        )
    return "\n".join(lines)


# ── E-4: Type constraint extraction ─────────────────────────────────

_PRIMITIVE_SAFE_TYPES = frozenset({
    "int", "float", "bool", "bytes", "complex",
    "i8", "i16", "i32", "i64", "i128", "isize",
    "u8", "u16", "u32", "u64", "u128", "usize",
    "f32", "f64",
    "byte", "short", "long", "char",
    "int8_t", "int16_t", "int32_t", "int64_t",
    "uint8_t", "uint16_t", "uint32_t", "uint64_t",
    "size_t", "ssize_t", "ptrdiff_t",
    "boolean", "Boolean",
})


def extract_type_constraints(
    source: str,
    file_path: str,
    function_name: str,
) -> list[dict[str, str]]:
    """Extract parameter type annotations that constrain input domain.

    For Python: reads type hints from function signatures.
    For C/Rust/Go/Java: extracts typed parameters from function declarations.
    Returns ``[{param, type, constraint_note}]`` for parameters whose
    types make certain attack vectors structurally impossible.
    """
    if file_path.endswith(".py"):
        return _extract_python_types(source, function_name)
    if file_path.endswith((".c", ".h", ".cpp", ".cc", ".cxx")):
        return _extract_c_types(source, function_name)
    if file_path.endswith(".rs"):
        return _extract_rust_types(source, function_name)
    if file_path.endswith(".go"):
        return _extract_go_types(source, function_name)
    if file_path.endswith(".java"):
        return _extract_java_types(source, function_name)
    return []


def format_type_constraints(constraints: list[dict[str, str]]) -> str:
    if not constraints:
        return ""
    lines = ["TYPE CONSTRAINTS (mechanical):"]
    for tc in constraints:
        lines.append(
            f"- param `{tc['param']}` is `{tc['type']}` — "
            f"{tc['constraint_note']}"
        )
    return "\n".join(lines)


def _extract_python_types(source: str, function_name: str) -> list[dict[str, str]]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name != function_name:
                continue
            results: list[dict[str, str]] = []
            for arg in node.args.args + node.args.posonlyargs + node.args.kwonlyargs:
                if arg.arg == "self" or arg.arg == "cls":
                    continue
                ann = arg.annotation
                if ann is None:
                    continue
                type_name = _ast_type_name(ann)
                if not type_name:
                    continue
                note = _constraint_note_for_type(type_name)
                if note:
                    results.append({
                        "param": arg.arg,
                        "type": type_name,
                        "constraint_note": note,
                    })
            return results
    return []


def _ast_type_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Attribute):
        parts = []
        obj = node
        while isinstance(obj, ast.Attribute):
            parts.append(obj.attr)
            obj = obj.value
        if isinstance(obj, ast.Name):
            parts.append(obj.id)
        return ".".join(reversed(parts))
    if isinstance(node, ast.Subscript):
        base = _ast_type_name(node.value)
        return base
    return ""


_C_FUNC_PAT = re.compile(
    r"(?:static\s+|inline\s+|extern\s+|const\s+)*"
    r"(\w[\w\s\*]*?)\s+"
    r"(\w+)\s*\(([^)]*)\)",
    re.MULTILINE,
)


def _extract_c_types(source: str, function_name: str) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    for m in _C_FUNC_PAT.finditer(source):
        if m.group(2) != function_name:
            continue
        params_str = m.group(3).strip()
        if not params_str or params_str == "void":
            break
        for param in params_str.split(","):
            param = param.strip()
            if not param:
                continue
            parts = param.rsplit(None, 1)
            if len(parts) < 2:
                continue
            ptype, pname = parts
            is_pointer = "*" in pname or "*" in ptype
            pname = pname.lstrip("*")
            ptype = ptype.strip()
            base = ptype.replace("const ", "").replace("unsigned ", "").replace("*", "").strip()
            note = _constraint_note_for_type(base)
            if note and not is_pointer:
                results.append({
                    "param": pname,
                    "type": ptype,
                    "constraint_note": note,
                })
        break
    return results


_RUST_FUNC_PAT = re.compile(
    r"fn\s+(\w+)\s*(?:<[^>]*>)?\s*\(([^)]*)\)",
    re.MULTILINE,
)


def _extract_rust_types(source: str, function_name: str) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    for m in _RUST_FUNC_PAT.finditer(source):
        if m.group(1) != function_name:
            continue
        params_str = m.group(2).strip()
        if not params_str:
            break
        for param in params_str.split(","):
            param = param.strip()
            if param in ("self", "&self", "&mut self"):
                continue
            if ":" not in param:
                continue
            pname, ptype = param.split(":", 1)
            pname = pname.strip()
            ptype = ptype.strip()
            is_ref = ptype.startswith("&")
            ptype = ptype.removeprefix("&").removeprefix("mut ").strip()
            if is_ref and ptype in ("str", "[u8]"):
                continue
            note = _constraint_note_for_type(ptype)
            if note:
                results.append({
                    "param": pname,
                    "type": ptype,
                    "constraint_note": note,
                })
        break
    return results


_GO_FUNC_PAT = re.compile(
    r"func\s+(?:\([^)]*\)\s+)?(\w+)\s*\(([^)]*)\)",
    re.MULTILINE,
)


def _extract_go_types(source: str, function_name: str) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    for m in _GO_FUNC_PAT.finditer(source):
        if m.group(1) != function_name:
            continue
        params_str = m.group(2).strip()
        if not params_str:
            break
        for param in params_str.split(","):
            param = param.strip()
            parts = param.split()
            if len(parts) < 2:
                continue
            pname = parts[0]
            ptype = " ".join(parts[1:])
            if ptype.startswith("*"):
                continue
            note = _constraint_note_for_type(ptype)
            if note:
                results.append({
                    "param": pname,
                    "type": ptype,
                    "constraint_note": note,
                })
        break
    return results


_JAVA_METHOD_PAT = re.compile(
    r"(?:public|private|protected|static|final|abstract|synchronized|\s)*"
    r"(\w[\w<>\[\],\s]*?)\s+"
    r"(\w+)\s*\(([^)]*)\)",
    re.MULTILINE,
)


def _extract_java_types(source: str, function_name: str) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    for m in _JAVA_METHOD_PAT.finditer(source):
        if m.group(2) != function_name:
            continue
        params_str = m.group(3).strip()
        if not params_str:
            break
        for param in params_str.split(","):
            param = param.strip()
            parts = param.rsplit(None, 1)
            if len(parts) < 2:
                continue
            ptype, pname = parts
            ptype = ptype.strip()
            note = _constraint_note_for_type(ptype)
            if note:
                results.append({
                    "param": pname,
                    "type": ptype,
                    "constraint_note": note,
                })
        break
    return results


def _constraint_note_for_type(type_name: str) -> str:
    base = type_name.rsplit(".", 1)[-1] if "." in type_name else type_name
    if base in _PRIMITIVE_SAFE_TYPES:
        return "numeric/boolean — cannot contain string injection payloads"
    if base.startswith(("Enum", "enum")) or base.endswith(("Enum", "Flag")):
        return "enum — value domain is fixed at compile time"
    if base in ("Path", "PurePath", "PosixPath", "WindowsPath", "PathBuf"):
        return "path type — structured, not raw string"
    if base in ("UUID", "Uuid", "uuid"):
        return "UUID — fixed format, no injection surface"
    if base in ("datetime", "date", "time", "Duration", "Instant", "NaiveDateTime"):
        return "temporal type — fixed format, no injection surface"
    if base in ("IpAddr", "Ipv4Addr", "Ipv6Addr", "IPAddress", "IPv4Address"):
        return "IP address type — validated format"
    return ""
