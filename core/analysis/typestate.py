"""Type-state analysis for audit review.

Models object lifecycle states and finds violations: use-after-free,
use-before-init, double-free, missing-cleanup-on-error-path, lock-held-
across-blocking-call. These bugs are path-dependent — they depend on
which code paths execute in which order, not on patterns (Cap 5).

All analysis is mechanical (no LLM calls). Models are inferred from
naming conventions and a set of built-in models for common C/Python types.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class TypeStateModel:
    """Lifecycle state machine for a resource type.

    The checker (`check_typestate_violations`) drives its transitions
    from `alloc_methods`/`free_methods` lookups; the forbidden
    transitions are encoded in its control flow per violation kind.
    """

    type_name: str
    states: list[str] = field(default_factory=list)
    alloc_methods: list[str] = field(default_factory=list)
    free_methods: list[str] = field(default_factory=list)


@dataclass
class TypeStateViolation:
    """A detected lifecycle violation."""

    type_name: str
    operation: str
    current_state: str
    required_states: set[str]
    location: str
    path_description: str
    violation_kind: str


_LIFECYCLE_PAIRS = [
    ("malloc", "free"),
    ("calloc", "free"),
    ("realloc", "free"),
    ("strdup", "free"),
    ("strndup", "free"),
    ("xmalloc", "xfree"),
    ("kmalloc", "kfree"),
    ("kzalloc", "kfree"),
    ("vmalloc", "vfree"),
    ("fopen", "fclose"),
    ("fdopen", "fclose"),
    ("open", "close"),
    ("socket", "close"),
    ("accept", "close"),
    ("opendir", "closedir"),
    ("pthread_mutex_lock", "pthread_mutex_unlock"),
    ("pthread_spin_lock", "pthread_spin_unlock"),
    ("pthread_rwlock_rdlock", "pthread_rwlock_unlock"),
    ("pthread_rwlock_wrlock", "pthread_rwlock_unlock"),
    ("sem_wait", "sem_post"),
    # OpenSSL *_new/*_free pairs (SSL_new/SSL_free, BIO_new/BIO_free,
    # EVP_*_CTX_new/free, ...) are deliberately NOT listed: they follow
    # the `_new`/`_free` naming convention exactly, so mechanical pair
    # discovery (_INIT_DESTROY_PATTERNS over checklist names, Joern
    # callees, and the analyzed source's own call names) synthesizes
    # their models wherever both ends of the pair appear.
    ("CreateFile", "CloseHandle"),
    ("CreateMutex", "CloseHandle"),
    ("CreateEvent", "CloseHandle"),
    ("mmap", "munmap"),
    ("dlopen", "dlclose"),
]

_INIT_DESTROY_PATTERNS = [
    (re.compile(r"^(\w+?)_init$"), re.compile(r"^(\w+?)_(?:destroy|fini|cleanup|deinit)$")),
    (re.compile(r"^(\w+?)_create$"), re.compile(r"^(\w+?)_(?:delete|destroy|free)$")),
    (re.compile(r"^(\w+?)_open$"), re.compile(r"^(\w+?)_close$")),
    (re.compile(r"^(\w+?)_alloc$"), re.compile(r"^(\w+?)_free$")),
    (re.compile(r"^(\w+?)_new$"), re.compile(r"^(\w+?)_(?:free|del|delete)$")),
    (re.compile(r"^(\w+?)_acquire$"), re.compile(r"^(\w+?)_release$")),
    (re.compile(r"^(\w+?)_lock$"), re.compile(r"^(\w+?)_unlock$")),
    (re.compile(r"^(\w+?)_start$"), re.compile(r"^(\w+?)_stop$")),
    (re.compile(r"^(\w+?)_connect$"), re.compile(r"^(\w+?)_disconnect$")),
    (re.compile(r"^(\w+?)_begin$"), re.compile(r"^(\w+?)_end$")),
    (re.compile(r"^(\w+?)_ref$"), re.compile(r"^(\w+?)_unref$")),
    (re.compile(r"^(\w+?)_get$"), re.compile(r"^(\w+?)_put$")),
]

# Only names a model-discovery source can actually produce belong
# here: the builtin _LIFECYCLE_PAIRS entries plus _lock/_unlock
# convention names. Kernel semaphore names (down/down_read/down_write)
# and spin_lock_irqsave don't match any pair or suffix pattern, so
# membership could never test true — they are omitted rather than
# carried as dead entries.
_LOCK_METHODS = frozenset({
    "pthread_mutex_lock", "pthread_spin_lock",
    "pthread_rwlock_rdlock", "pthread_rwlock_wrlock",
    "sem_wait", "spin_lock", "mutex_lock",
    "read_lock", "write_lock",
})

_BLOCKING_CALLS = frozenset({
    "sleep", "usleep", "nanosleep", "poll", "select", "epoll_wait",
    "read", "write", "recv", "send", "recvfrom", "sendto",
    "accept", "connect", "waitpid", "wait", "fgets", "scanf",
    "getline", "fread", "fwrite", "pread", "pwrite",
    "msgsnd", "msgrcv", "semop",
})


def _build_alloc_free_model(alloc: str, free: str) -> TypeStateModel:
    """Build a standard allocate/free lifecycle model."""
    is_lock = alloc in _LOCK_METHODS

    if is_lock:
        return TypeStateModel(
            type_name=f"{alloc}/{free}",
            states=["unlocked", "locked"],
            alloc_methods=[alloc],
            free_methods=[free],
        )

    return TypeStateModel(
        type_name=f"{alloc}/{free}",
        states=["unallocated", "allocated", "freed"],
        alloc_methods=[alloc],
        free_methods=[free],
    )


def build_builtin_models() -> dict[str, TypeStateModel]:
    """Build the set of built-in type-state models."""
    models: dict[str, TypeStateModel] = {}

    for alloc, free in _LIFECYCLE_PAIRS:
        key = f"{alloc}/{free}"
        models[key] = _build_alloc_free_model(alloc, free)

    return models


def extract_typestate_models(
    checklist: dict[str, Any] | None = None,
    *,
    joern_summaries: dict[str, Any] | None = None,
) -> dict[str, TypeStateModel]:
    """Extract type-state models from a codebase checklist.

    Combines built-in models with project-specific models inferred
    from naming conventions in the checklist. When Joern summaries
    are available, lifecycle pairs confirmed by CPG callee/caller
    relationships are promoted to higher confidence.
    """
    models = build_builtin_models()

    if not checklist:
        return models

    items = checklist.get("items", [])
    func_names = [item.get("name", "") for item in items]

    # Discovery input: project-defined names PLUS callee names from the
    # Joern summaries. Callees cover external-library lifecycle APIs
    # (SSL_new/SSL_free, X_CTX_new/X_CTX_free, ...) that a consumer
    # project calls but does not define — the checklist alone only
    # covers the library's own tree.
    callee_names: set = set()
    for summary in (joern_summaries or {}).values():
        if hasattr(summary, "callees"):
            callee_names.update(summary.callees)
        elif isinstance(summary, dict):
            callee_names.update(summary.get("callees", []))
    if callee_names:
        func_names = func_names + sorted(callee_names)

    discovered = _discover_lifecycle_pairs(func_names)
    for alloc, free, prefix in discovered:
        key = f"{alloc}/{free}"
        if key not in models:
            models[key] = _build_alloc_free_model(alloc, free)
            logger.debug(
                "typestate: discovered lifecycle pair %s/%s (prefix: %s)",
                alloc, free, prefix,
            )

    if discovered:
        logger.info(
            "typestate: %d built-in + %d discovered models",
            len(_LIFECYCLE_PAIRS), len(discovered),
        )

    if joern_summaries:
        joern_discovered = _extract_pairs_from_joern(joern_summaries, models)
        if joern_discovered:
            logger.info(
                "typestate: %d additional lifecycle pairs from Joern CPG",
                len(joern_discovered),
            )

    return models


_CALL_NAME_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")


def check_typestate_violations(
    source: str,
    models: dict[str, TypeStateModel],
) -> list[TypeStateViolation]:
    """Check source code for type-state violations.

    Walks the source line-by-line tracking object states. Reports when
    an operation occurs in a forbidden state.
    """
    if not source or not models:
        return []

    # Convention-based discovery over the source's OWN call names:
    # synthesize models for init/destroy pairs whose both ends appear
    # in this function (e.g. SSL_new + SSL_free in an OpenSSL client).
    # This is what lets the builtin table stay seed-sized — library
    # pairs that follow the naming conventions need no hardcoding.
    models = dict(models)
    call_names = sorted(set(_CALL_NAME_RE.findall(source)))
    for alloc, free, _prefix in _discover_lifecycle_pairs(call_names):
        key = f"{alloc}/{free}"
        if key not in models:
            models[key] = _build_alloc_free_model(alloc, free)

    violations: list[TypeStateViolation] = []
    lines = source.split("\n")

    alloc_lookup: dict[str, list[TypeStateModel]] = {}
    free_lookup: dict[str, list[TypeStateModel]] = {}

    for model in models.values():
        for m in model.alloc_methods:
            alloc_lookup.setdefault(m, []).append(model)
        for m in model.free_methods:
            free_lookup.setdefault(m, []).append(model)

    tracked: dict[str, _TrackedObject] = {}

    error_path = False
    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()

        if _is_error_path_start(stripped):
            error_path = True
        elif _is_block_end(stripped) and error_path:
            _check_error_path_cleanup(tracked, line_num, violations)
            error_path = False

        for alloc_name, alloc_models in alloc_lookup.items():
            if _call_present(stripped, alloc_name):
                var = _extract_assigned_var(stripped, alloc_name)
                if var:
                    for am in alloc_models:
                        obj_key = f"{var}:{am.type_name}"
                        if obj_key in tracked and tracked[obj_key].state == "allocated":
                            prev = tracked[obj_key]
                            violations.append(TypeStateViolation(
                                type_name=am.type_name,
                                operation=alloc_name,
                                current_state="allocated",
                                required_states={"unallocated"},
                                location=f"line {line_num}",
                                path_description=(
                                    f"`{var}` allocated at line "
                                    f"{prev.alloc_line}, "
                                    f"reallocated at line "
                                    f"{line_num} without freeing"
                                ),
                                violation_kind="resource_leak",
                            ))
                        tracked[obj_key] = _TrackedObject(
                            var=var, model=am,
                            state="allocated",
                            alloc_line=line_num,
                            on_error_path=error_path,
                        )

        for free_name, free_models in free_lookup.items():
            if _call_present(stripped, free_name):
                var = _extract_freed_var(stripped, free_name)
                if var:
                    for fm in free_models:
                        obj_key = f"{var}:{fm.type_name}"
                        obj = tracked.get(obj_key)

                        if obj and obj.state == "freed":
                            violations.append(TypeStateViolation(
                                type_name=fm.type_name,
                                operation=free_name,
                                current_state="freed",
                                required_states={"allocated"},
                                location=f"line {line_num}",
                                path_description=(
                                    f"`{var}` freed at line {obj.freed_line}, "
                                    f"freed again at line {line_num}"
                                ),
                                violation_kind="double_free",
                            ))
                        elif obj and obj.state == "allocated":
                            obj.state = "freed"
                            obj.freed_line = line_num
                        elif not obj:
                            tracked[obj_key] = _TrackedObject(
                                var=var, model=fm,
                                state="freed",
                                alloc_line=0,
                                freed_line=line_num,
                                on_error_path=error_path,
                            )

        for obj in tracked.values():
            if (obj.state == "freed" and obj.var
                    and _var_used_after_free(stripped, obj.var, free_lookup)):
                    violations.append(TypeStateViolation(
                        type_name=obj.model.type_name,
                        operation="use",
                        current_state="freed",
                        required_states={"allocated"},
                        location=f"line {line_num}",
                        path_description=(
                            f"`{obj.var}` freed at line {obj.freed_line}, "
                            f"used at line {line_num}"
                        ),
                        violation_kind="use_after_free",
                    ))

    _check_resource_leaks(tracked, len(lines), violations)

    return violations


def format_typestate_for_context(
    violations: list[TypeStateViolation],
) -> str:
    """Render type-state violations for LLM context injection."""
    if not violations:
        return ""

    lines = ["### Type-state violations"]
    for v in violations[:8]:
        required = "/".join(sorted(v.required_states)) or "none"
        lines.append(
            f"- **{v.violation_kind}**: `{v.operation}` on `{v.type_name}` "
            f"at {v.location} (state: {v.current_state}, requires: "
            f"{required}) — {v.path_description}"
        )

    return "\n".join(lines)


@dataclass
class _TrackedObject:
    """Internal tracking state for one object instance."""

    var: str
    model: TypeStateModel
    state: str
    alloc_line: int = 0
    freed_line: int = 0
    on_error_path: bool = False


def _discover_lifecycle_pairs(
    func_names: list[str],
) -> list[tuple]:
    """Discover project-specific lifecycle pairs from function names."""
    discovered = []

    for init_pat, destroy_pat in _INIT_DESTROY_PATTERNS:
        init_matches: dict[str, str] = {}
        for name in func_names:
            m = init_pat.match(name)
            if m:
                init_matches[m.group(1)] = name

        for name in func_names:
            m = destroy_pat.match(name)
            if m:
                prefix = m.group(1)
                if prefix in init_matches:
                    discovered.append((init_matches[prefix], name, prefix))

    return discovered


def _extract_pairs_from_joern(
    joern_summaries: dict[str, Any],
    existing_models: dict[str, TypeStateModel],
) -> list[tuple]:
    """Extract lifecycle pairs from Joern CPG summaries.

    When Joern provides callee/caller relationships, we can confirm
    alloc/free pairings that naming conventions alone might miss (e.g.
    project-specific wrappers that don't follow standard naming).
    """
    discovered = []
    alloc_fns: set[str] = set()
    free_fns: set[str] = set()
    for model in existing_models.values():
        alloc_fns.update(model.alloc_methods)
        free_fns.update(model.free_methods)

    callee_map: dict[str, set[str]] = {}
    for key, summary in joern_summaries.items():
        callees = set()
        if hasattr(summary, "callees"):
            callees = set(summary.callees)
        elif isinstance(summary, dict):
            callees = set(summary.get("callees", []))
        if callees:
            func_name = key.rsplit(":", 1)[-1] if ":" in key else key
            callee_map[func_name] = callees

    for func_name, callees in callee_map.items():
        calls_alloc = callees & alloc_fns
        calls_free = callees & free_fns
        if not calls_alloc or not calls_free:
            continue
        for alloc in calls_alloc:
            for free in calls_free:
                pair_key = f"{func_name}_wrap:{alloc}/{free}"
                if pair_key not in existing_models:
                    existing_models[pair_key] = _build_alloc_free_model(alloc, free)
                    discovered.append((alloc, free, func_name))
                    logger.debug(
                        "typestate: Joern confirmed %s wraps %s/%s",
                        func_name, alloc, free,
                    )

    return discovered


def _call_present(line: str, func_name: str) -> bool:
    """Check if a function call is present on a line."""
    pattern = rf"\b{re.escape(func_name)}\s*\("
    return bool(re.search(pattern, line))


def _extract_assigned_var(line: str, func_name: str) -> str:
    """Extract the variable assigned from an alloc call.

    For assignment-style calls (p = malloc(...)), returns the lvalue.
    For parameter-style calls (pthread_mutex_lock(&mtx)), returns the
    first parameter (stripped of &).
    """
    m = re.match(
        rf"\s*(?:[\w*]+\s+)*(\w+)\s*=\s*{re.escape(func_name)}\s*\(",
        line,
    )
    if m:
        return m.group(1)

    m = re.match(
        rf"\s*(\w+)\s*=\s*(?:\([^)]+\)\s*)?{re.escape(func_name)}\s*\(",
        line,
    )
    if m:
        return m.group(1)

    m = re.search(
        rf"{re.escape(func_name)}\s*\(\s*&?(\w+)",
        line,
    )
    if m:
        return m.group(1)

    return ""


def _extract_freed_var(line: str, func_name: str) -> str:
    """Extract the variable passed to a free/close call."""
    m = re.search(
        rf"{re.escape(func_name)}\s*\(\s*&?(\w+)",
        line,
    )
    return m.group(1) if m else ""


def _var_used_after_free(
    line: str,
    var: str,
    free_lookup: dict[str, list],
) -> bool:
    """Check if a variable is used (not in a free call) on a line."""
    if not re.search(rf"\b{re.escape(var)}\b", line):
        return False

    for free_name in free_lookup:
        if _call_present(line, free_name):
            m = re.search(rf"{re.escape(free_name)}\s*\(\s*{re.escape(var)}\b", line)
            if m:
                return False

    if re.search(rf"\b{re.escape(var)}\s*=\s*NULL\b", line):
        return False
    return not re.search(rf"\b{re.escape(var)}\s*=\s*0\s*;", line)


def _is_error_path_start(line: str) -> bool:
    """Detect the start of an error-handling path."""
    return bool(
        re.match(r"\s*(?:goto\s+\w*err|goto\s+\w*fail|goto\s+\w*out|goto\s+\w*cleanup)", line)
        or re.match(r"\s*(?:if\s*\(\s*(?:ret|rc|err|status)\s*[<!=])", line)
        or re.match(r"\s*(?:except|catch)\b", line)
    )


def _is_block_end(line: str) -> bool:
    """Detect end of a code block."""
    return line.strip() in ("}", "};", "end", "fi")


def _check_error_path_cleanup(
    tracked: dict[str, _TrackedObject],
    line_num: int,
    violations: list[TypeStateViolation],
) -> None:
    """Check that all allocated resources are freed on error path exit."""
    for obj in tracked.values():
        if obj.state == "allocated" and not obj.on_error_path:
            is_lock = any(
                m in _LOCK_METHODS for m in obj.model.alloc_methods
            )
            kind = "lock_held_on_error" if is_lock else "missing_cleanup"
            violations.append(TypeStateViolation(
                type_name=obj.model.type_name,
                operation="error_path_exit",
                current_state="allocated",
                required_states={"freed"},
                location=f"line {line_num}",
                path_description=(
                    f"`{obj.var}` allocated at line {obj.alloc_line}, "
                    f"not released on error path ending at line {line_num}"
                ),
                violation_kind=kind,
            ))


def _check_resource_leaks(
    tracked: dict[str, _TrackedObject],
    total_lines: int,
    violations: list[TypeStateViolation],
) -> None:
    """Check for resources that were allocated but never freed."""
    for obj in tracked.values():
        if obj.state == "allocated" and obj.alloc_line > 0:
            is_lock = any(
                m in _LOCK_METHODS for m in obj.model.alloc_methods
            )
            if is_lock:
                violations.append(TypeStateViolation(
                    type_name=obj.model.type_name,
                    operation="function_exit",
                    current_state="locked",
                    required_states={"unlocked"},
                    location=f"line {total_lines}",
                    path_description=(
                        f"`{obj.var}` locked at line {obj.alloc_line}, "
                        f"never unlocked before function exit"
                    ),
                    violation_kind="lock_not_released",
                ))
