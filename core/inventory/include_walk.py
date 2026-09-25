"""Per-entry constant-environment walk — phase 1b of the PHP
include model.

For each entry candidate, walks file-scope include edges in
statement order carrying a CONSTANT ENVIRONMENT: seeded by the
entry's own unconditional literal ``define()`` statements, extended
in execution order by the files it includes, and consulted to
resolve ``const_prefix`` edges exactly — the semantics PHP gives
constants (global once defined, first definition wins, redefinition
fails). Rules, all refuse-over-guess:

* ``if (!defined('C')) define('C', …)`` (the fallback shape) is a
  NO-OP under a carried binding and the binding supplier when the
  walked root is the file itself — library files stay walkable
  standalone.
* an unconditional re-define of a carried constant with a different
  value POISONS the constant (the doc's refusal: hostile or
  ambiguous definition order must never steer resolution); same
  value/anchor is a no-op.
* non-literal values poison when they would bind (the walk does no
  constant propagation beyond literal ``define()``);
  conditional non-fallback defines poison an unbound constant
  (runtime MIGHT have bound it first — unknowable) and no-op a
  bound one (runtime ``define`` on a defined name keeps the
  original).
* defines below the file's effective straight-line boundary might
  never have executed — they poison when unbound (adjudication of
  the mid-walk-defines ambiguity: included files DO extend the
  environment, in execution order, because bootstrap files defining
  constants for later includes is the dominant honest idiom — but
  only from straight-line, unconditional, literal positions).

**Path anchoring follows the environment, not the includer**: a
binding's value is resolved relative to the DEFINING file's
directory, so ``'../'`` defined in ``src/entry.php`` and ``'../../'``
defined in a two-level plugin entry both denote the tree root. The
candidate must exist in the tree listing and stay inside the tree —
full-path resolution, no suffix matching, which is also what closes
the 1a dotfile-tail census residue exactly.

**Guarantee direction** (the doc's invariant): a prefix member is
``guaranteed`` only when every edge on its chain is unconditional,
resolution-grounded (literal target or environment-resolved), sits
ABOVE the includer's effective straight-line boundary, below no
``__halt_compiler`` (post-halt bytes are data), and no includer on
the chain has an ERROR-bearing parse tree (recovery can fabricate
``conditional: false``). Conditional edges still contribute
reachability members (``guaranteed: false``); dynamic edges never
resolve. Effective boundaries are environment-aware: a
``!defined(C)`` conditional abort is a no-op under a bound C, a
``defined(C)`` one fires; ``goto``, terminators, and the boundary
overflow sentinel always apply.

**The environment carries a trust dimension aligned with the
guarantee chain**: bindings acquired in files reached over
conditional/unresolved edges, or in parse-errored files, are
poison-grade — they never skip a ``!defined()`` boundary and never
ground a const-prefix resolution (a direct request may never
execute the define that produced them).

Known attribution choice: ``*_once`` first-occurrence semantics
attribute a shared file's subtree to whichever include reached it
first; two entries whose includes ORDER differently can therefore
land in one class when their guaranteed closures coincide as sets.
Safe direction (classes partition by the guaranteed SET, and
ordering facts are carried per entry in the member lists), noted
for consumers of the class partition.

Everything here is mechanical; no LLM enumerates anything. The
output is hint-tier like the rest of the graph — nothing derived
here refutes, demotes, or suppresses.
"""

from __future__ import annotations

import hashlib
import posixpath
from dataclasses import dataclass, field
from typing import Any

# Bounds — walk inputs come from hostile content.
MAX_WALK_DEPTH = 64
MAX_WALK_MEMBERS = 512
MAX_ENTRIES_WALKED = 512
MAX_WALK_UNRESOLVED = 256
MAX_MEMO_ENTRIES = 4096
MAX_ENV_CONSTANTS = 256
# Global statement-visit budget across ALL entries of one
# derivation (the run-level probe-budget precedent): entries ×
# fan-out × defines is attacker-shaped, and per-entry caps alone
# left the product unbounded. Exhaustion truncates HONESTLY — the
# remaining entries are censused, never silently classless.
MAX_WALK_STMT_VISITS = 500_000


@dataclass(slots=True)
class Binding:
    value: str
    anchor_dir: str
    site: str
    poisoned: str | None = None  # None | conflict | unknown_value | …


@dataclass
class _EntryWalk:
    members: list[dict[str, Any]] = field(default_factory=list)
    unresolved: list[dict[str, Any]] = field(default_factory=list)
    resolutions: list[tuple[str, dict[str, Any], str]] = field(
        default_factory=list)
    visited: set[str] = field(default_factory=set)
    skipped: list[str] = field(default_factory=list)
    truncated: bool = False
    unresolved_overflow: bool = False


def _merge_binding(env: dict[str, Binding], name: str, b: Binding,
                   outcomes: dict[str, int]) -> None:
    """Adopt a memo-replayed binding under first-wins semantics:
    absent → adopt verbatim; identical → keep; different → poison
    (the same refuse-over-guess rule as a live re-define)."""
    existing = env.get(name)
    if existing is None:
        env[name] = Binding(b.value, b.anchor_dir, b.site, b.poisoned)
        return
    if (existing.value == b.value
            and existing.anchor_dir == b.anchor_dir
            and existing.poisoned == b.poisoned):
        return
    env[name] = Binding(existing.value, existing.anchor_dir,
                        existing.site, poisoned="conflict")
    outcomes["define_conflict_poisoned"] = outcomes.get(
        "define_conflict_poisoned", 0) + 1


def _env_signature(env: dict[str, Binding]) -> tuple:
    return tuple(sorted(
        (n, b.value, b.anchor_dir, b.poisoned or "")
        for n, b in env.items()
    ))


def _apply_define(
    env: dict[str, Binding],
    outcomes: dict[str, int],
    *,
    name: str,
    value: str | None,
    site: str,
    anchor_dir: str,
    fallback: bool,
    conditional: bool,
    below_boundary: bool,
    trusted: bool,
) -> None:
    """First-definition-wins with refuse-over-guess (see module
    docstring for each rule's rationale).

    ``trusted`` is the environment's TRUST DIMENSION, aligned with
    the guarantee chain: a define encountered in a file that was
    reached over a conditional/unresolved edge, or whose parse tree
    carries ERROR nodes, is a binding a direct request may never
    establish — using it to ground a const-prefix resolution or to
    no-op a ``!defined()`` boundary would fabricate "the gate ran
    first" from code that can be skipped. Untrusted defines apply
    with conditional semantics: no-op when bound, POISON when
    unbound (first-definition-wins means a later trusted define
    cannot claim the slot either — runtime order is unknowable)."""
    if len(env) >= MAX_ENV_CONSTANTS and name not in env:
        outcomes["env_constant_cap"] = outcomes.get(
            "env_constant_cap", 0) + 1
        return
    existing = env.get(name)

    def _bump(k: str) -> None:
        outcomes[k] = outcomes.get(k, 0) + 1

    if not trusted:
        if existing is not None:
            _bump("define_untrusted_noop")
            return
        env[name] = Binding("", anchor_dir, site,
                            poisoned="untrusted_chain")
        _bump("define_poisoned")
        return

    if fallback:
        if existing is not None:
            _bump("define_fallback_noop")
            return
        if below_boundary or value is None:
            env[name] = Binding("", anchor_dir, site,
                                poisoned="unknown_value"
                                if value is None else "below_boundary")
            _bump("define_poisoned")
            return
        env[name] = Binding(value, anchor_dir, site)
        _bump("define_bound")
        return

    if conditional or below_boundary:
        if existing is not None:
            _bump("define_conditional_noop")
            return
        env[name] = Binding("", anchor_dir, site,
                            poisoned="conditional_define"
                            if conditional else "below_boundary")
        _bump("define_poisoned")
        return

    # unconditional, straight-line
    if existing is None:
        if value is None:
            env[name] = Binding("", anchor_dir, site,
                                poisoned="unknown_value")
            _bump("define_poisoned")
        else:
            env[name] = Binding(value, anchor_dir, site)
            _bump("define_bound")
        return
    if (not existing.poisoned and value is not None
            and existing.value == value
            and existing.anchor_dir == anchor_dir):
        _bump("define_redefine_noop")
        return
    env[name] = Binding(existing.value, existing.anchor_dir,
                        existing.site, poisoned="conflict")
    _bump("define_conflict_poisoned")


def _effective_boundary(
    boundaries: list[dict[str, Any]],
    env: dict[str, Binding],
    *,
    parse_errors: bool = False,
) -> int | None:
    """MINIMUM applicable boundary line under this environment.

    A ``!defined(C)`` conditional abort with C bound (unpoisoned —
    the trust dimension folds in here: untrusted-chain bindings are
    poison-grade and never skip) is a no-op — the guard the
    environment satisfies. Everything else (terminators, goto, halt,
    overflow, guardless conditionals, ``defined(C)`` conditionals in
    every binding state) applies. In a parse-errored file NOTHING is
    skippable — recovery can launder the guard shape itself. The
    minimum over applicable lines (not the first list element) keeps
    a hostile out-of-order boundary list from hiding an earlier
    boundary behind a skippable first entry."""
    lines: list[int] = []
    for b in boundaries:
        line = b.get("line")
        if not isinstance(line, int) or isinstance(line, bool):
            continue
        kind = b.get("kind")
        if (not parse_errors
                and kind in ("conditional_return", "conditional_abort")):
            gc = b.get("guard_constant")
            if (isinstance(gc, str) and b.get("guard_negated")
                    and gc in env and not env[gc].poisoned):
                continue
        lines.append(line)
    return min(lines) if lines else None


def _halt_line(boundaries: list[dict[str, Any]]) -> int | None:
    for b in boundaries:
        if b.get("kind") == "halt" and isinstance(b.get("line"), int):
            return b["line"]
    return None


def _resolve_edge(
    edge: dict[str, Any],
    env: dict[str, Binding],
    tree_set: set[str],
) -> tuple[str | None, str]:
    """(target, reason). ``target`` is None with a reason when the
    walk cannot ground the edge; full-path resolution only."""
    shape = edge.get("shape")
    if shape == "literal":
        target = edge.get("target")
        if isinstance(target, str) and target in tree_set:
            return target, "literal"
        return None, "walk_target_missing"
    if shape != "const_prefix":
        return None, "dynamic"
    const = edge.get("const_name")
    tail = edge.get("literal_tail")
    if not isinstance(const, str) or not isinstance(tail, str) or not tail:
        return None, "env_unbound"
    binding = env.get(const)
    if binding is None:
        return None, "env_unbound"
    if binding.poisoned:
        return None, "env_conflict"
    # NO backslash normalisation: on POSIX runtimes a backslash is an
    # ordinary filename character — PHP includes the literally-named
    # file, and "helpfully" rewriting the separator resolved a decoy
    # sibling instead of the file that actually runs. Windows-style
    # source spellings simply refuse (target missing) — refuse over
    # guess.
    joined = binding.value + tail
    first_seg = joined.replace("\\", "/").split("/", 1)[0]
    if joined.startswith("/") or ":" in first_seg:
        return None, "env_escapes_tree"
    candidate = posixpath.normpath(
        posixpath.join(binding.anchor_dir, joined))
    if candidate == ".." or candidate.startswith("../"):
        return None, "env_escapes_tree"
    if candidate.startswith("./"):
        candidate = candidate[2:]
    if candidate in tree_set:
        return candidate, "env_resolved"
    return None, "env_target_missing"


def walk_entries(
    entries: list[str],
    *,
    edges_by_file: dict[str, list[dict[str, Any]]],
    defines_by_file: dict[str, list[dict[str, Any]]],
    meta_by_file: dict[str, dict[str, Any]],
    tree_set: set[str],
) -> dict[str, Any]:
    """Walk each entry; return prefixes, entry classes, env
    resolutions (for the 1a basis supersede), and outcome counters.

    Deterministic and memoised on (file, environment-signature):
    entries sharing a bootstrap closure under the same bindings pay
    for it once. Memoised subtree results are re-filtered through
    the reusing entry's visited set (first-include-wins semantics)
    and their guarantees AND-folded with the reusing chain's."""
    outcomes: dict[str, int] = {}
    env_resolutions: dict[tuple[str, int], dict[str, Any]] = {}
    prefixes: dict[str, dict[str, Any]] = {}
    memo: dict[tuple, dict[str, Any]] = {}
    stmt_budget = [MAX_WALK_STMT_VISITS]

    def _bump(k: str, n: int = 1) -> None:
        outcomes[k] = outcomes.get(k, 0) + n

    def _stmts(path: str) -> list[tuple[int, str, dict[str, Any]]]:
        out: list[tuple[int, str, dict[str, Any]]] = []
        for d in defines_by_file.get(path, ()):  # stable per kind
            if d.get("position") == "file_scope" and isinstance(
                    d.get("line"), int):
                out.append((d["line"], "define", d))
        for e in edges_by_file.get(path, ()):
            if isinstance(e.get("line"), int):
                out.append((e["line"], "edge", e))
        # Same-line polarity is refuse-over-guess: the EDGE sorts
        # before the define, so `include(C.'x'); define('C',…)` on
        # one line resolves against the pre-define environment
        # (unbound → refused) instead of guessing that the later
        # define ran first.
        out.sort(key=lambda t: (t[0], 0 if t[1] == "edge" else 1))
        return out

    def _note_env_resolution(path: str, edge: dict[str, Any],
                             target: str, entry: str) -> None:
        key = (path, edge.get("line") or 0)
        rec = env_resolutions.setdefault(key, {
            "includer": path,
            "line": edge.get("line") or 0,
            "keyword": str(edge.get("keyword") or "include"),
            "conditional": bool(edge.get("conditional", False)),
            "position": str(edge.get("position") or "file_scope"),
            "targets": {},
        })
        rec["targets"].setdefault(target, []).append(entry)

    def _walk_file(
        state: _EntryWalk,
        env: dict[str, Binding],
        path: str,
        chain: list[str],
        guaranteed: bool,
        depth: int,
        entry: str,
    ) -> None:
        if path in state.visited:
            _bump("walk_revisit_skipped")
            state.skipped.append(path)
            return
        if (len(state.members) >= MAX_WALK_MEMBERS
                or depth > MAX_WALK_DEPTH or stmt_budget[0] <= 0):
            state.truncated = True
            _bump("walk_closure_truncated"
                  if stmt_budget[0] > 0 else "walk_budget_exhausted")
            return
        state.visited.add(path)
        meta = meta_by_file.get(path)
        member: dict[str, Any] = {
            "file": path,
            "via": list(chain),
            "guaranteed": guaranteed,
        }
        if not chain:
            member["root"] = True
        if meta is None:
            member["unwalked"] = True
            state.members.append(member)
            _bump("walk_unwalked_member")
            return
        boundaries = meta.get("boundaries") or []
        parse_errors = bool(meta.get("parse_errors"))
        if parse_errors:
            member["parse_errors"] = True
            _bump("walk_parse_error_refusals")
        eff_boundary = _effective_boundary(
            boundaries, env, parse_errors=parse_errors)
        if eff_boundary is not None:
            member["boundary_line"] = eff_boundary
        state.members.append(member)

        # Memoised subtree walk. The signature captures everything
        # the subtree result depends on: the file, the incoming
        # environment, and the incoming guarantee state (the walk is
        # deterministic given all three). Replayed members are
        # filtered through the reusing entry's visited set
        # (first-include-wins) and their guarantees AND-folded.
        memo_key = (path, _env_signature(env), guaranteed)
        cached = memo.get(memo_key)
        if cached is not None:
            _bump("walk_memo_hits")
            for name, b in cached["env_after"].items():
                _merge_binding(env, name, b, outcomes)
            for sub in cached["members"]:
                sub_path = sub["file"]
                if sub_path in state.visited:
                    state.skipped.append(sub_path)
                    continue
                if len(state.members) >= MAX_WALK_MEMBERS:
                    state.truncated = True
                    _bump("walk_closure_truncated")
                    break
                state.visited.add(sub_path)
                m = dict(sub)
                m["via"] = chain + sub["via"]
                m["guaranteed"] = bool(sub["guaranteed"]) and guaranteed
                state.members.append(m)
            for u in cached["unresolved"]:
                if len(state.unresolved) < MAX_WALK_UNRESOLVED:
                    state.unresolved.append(dict(u))
            for pth, edge, target in cached["resolutions"]:
                _note_env_resolution(pth, edge, target, entry)
                state.resolutions.append((pth, edge, target))
            if cached["truncated"]:
                state.truncated = True
            return

        members_before = len(state.members)
        unresolved_before = len(state.unresolved)
        resolutions_before = len(state.resolutions)
        skipped_before = len(state.skipped)
        halt = _halt_line(boundaries)
        anchor_dir = posixpath.dirname(path)
        # The trust dimension, aligned with the guarantee chain: a
        # define is grounding-grade only when the file it sits in was
        # reached over a fully guaranteed chain AND its parse tree is
        # clean — otherwise a direct request may never execute it,
        # and its binding must not skip guards or ground resolutions.
        defines_trusted = guaranteed and not parse_errors

        for line, kind, item in _stmts(path):
            if stmt_budget[0] <= 0:
                state.truncated = True
                _bump("walk_budget_exhausted")
                break
            stmt_budget[0] -= 1
            if halt is not None and line > halt:
                _bump("stmts_after_halt_skipped")
                continue
            below = eff_boundary is not None and line >= eff_boundary
            if kind == "define":
                name = item.get("name")
                if not isinstance(name, str) or not name:
                    continue
                _apply_define(
                    env, outcomes,
                    name=name,
                    value=item.get("value")
                    if isinstance(item.get("value"), str) else None,
                    site=f"{path}:{line}",
                    anchor_dir=anchor_dir,
                    fallback=bool(item.get("fallback")),
                    conditional=bool(item.get("conditional")),
                    below_boundary=below,
                    trusted=defines_trusted,
                )
                continue
            # edge
            if item.get("position") == "function_body":
                _bump("function_body_edges_skipped")
                continue
            target, reason = _resolve_edge(item, env, tree_set)
            _bump("edge_" + reason)
            site = f"{path}:{line}"
            if target is None:
                if len(state.unresolved) < MAX_WALK_UNRESOLVED:
                    state.unresolved.append({
                        "site": site, "reason": reason,
                        "shape": str(item.get("shape") or "dynamic"),
                    })
                else:
                    state.unresolved_overflow = True
                    _bump("walk_unresolved_overflow")
                continue
            if reason == "env_resolved":
                _note_env_resolution(path, item, target, entry)
                state.resolutions.append((path, item, target))
            child_guaranteed = (
                guaranteed
                and not parse_errors
                and not bool(item.get("conditional", False))
                and not below
            )
            _walk_file(
                state, env, target, chain + [f"{site}->{target}"],
                child_guaranteed, depth + 1, entry,
            )

        # Never memoise a truncated subtree: replaying a partial
        # closure as complete for another entry would silently
        # under-report its prefix. Same for a subtree that SKIPPED
        # files the storing walk had already visited OUTSIDE this
        # subtree (the diamond shape: entry → a → c, then entry →
        # b → c skips c because a already brought it in) — the
        # stored member list omits them, and a replaying entry that
        # never visited them would lose real prefix members with no
        # census. The memo key (file, env-signature, guarantee)
        # cannot see this: signature equality proves identical
        # ENVIRONMENT decisions, but the member list also depends on
        # the storing walk's visited-set state, which the key does
        # not capture — replay-side filtering handles the reuse
        # direction, so the store side must refuse when its own list
        # is already a filtered one. Skips of files WITHIN the
        # subtree (a file included twice inside it) are fine: the
        # member is present from its first occurrence.
        subtree_files = {
            m["file"] for m in state.members[members_before:]}
        outer_skips = [
            p for p in state.skipped[skipped_before:]
            if p not in subtree_files
        ]
        if (not state.truncated and not outer_skips
                and len(memo) < MAX_MEMO_ENTRIES):
            sub_members = []
            for m in state.members[members_before:]:
                rel = dict(m)
                # store chains relative to this file's position
                rel["via"] = m["via"][len(chain):]
                sub_members.append(rel)
            memo[memo_key] = {
                "members": sub_members,
                "env_after": {n: Binding(b.value, b.anchor_dir,
                                         b.site, b.poisoned)
                              for n, b in env.items()},
                "unresolved": [
                    dict(u) for u in state.unresolved[unresolved_before:]
                ],
                "resolutions": list(
                    state.resolutions[resolutions_before:]),
                "truncated": state.truncated,
            }

    truncated_entries = False
    walk_list = entries[:MAX_ENTRIES_WALKED]
    if len(entries) > MAX_ENTRIES_WALKED:
        truncated_entries = True
        _bump("entries_truncated", len(entries) - MAX_ENTRIES_WALKED)
    for entry in walk_list:
        state = _EntryWalk()
        env: dict[str, Binding] = {}
        _walk_file(state, env, entry, [], True, 0, entry)
        if state.truncated:
            # A truncated closure's guaranteed set is partial —
            # classing it with complete ones would lie about shared
            # prefixes. Unclassed, censused.
            class_id = None
            _bump("entries_unclassed_truncated")
        else:
            guaranteed_set = tuple(sorted(
                m["file"] for m in state.members
                if m["guaranteed"] and not m.get("root")))
            # Full digest: a truncated id is a partition KEY, and a
            # birthday-collidable key merges a gateless entry into a
            # gated class.
            class_id = "ec" + hashlib.sha256(
                "\0".join(guaranteed_set).encode()).hexdigest()
        prefixes[entry] = {
            "class": class_id,
            "members": state.members,
            "closure_truncated": state.truncated,
            "unresolved": state.unresolved,
            "unresolved_overflow": state.unresolved_overflow,
        }

    # Entry classes: partition of entries by shared guaranteed prefix.
    classes: dict[str, dict[str, Any]] = {}
    for entry, p in prefixes.items():
        if p["class"] is None:
            continue
        guaranteed = sorted(
            m["file"] for m in p["members"]
            if m["guaranteed"] and not m.get("root"))
        c = classes.setdefault(p["class"], {
            "class": p["class"],
            "guaranteed_prefix": guaranteed,
            "entries": [],
        })
        c["entries"].append(entry)
    entry_classes = sorted(classes.values(),
                           key=lambda c: (-len(c["entries"]), c["class"]))
    for c in entry_classes:
        c["entries"].sort()
        c["entry_count"] = len(c["entries"])

    return {
        "entries_walked": len(walk_list),
        "entries_truncated": truncated_entries,
        "budget_exhausted": stmt_budget[0] <= 0,
        "outcomes": outcomes,
        "prefixes": prefixes,
        "entry_classes": entry_classes,
        "env_resolutions": env_resolutions,
    }
