"""Cross-version comparison of Ghidra RE databases.

Given two REDatabase instances (typically from different firmware or
binary versions), produces a structured diff showing added, removed,
and changed functions — plus annotation/comment deltas.

Default matching is by function name. Address-based matching is
unreliable across compilation versions since addresses shift. For
stripped or renamed binaries, pass ``matches=`` (a
:class:`packages.ghidra.match.MatchResult`) to diff over the tiered
match pairs instead: renamed functions compare as changes rather than
an added+removed pair, and comparison is normalized so a pure rename
does not read as a code change.

Usage::

    from packages.ghidra.diff import diff_databases

    diff = diff_databases(db_old, db_new)
    print(diff.summary())
    diff.write_json(output_dir / "version-diff.json")
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional

from .model import REDatabase, REFunction

logger = logging.getLogger(__name__)


def _display(name: object, limit: int = 120) -> str:
    """Attacker-derived name made safe for terminal output.

    Function names come from the analysed binary: ESC sequences can
    redraw an operator's terminal, newlines can forge summary lines,
    and bidi overrides can visually reorder them — so every name is
    scrubbed and clipped at display time. Shares the scrub class with
    match._clip so the two layers cannot drift.
    """
    from .match import _CONTROL
    s = _CONTROL.sub(" ", str(name or ""))
    return s if len(s) <= limit else s[:limit] + "…"


@dataclass
class FunctionChange:
    """A single function that changed between versions."""

    name: str
    address_old: int
    address_new: int
    size_old: int
    size_new: int
    signature_old: Optional[str] = None
    signature_new: Optional[str] = None
    calling_convention_old: Optional[str] = None
    calling_convention_new: Optional[str] = None
    decompilation_changed: bool = False
    name_new: Optional[str] = None
    match_tier: Optional[int] = None
    #: rename-aware compare only: code structure matches but hex
    #: constants differ (bounds, masks, auth constants)
    constants_changed: bool = False
    #: rename-aware compare only: the pair's call targets, mapped
    #: through the match, differ (a callee was added, removed, or
    #: retargeted — visible even when every callee is auto-named)
    calls_changed: bool = False
    #: rename-aware compare only: signature verdict computed on
    #: normalized text; raw comparison would flag every renamed pair
    signature_verdict: Optional[bool] = None

    @property
    def size_delta(self) -> int:
        return self.size_new - self.size_old

    @property
    def address_shifted(self) -> bool:
        return self.address_old != self.address_new

    @property
    def signature_changed(self) -> bool:
        if self.signature_verdict is not None:
            return self.signature_verdict
        return self.signature_old != self.signature_new

    @property
    def calling_convention_changed(self) -> bool:
        return self.calling_convention_old != self.calling_convention_new

    @property
    def renamed(self) -> bool:
        return self.name_new is not None and self.name_new != self.name

    def to_dict(self) -> Dict[str, Any]:
        from .match import _clip
        d: Dict[str, Any] = {
            "name": _clip(self.name),
            "address_old": self.address_old,
            "address_new": self.address_new,
            "size_old": self.size_old,
            "size_new": self.size_new,
            "size_delta": self.size_delta,
        }
        if self.signature_changed:
            d["signature_old"] = _clip(self.signature_old, 512) \
                if self.signature_old is not None else None
            d["signature_new"] = _clip(self.signature_new, 512) \
                if self.signature_new is not None else None
        if self.calling_convention_changed:
            d["calling_convention_old"] = self.calling_convention_old
            d["calling_convention_new"] = self.calling_convention_new
        if self.address_shifted:
            d["address_shifted"] = True
        if self.decompilation_changed:
            d["decompilation_changed"] = True
        if self.renamed:
            d["name_new"] = _clip(self.name_new)
        if self.match_tier is not None:
            d["match_tier"] = self.match_tier
        if self.constants_changed:
            d["constants_changed"] = True
        if self.calls_changed:
            d["calls_changed"] = True
        return d


@dataclass
class CommentDelta:
    """A comment that was added, removed, or changed."""

    function: Optional[str]
    address: int
    kind: str
    action: str  # "added", "removed", "changed"
    text_old: Optional[str] = None
    text_new: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        # Comment texts and function names come from the analysed
        # project — scrub and bound them at the JSON emission layer
        # like every other name (operators `jq` these files straight
        # to a terminal; comments are also unbounded in size).
        from .match import _clip
        d: Dict[str, Any] = {
            "address": self.address,
            "kind": self.kind,
            "action": self.action,
        }
        if self.function:
            d["function"] = _clip(self.function)
        if self.text_old is not None:
            d["text_old"] = _clip(self.text_old, 512)
        if self.text_new is not None:
            d["text_new"] = _clip(self.text_new, 512)
        return d


@dataclass
class REDiff:
    """Structured diff between two REDatabase instances."""

    label_old: str
    label_new: str
    added: List[REFunction] = field(default_factory=list)
    removed: List[REFunction] = field(default_factory=list)
    changed: List[FunctionChange] = field(default_factory=list)
    comment_deltas: List[CommentDelta] = field(default_factory=list)
    import_deltas: Dict[str, List[str]] = field(default_factory=dict)
    match_stats: Dict[str, int] = field(default_factory=dict)
    match_notes: List[str] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed or self.changed
                     or self.comment_deltas)

    def summary(self) -> str:
        """Human-readable summary of the diff."""
        lines = [f"{self.label_old} -> {self.label_new}", ""]

        if self.added:
            lines.append(f"Added ({len(self.added)} functions):")
            for f in self.added[:20]:
                lines.append(
                    f"  {_display(f.name)}  {f.address:#x}  size={f.size}"
                )
            if len(self.added) > 20:
                lines.append(f"  ... and {len(self.added) - 20} more")
            lines.append("")

        if self.removed:
            lines.append(f"Removed ({len(self.removed)} functions):")
            for f in self.removed[:20]:
                lines.append(
                    f"  {_display(f.name)}  (was {f.address:#x}, size={f.size})"
                )
            if len(self.removed) > 20:
                lines.append(f"  ... and {len(self.removed) - 20} more")
            lines.append("")

        if self.changed:
            lines.append(f"Changed ({len(self.changed)} functions):")
            for c in self.changed[:30]:
                parts = [f"  {_display(c.name)}"]
                if c.renamed:
                    parts.append(f"renamed -> {_display(c.name_new)}")
                if c.size_delta != 0:
                    sign = "+" if c.size_delta > 0 else ""
                    parts.append(
                        f"size: {c.size_old} -> {c.size_new} "
                        f"({sign}{c.size_delta} bytes)"
                    )
                if c.signature_changed:
                    parts.append("signature changed")
                if c.calling_convention_changed:
                    parts.append("calling convention changed")
                if c.decompilation_changed:
                    parts.append("code changed")
                if c.constants_changed:
                    parts.append("constants changed")
                if c.calls_changed:
                    parts.append("call targets changed")
                if c.address_shifted:
                    parts.append(f"moved {c.address_old:#x} -> {c.address_new:#x}")
                lines.append("  ".join(parts))
            if len(self.changed) > 30:
                lines.append(f"  ... and {len(self.changed) - 30} more")
            lines.append("")

        if self.comment_deltas:
            added_c = [d for d in self.comment_deltas if d.action == "added"]
            removed_c = [d for d in self.comment_deltas if d.action == "removed"]
            changed_c = [d for d in self.comment_deltas if d.action == "changed"]
            parts = []
            if added_c:
                parts.append(f"{len(added_c)} added")
            if removed_c:
                parts.append(f"{len(removed_c)} removed")
            if changed_c:
                parts.append(f"{len(changed_c)} changed")
            lines.append(f"Comments: {', '.join(parts)}")
            lines.append("")

        if self.import_deltas:
            added_i = self.import_deltas.get("added", [])
            removed_i = self.import_deltas.get("removed", [])
            if added_i:
                lines.append(f"New imports ({len(added_i)}):")
                for name in added_i[:10]:
                    lines.append(f"  {_display(name)}")
                if len(added_i) > 10:
                    lines.append(f"  ... and {len(added_i) - 10} more")
            if removed_i:
                lines.append(f"Removed imports ({len(removed_i)}):")
                for name in removed_i[:10]:
                    lines.append(f"  {_display(name)}")

        if self.match_stats:
            matched = self.match_stats.get("matched", 0)
            tiers = ", ".join(
                f"{k}={v}"
                for k, v in sorted(self.match_stats.items())
                if k.startswith("tier") and v)
            lines.append(
                f"Matched {matched} function pairs"
                + (f" ({tiers})" if tiers else ""))
            for note in self.match_notes:
                lines.append(f"  note: {_display(note, 500)}")
            lines.append("")

        if not self.has_changes:
            lines.append("No differences found.")

        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        from .match import _clip
        return {
            "label_old": self.label_old,
            "label_new": self.label_new,
            "added": [
                {"name": _clip(f.name), "address": f.address,
                 "size": f.size}
                for f in self.added
            ],
            "removed": [
                {"name": _clip(f.name), "address": f.address,
                 "size": f.size}
                for f in self.removed
            ],
            "changed": [c.to_dict() for c in self.changed],
            "comment_deltas": [d.to_dict() for d in self.comment_deltas],
            # import names are attacker-derived symbol names — same
            # scrub/clip chokepoint as function names above
            "import_deltas": {
                action: [_clip(name) for name in names]
                for action, names in self.import_deltas.items()
            },
            "stats": {
                "added_count": len(self.added),
                "removed_count": len(self.removed),
                "changed_count": len(self.changed),
                "comment_delta_count": len(self.comment_deltas),
                **({"match": dict(self.match_stats)}
                   if self.match_stats else {}),
            },
            **({"match_notes": list(self.match_notes)}
               if self.match_notes else {}),
        }

    @property
    def changed_function_names(self) -> List[str]:
        """Names of all added or changed functions (priority targets)."""
        names = [f.name for f in self.added if not f.is_auto_named]
        names.extend(c.name for c in self.changed)
        return names

    def write_json(self, path: Path) -> None:
        """Write the diff to a JSON file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)
        logger.info("wrote version diff: %s", path)


def _compare_pair(
    fo: REFunction,
    fn: REFunction,
    *,
    rename_aware: bool = False,
    match_tier: Optional[int] = None,
    calls_changed: bool = False,
) -> Optional[FunctionChange]:
    """FunctionChange for a matched pair, or None if unchanged.

    With ``rename_aware`` the comparison is normalized so the pair's
    own (possibly different) names, auto-generated names, and hex
    constants do not count as change — a pure rename or rebase must
    not read as a code change. Because full masking would also
    swallow constant-only patches (a changed bound or auth constant),
    a pair whose structure matches but whose hex constants differ is
    reported with ``constants_changed`` instead of silence.
    """
    do = fo.decompilation or None
    dn = fn.decompilation or None
    so, sn = fo.signature, fn.signature
    constants_changed = False
    if rename_aware:
        from .match import (_mask_own_name, _normalize_decomp,
                            _normalize_keep_constants, _strip_nul)

        def _norm(text: Optional[str], own: str,
                  normalizer) -> Optional[str]:
            if text is None:
                return None
            # raw NULs could forge a mask sentinel; scrub BEFORE any
            # masking so attacker text cannot fake normalized equality
            return normalizer(_mask_own_name(_strip_nul(text), own))

        own_o = str(fo.name or "")
        own_n = str(fn.name or "")
        do = _norm(do, own_o, _normalize_decomp)
        dn = _norm(dn, own_n, _normalize_decomp)
        so = _norm(so, own_o, _normalize_decomp)
        sn = _norm(sn, own_n, _normalize_decomp)
        if do == dn and do is not None:
            constants_changed = (
                _norm(fo.decompilation, own_o,
                      _normalize_keep_constants)
                != _norm(fn.decompilation, own_n,
                         _normalize_keep_constants))

    decomp_changed = do != dn
    signature_verdict = (so != sn) if rename_aware else None
    address_changed = (not rename_aware) and fo.address != fn.address

    if (fo.size != fn.size
            or so != sn
            or fo.calling_convention != fn.calling_convention
            or address_changed
            or decomp_changed
            or constants_changed
            or calls_changed):
        return FunctionChange(
            name=str(fo.name),
            address_old=fo.address,
            address_new=fn.address,
            size_old=fo.size,
            size_new=fn.size,
            signature_old=fo.signature,
            signature_new=fn.signature,
            calling_convention_old=fo.calling_convention,
            calling_convention_new=fn.calling_convention,
            decompilation_changed=decomp_changed,
            name_new=(str(fn.name) if fn.name != fo.name else None),
            match_tier=match_tier,
            constants_changed=constants_changed,
            calls_changed=calls_changed,
            signature_verdict=signature_verdict,
        )
    return None


def diff_databases(
    old: REDatabase,
    new: REDatabase,
    *,
    label_old: str = "",
    label_new: str = "",
    matches: Optional[Any] = None,
) -> REDiff:
    """Compare two REDatabase instances and produce a structured diff.

    By default matches functions by name. Functions present in *new*
    but not *old* are ``added``; present in *old* but not *new* are
    ``removed``. Functions present in both are compared for size,
    signature, calling convention, and decompilation changes.

    With ``matches`` (a :class:`packages.ghidra.match.MatchResult`
    from :func:`packages.ghidra.match.match_databases` over the same
    two databases), the diff runs over the matched pairs instead:
    renamed and address-shifted functions compare correctly, added =
    unmatched new, removed = unmatched old, and each change carries
    its match tier.

    Args:
        old: The older / baseline REDatabase.
        new: The newer / comparison REDatabase.
        label_old: Human label for the old version (e.g. "v7.20_rel411").
        label_new: Human label for the new version.
        matches: Optional tiered match result to diff over.

    Returns:
        An REDiff with the comparison results.
    """
    if not label_old:
        label_old = old.metadata.get("program_name", "old")
    if not label_new:
        label_new = new.metadata.get("program_name", "new")

    changed: List[FunctionChange] = []
    match_stats: Dict[str, int] = {}
    match_notes: List[str] = []

    if matches is not None:
        old_by_addr: Dict[int, REFunction] = {}
        for f in old.functions:
            old_by_addr.setdefault(f.address, f)
        new_by_addr: Dict[int, REFunction] = {}
        for f in new.functions:
            new_by_addr.setdefault(f.address, f)

        added = sorted(
            (new_by_addr[u["address"]] for u in matches.unmatched_new
             if u.get("address") in new_by_addr),
            key=lambda f: f.address,
        )
        removed = sorted(
            (old_by_addr[u["address"]] for u in matches.unmatched_old
             if u.get("address") in old_by_addr),
            key=lambda f: f.address,
        )
        # compare each pair's call targets THROUGH the match mapping:
        # rebase-invariant, and catches a retargeted call even when
        # every callee is auto-named (text normalization masks those)
        o2n = matches.old_to_new()
        matched_new = set(o2n.values())
        callees_old = getattr(matches, "callees_old", {})
        callees_new = getattr(matches, "callees_new", {})
        self_old: FrozenSet[int] = getattr(
            matches, "self_calls_old", frozenset())
        self_new: FrozenSet[int] = getattr(
            matches, "self_calls_new", frozenset())
        for p in matches.pairs:
            fo = old_by_addr.get(p.old_address)
            fn = new_by_addr.get(p.new_address)
            if fo is None or fn is None:
                continue
            old_callees = callees_old.get(p.old_address, ())
            new_callees = callees_new.get(p.new_address, ())
            mapped = {o2n[c] for c in old_callees if c in o2n}
            actual = {c for c in new_callees if c in matched_new}
            # unmatched callees have no cross-side identity, but a
            # difference in how many there are is still a change; a
            # retarget between two unmatched callees stays invisible
            n_unmatched_old = len(old_callees) - len(mapped)
            n_unmatched_new = len(new_callees) - len(actual)
            recursion_changed = ((p.old_address in self_old)
                                 != (p.new_address in self_new))
            change = _compare_pair(
                fo, fn, rename_aware=True, match_tier=p.tier,
                calls_changed=(mapped != actual
                               or n_unmatched_old != n_unmatched_new
                               or recursion_changed))
            if change is not None:
                changed.append(change)
        match_stats = {k: v for k, v in matches.stats.items()
                       if isinstance(v, int)}
        match_notes = [str(n) for n in
                       getattr(matches, "notes", [])]
    else:
        old_by_name = {f.name: f for f in old.functions}
        new_by_name = {f.name: f for f in new.functions}

        old_names = set(old_by_name.keys())
        new_names = set(new_by_name.keys())

        added = sorted(
            [new_by_name[n] for n in (new_names - old_names)],
            key=lambda f: f.address,
        )
        removed = sorted(
            [old_by_name[n] for n in (old_names - new_names)],
            key=lambda f: f.address,
        )

        for name in sorted(old_names & new_names):
            change = _compare_pair(old_by_name[name],
                                   new_by_name[name])
            if change is not None:
                changed.append(change)

    comment_deltas = _diff_comments(old, new)
    import_deltas = _diff_imports(old, new)

    return REDiff(
        label_old=label_old,
        label_new=label_new,
        added=added,
        removed=removed,
        changed=changed,
        comment_deltas=comment_deltas,
        import_deltas=import_deltas,
        match_stats=match_stats,
        match_notes=match_notes,
    )


def _diff_comments(old: REDatabase, new: REDatabase) -> list[CommentDelta]:
    """Diff comments by (address, kind) key."""
    old_comments = {
        (c.address, c.kind): c for c in old.comments
    }
    new_comments = {
        (c.address, c.kind): c for c in new.comments
    }

    deltas = []
    for key in sorted(set(old_comments) | set(new_comments)):
        co = old_comments.get(key)
        cn = new_comments.get(key)

        if co and not cn:
            deltas.append(CommentDelta(
                function=co.function,
                address=key[0],
                kind=key[1],
                action="removed",
                text_old=co.text,
            ))
        elif cn and not co:
            deltas.append(CommentDelta(
                function=cn.function,
                address=key[0],
                kind=key[1],
                action="added",
                text_new=cn.text,
            ))
        elif co and cn and co.text != cn.text:
            deltas.append(CommentDelta(
                function=cn.function,
                address=key[0],
                kind=key[1],
                action="changed",
                text_old=co.text,
                text_new=cn.text,
            ))

    return deltas


def _diff_imports(old: REDatabase, new: REDatabase) -> dict[str, list[str]]:
    """Diff import symbols by name."""
    old_names = {i["name"] for i in old.imports if "name" in i}
    new_names = {i["name"] for i in new.imports if "name" in i}

    result: dict[str, list[str]] = {}
    added = sorted(new_names - old_names)
    removed = sorted(old_names - new_names)
    if added:
        result["added"] = added
    if removed:
        result["removed"] = removed
    return result
