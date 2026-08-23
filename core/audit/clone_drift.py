"""Cloned-block drift — copied code where one copy missed the fix (§3.9).

Two legs, deliberately unequal in evidence rank:

* **Fix-anchored (promote-capable)** — composes with the landed
  ``fix_history`` variant-hunt machinery. A past security fix is a
  *contract witness*: the project itself asserted "this shape was a
  bug" (registry-grade, ``contract_source: fix_commit``). The variant
  sites the fix hunt already found become promote-capable when their
  clone similarity to the fixed region is high AND the fix's guard is
  demonstrably absent. ``git_oracle``'s corroboration-only rule is
  respected: the namespace stays ``consistency`` — the fix commit is
  the contract premise, the AST/token facts are the evidence.

* **Generic winnowing (detection-grade)** — bounded token-shingle
  winnowing over the run's function bodies (identifiers/numbers
  normalised, k-gram hashes, per-window minima), fingerprint
  *containment against the smaller clone* ≥ ``CLONE_SIMILARITY`` over
  ≥ ``MIN_CLONE_TOKENS`` tokens. Containment, not Jaccard,
  deliberately: the divergence being hunted (a missing guard block)
  would itself depress a symmetric score below threshold on small
  functions — the metric must not penalise the signal. Clone
  pairs are then diffed on *security-relevant* tokens only: calls
  inside guard conditions, strict-vs-inclusive bound styles, and
  security-stem calls (structural stems, never project vocabulary).
  Rule-id ``consistency:clone-drift-majority`` — a two-member clone
  group has no majority worth the name, so this leg never promotes
  alone and only participates in cross-namespace aggregation.

Bounds (documented per the series rule): ≤ ``MAX_CLONE_FUNCTIONS``
function bodies enter the winnower (largest first is deliberately NOT
used — deterministic file order keeps runs reproducible), candidate
pairs must share ≥ ``MIN_SHARED_FINGERPRINTS`` fingerprints before a
Jaccard is computed, ≤ ``MAX_CLONE_PAIRS`` pairs are reported, and
fix regions are capped at ``MAX_REGION_CHARS`` characters.
"""

from __future__ import annotations

import logging
import re
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .callsite_consistency import _KEYWORDS, _SECURITY_CALLEE_RE
from .consistency_dimensions import _function_spans
from .peer_evidence import PeerEvidence, PeerExhibit

logger = logging.getLogger(__name__)

DIMENSION_CLONE_DRIFT = "clone-drift"


def _grammar_ready() -> bool:
    """Shared tree-sitter availability flag (patchable in tests via
    ``core.testing.treesitter``)."""
    from . import consistency_dimensions as _cd
    return bool(getattr(_cd, "_TS_AVAILABLE", False))


def _signal_degraded(
    telemetry: dict[str, Any] | None, leg: str, detail: str,
) -> None:
    """Loud degradation signal — grammar-absent must never read as a
    clean zero-deviation result. Warned always; recorded into the
    prepass dimension telemetry when the caller passed it."""
    logger.warning("clone_drift: %s leg degraded — %s", leg, detail)
    if telemetry is not None:
        telemetry["degraded"] = telemetry.get("degraded", 0) + 1
        reasons = telemetry.setdefault("degraded_reasons", [])
        entry = f"{leg}: {detail}"
        if entry not in reasons:
            reasons.append(entry)


K_GRAM = 5
WINNOW_WINDOW = 4
CLONE_SIMILARITY = 0.85
# The fix-anchored leg tolerates a lower containment: the anchor
# already carries two independent constraints (the fix hunt matched
# the same sensitive callee, and the guard's absence is re-verified
# against the variant body), and k-grams crossing the stripped guard
# seam are perturbed even on a perfect clone — 0.85 there would
# reject true drifted copies of small regions.
FIX_ANCHOR_SIMILARITY = 0.75
MIN_CLONE_TOKENS = 40
MAX_CLONE_FUNCTIONS = 500
MAX_CLONE_PAIRS = 40
MIN_SHARED_FINGERPRINTS = 8
MAX_REGION_CHARS = 3000
_MAX_DIVERGENCES_PER_PAIR = 3

_TOKEN_RE = re.compile(
    r"[A-Za-z_]\w*|\d+|==|!=|<=|>=|&&|\|\||->|"
    r"[-+*/%<>=!&|^~.;,(){}\[\]]",
)
_STRING_RE = re.compile(r'"(?:[^"\\]|\\.)*"' + r"|'(?:[^'\\]|\\.)*'")
_LINE_COMMENT_RE = re.compile(r"//[^\n]*|#[^\n]*")
_GUARD_LINE_RE = re.compile(r"^\s*(?:if|while|elif|else\s+if)\b")
_CALL_NAME_RE = re.compile(r"\b([A-Za-z_]\w{1,})\s*\(")
_STRICT_BOUND_RE = re.compile(r"[^<]<(?!=)[^<]")
_INCLUSIVE_BOUND_RE = re.compile(r"<=")


def _normalise_tokens(body: str) -> list[str]:
    """Type-2 clone view: identifiers → ``I``, numbers → ``N``,
    strings/comments stripped, keywords and punctuation kept."""
    text = _STRING_RE.sub('""', body)
    text = _LINE_COMMENT_RE.sub("", text)
    out: list[str] = []
    for tok in _TOKEN_RE.findall(text):
        if tok[0].isdigit():
            out.append("N")
        elif tok[0].isalpha() or tok[0] == "_":
            out.append(tok if tok in _KEYWORDS else "I")
        else:
            out.append(tok)
    return out


def _fingerprints(tokens: list[str]) -> frozenset[int]:
    """Winnowed k-gram fingerprint set (Schleimer, Wilkerson &
    Aiken, SIGMOD 2003)."""
    if len(tokens) < K_GRAM:
        return frozenset()
    hashes = [
        zlib.crc32("\x00".join(tokens[i:i + K_GRAM]).encode())
        for i in range(len(tokens) - K_GRAM + 1)
    ]
    if len(hashes) <= WINNOW_WINDOW:
        return frozenset(hashes)
    picked: set[int] = set()
    for i in range(len(hashes) - WINNOW_WINDOW + 1):
        picked.add(min(hashes[i:i + WINNOW_WINDOW]))
    return frozenset(picked)


def _pair_similarity(a: frozenset[int], b: frozenset[int]) -> float:
    """Fingerprint containment against the smaller set (see module
    docstring for why this beats Jaccard here)."""
    if not a or not b:
        return 0.0
    return len(a & b) / min(len(a), len(b))


def _containment(region: frozenset[int], body: frozenset[int]) -> float:
    """How much of *region* the *body* reproduces (fix-anchored leg:
    the fixed region is a window, the variant is a whole function)."""
    if not region or not body:
        return 0.0
    return len(region & body) / len(region)


@dataclass(frozen=True)
class _FnBody:
    file: str
    function: str
    line: int
    text: str
    tokens: int
    prints: frozenset[int]


def _function_bodies(
    source_texts: dict[str, str],
    *,
    max_functions: int = MAX_CLONE_FUNCTIONS,
) -> list[_FnBody]:
    bodies: list[_FnBody] = []
    for file_path, name, start, lines in _function_spans(source_texts):
        if len(bodies) >= max_functions:
            break
        text = "\n".join(lines)
        tokens = _normalise_tokens(text)
        if len(tokens) < MIN_CLONE_TOKENS:
            continue
        bodies.append(_FnBody(
            file=file_path,
            function=name,
            line=start,
            text=text,
            tokens=len(tokens),
            prints=_fingerprints(tokens),
        ))
    return bodies


@dataclass
class CloneDriftDeviation:
    """One clone whose twin carries a guard/bound/call it lacks."""

    kind: str              # "guard" | "bound" | "call" | "fix_anchor"
    token: str             # the diverging guard/call name or bound note
    file: str              # the deviant clone (lacking the token)
    line: int
    enclosing_function: str
    peer_file: str
    peer_function: str
    peer_line: int
    similarity: float
    fix_sha: str = ""      # fix-anchored leg only
    cwe: str = ""
    peer_evidence: PeerEvidence | None = None

    @property
    def registry_grade(self) -> bool:
        return bool(self.fix_sha)

    @property
    def description(self) -> str:
        if self.fix_sha:
            return (
                f"{self.enclosing_function} reproduces the region "
                f"fix {self.fix_sha[:12]} patched "
                f"(containment {self.similarity:.2f}) but lacks the "
                f"added guard {self.token}()"
            )
        return (
            f"near-clone of {self.peer_function} "
            f"(similarity {self.similarity:.2f}) diverges: "
            f"{self.kind} {self.token!r} present in the twin, absent "
            f"here"
        )

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "kind": self.kind,
            "token": self.token,
            "file": self.file,
            "line": self.line,
            "enclosing_function": self.enclosing_function,
            "peer_file": self.peer_file,
            "peer_function": self.peer_function,
            "peer_line": self.peer_line,
        }
        d["similarity"] = round(self.similarity, 3)
        d["cwe"] = self.cwe
        if self.fix_sha:
            d["fix_sha"] = self.fix_sha
        if self.peer_evidence is not None:
            d["peer_evidence"] = self.peer_evidence.to_dict()
        return d


def _guard_calls(text: str) -> set[str]:
    calls: set[str] = set()
    for line in text.splitlines():
        if not _GUARD_LINE_RE.match(line):
            continue
        for m in _CALL_NAME_RE.finditer(line):
            name = m.group(1)
            if name not in _KEYWORDS:
                calls.add(name)
    return calls


def _security_calls(text: str) -> set[str]:
    return {
        m.group(1) for m in _CALL_NAME_RE.finditer(text)
        if m.group(1) not in _KEYWORDS
        and _SECURITY_CALLEE_RE.search(m.group(1))
    }


def _bound_style(text: str) -> tuple[int, int]:
    guard_text = "\n".join(
        ln for ln in text.splitlines() if _GUARD_LINE_RE.match(ln)
    )
    return (
        len(_STRICT_BOUND_RE.findall(guard_text)),
        len(_INCLUSIVE_BOUND_RE.findall(guard_text)),
    )


def _divergences(a: _FnBody, b: _FnBody) -> list[tuple[str, str, _FnBody]]:
    """(kind, token, deviant body) triples — the deviant is the clone
    *lacking* the security-relevant token its twin carries."""
    guards_a, guards_b = _guard_calls(a.text), _guard_calls(b.text)
    out: list[tuple[str, str, _FnBody]] = [("guard", token, b) for token in sorted(guards_a - guards_b)]
    out.extend(("guard", token, a) for token in sorted(guards_b - guards_a))
    sec_a = _security_calls(a.text) - guards_a
    sec_b = _security_calls(b.text) - guards_b
    out.extend(("call", token, b) for token in sorted(sec_a - sec_b))
    out.extend(("call", token, a) for token in sorted(sec_b - sec_a))
    strict_a, incl_a = _bound_style(a.text)
    strict_b, incl_b = _bound_style(b.text)
    if strict_a + incl_a and strict_b + incl_b \
            and (strict_a > 0) != (strict_b > 0) \
            and (incl_a > 0) != (incl_b > 0):
        # One clone bounds strictly, the other inclusively — the
        # inclusive one is the off-by-one suspect (CWE-193 family).
        deviant = a if incl_a else b
        out.append(("bound", "<= where twin uses <", deviant))
    return out[:_MAX_DIVERGENCES_PER_PAIR]


_DIVERGENCE_CWE = {"guard": "", "call": "", "bound": "CWE-193"}


def detect_clone_drift(
    source_texts: dict[str, str],
    *,
    similarity: float = CLONE_SIMILARITY,
    max_pairs: int = MAX_CLONE_PAIRS,
    telemetry: dict[str, Any] | None = None,
) -> list[CloneDriftDeviation]:
    """Generic winnowing leg (detection-grade). See module docstring
    for bounds and the divergence classes."""
    if source_texts and not _grammar_ready():
        _signal_degraded(
            telemetry, "winnowing",
            "tree-sitter unavailable — clone winnowing skipped",
        )
        return []
    bodies = _function_bodies(source_texts)
    if len(bodies) < 2:
        return []

    # Inverted fingerprint index → candidate pairs.
    by_print: dict[int, list[int]] = {}
    for idx, body in enumerate(bodies):
        for fp in body.prints:
            by_print.setdefault(fp, []).append(idx)
    shared: dict[tuple[int, int], int] = {}
    for indices in by_print.values():
        if len(indices) < 2 or len(indices) > 20:
            continue
        for i, ia in enumerate(indices):
            for ib in indices[i + 1:]:
                shared[(ia, ib)] = shared.get((ia, ib), 0) + 1

    deviations: list[CloneDriftDeviation] = []
    n_pairs = 0
    for (ia, ib), count in sorted(
            shared.items(), key=lambda kv: (-kv[1], kv[0])):
        if n_pairs >= max_pairs:
            break
        if count < MIN_SHARED_FINGERPRINTS:
            continue
        a, b = bodies[ia], bodies[ib]
        sim = _pair_similarity(a.prints, b.prints)
        if sim < similarity:
            continue
        n_pairs += 1
        for kind, token, deviant in _divergences(a, b):
            peer = b if deviant is a else a
            deviations.append(CloneDriftDeviation(
                kind=kind,
                token=token,
                file=deviant.file,
                line=deviant.line,
                enclosing_function=deviant.function,
                peer_file=peer.file,
                peer_function=peer.function,
                peer_line=peer.line,
                similarity=sim,
                cwe=_DIVERGENCE_CWE.get(kind, ""),
                peer_evidence=PeerEvidence(
                    dimension=DIMENSION_CLONE_DRIFT,
                    formation="clone",
                    group_key=(
                        f"{a.function}~{b.function}"
                    ),
                    n=2,
                    conforming=1,
                    ratio=0.5,
                    deviant=PeerExhibit(
                        deviant.file, deviant.line,
                        f"{deviant.function} lacks {kind} "
                        f"{token!r} (clone similarity {sim:.2f})",
                    ),
                    exhibits=[PeerExhibit(
                        peer.file, peer.line,
                        f"{peer.function} carries {kind} {token!r}",
                    )],
                    contract_source="majority",
                    provenance=f"clone_drift:{kind}",
                ),
            ))
    deviations.sort(key=lambda d: (d.file, d.line, d.token))
    return deviations


# ── fix-anchored leg ─────────────────────────────────────────────────


def load_fix_anchors(out_dir: Path | None) -> list[dict[str, Any]]:
    """Variant-site anchor records persisted by ``apply_fix_history``
    (``fix-history.json`` → ``variant_sites``, additive field)."""
    if out_dir is None:
        return []
    path = Path(out_dir) / "fix-history.json"
    if not path.is_file():
        return []
    import json
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    sites = raw.get("variant_sites")
    return [s for s in sites or [] if isinstance(s, dict)]


def fix_anchored_drift(
    anchors: list[dict[str, Any]],
    source_texts: dict[str, str],
    *,
    similarity: float = FIX_ANCHOR_SIMILARITY,
    telemetry: dict[str, Any] | None = None,
) -> list[CloneDriftDeviation]:
    """Fix-anchored leg: a variant site becomes promote-capable when
    its function body reproduces the fixed region (fingerprint
    containment ≥ *similarity*) and the fix's guard is absent."""
    if not anchors or not source_texts:
        return []
    if not _grammar_ready():
        # Promote-capable leg: silently dropping every fix anchor on
        # a grammar-less host looked identical to "no drifted
        # clones". Degrade loudly instead.
        _signal_degraded(
            telemetry, "fix-anchored",
            f"tree-sitter unavailable — {len(anchors)} fix "
            "anchor(s) dropped unchecked",
        )
        return []
    spans = {
        (f, name): (start, "\n".join(lines))
        for f, name, start, lines in _function_spans(source_texts)
    }
    if not spans:
        _signal_degraded(
            telemetry, "fix-anchored",
            "no function spans parsed from the supplied sources — "
            f"{len(anchors)} fix anchor(s) dropped unchecked",
        )
        return []
    deviations: list[CloneDriftDeviation] = []
    for anchor in anchors:
        file_path = str(anchor.get("file") or "")
        function = str(anchor.get("name") or "")
        guard = str(anchor.get("guard") or "")
        sha = str(anchor.get("sha") or "")
        region = str(anchor.get("fixed_region") or "")[:MAX_REGION_CHARS]
        if not file_path or not function or not guard or not region:
            continue
        span = spans.get((file_path, function))
        if span is None:
            continue
        start, body = span
        if re.search(rf"\b{re.escape(guard)}\s*\(", body):
            continue  # guard present after all — not a drifted clone
        # The variant lacks the guard *by construction* — strip the
        # guard's own lines from the region so the containment score
        # measures the surrounding fixed context, not the guard.
        region = "\n".join(
            ln for ln in region.splitlines() if guard not in ln
        )
        region_prints = _fingerprints(_normalise_tokens(region))
        body_prints = _fingerprints(_normalise_tokens(body))
        containment = _containment(region_prints, body_prints)
        if containment < similarity:
            continue
        fixed_file = str(anchor.get("fixed_file") or "")
        deviations.append(CloneDriftDeviation(
            kind="fix_anchor",
            token=guard,
            file=file_path,
            line=start,
            enclosing_function=function,
            peer_file=fixed_file,
            peer_function=str(anchor.get("sensitive") or ""),
            peer_line=int(anchor.get("fixed_line") or 0),
            similarity=containment,
            fix_sha=sha,
            cwe=str(anchor.get("cwe") or ""),
            peer_evidence=PeerEvidence(
                dimension=DIMENSION_CLONE_DRIFT,
                formation="clone",
                group_key=f"fix:{sha[:12]}",
                n=2,
                conforming=1,
                ratio=0.5,
                deviant=PeerExhibit(
                    file_path, start,
                    f"{function} reproduces the fixed region "
                    f"(containment {containment:.2f}) without "
                    f"{guard}()",
                ),
                exhibits=[PeerExhibit(
                    fixed_file, int(anchor.get("fixed_line") or 0),
                    f"fix {sha[:12]} added {guard}() here",
                )],
                contract_source="fix_commit",
                provenance=f"fix_commit:{sha[:12]}",
            ),
        ))
    deviations.sort(key=lambda d: (d.file, d.line))
    return deviations
