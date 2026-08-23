"""Structured edge conditions for CFG analysis (PR2).

ControlCondition captures the guard expression on a CFG edge.
extract_conditions_from_cfg() walks an existing PythonCFG or CPPCFG
and produces ConditionEdge records for every conditional branch.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


_IDENT_RE = re.compile(r"\b([a-zA-Z_]\w*(?:->[a-zA-Z_]\w*)*(?:\.[a-zA-Z_]\w*)*)\b")


@dataclass(frozen=True)
class ControlCondition:
    """A guard expression on a CFG edge."""

    text: str
    references: frozenset[str]
    smt_parseable: bool = False
    polarity: bool = True

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "text": self.text,
            "references": sorted(self.references),
        }
        if self.smt_parseable:
            d["smt_parseable"] = True
        if not self.polarity:
            d["polarity"] = False
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ControlCondition:
        return cls(
            text=data["text"],
            references=frozenset(data.get("references", [])),
            smt_parseable=data.get("smt_parseable", False),
            polarity=data.get("polarity", True),
        )

    def negated(self) -> ControlCondition:
        return ControlCondition(
            text=self.text,
            references=self.references,
            smt_parseable=self.smt_parseable,
            polarity=not self.polarity,
        )


@dataclass(frozen=True)
class ConditionEdge:
    """A CFG edge carrying an optional condition."""

    src_line: int
    dst_line: int
    condition: ControlCondition | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "src_line": self.src_line,
            "dst_line": self.dst_line,
        }
        if self.condition is not None:
            d["condition"] = self.condition.to_dict()
        return d


def extract_references(text: str) -> frozenset[str]:
    """Extract variable/field references from a condition expression."""
    keywords = frozenset({
        "if", "else", "elif", "while", "for", "return", "not", "and",
        "or", "in", "is", "None", "True", "False", "NULL", "null",
        "sizeof", "typeof", "void", "int", "char", "long", "unsigned",
        "signed", "short", "double", "float", "const", "struct",
    })
    refs: set[str] = set()
    for m in _IDENT_RE.finditer(text):
        name = m.group(1)
        if name not in keywords and not name.isdigit():
            refs.add(name)
    return frozenset(refs)


_CONDITION_LABEL_RE = re.compile(
    r"^(?:If|While|ElIf|For)\s*\((.+)\)$",
    re.IGNORECASE,
)

_SMT_PARSEABLE_OPS = frozenset({"<", ">", "<=", ">=", "==", "!=", "+", "-", "*", "/"})


def _is_smt_parseable(text: str) -> bool:
    """Heuristic: condition is SMT-parseable if it contains only
    arithmetic comparisons and identifiers."""
    return any(op in text for op in _SMT_PARSEABLE_OPS)


def extract_conditions_from_cfg(cfg) -> list[ConditionEdge]:
    """Walk an existing PythonCFG or CPPCFG and produce ConditionEdge records.

    For each conditional node (If/While/ElIf), creates edges to
    successors with the appropriate polarity. Non-conditional edges
    get condition=None.
    """
    edges: list[ConditionEdge] = []

    for node in cfg.nodes():
        successors = list(cfg.successors(node))
        m = _CONDITION_LABEL_RE.match(node.label.strip())

        if m and len(successors) >= 2:
            cond_text = m.group(1).strip()
            refs = extract_references(cond_text)
            smt = _is_smt_parseable(cond_text)

            true_cond = ControlCondition(
                text=cond_text, references=refs,
                smt_parseable=smt, polarity=True,
            )
            false_cond = true_cond.negated()

            # Determine true/false successor.  CFG builders link the
            # then-body first (closest line to the condition node) and
            # the else/fallthrough second.  Verify by line proximity;
            # if the second successor is closer, swap.
            true_succ, false_succ = successors[0], successors[1]
            d_false = abs(false_succ.lineno - node.lineno)
            d_true = abs(true_succ.lineno - node.lineno)
            if d_false < d_true:
                true_succ, false_succ = false_succ, true_succ

            edges.append(ConditionEdge(
                src_line=node.lineno,
                dst_line=true_succ.lineno,
                condition=true_cond,
            ))
            edges.append(ConditionEdge(
                src_line=node.lineno,
                dst_line=false_succ.lineno,
                condition=false_cond,
            ))
            edges.extend(ConditionEdge(
                    src_line=node.lineno,
                    dst_line=succ.lineno,
                ) for succ in successors[2:])
        else:
            edges.extend(ConditionEdge(
                    src_line=node.lineno,
                    dst_line=succ.lineno,
                ) for succ in successors)

    return edges
