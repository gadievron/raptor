"""Hypothesis-driven, tool-grounded security review of coverage gaps.

Modules:
    gaps        Gap computation from inventory + coverage records
    context     Context-slice assembly (source + callers/callees)
    strategy    Adaptive strategy selection from function metadata
    record      Annotation writing + coverage-audit record emission
    report      Final summary report generation
    findings    Findings emission in standard RAPTOR format
"""
