"""Hypothesis-driven, tool-grounded security review of coverage gaps.

Modules:
    gaps        Gap computation from inventory + coverage records
    context     Context-slice assembly (source + callers/callees)
    strategy    Adaptive strategy selection from function metadata
    record      Source-hash + audit-log helpers for the review loop
    report      Final summary report generation
    findings    Findings emission in standard RAPTOR format
"""
