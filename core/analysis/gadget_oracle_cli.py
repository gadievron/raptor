"""CLI for the PHP gadget-chain oracle (``libexec/raptor-gadget-scan``).

Standalone operator surface over :mod:`core.analysis.gadget_oracle`:
scan a tree, print a summary (chains, unserialize sites, census), and
optionally write ``gadget-chains.json`` into a run directory where the
audit context and /validate Stage C pick it up automatically.

Exit codes:
  0  scan ran (chains found or not — the oracle is a witness tool,
     never a gate)
  1  usable-target error (missing/not a directory)
  2  usage error (argparse)
  3  capability absent — tree-sitter-php not installed (recorded
     loudly, never a silent pass)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from core.security.log_sanitisation import sanitise_for_terminal


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="raptor-gadget-scan",
        description=(
            "Mechanical PHP gadget-chain oracle (CWE-502): enumerate "
            "magic methods and property-to-sink flows across a tree. "
            "Found chains are witness exhibits; absence renders with "
            "a completeness census. Hint-tier both ways — never a "
            "verdict."
        ),
    )
    parser.add_argument("target", help="PHP source tree to scan")
    parser.add_argument(
        "--out", default=None,
        help=(
            "Run directory to write gadget-chains.json into (audit "
            "context and /validate Stage C consume it from there)"
        ),
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Print the full artifact JSON to stdout instead of the summary",
    )
    parser.add_argument(
        "--max-chains", type=int, default=20,
        help="Chains rendered in the human summary (default 20)",
    )
    return parser


def _print_summary(report: dict, max_chains: int) -> None:
    # The report is derived from hostile tree content, so every value
    # is sanitised DIRECTLY at its print site (aliases/wrappers are
    # invisible to the report-writer closure gate).
    census = report.get("census") or {}
    chains = report.get("chains") or []
    sites = report.get("unserialize_sites") or []
    magic = report.get("magic_method_census") or {}

    print("Target: " + sanitise_for_terminal(
        str(report.get("target_path", "?")), max_len=512))
    print(
        f"Census: {sanitise_for_terminal(str(census.get('parsed_clean', '?')), max_len=32)}/"
        f"{sanitise_for_terminal(str(census.get('php_files', '?')), max_len=32)}"
        " PHP file(s) parsed clean — "
        + ("Complete" if census.get("complete") else "Incomplete: "
           + sanitise_for_terminal(
               ", ".join(str(r) for r in
                         (census.get("incomplete_reasons") or [])),
               max_len=200))
    )
    print(
        "Classes: " + sanitise_for_terminal(
            str(magic.get("classes", 0)), max_len=32)
        + "; magic methods: "
        + (sanitise_for_terminal(
            ", ".join(f"{k}={v}" for k, v in
                      (magic.get("by_method") or {}).items()),
            max_len=200) or "none")
    )
    print(f"unserialize() sites: {len(sites)}"
          + (" (list truncated)" if report.get(
              "unserialize_sites_truncated") else ""))
    for s in sites[:10]:
        rd = " [request-derived arg]" if s.get("request_derived") else ""
        print("  " + sanitise_for_terminal(
            str(s.get("file", "?")), max_len=512)
            + ":" + sanitise_for_terminal(
                str(s.get("line", "?")), max_len=32) + rd)
    if len(sites) > 10:
        print(f"  (+{len(sites) - 10} more)")
    if chains:
        shown = chains[:max_chains]
        print(f"Gadget chains: {len(chains)}"
              + (" (list truncated)" if report.get("chains_truncated")
                 else "") + " — witness exhibits, verify against source")
        for c in shown:
            sink = c.get("sink") or {}
            steps = c.get("steps") or []
            hop = ("".join(
                " -> " + sanitise_for_terminal(
                    str(st.get("method", "?")), max_len=128) + "()"
                for st in steps if isinstance(st, dict))) if steps else ""
            req = c.get("trigger_requires")
            print(
                "  "
                + sanitise_for_terminal(str(c.get("class", "?")),
                                        max_len=256)
                + "::"
                + sanitise_for_terminal(str(c.get("magic_method", "?")),
                                        max_len=64)
                + hop + " -> "
                + sanitise_for_terminal(str(sink.get("category", "?")),
                                        max_len=32)
                + ":"
                + sanitise_for_terminal(str(sink.get("callee", "?")),
                                        max_len=128)
                + " via $this->"
                + sanitise_for_terminal(str(c.get("property_path", "?")),
                                        max_len=120)
                + " ("
                + sanitise_for_terminal(str(c.get("file", "?")),
                                        max_len=512)
                + ":"
                + sanitise_for_terminal(str(sink.get("line", "?")),
                                        max_len=32)
                + "; availability: "
                + sanitise_for_terminal(str(c.get("availability", "?")),
                                        max_len=64)
                + (("; requires: " + sanitise_for_terminal(
                    str(req), max_len=200)) if req else "")
                + ")"
            )
        if len(chains) > max_chains:
            print(f"  (+{len(chains) - max_chains} more)")
    else:
        print("Gadget chains: none found")
    print("Qualifier: ", end="")
    from core.analysis.gadget_oracle import census_qualifier
    print(sanitise_for_terminal(census_qualifier(report), max_len=700))


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    from core.analysis.gadget_oracle import (
        ARTIFACT_NAME,
        php_grammar_available,
        save_gadget_report,
        scan_tree,
    )

    target = Path(args.target)
    if not target.is_dir():
        print(
            f"raptor-gadget-scan: target is not a directory: "
            f"{sanitise_for_terminal(str(target), max_len=512)}",
            file=sys.stderr,
        )
        return 1
    if not php_grammar_available():
        print(
            "raptor-gadget-scan: capability absent — tree-sitter-php "
            "is not installed (pip install -r "
            "requirements-grammars.txt). No scan ran; absence of "
            "output is NOT evidence of gadget absence.",
            file=sys.stderr,
        )
        return 3

    include_graph = None
    if args.out:
        try:
            from core.inventory.include_graph import load_include_graph
            include_graph = load_include_graph(args.out)
        except ImportError:
            include_graph = None

    report = scan_tree(target, include_graph=include_graph)
    if args.out:
        save_gadget_report(args.out, report)
        print(f"Artifact: {Path(args.out) / ARTIFACT_NAME}",
              file=sys.stderr)
    if args.json:
        from core.json import dumps_artifact
        # ensure_ascii=True: the report carries hostile tree content
        # and this print targets a terminal — non-ASCII (and thus any
        # raw control/bidi bytes) leaves as \uXXXX escapes.
        print(dumps_artifact(report, ensure_ascii=True))
    else:
        _print_summary(report, max(args.max_chains, 0))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
