"""Portable receipts over a completed native corpus profile; no sample rereads."""
from __future__ import annotations

from pathlib import Path
import sys

from core.reporting.results import NativeResult, complete_native_result
from core.reporting.service import unrefreshed_report_notice

# Deliberately omit sample names, header values, seed payloads and dictionary
# contents. Keep aggregate coverage and native omissions, not only success counts.
_FAMILY_FIELDS = ("id", "key", "sample_count", "size_min", "size_max", "truncated_reads", "confidence", "corroboration")


def complete_corpus_report(args, profile: dict, samples_dir: Path, out_dir: Path):
    options = args._report_options
    if not options.enabled:
        notice = unrefreshed_report_notice(out_dir)
        if notice:
            print("Warning: " + notice, file=sys.stderr)
        return None
    if not (args.report_format or args.report_output):
        return None
    try:
        root = out_dir
        if options.output is not None:
            root = options.output if options.output.is_dir() or not options.output.suffix else options.output.parent / ("." + options.output.stem + "-report")
        destinations = [root] + ([options.output] if options.output is not None else [])
        if any(path.resolve().is_relative_to(samples_dir.resolve()) for path in destinations):
            raise ValueError("Report destination is inside the sample input directory")
        families = profile["families"]
        payload = {"summary": {key: value for key, value in profile["summary"].items() if key != "skipped"}, "options": profile["options"],
                   "provenance": profile["provenance"],
                   "families": [{key: family.get(key) for key in _FAMILY_FIELDS} for family in families[:100]],
                   "families_omitted": max(0, len(families) - 100)}
        # Artifact pointers protect native outputs; directory pointers are not
        # expanded into contents by the reporting engine.
        artifacts = [{"path": str(samples_dir)}]
        artifacts.extend({"path": value} for value in profile["artifacts"].values() if isinstance(value, str) and value)
        summary = profile["summary"]
        result = NativeResult("binary-corpus", str(samples_dir), "unknown", payload,
                              state="completed", artifacts=artifacts,
                              metrics={key: summary[key] for key in ("samples_seen", "samples_profiled", "samples_skipped", "family_count")},
                              diagnostics=["Corpus byte statistics are uncorroborated observations, not confirmed vulnerabilities or a complete format specification.",
                                           "Family detail is limited to 100 records; full counts, native caps and skip accounting are retained. Sample contents, filenames, seed bytes and dictionary entries are omitted."],
                              lifecycle_dir=getattr(args, "_report_lifecycle_dir", None),
                              lifecycle_producer="understand", lifecycle_metadata=getattr(args, "_report_lifecycle_metadata", None))
        return complete_native_result(result, root, stem="binary-corpus-report", options=options, stream=sys.stderr)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print("Optional corpus report unavailable (" + type(exc).__name__ + "); native profile retained", file=sys.stderr)
        return None
