"""Shared path policy for early report validation and final publication."""
from pathlib import Path


PERSISTENCE_FILENAMES = frozenset({
    "report-context.json", "report-document.json", "reporting-manifest.json",
    "summary.json", "summary.md", "diagrams.md", "manifest.json",
    ".raptor-run.json", ".raptor-imported.json", "reporting-input.json", "findings-import.json",
})


def check_report_destination(path: Path) -> None:
    # Check both spellings: an innocuous filename must not alias internal state.
    for candidate in (path, path.resolve()):
        if candidate.name in PERSISTENCE_FILENAMES:
            raise ValueError("Report output uses a reserved persistence filename")
        if any(parent.name == ".reporting" for parent in candidate.parents):
            raise ValueError("Report output cannot modify an immutable reporting generation")


def check_report_directory(path: Path) -> None:
    """A directory may share a persistence filename, but cannot be a generation."""
    for candidate in (path, path.resolve()):
        if any(part.name == ".reporting" for part in (candidate, *candidate.parents)):
            raise ValueError("Report output cannot modify an immutable reporting generation")

