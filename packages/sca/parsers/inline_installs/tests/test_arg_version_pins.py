"""Tests for the Dockerfile ``ARG <NAME>_VERSION=<value>`` extractor.

Substrate context lives in ``_arg_version_pins.py`` — this file
covers the parser's behaviour against realistic Dockerfile shapes
(common pins, inline overrides, skip directives, edge cases).

Origin: extracted as the SCA-side complement to PR #467
(``gadievron/raptor``, Natalie Somersall) which auto-bumps
devcontainer ARG pins. Where that PR keeps versions current,
this extractor keeps the operator informed of CVE exposure on
the pinned versions."""

from __future__ import annotations

from pathlib import Path

from packages.sca.parsers.inline_installs._arg_version_pins import (
    _BUILTIN_ARG_MAP,
    extract,
)


def test_builtin_semgrep_extracted_as_pypi() -> None:
    """``ARG SEMGREP_VERSION=1.117.0`` — built-in map entry."""
    text = "ARG SEMGREP_VERSION=1.117.0\n"
    deps = extract(text, Path("/repo/Dockerfile"))
    assert len(deps) == 1
    d = deps[0]
    assert d.ecosystem == "PyPI"
    assert d.name == "semgrep"
    assert d.version == "1.117.0"
    assert d.scope == "build"
    assert d.source_kind == "dockerfile_arg"


def test_builtin_claude_code_namespace_handling() -> None:
    """``CLAUDE_CODE_VERSION`` resolves to the scoped npm package
    ``@anthropic-ai/claude-code``. The purl must put the scope in
    the namespace position."""
    text = "ARG CLAUDE_CODE_VERSION=2.1.138\n"
    deps = extract(text, Path("/repo/Dockerfile"))
    assert len(deps) == 1
    d = deps[0]
    assert d.ecosystem == "npm"
    assert d.name == "@anthropic-ai/claude-code"
    assert d.version == "2.1.138"
    # purl with namespace: pkg:npm/@anthropic-ai/claude-code@2.1.138
    assert d.purl == "pkg:npm/@anthropic-ai/claude-code@2.1.138"


def test_v_prefix_stripped() -> None:
    """OSV uses bare semver for most ecosystems. Strip the leading
    ``v`` so the version matches OSV's shape."""
    text = "ARG SEMGREP_VERSION=v1.117.0\n"
    deps = extract(text, Path("/repo/Dockerfile"))
    assert deps[0].version == "1.117.0"


def test_known_non_sca_arg_silently_skipped() -> None:
    """``CODEQL_VERSION`` is in the built-in map with value
    ``None`` — github-releases-only CLI, no SCA ecosystem. Skip
    without requiring ``# raptor-sca: skip`` boilerplate."""
    text = (
        "ARG CODEQL_VERSION=2.25.3\n"
        "ARG PYTHON_VERSION=3.12\n"
        "ARG GO_VERSION=1.22\n"
    )
    assert extract(text, Path("/repo/Dockerfile")) == []


def test_unknown_arg_silently_skipped_without_override() -> None:
    """An ARG name not in the built-in map and without an inline
    override is ignored — better to under-emit than pollute
    findings with deps we can't query."""
    text = "ARG SOME_RANDOM_VERSION=1.0.0\n"
    assert extract(text, Path("/repo/Dockerfile")) == []


def test_inline_override_emits_dep() -> None:
    """``# raptor-sca: <eco>:<name>`` after the ARG line forces
    extraction even when the ARG isn't in the built-in map."""
    text = "ARG VENDORED_LIB_VERSION=2.0.1  # raptor-sca: PyPI:vendored-lib\n"
    deps = extract(text, Path("/repo/Dockerfile"))
    assert len(deps) == 1
    assert deps[0].ecosystem == "PyPI"
    assert deps[0].name == "vendored-lib"
    assert deps[0].version == "2.0.1"


def test_inline_override_skip_wins_over_builtin() -> None:
    """``# raptor-sca: skip`` forces a skip even when the ARG name
    is in the built-in map — operator may have already evaluated
    that version and accepted risk."""
    text = "ARG SEMGREP_VERSION=1.117.0  # raptor-sca: skip\n"
    assert extract(text, Path("/repo/Dockerfile")) == []


def test_non_version_arg_skipped() -> None:
    """``ARG SOME_VERSION=latest`` is not a real pin — can't
    query OSV for ``latest``. Skip rather than emit a bogus dep."""
    text = (
        "ARG SEMGREP_VERSION=latest\n"
        "ARG BANDIT_VERSION=main\n"
        'ARG CLAUDE_CODE_VERSION="${OTHER_VAR}"\n'
    )
    assert extract(text, Path("/repo/Dockerfile")) == []


def test_arg_with_quoted_value_extracted() -> None:
    """``ARG FOO_VERSION="1.2.3"`` (quoted) should still work —
    Docker accepts both forms."""
    text = 'ARG SEMGREP_VERSION="1.117.0"\n'
    deps = extract(text, Path("/repo/Dockerfile"))
    assert len(deps) == 1
    assert deps[0].version == "1.117.0"


def test_arg_without_version_suffix_ignored() -> None:
    """``ARG BUILD_TARGET=runtime`` doesn't end in ``_VERSION`` —
    out of scope for this extractor. Generic ARGs aren't version
    pins."""
    text = (
        "ARG BUILD_TARGET=runtime\n"
        "ARG USER=raptor\n"
        "ARG WORKDIR=/app\n"
    )
    assert extract(text, Path("/repo/Dockerfile")) == []


def test_multiple_args_one_dockerfile() -> None:
    """Realistic devcontainer Dockerfile shape: several ARG pins,
    a mix of built-in and inline-override + skipped boilerplate."""
    text = (
        "FROM python:3.12-bookworm\n"
        "ARG SEMGREP_VERSION=1.117.0\n"
        "ARG CODEQL_VERSION=2.25.3\n"
        "ARG CLAUDE_CODE_VERSION=2.1.138\n"
        "ARG PYTHON_VERSION=3.12\n"
        "ARG MY_INTERNAL_VERSION=4.0  # raptor-sca: PyPI:internal-tool\n"
        "RUN pip install semgrep==${SEMGREP_VERSION}\n"
    )
    deps = extract(text, Path("/repo/.devcontainer/Dockerfile"))
    by_name = {d.name: d for d in deps}
    # Built-in: semgrep + claude-code; inline override: internal-tool.
    # Skipped: codeql (None in map), python (None in map).
    assert set(by_name.keys()) == {
        "semgrep", "@anthropic-ai/claude-code", "internal-tool",
    }
    assert by_name["semgrep"].version == "1.117.0"
    assert by_name["internal-tool"].ecosystem == "PyPI"


def test_arg_line_with_leading_whitespace_extracted() -> None:
    """Docker accepts leading whitespace on ARG lines (uncommon
    but legal); the regex should tolerate it."""
    text = "    ARG SEMGREP_VERSION=1.117.0\n"
    deps = extract(text, Path("/repo/Dockerfile"))
    assert len(deps) == 1


def test_pin_style_is_exact_with_high_confidence() -> None:
    """ARG pins are explicit single-version declarations — pin
    style EXACT, confidence high. Distinguishes them from the
    ``RUN pip install foo`` extractor which uses medium because
    of shell-parsing ambiguity."""
    text = "ARG SEMGREP_VERSION=1.117.0\n"
    d = extract(text, Path("/repo/Dockerfile"))[0]
    assert d.pin_style.value == "exact"
    assert d.parser_confidence.level == "high"


def test_builtin_map_contains_no_empty_strings() -> None:
    """Guard against accidental empty-string entries in the
    built-in map — would short-circuit ``eco.strip()`` parsing."""
    for arg, mapping in _BUILTIN_ARG_MAP.items():
        if mapping is None:
            continue
        eco, name = mapping
        assert eco.strip(), f"{arg}: empty ecosystem"
        assert name.strip(), f"{arg}: empty name"


# ---------------------------------------------------------------------------
# Integration with the Dockerfile parser
# ---------------------------------------------------------------------------

def test_pep440_versions_accepted() -> None:
    """PEP440 pre-release / dev shapes (``20.8b1``, ``20.8rc1``,
    ``20.8.dev0``) are valid Python package versions and must be
    accepted. Pre-fix the regex rejected them because it required
    a ``-`` or ``+`` before any alpha suffix."""
    cases = ["20.8b1", "20.8rc1", "20.8.dev0", "1.2.3a1"]
    for v in cases:
        text = f"ARG BLACK_VERSION={v}\n"
        deps = extract(text, Path("/repo/Dockerfile"))
        assert len(deps) == 1, f"failed to extract version {v!r}"
        assert deps[0].version == v


def test_arg_pin_wins_over_placeholder_run_install(tmp_path: Path) -> None:
    """When a Dockerfile both ``ARG FOO_VERSION=1.0`` AND
    ``RUN pip install foo==${FOO_VERSION}``, the RUN scanner emits
    ``foo@${FOO_VERSION}`` (literal placeholder string). The ARG
    extractor emits ``foo@1.0`` (resolved). ``select_canonical_for_osv``
    picks the first manifest row per ``(eco, name)``, so the ARG
    pass must run FIRST in ``parse_dockerfile`` to ensure the
    concrete version wins the dedup.

    Pre-fix: the placeholder won, OSV treated it as "no version"
    and returned all-CVE noise for the package."""
    from packages.sca.parsers.inline_installs import parse_dockerfile
    from packages.sca.pipeline import select_canonical_for_osv
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.12\n"
        "ARG BLACK_VERSION=20.8b1\n"
        "RUN pip install black==${BLACK_VERSION}\n"
    )
    canonical = select_canonical_for_osv(parse_dockerfile(dockerfile))
    black = [d for d in canonical
              if d.ecosystem == "PyPI" and d.name == "black"]
    assert len(black) == 1, (
        f"expected single canonical black dep; got "
        f"{[(d.version, d.source_kind) for d in black]}"
    )
    # The concrete version wins, not the placeholder.
    assert black[0].version == "20.8b1"


def test_parse_dockerfile_includes_arg_pins(tmp_path: Path) -> None:
    """End-to-end: ``parse_dockerfile`` returns the union of apt
    deps, RUN-install deps, AND ARG version pins. Previously the
    union was just the first two — ARGs were dropped."""
    from packages.sca.parsers.inline_installs import parse_dockerfile
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.12-bookworm\n"
        "ARG SEMGREP_VERSION=1.117.0\n"
        "RUN pip install requests==2.31.0\n"
    )
    deps = parse_dockerfile(dockerfile)
    by_name = {d.name: d for d in deps}
    # ARG pin AND inline pip install both surface.
    assert "semgrep" in by_name
    assert "requests" in by_name
    # ARG pin specifically carries source_kind=dockerfile_arg.
    assert by_name["semgrep"].source_kind == "dockerfile_arg"
    assert by_name["semgrep"].scope == "build"
    # The RUN pip install is the existing path; preserves the
    # pre-fix source_kind.
    assert by_name["requests"].source_kind == "dockerfile"
