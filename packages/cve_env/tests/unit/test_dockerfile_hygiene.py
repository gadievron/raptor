"""Tests for the LLM-output sanitization utilities (cve_env.utils.dockerfile_hygiene).

Phase 59.4 — closes the 44.7% coverage gap on dockerfile_hygiene.py.
This module wraps EVERY piece of LLM-produced Dockerfile or JSON before
it touches disk, so its correctness is load-bearing for build-time
safety. Tests cover all 3 public functions + the 3 private helpers
(_check_from_line, _check_run_line, _check_copy_line).
"""

from __future__ import annotations

from cve_env.utils.dockerfile_hygiene import (
    _EMPTY_LABEL_MARKER,
    _check_copy_line,
    _check_from_line,
    _check_run_line,
    robust_json_parse,
    sanitize_dockerfile,
    validate_dockerfile_semantics,
)

# ─── robust_json_parse ───────────────────────────────────────────────────


def test_robust_json_parse_clean_json_returns_dict() -> None:
    assert robust_json_parse('{"key": "value"}') == {"key": "value"}


def test_robust_json_parse_empty_string_returns_none() -> None:
    assert robust_json_parse("") is None


def test_robust_json_parse_non_string_returns_none() -> None:
    # Type-narrow check: function explicitly handles None as input.
    assert robust_json_parse(None) is None  # type: ignore[arg-type]


def test_robust_json_parse_recovers_from_markdown_json_fence() -> None:
    text = 'Here is the JSON:\n```json\n{"a": 1}\n```\n'
    assert robust_json_parse(text) == {"a": 1}


def test_robust_json_parse_recovers_from_plain_code_fence() -> None:
    text = 'Look at this:\n```\n{"a": 1}\n```'
    assert robust_json_parse(text) == {"a": 1}


def test_robust_json_parse_recovers_from_surrounding_prose() -> None:
    text = 'The agent said: {"action": "build"} and proceeded.'
    assert robust_json_parse(text) == {"action": "build"}


def test_robust_json_parse_recovers_from_trailing_comma_in_object() -> None:
    text = '{"a": 1, "b": 2,}'
    assert robust_json_parse(text) == {"a": 1, "b": 2}


def test_robust_json_parse_recovers_from_trailing_comma_in_array() -> None:
    text = '{"items": [1, 2, 3,]}'
    assert robust_json_parse(text) == {"items": [1, 2, 3]}


def test_robust_json_parse_strips_control_chars() -> None:
    # Stray \x01 in the middle of a value
    text = '{"key": "val\x01ue"}'
    result = robust_json_parse(text)
    assert result == {"key": "value"}


def test_robust_json_parse_returns_none_for_non_dict_top_level() -> None:
    # Top-level array, not dict → return None per contract
    assert robust_json_parse("[1, 2, 3]") is None


def test_robust_json_parse_returns_none_for_unrecoverable_garbage() -> None:
    assert robust_json_parse("just plain text no json here") is None


def test_robust_json_parse_returns_none_for_no_braces_at_all() -> None:
    assert robust_json_parse("plain text without braces") is None


# ─── sanitize_dockerfile ─────────────────────────────────────────────────


def test_sanitize_dockerfile_empty_returns_empty() -> None:
    assert sanitize_dockerfile("") == ""


def test_sanitize_dockerfile_collapses_quadruple_backslash() -> None:
    text = "RUN echo \\\\\\\\hello"
    result = sanitize_dockerfile(text)
    # Four+ backslashes collapse to single
    assert "\\\\\\\\" not in result


def test_sanitize_dockerfile_preserves_clean_dockerfile() -> None:
    clean = "FROM alpine:3.19\nRUN apk add --no-cache curl\n"
    assert sanitize_dockerfile(clean) == clean


def test_sanitize_dockerfile_marks_malformed_label_without_equals() -> None:
    text = "FROM alpine:3.19\nLABEL malformed-no-equals\n"
    result = sanitize_dockerfile(text)
    assert _EMPTY_LABEL_MARKER in result


def test_sanitize_dockerfile_keeps_valid_label() -> None:
    text = 'FROM alpine:3.19\nLABEL maintainer="user@example.com"\n'
    result = sanitize_dockerfile(text)
    assert _EMPTY_LABEL_MARKER not in result


# ─── _check_from_line ────────────────────────────────────────────────────


def test_check_from_line_clean_image_returns_no_issues() -> None:
    images: list[str] = []
    issues = _check_from_line("FROM nginx:1.20", images)
    assert issues == []
    assert images == ["nginx:1.20"]


def test_check_from_line_with_platform_flag_skips_flag() -> None:
    images: list[str] = []
    issues = _check_from_line("FROM --platform=linux/arm64 alpine:3.19", images)
    assert issues == []
    assert images == ["alpine:3.19"]


def test_check_from_line_missing_image_name_returns_issue() -> None:
    images: list[str] = []
    issues = _check_from_line("FROM --platform=linux/arm64", images)
    assert len(issues) == 1
    assert "missing image name" in issues[0]


def test_check_from_line_path_prefix_returns_issue() -> None:
    images: list[str] = []
    issues = _check_from_line("FROM ./localpath", images)
    assert len(issues) == 1
    assert "looks like a path" in issues[0]


def test_check_from_line_forbidden_latest_tag_returns_p14() -> None:
    images: list[str] = []
    issues = _check_from_line("FROM nginx:latest", images)
    assert len(issues) == 1
    assert "P14" in issues[0]
    assert "latest" in issues[0]


def test_check_from_line_digest_pinned_image_no_issues() -> None:
    images: list[str] = []
    # digest-pinned (sha256:...) — the @ sign disables the tag check
    digest_ref = "FROM alpine@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    issues = _check_from_line(digest_ref, images)
    assert issues == []


def test_phase61_check_from_line_rejects_latest_tag_with_digest_suffix() -> None:
    """Phase 61.3 — ``FROM nginx:latest@sha256:<digest>`` must be rejected.

    Pre-fix: rsplit(":", 1)[1] looked at the digest, never saw ``latest``.
    Post-fix: strip ``@sha256:.*`` first so the tag is correctly parsed.
    """
    images: list[str] = []
    digest = "a" * 64
    issues = _check_from_line(f"FROM nginx:latest@sha256:{digest}", images)
    assert any("P14" in i and "latest" in i for i in issues), (
        f"P14 must reject :latest@sha256:... in FROM, got {issues!r}"
    )


def test_phase61_check_from_line_rejects_nightly_tag_with_digest_suffix() -> None:
    images: list[str] = []
    digest = "b" * 64
    issues = _check_from_line(f"FROM myapp:nightly@sha256:{digest}", images)
    assert any("P14" in i and "nightly" in i for i in issues), (
        f"P14 must reject :nightly@sha256:... in FROM, got {issues!r}"
    )


def test_check_from_line_rejects_latest_hidden_behind_double_digest() -> None:
    """Security hardening — stacked ``@sha256:`` digests must not hide a tag.

    Pre-fix the single-digest strip removed only the trailing digest, leaving
    ``nginx:latest@sha256:<64>`` whose tag check still failed; the ``(?:...)+``
    strip removes all of them so ``:latest`` is seen and rejected.
    """
    images: list[str] = []
    digest = "a" * 64
    issues = _check_from_line(
        f"FROM nginx:latest@sha256:{digest}@sha256:{digest}", images
    )
    assert any("P14" in i and "latest" in i for i in issues), (
        f"P14 must see :latest behind stacked digests in FROM, got {issues!r}"
    )


# ─── _check_run_line ─────────────────────────────────────────────────────


def test_check_run_line_normal_command_no_issues() -> None:
    assert _check_run_line("RUN apk add curl") == []


def test_check_run_line_empty_run_returns_issue() -> None:
    issues = _check_run_line("RUN ")
    assert len(issues) == 1
    assert "empty RUN" in issues[0]


def test_check_run_line_run_with_only_continuation_returns_issue() -> None:
    issues = _check_run_line("RUN \\")
    assert len(issues) == 1


# ─── _check_copy_line ────────────────────────────────────────────────────


def test_check_copy_line_clean_no_issues() -> None:
    assert _check_copy_line("COPY src/ /app/") == []


def test_check_copy_line_only_one_arg_returns_issue() -> None:
    issues = _check_copy_line("COPY src")
    assert len(issues) == 1
    assert "needs source and destination" in issues[0]


# ─── validate_dockerfile_semantics ───────────────────────────────────────


def test_validate_dockerfile_semantics_no_from_returns_issue() -> None:
    issues = validate_dockerfile_semantics("RUN echo hello\n")
    assert any("no FROM" in i for i in issues)


def test_validate_dockerfile_semantics_clean_dockerfile_no_issues() -> None:
    text = "FROM alpine:3.19\nRUN apk add --no-cache curl\nCOPY app /app\n"
    issues = validate_dockerfile_semantics(text)
    assert issues == []


def test_validate_dockerfile_semantics_latest_tag_returns_p14() -> None:
    text = "FROM nginx:latest\n"
    issues = validate_dockerfile_semantics(text)
    assert any("P14" in i for i in issues)


def test_validate_dockerfile_semantics_empty_run_returns_issue() -> None:
    text = "FROM alpine:3.19\nRUN \n"
    issues = validate_dockerfile_semantics(text)
    assert any("empty RUN" in i for i in issues)


def test_validate_dockerfile_semantics_unresolved_label_marker_returns_issue() -> None:
    # Simulates output from sanitize_dockerfile that wasn't fixed by user
    text = f"FROM alpine:3.19\n{_EMPTY_LABEL_MARKER}LABEL bad\n"
    issues = validate_dockerfile_semantics(text)
    assert any("unresolved malformed LABEL" in i for i in issues)


def test_validate_dockerfile_semantics_copy_missing_dest_returns_issue() -> None:
    text = "FROM alpine:3.19\nCOPY src\n"
    issues = validate_dockerfile_semantics(text)
    assert any("needs source and destination" in i for i in issues)


def test_validate_dockerfile_semantics_add_missing_dest_returns_issue() -> None:
    # ADD has the same shape as COPY
    text = "FROM alpine:3.19\nADD file.tar\n"
    issues = validate_dockerfile_semantics(text)
    assert any("needs source and destination" in i for i in issues)


def test_validate_dockerfile_semantics_round_trip_with_sanitize() -> None:
    """sanitize_dockerfile → validate_dockerfile_semantics flows together."""
    raw = "FROM alpine:3.19\nLABEL bad-label-no-equals\nRUN echo hi\n"
    sanitized = sanitize_dockerfile(raw)
    issues = validate_dockerfile_semantics(sanitized)
    # The sanitized version flags the malformed label as unresolved
    assert any("unresolved malformed LABEL" in i for i in issues)


# -- Phase 67.0 TDD safety net ------------------------------------------------
# Phase 67 audit issue #14 (severity 6): _check_run_line treats each line
# in isolation. A multi-line continuation like ``RUN \\\n    apt-get ...\n``
# has a first physical line of just ``RUN \`` which the current validator
# flags as ``empty RUN command`` (false positive — the command continues
# on the next line). Phase 67.2 will merge backslash-continuation lines
# before per-line classification.


from cve_env.utils.dockerfile_hygiene import (  # noqa: E402
    validate_dockerfile_semantics as _phase67_validate,
)


def test_phase67_validate_dockerfile_handles_multiline_run_continuation() -> None:
    """Phase 67.2 contract: a multi-line ``RUN`` with backslash continuation
    is a single logical command. The validator must NOT flag the first
    physical line ``RUN \\`` as ``empty RUN command``.

    Forensic motivation: agents legitimately split long RUN commands across
    multiple lines for readability. Today the validator false-positives on
    every such Dockerfile, forcing dockerfile_gen to emit single-line RUNs.
    """
    text = (
        "FROM ubuntu:22.04@sha256:" + "a" * 64 + "\n"
        "RUN \\\n"
        "    apt-get update \\\n"
        "    && apt-get install -y curl \\\n"
        "    && rm -rf /var/lib/apt/lists/*\n"
    )
    issues = _phase67_validate(text)
    bad = [i for i in issues if "empty RUN" in i]
    assert not bad, (
        f"multi-line RUN with backslash continuation falsely flagged as empty: {bad!r}"
    )
