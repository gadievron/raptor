"""Tests for core.startup.banner version injection.

The banner asset carries a ``__VERSION__`` placeholder; ``read_logo`` injects
the live version at render time and re-pads the box so the border stays
aligned regardless of the version string's length (a clone's git-describe
string is much longer than a clean release number)."""

from core.startup import banner
from core.config import RaptorConfig
import re
import pytest


@pytest.mark.parametrize('codex,prefix', [(False, '/'), (True, '$')])
@pytest.mark.parametrize('affects', sorted({
    dep['affects'] for dep in RaptorConfig.TOOL_DEPS.values()
} | {group['affects'] for group in RaptorConfig.TOOL_GROUPS.values()}))
def test_all_tool_warning_command_references(affects, codex, prefix):
    warning = affects + ' limited — tool not found'
    output = banner.format_banner('', 'quote', [], [warning], [], [], [], [], codex=codex)
    expected = re.sub(r'/([a-z][a-z-]*)', lambda match: prefix + match[1], warning)
    assert expected in output


def test_codex_warning_preserves_paths():
    warning = '/scan, /agentic limited — /usr/bin/true /scan/config.toml /scan.py /tmp/foo'
    output = banner.format_banner('', 'quote', [], [warning], [], [], [], [], codex=True)
    assert '$scan, $agentic limited — /usr/bin/true /scan/config.toml /scan.py /tmp/foo' in output


@pytest.mark.parametrize('codex,prefix', [(False, '/'), (True, '$')])
def test_host_command_references_preserve_status_and_target_paths(codex, prefix):
    output = banner.format_banner(
        '', 'quote', [], ['/crash-analysis limited — rr not found'], [], [], [],
        ['/oss-forensics unavailable — BigQuery not configured'],
        'Project: corpus (/tmp) — `/project none` to clear for this session',
        codex=codex,
    )
    assert f'{prefix}oss-forensics unavailable — BigQuery not configured' in output
    assert f'{prefix}crash-analysis limited — rr not found' in output
    assert f'`{prefix}project none` to clear for this session' in output
    assert 'Project: corpus (/tmp)' in output


def _version_line(text: str) -> str:
    return next(ln for ln in text.splitlines() if "Based on Claude Code" in ln)


def test_injects_version_with_leading_v_and_preserves_box_width():
    line = _version_line(banner.read_logo("3.0.0-1786-g7fcf38ea"))
    assert "v3.0.0-1786-g7fcf38ea" in line   # leading 'v' added
    assert "__VERSION__" not in line          # placeholder consumed
    assert line.startswith("║") and line.endswith("║")
    assert len(line) == 77                    # box width unchanged


def test_clean_release_number_keeps_box_width():
    line = _version_line(banner.read_logo("3.0.0"))
    assert "v3.0.0" in line
    assert len(line) == 77


def test_does_not_double_the_v_prefix():
    line = _version_line(banner.read_logo("v3.0.0"))
    assert "vv" not in line
    assert "v3.0.0" in line


def test_overlong_version_still_closes_the_box():
    # Pathologically long string: box can't keep width 77 but must stay closed.
    line = _version_line(banner.read_logo("9" * 60))
    assert line.endswith("║")


def test_empty_version_leaves_placeholder_untouched():
    line = _version_line(banner.read_logo(""))
    assert "__VERSION__" in line


class TestToolUpdateFootnote:
    _TOOL_RESULTS = [
        ("afl++", True),
        ("semgrep 1.79.0", True),
        ("z3", True),
    ]

    def test_asterisk_appended_to_updatable_tool(self):
        out = banner.format_banner(
            "", "quote", self._TOOL_RESULTS, [], [], [], [], [],
            tool_updates={"semgrep"},
        )
        assert "semgrep 1.79.0*" in out

    def test_no_asterisk_when_no_updates(self):
        out = banner.format_banner(
            "", "quote", self._TOOL_RESULTS, [], [], [], [], [],
            tool_updates=set(),
        )
        assert "semgrep 1.79.0 ✓" in out
        assert "*" not in out

    def test_non_updatable_tool_unchanged(self):
        out = banner.format_banner(
            "", "quote", self._TOOL_RESULTS, [], [], [], [], [],
            tool_updates={"semgrep"},
        )
        assert "afl++ ✓" in out
        assert "z3 ✓" in out
