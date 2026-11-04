"""Descriptor path parsing refuses malformed text without raising."""
import sys

import pytest

from core.sandbox.evidence import fd_path, parse_fd_path


@pytest.mark.parametrize('prefix', ['/proc/self/fd/', '/dev/fd/'])
@pytest.mark.parametrize('tail', ['', '-1', '+3', ' 3', '3 ', '3/other',
                                  '3\n', '\u00b2', '\u0663', '１２'])
def test_noncanonical_descriptor_text_is_refused(prefix, tail):
    assert parse_fd_path(prefix + tail) is None


@pytest.mark.parametrize('platform', ['linux', 'darwin'])
@pytest.mark.parametrize('fd', [0, 1, 2, 19, 1024])
def test_generated_paths_round_trip(platform, fd):
    assert parse_fd_path(fd_path(fd, platform=platform)) == fd


@pytest.mark.parametrize('prefix', ['/proc/self/fd/', '/dev/fd/'])
def test_oversized_decimal_conversion_is_refused(prefix):
    if not hasattr(sys, 'get_int_max_str_digits'):
        pytest.skip('Python does not limit decimal conversion')
    limit = sys.get_int_max_str_digits()
    if not limit:
        pytest.skip('decimal conversion limit is disabled')
    assert parse_fd_path(prefix + '9' * (limit + 1)) is None


@pytest.mark.parametrize('path', ['/proc/123/fd/3', '/tmp/fd/3', '3'])
def test_unrelated_paths_are_refused(path):
    assert parse_fd_path(path) is None
