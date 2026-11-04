"""Formatting valid integer counts cannot abort egress finalization."""
import json

import pytest

from core.sandbox import egress_summary as egress


@pytest.mark.parametrize('count', [0, 1, 1023, 1024, 1280, 1536, 1792,
                                  1024 * 1024 - 1, 1024 * 1024,
                                  1280 * 1024, 1792 * 1024, 10 ** 12])
def test_format_matches_existing_units_and_rounding(count):
    if count < 1024:
        expected = f'{count} B'
    elif count < 1024 * 1024:
        expected = f'{count / 1024:.1f} KiB'
    else:
        expected = f'{count / (1024 * 1024):.1f} MiB'
    assert egress._format_bytes(count) == expected


def test_large_integer_formats_without_float_conversion():
    count = (10 ** 400) * 1024 * 1024
    assert egress._format_bytes(count) == str(10 ** 400) + '.0 MiB'


def test_large_integer_count_survives_finalization(tmp_path):
    count = 10 ** 400
    event = {'result': 'allowed', 'host': 'example.test', 'port': 443,
             'bytes_u2c': count, 'bytes_c2u': count}
    (tmp_path / egress.PROXY_EVENTS_FILENAME).write_text(json.dumps(event) + '\n')
    result = egress.finalize_egress_summary(tmp_path)
    assert result is not None
    assert result['total_bytes_in'] == count
    assert result['total_bytes_out'] == count
    saved = json.loads((tmp_path / egress.EGRESS_SUMMARY_FILE).read_text())
    assert saved == result
