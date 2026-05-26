"""Tests for ``packages.sca.clean_cache``.

The ``raptor-sca clean-cache`` subcommand replaces the legacy
``raptor-sca-gate --clean-cache`` mode. Verifies arg validation and
the eviction call surface.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch


from packages.sca import clean_cache


def test_negative_max_age_returns_2(capsys):
    rc = clean_cache.main(["--max-age", "-1"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "must be positive" in err


def test_zero_max_age_returns_2(capsys):
    rc = clean_cache.main(["--max-age", "0"])
    assert rc == 2


def test_default_max_age_uses_module_default(capsys, tmp_path):
    """When --max-age is omitted, the eviction call uses the package
    default. Just verify it doesn't error and reports something."""
    # Mock evict_stale to avoid touching the real cache.
    fake_result = MagicMock(
        files_removed=0, files_scanned=0, dirs_removed=0,
        bytes_freed=0, errors=0,
    )
    with patch("packages.sca.clean_cache.evict_stale",
               return_value=fake_result) as m:
        rc = clean_cache.main(["--cache-root", str(tmp_path)])
    assert rc == 0
    # evict_stale called once with cache_root + a positive max_age.
    assert m.call_count == 1
    args, kwargs = m.call_args
    assert args[0] == tmp_path
    assert kwargs["max_age_days"] > 0


def test_eviction_failure_returns_3(capsys, tmp_path):
    """OSError / RuntimeError from evict_stale → exit 3."""
    with patch("packages.sca.clean_cache.evict_stale",
               side_effect=OSError("disk gone")):
        rc = clean_cache.main(["--cache-root", str(tmp_path)])
    assert rc == 3
    err = capsys.readouterr().err
    assert "cache eviction failed" in err
    assert "disk gone" in err


def test_reports_cleaned_count(capsys, tmp_path):
    """Output prints the eviction stats."""
    fake_result = MagicMock(
        files_removed=42, files_scanned=100, dirs_removed=3,
        bytes_freed=1024 * 1024 * 5,  # 5 MiB
        errors=0,
    )
    with patch("packages.sca.clean_cache.evict_stale",
               return_value=fake_result):
        rc = clean_cache.main(["--cache-root", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "42/100" in out
    assert "5.0 MB" in out
