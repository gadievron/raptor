"""Discovery parsers face one hostile response with no budget in front
of them: retained state and per-line work must be bounded. No network."""

from __future__ import annotations

import time

from packages.web.discovery.robots import (
    _MAX_PARSE_BYTES,
    _MAX_PATHS,
    _parse_disallow,
)


class TestRobotsDisallowParseIsBounded:
    def test_semantics_unchanged_on_normal_input(self):
        text = (
            "User-agent: *\n"
            "Disallow: /admin\n"
            "Disallow: /admin\n"          # duplicate collapses
            "Disallow: /\n"               # root skipped
            "Disallow: /tmp/*.log\n"      # wildcard stripped to base
            "Disallow: /search?\n"        # trailing ? stripped
            "Sitemap: https://t.example/sitemap.xml\n"
        )
        assert _parse_disallow(text) == ["/admin", "/tmp/", "/search"]

    def test_hostile_line_count_is_linear_and_path_capped(self):
        # One served-to-order robots.txt wedged Phase 2 for hours:
        # list-membership dedup made the parse O(n^2) and nothing
        # capped the retained path list. 60k unique Disallow lines must
        # parse in linear time and retain at most _MAX_PATHS.
        text = "\n".join(f"Disallow: /p{i}" for i in range(60_000))
        start = time.monotonic()
        paths = _parse_disallow(text)
        elapsed = time.monotonic() - start
        assert len(paths) <= _MAX_PATHS
        assert paths[0] == "/p0"
        assert elapsed < 3.0, f"parse took {elapsed:.1f}s — quadratic again?"

    def test_oversized_input_is_truncated_before_parsing(self):
        filler = "Disallow: /kept\n" * 4
        text = filler + ("#" + "x" * 1024 + "\n") * (
            _MAX_PARSE_BYTES // 1024 + 16
        ) + "Disallow: /past-the-cap\n"
        paths = _parse_disallow(text)
        assert "/kept" in paths
        assert "/past-the-cap" not in paths
