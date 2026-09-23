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


class TestCrawlerRetainedStateIsBounded:
    """max_pages bounds VISITS and _BS4_MAX_BYTES bounds one parse —
    neither bounds what a single hostile page inflates into retained
    discovery state, which consumers then re-materialise."""

    def _crawler(self, monkeypatch, **caps):
        import packages.web.crawler as crawler_module
        from unittest.mock import MagicMock

        for name, value in caps.items():
            monkeypatch.setattr(crawler_module, name, value, raising=False)
        client = MagicMock()
        client._is_in_scope.return_value = True
        client.reveal_secrets = False
        client.base_url = "http://t.example"
        return crawler_module.WebCrawler(client, max_depth=2, max_pages=100)

    def _response(self, html: str):
        from types import SimpleNamespace

        return SimpleNamespace(
            content=html.encode(),
            headers={"Content-Type": "text/html"},
            status_code=200,
        )

    def test_one_hostile_page_cannot_inflate_discovery_past_the_caps(
        self, monkeypatch,
    ):
        import pytest as pytest_module

        pytest_module.importorskip("bs4")
        from collections import deque

        crawler = self._crawler(
            monkeypatch,
            _MAX_LINKS_PER_PAGE=50,
            _MAX_DISCOVERED_URLS=30,
            _MAX_DISCOVERED_PARAMS=10,
            _MAX_PARAM_URL_FANOUT=5,
        )
        anchors = "".join(
            f'<a href="/p?id={i}&u{i}=x">l</a>' for i in range(500)
        )
        queue: deque = deque()
        crawler._process_html_response(
            "http://t.example/", self._response(anchors), 0, _queue=queue,
        )
        assert len(crawler.discovered_urls) <= 30
        assert len(crawler.discovered_parameters) <= 10
        assert all(
            len(urls) <= 5 for urls in crawler.parameter_urls.values()
        )
        assert len(queue) <= 50

    def test_bfs_queue_dedups_repeated_links(self, monkeypatch):
        import pytest as pytest_module

        pytest_module.importorskip("bs4")
        from collections import deque

        crawler = self._crawler(monkeypatch)
        html = '<a href="/same">a</a>' * 40 + '<a href="/other">b</a>'
        queue: deque = deque()
        crawler._process_html_response(
            "http://t.example/", self._response(html), 0, _queue=queue,
        )
        assert sorted(url for url, _depth in queue) == [
            "http://t.example/other", "http://t.example/same",
        ]


class TestSignalCollectionIsBounded:
    def test_entries_past_the_cap_do_not_feed_the_token_scan(self):
        from packages.web.research_landscape import (
            _MAX_SIGNAL_ITEMS,
            _collect_signals,
        )

        urls = [f"http://t.example/x{i}" for i in range(_MAX_SIGNAL_ITEMS)]
        urls.append("http://t.example/zzz-beyond-cap-marker")
        tokens = _collect_signals(None, {"discovered_urls": urls})
        assert "x0" in tokens
        assert not any("beyond_cap_marker" in t or "beyond-cap-marker" in t
                       for t in tokens)


class TestLandscapeProvenanceClaims:
    def test_archive_years_reviewed_derive_from_cited_sources(self):
        from packages.web.research_landscape import (
            RESEARCH_THEMES,
            assess_research_landscape,
        )

        landscape = assess_research_landscape(
            discovery=None, crawl_data={}, registered_check_ids=[],
        )
        cited = sorted({y for t in RESEARCH_THEMES for y in t.years})
        assert landscape["archive_years_reviewed"] == cited
