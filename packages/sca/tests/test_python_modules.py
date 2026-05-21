"""Tests for ``packages.sca.python_modules.resolve_modules``.

Mocks the HttpClient at the boundary so no real PyPI / pythonhosted
traffic fires. The wheel-metadata extraction is tested against a
real ZIP synthesised in-memory (``zipfile`` writing to ``BytesIO``),
served back via fake HTTP Range responses to exercise the
``_RangedHTTPFile`` adapter.
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


from core.http import HttpError, Response
from packages.sca.python_modules import resolve_modules


# ---------------------------------------------------------------------------
# Test fixtures: synthesise a real .whl in-memory
# ---------------------------------------------------------------------------

def _make_wheel(
    *, dist: str, version: str, top_level_lines: List[str],
    extra_files: Optional[Dict[str, bytes]] = None,
) -> bytes:
    """Build a minimal wheel as ZIP bytes."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # Required dist-info entries.
        zf.writestr(f"{dist}-{version}.dist-info/METADATA",
                    f"Metadata-Version: 2.1\nName: {dist}\nVersion: {version}\n")
        zf.writestr(f"{dist}-{version}.dist-info/top_level.txt",
                    "\n".join(top_level_lines) + "\n")
        zf.writestr(f"{dist}-{version}.dist-info/WHEEL",
                    "Wheel-Version: 1.0\n")
        for name, body in (extra_files or {}).items():
            zf.writestr(name, body)
    return buf.getvalue()


class _FakeHttp:
    """Minimal HttpClient stub: serves PyPI JSON for ``get_json`` and
    HTTP Range slices of a single wheel via ``request("GET", ...)``."""

    def __init__(
        self, *, pypi_json: Dict[str, Any], wheel_url: str,
        wheel_bytes: bytes, honour_range: bool = True,
    ) -> None:
        self._pypi = pypi_json
        self._wheel_url = wheel_url
        self._wheel_bytes = wheel_bytes
        self._honour_range = honour_range
        self.requests: List[Tuple[str, Optional[str]]] = []

    def get_json(self, url: str, *args, **kwargs) -> Dict[str, Any]:
        self.requests.append((url, None))
        if "/pypi/" in url:
            return self._pypi
        raise HttpError(f"unexpected get_json: {url}")

    def request(
        self, method: str, url: str, *,
        headers: Optional[Dict[str, str]] = None, **kwargs,
    ) -> Response:
        rng = (headers or {}).get("Range")
        self.requests.append((url, rng))
        if url != self._wheel_url:
            raise HttpError(f"unexpected URL: {url}")
        if rng is None:
            return Response(
                status=200, headers={}, body=self._wheel_bytes, url=url)
        if not self._honour_range:
            # Server ignored Range — return full body with 200.
            return Response(
                status=200, headers={}, body=self._wheel_bytes, url=url)
        # Parse "bytes=A-B" (B is inclusive).
        prefix = "bytes="
        assert rng.startswith(prefix), f"unexpected Range: {rng}"
        a_s, b_s = rng[len(prefix):].split("-", 1)
        a = int(a_s)
        b = int(b_s) if b_s else len(self._wheel_bytes) - 1
        body = self._wheel_bytes[a:b + 1]
        return Response(status=206, headers={}, body=body, url=url)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_resolves_modules_from_top_level_txt():
    wheel = _make_wheel(
        dist="myapp", version="1.0.0",
        top_level_lines=["myapp", "myapp_internal"],
    )
    pypi = {
        "urls": [
            {"packagetype": "bdist_wheel",
             "url": "https://files.example/myapp-1.0.0-py3-none-any.whl",
             "size": len(wheel)},
        ],
    }
    http = _FakeHttp(
        pypi_json=pypi,
        wheel_url=pypi["urls"][0]["url"],
        wheel_bytes=wheel,
    )
    out = resolve_modules("myapp", "1.0.0", http=http)
    assert out == ("myapp", "myapp_internal")


def test_skips_sdist_only_releases():
    """A release with no bdist_wheel returns None — no module resolution
    possible from sdists without actually building the package."""
    pypi = {"urls": [
        {"packagetype": "sdist",
         "url": "https://files.example/myapp-1.0.0.tar.gz", "size": 12345},
    ]}
    http = _FakeHttp(pypi_json=pypi, wheel_url="", wheel_bytes=b"")
    assert resolve_modules("myapp", "1.0.0", http=http) is None


def test_picks_smallest_wheel_when_multiple_available():
    """For a multi-platform release we want the smallest wheel —
    typically the pure-py3-none-any one — to minimise bytes fetched."""
    wheel = _make_wheel(
        dist="myapp", version="1.0.0", top_level_lines=["myapp"])
    big_url = "https://files.example/myapp-1.0.0-cp39-linux_x86_64.whl"
    small_url = "https://files.example/myapp-1.0.0-py3-none-any.whl"
    pypi = {"urls": [
        {"packagetype": "bdist_wheel", "url": big_url, "size": 50_000_000},
        {"packagetype": "bdist_wheel", "url": small_url,
         "size": len(wheel)},
    ]}
    http = _FakeHttp(
        pypi_json=pypi, wheel_url=small_url, wheel_bytes=wheel)
    assert resolve_modules("myapp", "1.0.0", http=http) == ("myapp",)


def test_skips_wheels_over_size_cap():
    """A wheel larger than ``max_wheel_bytes`` is skipped — pathological
    cases (TF, PyTorch) shouldn't burn budget on metadata fetch."""
    pypi = {"urls": [
        {"packagetype": "bdist_wheel",
         "url": "https://files.example/big.whl",
         "size": 500 * 1024 * 1024},   # 500 MB
    ]}
    http = _FakeHttp(pypi_json=pypi, wheel_url="", wheel_bytes=b"")
    out = resolve_modules(
        "big", "1.0.0", http=http,
        max_wheel_bytes=200 * 1024 * 1024,
    )
    assert out is None


def test_returns_none_when_server_does_not_honour_range():
    """If the wheel CDN ignores Range headers, the partial-fetch parse
    is invalid (offsets don't line up). Detect via 200 response and
    abort with None — never silently corrupt the result."""
    wheel = _make_wheel(
        dist="myapp", version="1.0.0", top_level_lines=["myapp"])
    pypi = {"urls": [
        {"packagetype": "bdist_wheel",
         "url": "https://files.example/myapp.whl", "size": len(wheel)},
    ]}
    http = _FakeHttp(
        pypi_json=pypi, wheel_url=pypi["urls"][0]["url"],
        wheel_bytes=wheel, honour_range=False,
    )
    assert resolve_modules("myapp", "1.0.0", http=http) is None


def test_caches_successful_result_forever(tmp_path: Path):
    """Same ``(dist, version)`` queried twice should hit network once.
    PyPI versions are immutable — caching forever is correct."""
    from core.json import JsonCache
    wheel = _make_wheel(
        dist="myapp", version="1.0.0", top_level_lines=["myapp"])
    pypi = {"urls": [
        {"packagetype": "bdist_wheel",
         "url": "https://files.example/myapp.whl", "size": len(wheel)},
    ]}
    http = _FakeHttp(
        pypi_json=pypi, wheel_url=pypi["urls"][0]["url"], wheel_bytes=wheel)
    cache = JsonCache(root=tmp_path / "cache")
    assert resolve_modules("myapp", "1.0.0", http=http, cache=cache) == ("myapp",)
    n_after_first = len(http.requests)
    # Second call: should not hit the network at all.
    assert resolve_modules("myapp", "1.0.0", http=http, cache=cache) == ("myapp",)
    assert len(http.requests) == n_after_first, (
        f"expected cache hit, but {len(http.requests) - n_after_first} "
        f"new HTTP request(s) fired"
    )


def test_caches_negative_result_forever(tmp_path: Path):
    """An sdist-only release won't grow a wheel later. Cache the None
    result so subsequent runs don't re-fetch the PyPI metadata."""
    from core.json import JsonCache
    pypi = {"urls": [
        {"packagetype": "sdist",
         "url": "https://files.example/x.tar.gz", "size": 1000},
    ]}
    http = _FakeHttp(pypi_json=pypi, wheel_url="", wheel_bytes=b"")
    cache = JsonCache(root=tmp_path / "cache")
    assert resolve_modules("x", "1.0", http=http, cache=cache) is None
    n_after_first = len(http.requests)
    assert resolve_modules("x", "1.0", http=http, cache=cache) is None
    assert len(http.requests) == n_after_first


def test_pypi_metadata_error_returns_none():
    class _Failing:
        def get_json(self, url, *a, **kw):
            raise HttpError("upstream 503")
        def request(self, *a, **kw):
            raise AssertionError("should not be reached")
    assert resolve_modules("myapp", "1.0", http=_Failing()) is None


def test_top_level_txt_missing_returns_none():
    """Some wheels (rare, but valid PEP 491) have a METADATA file but
    no top_level.txt. Our parser treats that as "can't resolve" rather
    than guessing — caller falls back to PEP 503 heuristic."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("myapp-1.0.0.dist-info/METADATA",
                    "Metadata-Version: 2.1\nName: myapp\nVersion: 1.0.0\n")
        zf.writestr("myapp-1.0.0.dist-info/WHEEL", "Wheel-Version: 1.0\n")
    wheel = buf.getvalue()
    pypi = {"urls": [
        {"packagetype": "bdist_wheel",
         "url": "https://files.example/myapp.whl", "size": len(wheel)},
    ]}
    http = _FakeHttp(
        pypi_json=pypi, wheel_url=pypi["urls"][0]["url"], wheel_bytes=wheel)
    assert resolve_modules("myapp", "1.0.0", http=http) is None


def test_partial_fetch_minimises_bytes_pulled():
    """The whole point of Range fetch: we should NOT have downloaded
    the entire wheel. Each ``request`` call's Range header carves out
    a slice; sum-of-slices on success should be a fraction of the
    wheel size."""
    # Build a wheel padded with a chunky no-op file so its size is
    # large enough that "we pulled <half" is a meaningful assertion.
    chunky = {"data/big.bin": b"\x00" * 200_000}
    wheel = _make_wheel(
        dist="myapp", version="1.0.0", top_level_lines=["myapp"],
        extra_files=chunky,
    )
    pypi = {"urls": [
        {"packagetype": "bdist_wheel",
         "url": "https://files.example/myapp.whl", "size": len(wheel)},
    ]}
    http = _FakeHttp(
        pypi_json=pypi, wheel_url=pypi["urls"][0]["url"], wheel_bytes=wheel)

    # Track total bytes returned across Range calls.
    real_request = http.request
    total_bytes = [0]

    def tracking(method: str, url: str, **kwargs):
        resp = real_request(method, url, **kwargs)
        total_bytes[0] += len(resp.body)
        return resp

    http.request = tracking      # type: ignore[assignment]
    resolve_modules("myapp", "1.0.0", http=http)
    # Sanity: we pulled less than the whole wheel.
    assert total_bytes[0] < len(wheel), (
        f"pulled {total_bytes[0]} of {len(wheel)} — Range fetch did "
        f"not actually save bytes"
    )
