# Stage 3 — dry-run preview

## Per-file findings

### `osv.py` (187 LOC) — **clean, skip**

- 2-pass parse (references first, then range events) with documented intent
- `_normalize_repo` handles 4 URL shapes in a clear elif chain
- No simplifications.

### `nvd.py` (214 LOC) — **clean, skip**

- `get_payload` has memory→disk→fetch cascade — clean
- `_fetch_with_retry` handles 429 + Retry-After + exponential backoff. Appropriately complex; well-commented.
- `_read_disk_cache` / `_write_disk_cache` are clean helpers.
- The `_cache_path` shape (`re.sub` to safe filename + `dir / f"{safe}.json"`) is also in `distro_cache.py`. Could be moved to `cve_diff/infra/cache_path.py` shared helper, but cross-module abstraction is overkill for 4 lines.
- No simplifications.

### `distro_cache.py` (182 LOC) — **one real candidate**

`_fetch_debian`, `_fetch_ubuntu`, `_fetch_redhat` all start with the SAME 4-line preamble:

```python
resp = _get(URL.format(cve_id=cve_id))
if isinstance(resp, dict):
    return resp
if resp.status_code != 200:
    return {"error": f"http {resp.status_code}"}
```

That's 12 lines of duplicated boilerplate across the 3 fetchers. Could be a helper:

```python
def _http_or_error(url: str) -> tuple[requests.Response | None, dict[str, Any] | None]:
    """Return (resp, None) on a 200; (None, error_dict) otherwise.

    Centralizes the error-shape contract: ``{"error": "network: ..."}``
    on RequestException (from ``_get``), ``{"error": "http <code>"}`` on
    non-200. Each fetcher then handles only its own parse step.
    """
    resp = _get(url)
    if isinstance(resp, dict):
        return None, resp
    if resp.status_code != 200:
        return None, {"error": f"http {resp.status_code}"}
    return resp, None
```

Then each fetcher reduces to ~3 lines:

```python
def _fetch_debian(cve_id: str) -> dict[str, Any]:
    resp, err = _http_or_error(_DEBIAN_URL.format(cve_id=cve_id))
    if err:
        return err
    body = resp.text[:_MAX_BYTES]
    ...
```

**Net change**: −7 LOC across the file (12 lines deduped, 5-line helper added).

**Risk: low.**
- Error formats (`"http 404"`, `"network: ..."`) are unchanged — tests in `test_distro_cache.py` keying on these strings still pass.
- All 3 fetchers exercised by the same 5 tests; refactoring is uniform.
- `_get` itself is unchanged.

**Value: medium.**
- Clear DRY win. Reading a single fetcher now shows just the parsing logic, not the boilerplate.
- Sets a pattern for future per-distro adders.

---

## Stage 3 verdict

**One simplification to apply:** extract `_http_or_error` from
`distro_cache.py`. ~7 LOC saved, 0 behavior change, 0 risk to tests.

`osv.py` and `nvd.py` are clean — no candidates.

Proceeding to X1 (apply) → X2 (review) → V1-V6 (verify) → commit.
