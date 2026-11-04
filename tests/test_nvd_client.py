import httpx
from CVEVerdict.result import FailureKind
from CVEVerdict.sources.nvd import CachedCve, InMemoryCveCache, NvdClient


def test_invalid_cve_id_rejected_locally():
    client = NvdClient()
    res = client.get_cve("NOT-A-CVE")
    assert res.is_failure
    assert res.kind == FailureKind.INVALID_RESPONSE
    assert "Invalid CVE ID format" in res.message


def test_empty_results_maps_to_not_found(monkeypatch):
    def mock_get(*args, **kwargs):
        return httpx.Response(200, json={"vulnerabilities": []})

    client = NvdClient()
    monkeypatch.setattr(client._http, "get", mock_get)

    res = client.get_cve("CVE-2024-99999")
    assert res.is_failure
    assert res.kind == FailureKind.NOT_FOUND


def test_rate_limit_and_stale_cache_fallback(monkeypatch):
    cache = InMemoryCveCache()
    # Seed cache with an existing record
    existing = CachedCve(
        cve_id="CVE-2023-4863",
        raw_json={"cve": {"id": "CVE-2023-4863"}},
        fetched_at=None,
    )
    cache.set(existing)

    # Force HTTP calls to 429
    def mock_429(*args, **kwargs):
        return httpx.Response(429, headers={"Retry-After": "0"})

    client = NvdClient(cache=cache, max_retries=1)
    monkeypatch.setattr(client._http, "get", mock_429)

    # Force refresh should fail live, but fallback to cached record marked as stale
    res = client.get_cve("CVE-2023-4863", force_refresh=True)
    assert res.is_success
    record = res.unwrap()
    assert record.is_stale is True
    assert "Refresh failed" in record.staleness_reason


def test_timeout_without_cache_returns_failure(monkeypatch):
    def mock_timeout(*args, **kwargs):
        raise httpx.ReadTimeout("Connection timed out")

    client = NvdClient(max_retries=1)
    monkeypatch.setattr(client._http, "get", mock_timeout)

    res = client.get_cve("CVE-2023-4863")
    assert res.is_failure
    assert res.kind == FailureKind.TIMEOUT