from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional, Protocol

import httpx

from CVEVerdict.result import FailureKind, Result, fail, ok

CVE_REGEX = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@dataclass(frozen=True, slots=True)
class CachedCve:
    """Wrapper around raw NVD payload with metadata and staleness tracking."""
    cve_id: str
    raw_json: dict[str, Any]
    fetched_at: datetime
    last_modified: Optional[datetime] = None
    is_stale: bool = False
    staleness_reason: Optional[str] = None


class CveCacheProtocol(Protocol):
    """Protocol for cache backends (file, in-memory, SQLite, or Postgres)."""
    def get(self, cve_id: str) -> Optional[CachedCve]: ...
    def set(self, record: CachedCve) -> None: ...


class InMemoryCveCache:
    """Default lightweight cache for testing and offline development."""
    def __init__(self) -> None:
        self._store: dict[str, CachedCve] = {}

    def get(self, cve_id: str) -> Optional[CachedCve]:
        return self._store.get(cve_id.upper())

    def set(self, record: CachedCve) -> None:
        self._store[record.cve_id.upper()] = record


class NvdClient:
    """Client for NVD API 2.0 with retry, throttling, caching, and stale fallback."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        timeout: float = 10.0,
        max_retries: int = 3,
        backoff_factor: float = 1.5,
        cache: Optional[CveCacheProtocol] = None,
        http_client: Optional[httpx.Client] = None,
    ) -> None:
        self.api_key = api_key or os.getenv("NVD_API_KEY")
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.cache = cache if cache is not None else InMemoryCveCache()
        self._http = http_client or httpx.Client(timeout=self.timeout)

        # Minimum delay between requests to respect NVD limits
        # With key: ~0.6s; without key: ~6.0s
        self.min_interval = 0.6 if self.api_key else 6.0
        self._last_request_time: float = 0.0

    def _throttle(self) -> None:
        elapsed = time.monotonic() - self._last_request_time
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self._last_request_time = time.monotonic()

    def _parse_last_modified(self, raw_cve_item: dict[str, Any]) -> Optional[datetime]:
        """Extract lastModified timestamp from NVD JSON."""
        last_mod_str = raw_cve_item.get("cve", {}).get("lastModified")
        if not last_mod_str:
            return None
        try:
            # Handle ISO formats, e.g., '2023-09-12T15:15:12.345'
            return datetime.fromisoformat(last_mod_str.replace("Z", "+00:00"))
        except ValueError:
            return None

    def get_cve(self, cve_id: str, force_refresh: bool = False) -> Result[CachedCve]:
        normalized_cve = cve_id.strip().upper()

        # 1. Format validation
        if not CVE_REGEX.match(normalized_cve):
            return fail(
                FailureKind.INVALID_RESPONSE,
                f"Invalid CVE ID format: '{cve_id}'. Expected format 'CVE-YYYY-NNNN'.",
            )

        # 2. Cache hit (if not forcing refresh)
        cached_entry = self.cache.get(normalized_cve)
        if cached_entry and not force_refresh:
            return ok(cached_entry)

        # 3. Request setup
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["apiKey"] = self.api_key

        params = {"cveId": normalized_cve}
        delay = 1.0
        last_failure_kind: Optional[FailureKind] = None
        last_error_msg = ""

        # 4. Retry loop
        for attempt in range(self.max_retries + 1):
            try:
                self._throttle()
                resp = self._http.get(NVD_API_BASE_URL, headers=headers, params=params)

                # Check HTTP status
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                    except Exception as e:
                        return fail(FailureKind.INVALID_RESPONSE, f"Corrupted JSON from NVD: {e}")

                    vulnerabilities = data.get("vulnerabilities", [])
                    if not vulnerabilities:
                        return fail(
                            FailureKind.NOT_FOUND,
                            f"CVE '{normalized_cve}' not found in NVD.",
                        )

                    cve_item = vulnerabilities[0]
                    last_mod = self._parse_last_modified(cve_item)
                    record = CachedCve(
                        cve_id=normalized_cve,
                        raw_json=cve_item,
                        fetched_at=datetime.now(timezone.utc),
                        last_modified=last_mod,
                        is_stale=False,
                    )
                    self.cache.set(record)
                    return ok(record)

                if resp.status_code == 404:
                    return fail(FailureKind.NOT_FOUND, f"CVE '{normalized_cve}' not found (HTTP 404).")

                if resp.status_code == 429:
                    last_failure_kind = FailureKind.RATE_LIMITED
                    retry_after = resp.headers.get("Retry-After")
                    sleep_time = float(retry_after) if retry_after and retry_after.isdigit() else delay
                    last_error_msg = f"NVD rate limited (HTTP 429) on attempt {attempt + 1}"
                    if attempt < self.max_retries:
                        time.sleep(sleep_time)
                        delay *= self.backoff_factor
                        continue

                elif resp.status_code >= 500:
                    last_failure_kind = FailureKind.NETWORK
                    last_error_msg = f"NVD server error HTTP {resp.status_code} on attempt {attempt + 1}"
                    if attempt < self.max_retries:
                        time.sleep(delay)
                        delay *= self.backoff_factor
                        continue
                else:
                    # 4xx client errors that should NOT be retried
                    return fail(
                        FailureKind.INVALID_RESPONSE,
                        f"NVD returned unexpected HTTP {resp.status_code}: {resp.text[:200]}",
                    )

            except httpx.TimeoutException:
                last_failure_kind = FailureKind.TIMEOUT
                last_error_msg = f"NVD request timed out after {self.timeout}s on attempt {attempt + 1}"
                if attempt < self.max_retries:
                    time.sleep(delay)
                    delay *= self.backoff_factor
                    continue

            except httpx.RequestError as exc:
                last_failure_kind = FailureKind.NETWORK
                last_error_msg = f"Network connection error: {exc}"
                if attempt < self.max_retries:
                    time.sleep(delay)
                    delay *= self.backoff_factor
                    continue

        # 5. Stale cache fallback if all retries failed
        if cached_entry:
            stale_record = CachedCve(
                cve_id=cached_entry.cve_id,
                raw_json=cached_entry.raw_json,
                fetched_at=cached_entry.fetched_at,
                last_modified=cached_entry.last_modified,
                is_stale=True,
                staleness_reason=f"Refresh failed: {last_error_msg}",
            )
            return ok(stale_record)

        return fail(
            last_failure_kind or FailureKind.NETWORK,
            last_error_msg or "Failed to retrieve CVE after retries.",
        )