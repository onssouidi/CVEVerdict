from __future__ import annotations

import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

from CVEVerdict.result import FailureKind, Result, fail, ok

KEV_FEED_URL = os.getenv("KEV_FEED_URL")

@dataclass(frozen=True, slots=True)
class KevEntry:
    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: str
    required_action: str
    due_date: Optional[str] = None
    notes: Optional[str] = None


class CisaKevClient:
    """Client for CISA Known Exploited Vulnerabilities catalog with daily caching."""

    def __init__(
        self,
        timeout: float = 10.0,
        cache_ttl_seconds: int = 86400,  # 24 hours
        http_client: Optional[httpx.Client] = None,
    ) -> None:
        self.timeout = timeout
        self.cache_ttl = cache_ttl_seconds
        self._http = http_client or httpx.Client(timeout=self.timeout)
        self._catalog: dict[str, KevEntry] = {}
        self._last_fetched: float = 0.0

    def refresh_catalog(self) -> Result[int]:
        """Downloads and caches the full CISA KEV JSON catalog."""
        try:
            resp = self._http.get(KEV_FEED_URL)
            if resp.status_code != 200:
                return fail(
                    FailureKind.NETWORK,
                    f"CISA KEV feed returned HTTP {resp.status_code}",
                )

            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            new_catalog: dict[str, KevEntry] = {}

            for v in vulns:
                cve_id = v.get("cveID", "").upper()
                if cve_id:
                    new_catalog[cve_id] = KevEntry(
                        cve_id=cve_id,
                        vendor_project=v.get("vendorProject", ""),
                        product=v.get("product", ""),
                        vulnerability_name=v.get("vulnerabilityName", ""),
                        date_added=v.get("dateAdded", ""),
                        required_action=v.get("requiredAction", ""),
                        due_date=v.get("dueDate"),
                        notes=v.get("notes"),
                    )

            self._catalog = new_catalog
            self._last_fetched = time.monotonic()
            return ok(len(new_catalog))

        except httpx.TimeoutException:
            return fail(FailureKind.TIMEOUT, f"CISA KEV timed out after {self.timeout}s")
        except httpx.RequestError as exc:
            return fail(FailureKind.NETWORK, f"CISA KEV request error: {exc}")
        except Exception as exc:
            return fail(FailureKind.INVALID_RESPONSE, f"Failed parsing CISA KEV JSON: {exc}")

    def check_cve(self, cve_id: str) -> Result[Optional[KevEntry]]:
        """Checks if a CVE exists in the KEV catalog."""
        # Refresh if empty or cache expired
        if not self._catalog or (time.monotonic() - self._last_fetched > self.cache_ttl):
            refresh_res = self.refresh_catalog()
            if refresh_res.is_failure and not self._catalog:
                # If refresh failed and we have no cached catalog, return Failure
                return fail(refresh_res.kind, refresh_res.message)

        normalized = cve_id.strip().upper()
        return ok(self._catalog.get(normalized))