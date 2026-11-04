from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Optional

import httpx

from CVEVerdict.result import FailureKind, Result, fail, ok

EPSS_API_URL = os.getenv("EPSS_API_URL")


@dataclass(frozen=True, slots=True)
class EpssScore:
    cve_id: str
    probability: float  # 0.0 to 1.0 (e.g. 0.9412)
    percentile: float   # 0.0 to 1.0 (e.g. 0.9981)
    date: str


class FirstEpssClient:
    """Client for FIRST EPSS API with timeout and error handling."""

    def __init__(
        self,
        timeout: float = 10.0,
        http_client: Optional[httpx.Client] = None,
    ) -> None:
        self.timeout = timeout
        self._http = http_client or httpx.Client(timeout=self.timeout)

    def get_score(self, cve_id: str) -> Result[Optional[EpssScore]]:
        normalized = cve_id.strip().upper()
        try:
            resp = self._http.get(EPSS_API_URL, params={"cve": normalized})
            if resp.status_code == 429:
                return fail(FailureKind.RATE_LIMITED, "FIRST EPSS rate limited (HTTP 429)")
            if resp.status_code >= 500:
                return fail(FailureKind.NETWORK, f"FIRST EPSS server error HTTP {resp.status_code}")
            if resp.status_code != 200:
                return fail(FailureKind.INVALID_RESPONSE, f"EPSS unexpected status {resp.status_code}")

            data = resp.json()
            items = data.get("data", [])
            if not items:
                return ok(None)

            item = items[0]
            epss_val = item.get("epss")
            percentile_val = item.get("percentile")

            if epss_val is None:
                return ok(None)

            return ok(
                EpssScore(
                    cve_id=normalized,
                    probability=float(epss_val),
                    percentile=float(percentile_val or 0.0),
                    date=item.get("date", ""),
                )
            )

        except httpx.TimeoutException:
            return fail(FailureKind.TIMEOUT, f"FIRST EPSS timed out after {self.timeout}s")
        except httpx.RequestError as exc:
            return fail(FailureKind.NETWORK, f"FIRST EPSS request error: {exc}")
        except Exception as exc:
            return fail(FailureKind.INVALID_RESPONSE, f"Corrupted EPSS response: {exc}")