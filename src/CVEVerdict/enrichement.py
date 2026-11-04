from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from CVEVerdict.models import CveRecord
from CVEVerdict.result import FailureKind, Success
from CVEVerdict.sources.epss import EpssScore, FirstEpssClient
from CVEVerdict.sources.kev import CisaKevClient, KevEntry
from CVEVerdict.sources.nvd import NvdClient


@dataclass(frozen=True, slots=True)
class SourceCheckStatus:
    source_name: str
    state: str  # 'ok', 'failed', 'skipped'
    error: Optional[str] = None
    checked_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(slots=True)
class EnrichedCve:
    cve_id: str
    record: Optional[CveRecord] = None
    kev: Optional[KevEntry] = None
    epss: Optional[EpssScore] = None
    source_statuses: list[SourceCheckStatus] = field(default_factory=list)
    is_incomplete: bool = False
    failed_sources: list[str] = field(default_factory=list)


class EnrichmentCoordinator:
    """Enriches CVEs with KEV and EPSS while tracking feed health."""

    def __init__(
        self,
        nvd_client: Optional[NvdClient] = None,
        kev_client: Optional[CisaKevClient] = None,
        epss_client: Optional[FirstEpssClient] = None,
    ) -> None:
        self.nvd_client = nvd_client or NvdClient()
        self.kev_client = kev_client or CisaKevClient()
        self.epss_client = epss_client or FirstEpssClient()

    def enrich(self, cve_id: str, record: Optional[CveRecord] = None) -> EnrichedCve:
        statuses: list[SourceCheckStatus] = []
        failed_sources: list[str] = []

        # 1. KEV lookup
        kev_res = self.kev_client.check_cve(cve_id)
        kev_entry: Optional[KevEntry] = None
        if kev_res.is_success:
            kev_entry = kev_res.unwrap()
            statuses.append(SourceCheckStatus(source_name="cisa_kev", state="ok"))
        else:
            failed_sources.append("cisa_kev")
            statuses.append(
                SourceCheckStatus(
                    source_name="cisa_kev",
                    state="failed",
                    error=kev_res.message,
                )
            )

        # 2. EPSS lookup
        epss_res = self.epss_client.get_score(cve_id)
        epss_entry: Optional[EpssScore] = None
        if epss_res.is_success:
            epss_entry = epss_res.unwrap()
            statuses.append(SourceCheckStatus(source_name="first_epss", state="ok"))
        else:
            failed_sources.append("first_epss")
            statuses.append(
                SourceCheckStatus(
                    source_name="first_epss",
                    state="failed",
                    error=epss_res.message,
                )
            )

        # Rule R5: Incomplete flag if any source failed
        is_incomplete = len(failed_sources) > 0

        return EnrichedCve(
            cve_id=cve_id,
            record=record,
            kev=kev_entry,
            epss=epss_entry,
            source_statuses=statuses,
            is_incomplete=is_incomplete,
            failed_sources=failed_sources,
        )