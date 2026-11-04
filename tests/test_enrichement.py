import httpx
from CVEVerdict.enrichement import EnrichmentCoordinator
from CVEVerdict.sources.epss import FirstEpssClient
from CVEVerdict.sources.kev import CisaKevClient


def test_acceptance_a4_simulated_kev_down_marks_record_incomplete(monkeypatch):
    """
    Acceptance Test A4:
    With the KEV source simulated as down (e.g. timeout or 503),
    the enriched record MUST show is_incomplete = True and explicitly name 'cisa_kev'.
    """
    # 1. Simulate KEV failure (503 Service Unavailable)
    def mock_kev_down(*args, **kwargs):
        return httpx.Response(503, text="Service Unavailable")

    kev_client = CisaKevClient()
    monkeypatch.setattr(kev_client._http, "get", mock_kev_down)

    # 2. Simulate EPSS success
    def mock_epss_ok(*args, **kwargs):
        return httpx.Response(
            200,
            json={
                "data": [{"cve": "CVE-2023-4863", "epss": "0.9412", "percentile": "0.998"}]
            },
        )

    epss_client = FirstEpssClient()
    monkeypatch.setattr(epss_client._http, "get", mock_epss_ok)

    # 3. Run enrichment
    coordinator = EnrichmentCoordinator(kev_client=kev_client, epss_client=epss_client)
    enriched = coordinator.enrich("CVE-2023-4863")

    # 4. Verify Acceptance Test A4 criteria
    assert enriched.is_incomplete is True
    assert "cisa_kev" in enriched.failed_sources

    # Verify status report names the failed source
    kev_status = next(s for s in enriched.source_statuses if s.source_name == "cisa_kev")
    assert kev_status.state == "failed"
    assert "503" in (kev_status.error or "")

    # Verify EPSS still succeeded despite KEV failure
    epss_status = next(s for s in enriched.source_statuses if s.source_name == "first_epss")
    assert epss_status.state == "ok"
    assert enriched.epss is not None
    assert enriched.epss.probability == 0.9412