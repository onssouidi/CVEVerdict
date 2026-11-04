from CVEVerdict.parsing.record import parse_cve_record


def test_parse_complete_cve_record():
    raw_payload = {
        "cve": {
            "id": "CVE-2023-4863",
            "published": "2023-09-12T15:15:12.345Z",
            "lastModified": "2023-09-20T17:15:12.345Z",
            "vulnStatus": "Analyzed",
            "descriptions": [
                {"lang": "es", "value": "Descripcion en espanol"},
                {"lang": "en", "value": "Heap buffer overflow in libwebp."},
            ],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "cvssData": {
                            "version": "3.1",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                            "baseScore": 8.8,
                            "baseSeverity": "HIGH",
                        },
                    }
                ]
            },
            "weaknesses": [
                {"description": [{"lang": "en", "value": "CWE-787"}]}
            ],
            "references": [
                {"url": "https://example.com/advisory", "tags": ["Vendor Advisory"]}
            ],
            "cisaExploitAdd": "2023-09-13",
            "configurations": [
                {
                    "nodes": [
                        {
                            "operator": "OR",
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:a:webmproject:libwebp:*:*:*:*:*:*:*:*",
                                    "versionEndExcluding": "1.3.2",
                                }
                            ],
                        }
                    ]
                }
            ],
        }
    }

    res = parse_cve_record(raw_payload)
    assert res.is_success
    record = res.unwrap()

    assert record.cve_id == "CVE-2023-4863"
    assert record.description == "Heap buffer overflow in libwebp."
    assert record.has_configuration_data is True
    assert record.has_metrics_data is True
    assert len(record.cvss_metrics) == 1
    assert record.cvss_metrics[0].base_score == 8.8
    assert record.cvss_metrics[0].severity == "HIGH"
    assert record.cwes == ["CWE-787"]
    assert record.cisa_exploit_add == "2023-09-13"
    assert len(record.all_vulnerable_matches) == 1


def test_unanalyzed_cve_without_configurations():
    """A new or unanalyzed CVE must be marked with has_configuration_data = False."""
    raw_payload = {
        "cve": {
            "id": "CVE-2026-0001",
            "vulnStatus": "Received",
            "descriptions": [{"lang": "en", "value": "Newly reported vulnerability."}],
            # 'configurations' is missing
            # 'metrics' is missing
        }
    }

    res = parse_cve_record(raw_payload)
    assert res.is_success
    record = res.unwrap()

    assert record.cve_id == "CVE-2026-0001"
    assert record.has_configuration_data is False
    assert record.has_metrics_data is False
    assert len(record.configurations) == 0
    assert len(record.cvss_metrics) == 0