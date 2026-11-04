import json
from pathlib import Path

import pytest
from CVEVerdict.parsing.record import parse_cve_record

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


def load_fixture(filename: str) -> dict:
    path = FIXTURES_DIR / filename
    if not path.exists():
        pytest.fail(f"Fixture file '{filename}' not found in {FIXTURES_DIR}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def test_acceptance_a1_arts_linux_cve_2006_2916():
    """
    Acceptance Test A1: CVE-2006-2916
    An AND configuration where aRts is vulnerable (app) and Linux kernel
    is platform context only (vulnerable: false).
    """
    raw_json = load_fixture("CVE-2006-2916.json")
    res = parse_cve_record(raw_json)
    assert res.is_success, f"Failed parsing CVE-2006-2916: {res.message}"

    record = res.unwrap()
    assert record.cve_id == "CVE-2006-2916"
    assert len(record.configurations) == 1

    config = record.configurations[0]
    assert config.operator == "AND"
    assert len(config.nodes) == 2

    # 1. Verify vulnerable applications
    vuln_matches = config.vulnerable_matches
    assert len(vuln_matches) >= 1
    assert all(m.vulnerable is True for m in vuln_matches)
    # The affected application is arts
    assert any("arts" in m.cpe.product for m in vuln_matches)

    # 2. Verify platform context (Linux kernel is context, NOT marked vulnerable)
    context_matches = config.platform_context_matches
    assert len(context_matches) >= 1
    assert all(m.vulnerable is False for m in context_matches)
    linux_kernel_matches = [m for m in context_matches if "linux_kernel" in m.cpe.product]
    assert len(linux_kernel_matches) >= 1
    assert linux_kernel_matches[0].cpe.is_operating_system is True


def test_fixture_authentik_cve_2024_23647():
    """
    CVE-2024-23647 (Authentik):
    Configuration-level operator is absent (None), has affected version bounds,
    and has zero platform context entries.
    """
    raw_json = load_fixture("CVE-2024-23647.json")
    res = parse_cve_record(raw_json)
    assert res.is_success, f"Failed parsing CVE-2024-23647: {res.message}"

    record = res.unwrap()
    assert record.cve_id == "CVE-2024-23647"
    assert len(record.configurations) >= 1

    config = record.configurations[0]
    # No configuration-level operator
    assert config.operator is None
    # No platform context (standalone application)
    assert len(config.platform_context_matches) == 0

    vuln_matches = record.all_vulnerable_matches
    assert len(vuln_matches) >= 1
    assert any("authentik" in m.cpe.product for m in vuln_matches)
    # Confirms bounds are present
    assert any(m.version_start_including or m.version_end_excluding for m in vuln_matches)


def test_fixture_libwebp_cve_2023_4863():
    """
    CVE-2023-4863 (libwebp):
    9 configurations, 20 entries, all vulnerable, 0 platform context,
    and 12 distinct affected products.
    """
    raw_json = load_fixture("CVE-2023-4863.json")
    res = parse_cve_record(raw_json)
    assert res.is_success, f"Failed parsing CVE-2023-4863: {res.message}"

    record = res.unwrap()
    assert record.cve_id == "CVE-2023-4863"
    assert len(record.configurations) == 9
    assert len(record.all_platform_context_matches) == 0

    vuln_matches = record.all_vulnerable_matches
    assert len(vuln_matches) == 20
    assert all(m.vulnerable is True for m in vuln_matches)

    # 12 distinct downstream products
    distinct_products = {m.cpe.product for m in vuln_matches}
    assert len(distinct_products) == 12