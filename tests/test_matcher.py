import json
from pathlib import Path

from CVEVerdict.matching.matcher import Component, match_component_cve
from CVEVerdict.matching.version import MatchOutcome
from CVEVerdict.parsing.record import parse_cve_record

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


def load_fixture(name: str) -> dict:
    with open(FIXTURES_DIR / name, "r", encoding="utf-8") as f:
        return json.load(f)


def test_acceptance_a2_fixed_version_yields_no_match():
    """
    Acceptance Test A2:
    CVE-2023-4863 affects libwebp < 1.3.2 (versionEndExcluding = '1.3.2').
    A component with version 1.3.2 is at or above the fixed bound -> outcome must be NO_MATCH.
    """
    raw_json = load_fixture("CVE-2023-4863.json")
    cve = parse_cve_record(raw_json).unwrap()

    # Component patched to fixed version 1.3.2
    comp = Component(name="libwebp", version="1.3.2")
    result = match_component_cve(comp, cve)

    assert result.outcome == MatchOutcome.NO_MATCH
    assert "outside all vulnerable bounds" in result.reason or "at or above" in result.reason


def test_acceptance_a3_missing_version_yields_unknown():
    """
    Acceptance Test A3:
    For a component with no version, the match result is UNKNOWN,
    and a not_affected decision cannot be inferred.
    """
    raw_json = load_fixture("CVE-2023-4863.json")
    cve = parse_cve_record(raw_json).unwrap()

    # Component present but version is missing (None)
    comp = Component(name="libwebp", version=None)
    result = match_component_cve(comp, cve)

    assert result.outcome == MatchOutcome.UNKNOWN
    assert "version is missing" in result.reason


def test_vulnerable_version_yields_match():
    """Version inside the vulnerable bound (e.g. 1.3.1 < 1.3.2) -> MATCH."""
    raw_json = load_fixture("CVE-2023-4863.json")
    cve = parse_cve_record(raw_json).unwrap()

    comp = Component(name="libwebp", version="1.3.1")
    result = match_component_cve(comp, cve)

    assert result.outcome == MatchOutcome.MATCH
    assert "falls within the affected" in result.reason