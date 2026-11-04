from CVEVerdict.decisions.models import DecisionStatus, EvidenceItem, EvidenceKey, EvidenceValue, VexJustification
from CVEVerdict.decisions.rules import validate_decision
from CVEVerdict.matching.version import MatchOutcome
from CVEVerdict.result import FailureKind


def test_acceptance_a5_saving_not_affected_without_justification_is_refused():
    """
    Acceptance Test A5:
    Attempting to save a decision with status 'not_affected' without providing
    a valid standard VEX justification MUST be refused.
    """
    res = validate_decision(
        cve_id="CVE-2023-4863",
        product_id="prod-123",
        author="ons@example.com",
        status=DecisionStatus.NOT_AFFECTED,
        justification=None,  # Missing justification!
        note="We are definitely safe from this CVE.",
        evidence_items=[
            EvidenceItem(
                key=EvidenceKey.COMPONENT_PRESENT,
                value=EvidenceValue.NO,
                note="Not in production",
            )
        ],
    )

    assert res.is_failure
    assert res.kind == FailureKind.INVALID_RESPONSE
    assert "justification is mandatory" in res.message


def test_valid_not_affected_decision_succeeds():
    """Providing status, justification, note, and evidence succeeds."""
    res = validate_decision(
        cve_id="CVE-2023-4863",
        product_id="prod-123",
        author="ons@example.com",
        status=DecisionStatus.NOT_AFFECTED,
        justification=VexJustification.COMPONENT_NOT_PRESENT,
        note="The vulnerable libwebp image parsing library is not included in our container images.",
        evidence_items=[
            EvidenceItem(
                key=EvidenceKey.COMPONENT_PRESENT,
                value=EvidenceValue.NO,
                note="Verified via container image scan",
            )
        ],
    )

    assert res.is_success
    record = res.unwrap()
    assert record.status == DecisionStatus.NOT_AFFECTED
    assert record.justification == VexJustification.COMPONENT_NOT_PRESENT
    assert record.revision == 1


def test_rule_r1_default_status_is_under_investigation():
    """Rule R1: A newly created decision defaults to 'under_investigation'."""
    res = validate_decision(
        cve_id="CVE-2023-4863",
        product_id="prod-123",
        author="ons@example.com",
        status=None,  # Unspecified status
    )

    assert res.is_success
    record = res.unwrap()
    assert record.status == DecisionStatus.UNDER_INVESTIGATION


def test_rule_r6_unknown_match_cannot_claim_not_affected_without_evidence():
    """Rule R6: UNKNOWN version outcome cannot be used to declare not_affected."""
    res = validate_decision(
        cve_id="CVE-2023-4863",
        product_id="prod-123",
        author="ons@example.com",
        status=DecisionStatus.NOT_AFFECTED,
        justification=VexJustification.COMPONENT_NOT_PRESENT,
        note="Version is unknown so assuming we are safe.",
        match_outcome=MatchOutcome.UNKNOWN,
        evidence_items=[],  # No proof
    )

    assert res.is_failure
    assert "without explicit evidence" in res.message