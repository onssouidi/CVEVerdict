from CVEVerdict.decisions.models import DecisionStatus, EvidenceItem, EvidenceKey, EvidenceValue, VexJustification
from CVEVerdict.decisions.service import DecisionService


def test_acceptance_a6_editing_creates_new_revision_and_previous_stays_visible():
    """
    Acceptance Test A6:
    1. An initial decision is recorded (Revision 1: under_investigation).
    2. An edit is made (Revision 2: not_affected with justification and evidence).
    3. The previous revision remains completely intact and visible in the audit history.
    """
    service = DecisionService()
    product_id = "prod-auth-gateway"
    cve_id = "CVE-2023-4863"

    # Step 1: Record initial decision (Revision 1)
    res_1 = service.record_decision(
        product_id=product_id,
        cve_id=cve_id,
        author="alice@secops.io",
        status=DecisionStatus.UNDER_INVESTIGATION,
        note="Initial triage: assessing if image rendering module is exposed.",
    )
    assert res_1.is_success
    rev_1 = res_1.unwrap()
    assert rev_1.revision == 1
    assert rev_1.status == DecisionStatus.UNDER_INVESTIGATION

    # Step 2: Edit the decision (Revision 2)
    res_2 = service.record_decision(
        product_id=product_id,
        cve_id=cve_id,
        author="bob@secops.io",
        status=DecisionStatus.NOT_AFFECTED,
        justification=VexJustification.COMPONENT_NOT_PRESENT,
        note="Verified that libwebp is not included in our production base image.",
        evidence_items=[
            EvidenceItem(
                key=EvidenceKey.COMPONENT_PRESENT,
                value=EvidenceValue.NO,
                note="Container filesystem audit confirmed component absent.",
            )
        ],
    )
    assert res_2.is_success
    rev_2 = res_2.unwrap()
    assert rev_2.revision == 2
    assert rev_2.status == DecisionStatus.NOT_AFFECTED
    assert rev_2.author == "bob@secops.io"

    # Step 3: Verify append-only history (Acceptance Test A6)
    history = service.get_history(product_id, cve_id)
    assert len(history) == 2

    # Revision 1 is still completely preserved
    assert history[0].revision == 1
    assert history[0].status == DecisionStatus.UNDER_INVESTIGATION
    assert history[0].author == "alice@secops.io"
    assert "Initial triage" in (history[0].note or "")

    # Revision 2 is the latest active revision
    assert history[1].revision == 2
    assert history[1].status == DecisionStatus.NOT_AFFECTED
    assert history[1].justification == VexJustification.COMPONENT_NOT_PRESENT

    # Latest pointer returns Revision 2
    latest = service.get_latest(product_id, cve_id)
    assert latest is not None
    assert latest.revision == 2
    assert latest.status == DecisionStatus.NOT_AFFECTED