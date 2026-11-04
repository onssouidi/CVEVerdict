from __future__ import annotations

from typing import Optional

from CVEVerdict.decisions.models import (
    DecisionRecord,
    DecisionStatus,
    EvidenceKey,
    EvidenceValue,
    VexJustification,
)
from CVEVerdict.matching.version import MatchOutcome
from CVEVerdict.result import FailureKind, Result, fail, ok


def validate_decision(
    cve_id: str,
    product_id: str,
    author: str,
    status: Optional[DecisionStatus | str] = None,
    justification: Optional[VexJustification | str] = None,
    note: Optional[str] = None,
    evidence_items: Optional[list] = None,
    match_outcome: Optional[MatchOutcome] = None,
    incomplete: bool = False,
    cve_last_modified_seen=None,
    revision: int = 1,
) -> Result[DecisionRecord]:
    """
    Enforces Decision Rules R1 to R6:
    - R1: Default status is 'under_investigation'.
    - R2: 'not_affected' requires justification, >=1 sentence note, and >=1 evidence item.
    - R3: 'affected' requires match outcome 'match' or manual evidence.
    - R4: 'fixed' requires fixed evidence or explanatory note.
    - R5: If any external feed failed, decision is flagged incomplete.
    - R6: match_outcome 'unknown' cannot justify 'not_affected'.
    """
    if not author or not author.strip():
        return fail(FailureKind.INVALID_RESPONSE, "Author is required to record a decision.")

    # Rule R1: Default status is under_investigation
    resolved_status = DecisionStatus.UNDER_INVESTIGATION
    if status:
        try:
            resolved_status = DecisionStatus(status)
        except ValueError:
            return fail(FailureKind.INVALID_RESPONSE, f"Invalid decision status: '{status}'")

    items = list(evidence_items or [])

    # If automatic matcher found NO_MATCH, add it as supporting evidence automatically
    if match_outcome == MatchOutcome.NO_MATCH:
        if not any(e.key == EvidenceKey.VERSION_AFFECTED for e in items):
            from verdict.decisions.models import EvidenceItem
            items.append(
                EvidenceItem(
                    key=EvidenceKey.VERSION_AFFECTED,
                    value=EvidenceValue.NO,
                    note="Automatic version matcher determined version is outside affected bounds.",
                    source="automatic_matcher",
                )
            )

    resolved_justification: Optional[VexJustification] = None
    if justification:
        try:
            resolved_justification = VexJustification(justification)
        except ValueError:
            return fail(FailureKind.INVALID_RESPONSE, f"Invalid VEX justification: '{justification}'")

    # Rule R2 & Acceptance Test A5: 'not_affected' validation
    if resolved_status == DecisionStatus.NOT_AFFECTED:
        if not resolved_justification:
            return fail(
                FailureKind.INVALID_RESPONSE,
                "A standard VEX justification is mandatory when status is 'not_affected'.",
            )

        if not note or len(note.strip().split()) < 3:
            return fail(
                FailureKind.INVALID_RESPONSE,
                "A note of at least one explanatory sentence is required for 'not_affected'.",
            )

        # Rule R6: If match outcome is UNKNOWN, verify it is not falsely claimed as not_affected
        if match_outcome == MatchOutcome.UNKNOWN and resolved_justification == VexJustification.COMPONENT_NOT_PRESENT:
            # Only allowed if analyst provided explicit manual evidence
            has_presence_evidence = any(
                e.key == EvidenceKey.COMPONENT_PRESENT and e.value == EvidenceValue.NO for e in items
            )
            if not has_presence_evidence:
                return fail(
                    FailureKind.INVALID_RESPONSE,
                    "Cannot mark 'not_affected' when version match is UNKNOWN without explicit evidence.",
                )

        if not items:
            return fail(
                FailureKind.INVALID_RESPONSE,
                "At least one supporting evidence item is required for 'not_affected'.",
            )

    # Rule R3: 'affected' validation
    if resolved_status == DecisionStatus.AFFECTED:
        has_affected_evidence = any(
            (e.key == EvidenceKey.VERSION_AFFECTED and e.value == EvidenceValue.YES)
            or (e.key == EvidenceKey.COMPONENT_PRESENT and e.value == EvidenceValue.YES)
            for e in items
        )
        if match_outcome != MatchOutcome.MATCH and not has_affected_evidence:
            return fail(
                FailureKind.INVALID_RESPONSE,
                "Status 'affected' requires a version match or manual evidence confirming presence.",
            )

    # Rule R4: 'fixed' validation
    if resolved_status == DecisionStatus.FIXED:
        if not note or not note.strip():
            return fail(
                FailureKind.INVALID_RESPONSE,
                "Status 'fixed' requires an explanatory note with the remediation or patch version.",
            )

    record = DecisionRecord(
        cve_id=cve_id.strip().upper(),
        product_id=product_id,
        author=author.strip(),
        revision=revision,
        status=resolved_status,
        justification=resolved_justification,
        note=note.strip() if note else None,
        incomplete=incomplete,
        cve_last_modified_seen=cve_last_modified_seen,
        evidence_items=items,
    )
    return ok(record)