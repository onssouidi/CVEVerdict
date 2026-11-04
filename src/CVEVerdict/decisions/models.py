from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Optional


class DecisionStatus(StrEnum):
    UNDER_INVESTIGATION = "under_investigation"
    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    FIXED = "fixed"


class VexJustification(StrEnum):
    COMPONENT_NOT_PRESENT = "component_not_present"
    VULNERABLE_CODE_NOT_PRESENT = "vulnerable_code_not_present"
    VULNERABLE_CODE_NOT_IN_EXECUTE_PATH = "vulnerable_code_not_in_execute_path"
    VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY = "vulnerable_code_cannot_be_controlled_by_adversary"
    INLINE_MITIGATIONS_ALREADY_EXIST = "inline_mitigations_already_exist"


class EvidenceKey(StrEnum):
    COMPONENT_PRESENT = "component_present"
    VERSION_AFFECTED = "version_affected"
    CODE_REACHABLE = "code_reachable"
    EXPOSED = "exposed"
    MITIGATIONS = "mitigations"


class EvidenceValue(StrEnum):
    YES = "yes"
    NO = "no"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class EvidenceItem:
    """An individual verified claim supporting the decision."""
    key: EvidenceKey
    value: EvidenceValue
    note: Optional[str] = None
    source: str = "analyst"  # 'analyst' or 'automatic_matcher'


@dataclass(slots=True)
class DecisionRecord:
    """An immutable decision record revision for a product and CVE."""
    cve_id: str
    product_id: str
    author: str
    revision: int = 1
    status: DecisionStatus = DecisionStatus.UNDER_INVESTIGATION
    justification: Optional[VexJustification] = None
    note: Optional[str] = None
    incomplete: bool = False
    cve_last_modified_seen: Optional[datetime] = None
    evidence_items: list[EvidenceItem] = field(default_factory=list)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))