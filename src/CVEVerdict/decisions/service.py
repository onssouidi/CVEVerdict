from __future__ import annotations

from typing import Optional, Protocol

from CVEVerdict.decisions.models import DecisionRecord, DecisionStatus, VexJustification
from CVEVerdict.decisions.rules import validate_decision
from CVEVerdict.matching.version import MatchOutcome
from CVEVerdict.result import FailureKind, Result, fail, ok


class DecisionRepositoryProtocol(Protocol):
    """Protocol for decision storage backends (PostgreSQL, SQLite, or in-memory)."""
    def save(self, record: DecisionRecord) -> None: ...
    def get_history(self, product_id: str, cve_id: str) -> list[DecisionRecord]: ...
    def get_latest(self, product_id: str, cve_id: str) -> Optional[DecisionRecord]: ...


class InMemoryDecisionRepository:
    """In-memory append-only repository for testing and offline execution."""

    def __init__(self) -> None:
        # Key: (product_id, cve_id) -> list of revisions
        self._store: dict[tuple[str, str], list[DecisionRecord]] = {}

    def save(self, record: DecisionRecord) -> None:
        key = (record.product_id, record.cve_id.upper())
        if key not in self._store:
            self._store[key] = []
        self._store[key].append(record)

    def get_history(self, product_id: str, cve_id: str) -> list[DecisionRecord]:
        key = (product_id, cve_id.upper())
        revisions = self._store.get(key, [])
        return sorted(revisions, key=lambda r: r.revision)

    def get_latest(self, product_id: str, cve_id: str) -> Optional[DecisionRecord]:
        history = self.get_history(product_id, cve_id)
        return history[-1] if history else None


class DecisionService:
    """Manages append-only decision records enforcing monotonic revisions."""

    def __init__(self, repository: Optional[DecisionRepositoryProtocol] = None) -> None:
        self.repo = repository or InMemoryDecisionRepository()

    def record_decision(
        self,
        product_id: str,
        cve_id: str,
        author: str,
        status: Optional[DecisionStatus | str] = None,
        justification: Optional[VexJustification | str] = None,
        note: Optional[str] = None,
        evidence_items: Optional[list] = None,
        match_outcome: Optional[MatchOutcome] = None,
        incomplete: bool = False,
        cve_last_modified_seen=None,
    ) -> Result[DecisionRecord]:
        """
        Records a decision. If a decision already exists for this (product, cve),
        it automatically increments revision to n + 1 (Rule R7).
        """
        existing_history = self.repo.get_history(product_id, cve_id)
        next_revision = (existing_history[-1].revision + 1) if existing_history else 1

        # Validate against domain rules
        validation_res = validate_decision(
            cve_id=cve_id,
            product_id=product_id,
            author=author,
            status=status,
            justification=justification,
            note=note,
            evidence_items=evidence_items,
            match_outcome=match_outcome,
            incomplete=incomplete,
            cve_last_modified_seen=cve_last_modified_seen,
            revision=next_revision,
        )

        if validation_res.is_failure:
            return validation_res

        decision = validation_res.unwrap()
        self.repo.save(decision)
        return ok(decision)

    def get_latest(self, product_id: str, cve_id: str) -> Optional[DecisionRecord]:
        return self.repo.get_latest(product_id, cve_id)

    def get_history(self, product_id: str, cve_id: str) -> list[DecisionRecord]:
        return self.repo.get_history(product_id, cve_id)