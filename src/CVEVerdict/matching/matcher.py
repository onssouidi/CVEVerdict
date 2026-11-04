from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from CVEVerdict.matching.version import MatchOutcome, compare_version_to_bounds
from CVEVerdict.models import CveRecord


@dataclass(frozen=True, slots=True)
class Component:
    """An inventory component from a product profile."""
    name: str
    version: Optional[str] = None
    cpe: Optional[str] = None
    purl: Optional[str] = None


@dataclass(frozen=True, slots=True)
class ComponentMatchResult:
    component: Component
    cve_id: str
    outcome: MatchOutcome
    matched_cpe: Optional[str] = None
    reason: str = ""


def _normalize_name(name: str) -> str:
    return name.lower().replace("-", "_").replace(" ", "_")


def match_component_cve(component: Component, cve: CveRecord) -> ComponentMatchResult:
    """
    Matches an inventory component against a CVE's vulnerable entries.
    Never evaluates platform context (vulnerable: false) as an affected match.
    """
    vulnerable_entries = cve.all_vulnerable_matches

    if not vulnerable_entries:
        if not cve.has_configuration_data:
            return ComponentMatchResult(
                component=component,
                cve_id=cve.cve_id,
                outcome=MatchOutcome.UNKNOWN,
                reason="CVE has no configuration data analyzed yet.",
            )
        return ComponentMatchResult(
            component=component,
            cve_id=cve.cve_id,
            outcome=MatchOutcome.NO_MATCH,
            reason="No vulnerable configurations recorded for this CVE.",
        )

    # Rule R6: Component with missing version yields UNKNOWN
    if not component.version:
        # Check if the product name even matches
        norm_name = _normalize_name(component.name)
        product_matches = [
            m for m in vulnerable_entries
            if norm_name in _normalize_name(m.cpe.product) or (component.cpe and component.cpe in m.cpe.raw)
        ]
        if product_matches:
            return ComponentMatchResult(
                component=component,
                cve_id=cve.cve_id,
                outcome=MatchOutcome.UNKNOWN,
                matched_cpe=product_matches[0].cpe.raw,
                reason="Component name matches vulnerable software, but version is missing (unknown).",
            )
        return ComponentMatchResult(
            component=component,
            cve_id=cve.cve_id,
            outcome=MatchOutcome.NO_MATCH,
            reason="Component not found in vulnerable entries.",
        )

    norm_comp_name = _normalize_name(component.name)
    best_unknown_reason: Optional[str] = None
    candidate_matched_cpe: Optional[str] = None

    for match_entry in vulnerable_entries:
        norm_cpe_product = _normalize_name(match_entry.cpe.product)

        # Check product name match or CPE match
        is_candidate = (
            norm_comp_name == norm_cpe_product
            or norm_comp_name in norm_cpe_product
            or (component.cpe and component.cpe in match_entry.cpe.raw)
        )

        if not is_candidate:
            continue

        candidate_matched_cpe = match_entry.cpe.raw

        # Compare version against entry bounds
        res = compare_version_to_bounds(
            target_version_str=component.version,
            cpe_version_str=match_entry.cpe.version,
            start_including=match_entry.version_start_including,
            start_excluding=match_entry.version_start_excluding,
            end_including=match_entry.version_end_including,
            end_excluding=match_entry.version_end_excluding,
        )

        if res.outcome == MatchOutcome.MATCH:
            return ComponentMatchResult(
                component=component,
                cve_id=cve.cve_id,
                outcome=MatchOutcome.MATCH,
                matched_cpe=match_entry.cpe.raw,
                reason=res.reason,
            )
        elif res.outcome == MatchOutcome.UNKNOWN:
            best_unknown_reason = res.reason

    # If any candidate comparison was UNKNOWN, propagate UNKNOWN (Rule R6)
    if best_unknown_reason:
        return ComponentMatchResult(
            component=component,
            cve_id=cve.cve_id,
            outcome=MatchOutcome.UNKNOWN,
            matched_cpe=candidate_matched_cpe,
            reason=best_unknown_reason,
        )

    # If product matched but version was outside all bounds
    if candidate_matched_cpe:
        return ComponentMatchResult(
            component=component,
            cve_id=cve.cve_id,
            outcome=MatchOutcome.NO_MATCH,
            matched_cpe=candidate_matched_cpe,
            reason="Component version is outside all vulnerable bounds (e.g. patched).",
        )

    return ComponentMatchResult(
        component=component,
        cve_id=cve.cve_id,
        outcome=MatchOutcome.NO_MATCH,
        reason="Component not found in vulnerable entries.",
    )