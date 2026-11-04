from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Optional

try:
    from packaging.version import InvalidVersion, Version
    from packaging.version import parse as parse_version
except ImportError:
    # Minimal fallback if packaging is not installed
    class InvalidVersion(Exception):
        pass

    def parse_version(v: str):
        # Basic numeric tuple fallback
        parts = [int(p) for p in re.findall(r"\d+", v)]
        if not parts:
            raise InvalidVersion(v)
        return parts


class MatchOutcome(StrEnum):
    MATCH = "match"
    NO_MATCH = "no_match"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class VersionComparisonResult:
    outcome: MatchOutcome
    reason: str


def _clean_version_str(v: Optional[str]) -> Optional[str]:
    if not v:
        return None
    cleaned = v.strip()
    if cleaned in ("*", "-", ""):
        return None
    return cleaned


def compare_version_to_bounds(
    target_version_str: Optional[str],
    cpe_version_str: str,
    start_including: Optional[str] = None,
    start_excluding: Optional[str] = None,
    end_including: Optional[str] = None,
    end_excluding: Optional[str] = None,
) -> VersionComparisonResult:
    """
    Compares a component version against NVD CPE version and optional range bounds.
    Returns:
      - MATCH: Version is proven inside affected range
      - NO_MATCH: Version is proven outside affected range
      - UNKNOWN: Missing version, unparseable version, or non-comparable values
    """
    # Rule R6: Missing version -> UNKNOWN
    target_clean = _clean_version_str(target_version_str)
    if not target_clean:
        return VersionComparisonResult(
            outcome=MatchOutcome.UNKNOWN,
            reason="Component version is missing or not applicable ('-' or '*').",
        )

    # Try parsing target version
    try:
        target_ver = parse_version(target_clean)
    except (InvalidVersion, TypeError):
        return VersionComparisonResult(
            outcome=MatchOutcome.UNKNOWN,
            reason=f"Component version '{target_version_str}' could not be safely parsed.",
        )

    has_bounds = any([start_including, start_excluding, end_including, end_excluding])

    # Case 1: No bounds specified - evaluate CPE version field directly
    if not has_bounds:
        if cpe_version_str == "*":
            return VersionComparisonResult(
                outcome=MatchOutcome.MATCH,
                reason="All versions are affected (wildcard '*').",
            )
        if cpe_version_str == "-":
            return VersionComparisonResult(
                outcome=MatchOutcome.UNKNOWN,
                reason="CPE version specifies '-' (not applicable/unknown).",
            )
        # Exact version comparison
        try:
            cpe_ver = parse_version(cpe_version_str)
            if target_ver == cpe_ver:
                return VersionComparisonResult(
                    outcome=MatchOutcome.MATCH,
                    reason=f"Version {target_clean} exactly matches affected version {cpe_version_str}.",
                )
            else:
                return VersionComparisonResult(
                    outcome=MatchOutcome.NO_MATCH,
                    reason=f"Version {target_clean} does not match exact affected version {cpe_version_str}.",
                )
        except (InvalidVersion, TypeError):
            # Fallback to literal string match
            if target_clean == cpe_version_str:
                return VersionComparisonResult(outcome=MatchOutcome.MATCH, reason="Literal match.")
            return VersionComparisonResult(
                outcome=MatchOutcome.UNKNOWN,
                reason=f"Could not parse CPE exact version '{cpe_version_str}'.",
            )

    # Case 2: Range bounds are specified
    # Evaluate start bounds
    if start_including:
        try:
            start_inc_ver = parse_version(start_including)
            if target_ver < start_inc_ver:
                return VersionComparisonResult(
                    outcome=MatchOutcome.NO_MATCH,
                    reason=f"Version {target_clean} is below versionStartIncluding ({start_including}).",
                )
        except (InvalidVersion, TypeError):
            return VersionComparisonResult(
                outcome=MatchOutcome.UNKNOWN,
                reason=f"Cannot parse versionStartIncluding '{start_including}'.",
            )

    if start_excluding:
        try:
            start_exc_ver = parse_version(start_excluding)
            if target_ver <= start_exc_ver:
                return VersionComparisonResult(
                    outcome=MatchOutcome.NO_MATCH,
                    reason=f"Version {target_clean} is at or below versionStartExcluding ({start_excluding}).",
                )
        except (InvalidVersion, TypeError):
            return VersionComparisonResult(
                outcome=MatchOutcome.UNKNOWN,
                reason=f"Cannot parse versionStartExcluding '{start_excluding}'.",
            )

    # Evaluate end bounds (The fixed version bounds)
    if end_including:
        try:
            end_inc_ver = parse_version(end_including)
            if target_ver > end_inc_ver:
                return VersionComparisonResult(
                    outcome=MatchOutcome.NO_MATCH,
                    reason=f"Version {target_clean} is above versionEndIncluding ({end_including}).",
                )
        except (InvalidVersion, TypeError):
            return VersionComparisonResult(
                outcome=MatchOutcome.UNKNOWN,
                reason=f"Cannot parse versionEndIncluding '{end_including}'.",
            )

    if end_excluding:
        try:
            end_exc_ver = parse_version(end_excluding)
            if target_ver >= end_exc_ver:
                # Acceptance Test A2 condition: target >= fixed version bound
                return VersionComparisonResult(
                    outcome=MatchOutcome.NO_MATCH,
                    reason=f"Version {target_clean} is at or above fixed bound versionEndExcluding ({end_excluding}).",
                )
        except (InvalidVersion, TypeError):
            return VersionComparisonResult(
                outcome=MatchOutcome.UNKNOWN,
                reason=f"Cannot parse versionEndExcluding '{end_excluding}'.",
            )

    # If it survived all exclusion checks, it falls within the affected range
    return VersionComparisonResult(
        outcome=MatchOutcome.MATCH,
        reason=f"Version {target_clean} falls within the affected vulnerability bounds.",
    )