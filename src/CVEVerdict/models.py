from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from CVEVerdict.parsing.cpe import Cpe23


# ============================================================================
# Step 5: Configuration Tree Models
# ============================================================================

@dataclass(frozen=True, slots=True)
class CpeMatch:
    """
    Represents an individual cpeMatch entry in an NVD configuration node.
    
    Version Interpretation Rules:
    - Specific version string with NO bounds = exactly that version is targeted.
    - Version '*' with NO bounds = ANY version is targeted.
    - Version '-' = Not applicable / not comparable (evaluates to UNKNOWN).
    - If bounds are present, they define the affected range regardless of the version field.
    """
    cpe: Cpe23
    vulnerable: bool
    version_start_including: Optional[str] = None
    version_start_excluding: Optional[str] = None
    version_end_including: Optional[str] = None
    version_end_excluding: Optional[str] = None
    match_criteria_id: Optional[str] = None


@dataclass(slots=True)
class ConfigNode:
    """A logical node inside a configuration (grouped with OR or AND)."""
    operator: str  # Usually 'OR' or 'AND'
    negate: bool = False
    cpe_matches: list[CpeMatch] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Configuration:
    """
    Top-level configuration block for a CVE.
    Operator can be None if there is only a single node.
    """
    operator: Optional[str] = None  # 'AND', 'OR', or None
    nodes: list[ConfigNode] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def vulnerable_matches(self) -> list[CpeMatch]:
        """All entries explicitly marked vulnerable: true."""
        return [
            match
            for node in self.nodes
            for match in node.cpe_matches
            if match.vulnerable
        ]

    @property
    def platform_context_matches(self) -> list[CpeMatch]:
        """All entries marked vulnerable: false (platform context / runtime environment)."""
        return [
            match
            for node in self.nodes
            for match in node.cpe_matches
            if not match.vulnerable
        ]


# ============================================================================
# Step 6: Full CVE Record Models (CVSS, CWE, References, Metadata)
# ============================================================================

@dataclass(frozen=True, slots=True)
class CvssMetric:
    """Represents a CVSS score (v3.1, v3.0, or v2.0) with source attribution."""
    version: str          # '3.1', '3.0', '2.0'
    base_score: float
    vector_string: str
    severity: str         # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    type: str             # 'Primary' or 'Secondary'
    source: str           # e.g., 'nvd@nist.gov' or vendor


@dataclass(frozen=True, slots=True)
class CveReference:
    """Reference URL with tags."""
    url: str
    source: Optional[str] = None
    tags: tuple[str, ...] = ()


@dataclass(slots=True)
class CveRecord:
    """
    The complete, structured CVE representation.
    Adheres to the rule: Missing data != Negative data.
    """
    cve_id: str
    description: str
    configurations: list[Configuration] = field(default_factory=list)
    cvss_metrics: list[CvssMetric] = field(default_factory=list)
    cwes: list[str] = field(default_factory=list)
    references: list[CveReference] = field(default_factory=list)
    published_date: Optional[datetime] = None
    last_modified_date: Optional[datetime] = None
    vuln_status: Optional[str] = None
    
    # Flags to explicitly distinguish "no data yet" from "affects nothing"
    has_configuration_data: bool = True
    has_metrics_data: bool = True
    
    # CISA KEV data if embedded in the NVD record
    cisa_exploit_add: Optional[str] = None
    cisa_action_due: Optional[str] = None
    cisa_required_action: Optional[str] = None

    @property
    def all_vulnerable_matches(self) -> list[CpeMatch]:
        """Aggregates all vulnerable entries across all configurations."""
        return [
            m for config in self.configurations for m in config.vulnerable_matches
        ]

    @property
    def all_platform_context_matches(self) -> list[CpeMatch]:
        """Aggregates all platform context entries across all configurations."""
        return [
            m for config in self.configurations for m in config.platform_context_matches
        ]