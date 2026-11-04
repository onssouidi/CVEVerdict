from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from CVEVerdict.models import CveRecord, CveReference, CvssMetric
from CVEVerdict.parsing.config import parse_configurations
from CVEVerdict.result import FailureKind, Result, fail, ok


def _parse_iso_date(date_str: Optional[str]) -> Optional[datetime]:
    if not date_str:
        return None
    try:
        return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except ValueError:
        return None


def parse_cve_record(raw_cve_item: dict[str, Any]) -> Result[CveRecord]:
    """
    Parses a raw NVD 2.0 CVE JSON object into a structured CveRecord.
    Maintains explicit flags for missing data (e.g., has_configuration_data).
    """
    if not isinstance(raw_cve_item, dict):
        return fail(FailureKind.INVALID_RESPONSE, "CVE record payload must be a JSON dictionary.")
    
        # Unpack from NVD 2.0 API response envelope if present
    if "vulnerabilities" in raw_cve_item and raw_cve_item["vulnerabilities"]:
        cve_data = raw_cve_item["vulnerabilities"][0].get("cve", {})
    else:
        cve_data = raw_cve_item.get("cve", raw_cve_item)
    cve_id = cve_data.get("id")
    if not cve_id:
        return fail(FailureKind.INVALID_RESPONSE, "Missing 'id' in CVE record.")

    # 1. Description (find English or fallback)
    description = "No description provided."
    descriptions = cve_data.get("descriptions", [])
    for d in descriptions:
        if d.get("lang") == "en":
            description = d.get("value", description)
            break
    else:
        if descriptions:
            description = descriptions[0].get("value", description)

    # 2. Configurations & "No Data Yet" check
    raw_configs = cve_data.get("configurations", [])
    has_config_data = bool(raw_configs)
    parsed_configs = []
    if has_config_data:
        config_result = parse_configurations(raw_configs)
        if config_result.is_failure:
            return fail(config_result.kind, f"Failed parsing configurations: {config_result.message}")
        parsed_configs = config_result.unwrap()

    # 3. CVSS Metrics
    raw_metrics = cve_data.get("metrics", {})
    cvss_metrics: list[CvssMetric] = []

    # Map across CVSS v3.1, v3.0, and v2.0
    metric_mappings = [
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ]

    for metric_key, version_label in metric_mappings:
        for entry in raw_metrics.get(metric_key, []):
            cvss_data = entry.get("cvssData", {})
            score = cvss_data.get("baseScore")
            if score is None:
                continue

            severity = cvss_data.get("baseSeverity") or entry.get("baseSeverity", "UNKNOWN")
            metric = CvssMetric(
                version=version_label,
                base_score=float(score),
                vector_string=cvss_data.get("vectorString", ""),
                severity=str(severity).upper(),
                type=entry.get("type", "Secondary"),
                source=entry.get("source", "Unknown"),
            )
            cvss_metrics.append(metric)

    has_metrics_data = bool(cvss_metrics)

    # 4. Weaknesses (CWEs)
    cwes: list[str] = []
    for weakness in cve_data.get("weaknesses", []):
        for desc in weakness.get("description", []):
            val = desc.get("value")
            if val and val not in cwes:
                cwes.append(val)

    # 5. References (display URLs safely; never fetch them server-side)
    references: list[CveReference] = []
    for ref in cve_data.get("references", []):
        url = ref.get("url")
        if url:
            references.append(
                CveReference(
                    url=url,
                    source=ref.get("source"),
                    tags=tuple(ref.get("tags", [])),
                )
            )

    # 6. Dates and Status
    published_date = _parse_iso_date(cve_data.get("published"))
    last_modified_date = _parse_iso_date(cve_data.get("lastModified"))
    vuln_status = cve_data.get("vulnStatus")

    # 7. Embedded CISA KEV data
    cisa_exploit_add = cve_data.get("cisaExploitAdd")
    cisa_action_due = cve_data.get("cisaActionDue")
    cisa_required_action = cve_data.get("cisaRequiredAction")

    record = CveRecord(
        cve_id=cve_id,
        description=description,
        configurations=parsed_configs,
        cvss_metrics=cvss_metrics,
        cwes=cwes,
        references=references,
        published_date=published_date,
        last_modified_date=last_modified_date,
        vuln_status=vuln_status,
        has_configuration_data=has_config_data,
        has_metrics_data=has_metrics_data,
        cisa_exploit_add=cisa_exploit_add,
        cisa_action_due=cisa_action_due,
        cisa_required_action=cisa_required_action,
    )
    return ok(record)