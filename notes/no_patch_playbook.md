# Playbook: Response to Vulnerability Disclosure with No Available Patch

## Context
When a critical vulnerability is disclosed publicly (0-day or 1-day) before a vendor patch or upstream fix exists, the standard vulnerability remediation lifecycle ("patch and restart") is unavailable. Product security teams must execute a structured, risk-driven response.

---

## 1. Step-by-Step Response Lifecycle

### Phase 1: Verification (Confirm Presence & Reachability)
- **Component Presence**: Query software inventory / SBOM for the affected library, version, and dependencies.
- **Reachability & Execution Path**:
  - Determine if the vulnerable function/class is imported and invoked in production runtime.
  - Check whether attacker-controlled input can reach the affected code path (VEX justification: `vulnerable_code_not_in_execute_path`).

### Phase 2: Immediate Containment (Workaround or Feature Toggling)
- **Vendor Workaround**: Apply documented official workarounds (e.g. configuration flag, removing vulnerable class from classpath like `JndiLookup.class` in Log4j).
- **Feature Degradation**: If no safe workaround exists, disable the specific feature or endpoint via dynamic feature flags or service configuration until a patch is released.

### Phase 3: Compensating Controls
- **Network Perimeter**: Deploy WAF rules, API gateway inspection, or IPS signatures matching public Proof-of-Concept (PoC) exploit payloads.
- **Access Segmentation**: Restrict network access to the vulnerable service to trusted internal IP ranges or require mTLS / VPN.
- **Least Privilege**: Strip container capabilities or reduce process execution privileges to limit post-exploitation blast radius.

### Phase 4: Active Threat Monitoring
- **IOC Detection**: Ingest threat intelligence indicators of compromise (hashes, malicious IPs, scanning user-agents).
- **Log Telemetry**: Enable debug/audit logging on the vulnerable entry point to detect probe attempts.
- **Exploitation Signal Tracking**: Monitor CISA KEV additions and sudden EPSS score spikes.

### Phase 5: Governance & Accepted Risk Recording
- Record a formal, time-bound **Risk Acceptance** in the decision log.
- Document:
  - Documented evidence of presence and mitigations in place.
  - Assigned security owner.
  - Mandatory review date (e.g. re-evaluate every 48 hours).

### Phase 6: Patch Deployment & Post-Mortem
- As soon as the upstream patch or vendor update is released:
  - Validate in staging environment.
  - Deploy to production.
  - Decommission temporary workarounds or compensating controls.
  - Transition decision record status from `under_investigation` to `fixed`.