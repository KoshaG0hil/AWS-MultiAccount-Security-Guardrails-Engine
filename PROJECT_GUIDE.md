# Project Guide: Multi-Account Security Governance & SCP Guardrails Engine

## 1. Project Background & Architectural Problem

As enterprises scale on AWS, single-account architectures create untenable blast radiuses. When organizations transition to multi-account landing zones using AWS Organizations, they face three critical security dilemmas:

1. **Permission Creep & Shadow Ingress**: Member account administrators have elevated privileges within their local accounts. Without organization-level guardrails, developers can inadvertently spin up resources in unmonitored offshore regions or attach Internet Gateways to private VPCs.
2. **Telemetry Tampering by Adversaries**: In compromised accounts, the first move of sophisticated threat actors is disabling AWS CloudTrail, Amazon GuardDuty, and AWS Config to blind security operations teams.
3. **Slow Manual Incident Containment**: Isolating a breached AWS account traditionally requires manual IAM policy revocations, security group modifications, and routing table reconfigurations—often taking hours while attackers exfiltrate data.

---

## 2. Engineered Solution

This project implements an autonomous, defense-in-depth governance mesh combining:
- **Immutable Preventative Invariants**: Service Control Policies (SCPs) that supersede all local IAM permissions. Even the root user of a member account cannot override an SCP.
- **Continuous Detective Telemetry**: AWS Config Conformance Packs continuously evaluating against CIS AWS Foundations v3.0 and NIST CSF 2.0.
- **Autonomous Remediation**: EventBridge rules intercepting compliance state changes and executing idempotent Lambda handlers to reverse drift within seconds.
- **Zero-Trust Emergency Quarantine**: One-click and automated account isolation that shifts compromised accounts to a Quarantine OU governed by a Deny-All policy, leaving only an MFA-protected forensic break-glass role active.

---

## 3. Engineering Decisions & Trade-Offs

### A. 5,120-Byte Document Limit Optimization
- **Constraint**: AWS Organizations imposes a hard limit of 5,120 bytes per SCP.
- **Solution**: Rather than attempting a monolithic guardrail policy, we decomposed policies by responsibility:
  - *Root Level*: Global invariants (Region Restriction, Root User Denial).
  - *Workload OU Level*: Telemetry protection, network perimeter, and S3 ransomware controls.
  - *Quarantine OU Level*: Containment Deny-All.
- **Automation**: Created `src/scanners/scp_linter.py` in the CI pipeline to fail any PR containing an SCP exceeding 5,120 bytes.

### B. Dry-Run Capable & Unit Testable Architecture
- All Boto3 client calls are wrapped in injectable session handlers.
- The entire drift scanner, remediation enforcer, and quarantine system can run in dry-run mode and is validated with Moto 5.x mocks, achieving 100% test coverage with 0 live AWS costs during development.

---

## 4. Key Talking Points for Technical Interviews

1. **"How do you prevent developers from bypassing security controls in AWS?"**
   *Talk about Service Control Policies as the maximum permission boundary. Explain how `Effect: Deny` at the Organization root cannot be circumvented by `AdministratorAccess` or the member root account.*

2. **"How do you handle a compromised AWS account in under 60 seconds?"**
   *Explain the Quarantine OU mechanism. Discuss moving the account via the `organizations:MoveAccount` API, which immediately detaches normal workload policies and attaches a Deny-All SCP while preserving forensic access for `EmergencyIncidentResponseRole`.*

3. **"How do you ensure audit readiness for SOC 2 and CIS Benchmarks?"**
   *Discuss our automated `ComplianceManifest` generator (`src/reporters/compliance_manifest.py`), which exports cryptographically hashed, timestamped audit records linking policy enforcement directly to CIS AWS Foundations controls.*
