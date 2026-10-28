# Multi-Account Security Architecture & Landing Zone Governance

## 1. Executive Summary

This architecture establishes an enterprise-grade multi-account governance and containment framework for AWS Organizations. By integrating **preventative guardrails** (Service Control Policies), **detective controls** (AWS Config Conformance Packs & GuardDuty), and **autonomous corrective actions** (EventBridge-driven Lambda Self-Healing & Quarantine Isolation), the platform maintains continuous compliance with **CIS AWS Foundations Benchmark v3.0** and **NIST CSF 2.0 (PR.AC)**.

---

## 2. Structural Topology

The AWS Organization is structured into dedicated Organizational Units (OUs), each enforcing specific policy sets:

```text
                                 +------------------------------+
                                 |     AWS Organization Root    |
                                 |         (r-09a8)             |
                                 +--------------+---------------+
                                                |
               +--------------------------------+-------------------------------+
               |                                |                               |
               v                                v                               v
  +-------------------------+      +-------------------------+      +-------------------------+
  |         Core OU         |      |   Workloads (Prod) OU   |      | Workloads (Non-Prod) OU |
  +------------+------------+      +------------+------------+      +------------+------------+
               |                                |                                |
       +-------+-------+                +-------+-------+                +-------+-------+
       |               |                |               |                |               |
       v               v                v               v                v               v
+-------------+ +-------------+  +-------------+ +-------------+  +-------------+ +-------------+
| 222233334444| | 333344445555|  | 444455556666| | 555566667777|  | 666677778888| | 777788889999|
| Security &  | | Shared      |  | Payment     | | Customer    |  | Dev         | | Staging     |
| Log Archive | | Services    |  | Processing  | | Database    |  | Sandbox     | | Cluster     |
+-------------+ +-------------+  +-------------+ +-------------+  +-------------+ +-------------+
                                                                                 |
                                                                                 | (Drift / Breach Detected)
                                                                                 v
                                                                    +-------------------------+
                                                                    |      Quarantine OU      |
                                                                    |  (Isolation Containment)|
                                                                    +------------+------------+
                                                                                 |
                                                                                 v
                                                                          +-------------+
                                                                          | 999900001111|
                                                                          | Compromised |
                                                                          | Member Host |
                                                                          +-------------+
```

---

## 3. Defense-in-Depth Strategy

| Layer | AWS Technology | Purpose & Mechanism |
| :--- | :--- | :--- |
| **Layer 1: Hard Prevention** | Service Control Policies (SCPs) | Applied at Organization Root and OU levels. Acts as immutable guardrails that even account root administrators cannot bypass. |
| **Layer 2: Continuous Detection** | AWS Config & GuardDuty | Ingests real-time configuration snapshots and behavioral threat indicators across all regions and member accounts. |
| **Layer 3: Event Routing** | Amazon EventBridge | Filters compliance state changes (`NON_COMPLIANT`) and security findings, routing events with sub-second latency. |
| **Layer 4: Self-Healing Remediation** | AWS Lambda & Boto3 | Executes targeted idempotent remediation (e.g., re-enabling S3 block public access, detaching rogue Internet Gateways). |
| **Layer 5: Automated Containment** | Organizations API | Dynamically moves high-risk/compromised accounts into the Quarantine OU, applying Deny-All policies to freeze the blast radius. |

---

## 4. Threat Matrix & Defense Mapping

```text
+------------------------------+------------------------------+------------------------------+
| Attack Vector / Risk         | Detection & Prevention       | Autonomous Remediation       |
+------------------------------+------------------------------+------------------------------+
| Data Residency Breach        | SCP 01: DenyUnapprovedRegions| Blocks API calls in non-us   |
| (Exfiltration to offshore)   | NotAction whitelist          | regions; logs CloudWatch     |
+------------------------------+------------------------------+------------------------------+
| Member Account Root Misuse   | SCP 02: DenyRootUserActions  | Completely blocks root user  |
| (Credential theft)           | StringLike aws:PrincipalArn  | interactive and CLI sessions |
+------------------------------+------------------------------+------------------------------+
| Security Telemetry Bypass    | SCP 03: ProtectSecServices   | Blocks trail stop/delete;    |
| (Adversary blinding audit)   | CloudTrail, GuardDuty, Config| Lambda restarts if stopped   |
+------------------------------+------------------------------+------------------------------+
| Shadow Perimeter Ingress     | SCP 04: RestrictIGWCreation  | Denies IGW creation without  |
| (Rogue Internet Gateway)     | RequestTag authorization     | tag; Lambda detaches rogue   |
+------------------------------+------------------------------+------------------------------+
| S3 Ransomware / Tampering    | SCP 05: S3RansomwareDefense  | Blocks Public Access removal |
| (Data encryption/wipe)       | ObjectLock governance deny   | and unauthorized deletions   |
+------------------------------+------------------------------+------------------------------+
| Total Account Compromise     | SCP 06: QuarantineLockdown   | Account moved to Quarantine; |
| (Lateral blast radius)       | Deny-All except IR Role      | zero egress/API access       |
+------------------------------+------------------------------+------------------------------+
```

---

## 5. Security & Isolation Invariants

1. **Root Account Invariance**: The management root account is never used for day-to-day operations and is governed by strict MFA and break-glass procedures.
2. **Deterministic Inheritance**: SCPs applied to parent OUs flow down transitively to all child accounts without exception.
3. **Emergency Break-Glass Role**: SCP 06 (Quarantine Isolation) explicitly maintains an exemption for `arn:aws:iam::*:role/EmergencyIncidentResponseRole` to enable SecOps forensics and remediation teams to inspect compromised environments.
